package mirror

import (
	"container/heap"
	"errors"
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
	"golang.org/x/net/context"
)

// A worker represents an anti-entropy client session. Pending work is tracked wq,
// which sorts work items by depth, preferring nodes further from the root.
//
// To speed up downloads, worker runs multiple goroutines that each take work
// from wq. A worker keeps running even after wq is empty. To stop workers, set
// done to true and broadcast cond.
type worker struct {
	ctx context.Context

	// read-only
	conn        *wire.KeyTreeClient
	coordinator *Coordinator

	// work queue protected by mu
	mu   sync.Mutex
	cond *sync.Cond
	wq   workQueue
	old  map[*work]*trie.Node
}

func (worker *worker) getWork() (*work, *trie.Node, bool) {
	worker.mu.Lock()
	defer worker.mu.Unlock()

	for len(worker.wq) == 0 {
		if worker.ctx.Err() != nil {
			return nil, nil, false
		}

		worker.cond.Wait()
	}

	w := heap.Pop(&worker.wq).(*work)
	old := worker.old[w]
	delete(worker.old, w)
	return w, old, true
}

func (worker *worker) postWork(w *work, old *trie.Node) {
	worker.mu.Lock()
	defer worker.mu.Unlock()

	heap.Push(&worker.wq, w)
	worker.old[w] = old

	worker.cond.Signal()
}

// invariant: nodes returned from get have a dedup counted against them for this worker
// invariant: nodes returned in work have a dedup counted against them for every reference to the work

func (worker *worker) get(hash crypto.Hash, depth int, old *trie.Node) (*trie.Node, error) {
	if hash == crypto.EmptyHash {
		worker.coordinator.dedup.Add(old)
		return old, nil
	}

	if depth > crypto.HashBits {
		worker.coordinator.dedup.Add(old)
		return old, errors.New("too deep")
	}

	if node := worker.coordinator.dedup.FindAndAdd(hash); node != nil {
		return node, nil
	}

	for {
		w := worker.coordinator.findWork(hash, depth)
		worker.postWork(w, old)

		select {
		case <-w.done:
		case <-worker.ctx.Done():
			worker.coordinator.dedup.Add(old)
			return old, worker.ctx.Err()
		}

		// Invariant: we now have a ref on the node in w. This ref will
		// transfer to w.node in dedup, and we either pass that to our caller,
		// or clean it up ourselves.

		// Either return w.node, or remove the dedup ref.

		if w.err == nil {
			return w.node, nil
		} else if w.claimed != worker {
			// Lookup failed. We'll try again, because some other client
			// failed, and our server might still have the data.
			worker.coordinator.dedup.Remove(w.node)
			continue
		} else {
			// Lookup failed from our server. We'll return the (partial) result
			// so it can be reused.
			return w.node, w.err
		}
	}
}

func (worker *worker) run() {
	for worker.ctx.Err() == nil {
		w, old, ok := worker.getWork()
		if !ok {
			break
		}
		if w.claim(worker) {
			w.node, w.err = worker.do(w, old)
			worker.coordinator.finishWork(w)
		}
	}
}

func hashWireTrieNode(node *wire.TrieNode) crypto.Hash {
	if node.Leaf != nil {
		return crypto.CombineHashes(node.Leaf.NameHash, node.Leaf.EntryHash)
	} else {
		return crypto.CombineHashes(node.ChildHashes[0], node.ChildHashes[1])
	}
}

// Even if an inner get fails, we still store the partially fetched
// children so we can dedup the children and reuse them during future
// attempts!

func (worker *worker) do(w *work, old *trie.Node) (*trie.Node, error) {
	res, err := worker.conn.TrieNode(&wire.TrieNodeRequest{
		Hash: w.hash,
	})
	if err != nil {
		return old, err
	}

	node := res.Node

	if hashWireTrieNode(node) != w.hash {
		// TODO: don't recompute hash later on?
		return old, errors.New("bad hash")
	}

	if node.Leaf != nil {
		if err != nil {
			return old, err
		}
		return &trie.Node{
			Entry: node.Leaf,
		}, nil
	}

	hashes := node.ChildHashes

	oldChildren := old.Split(w.depth)
	var errs [2]error
	var children [2]*trie.Node

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			children[i], errs[i] = worker.get(hashes[i], w.depth+1, oldChildren[i])
			defer wg.Done()
		}(i)
	}
	wg.Wait()

	err = nil
	for i := 0; i < 2; i++ {
		if errs[i] != nil {
			err = errs[i]
			break
		}
	}

	return trie.Merge(children), err
}
