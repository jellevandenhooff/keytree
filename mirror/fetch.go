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

// A pendingNode represents a node to be fetched. Each node is uniquely identified by
// its hash.
//
// The depth is used to prioritize nodes further from the root.
//
// The result is stored in node and err, visible once done is closed.
//
// Only one fetcher downloads a given node. A fetcher claims a pendingNode
// piece by storing itself in claimed.
type pendingNode struct {
	// read-only
	hash  crypto.Hash
	depth int

	// information accessed only by coordinator
	refs int

	// claim information protected with mu
	mu      sync.Mutex
	claimed *fetcher

	// results protected by waiting for done
	done chan struct{}
	node *trie.Node
	err  error
}

func (pn *pendingNode) claim(fetcher *fetcher) bool {
	pn.mu.Lock()
	defer pn.mu.Unlock()

	if pn.claimed != nil {
		return false
	}
	pn.claimed = fetcher

	return true
}

// priority queue order: deeper nodes get resolved first
type queue []*pendingNode

func (q queue) Len() int           { return len(q) }
func (q queue) Less(a, b int) bool { return q[a].depth > q[b].depth }
func (q queue) Swap(a, b int)      { q[a], q[b] = q[b], q[a] }

func (q *queue) Push(x interface{}) {
	*q = append(*q, x.(*pendingNode))
}

func (q *queue) Pop() interface{} {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

// A Coordinator tracks nodes being fetched across multiple anti-entropy
// fetchers. Each such node is represented by a work item in pending. After
// fetching, it is removed from pending and stored in dedup.  A Coordinator is
// thread-safe.
//
// The basic coordination strategy is first-come, first-serve. Each
// anti-entropy fetcher prioritizes work as it sees fit, and no two fetchers
// download a work item at the same time. To ensure this, fetchers "claim" work
// items.
//
// If some fetchers claims a work item, but fails to download it, other
// fetchers interested in the item re-add it to the Coordinator. The fetcher
// that failed to download it gives up.
type Coordinator struct {
	// read-only
	dedup *trie.Dedup

	// pending work protected by mu
	mu      sync.Mutex
	pending map[crypto.Hash]*pendingNode
}

func NewCoordinator(dedup *trie.Dedup) *Coordinator {
	return &Coordinator{
		dedup:   dedup,
		pending: make(map[crypto.Hash]*pendingNode),
	}
}

func (c *Coordinator) findWork(h crypto.Hash, depth int) *pendingNode {
	c.mu.Lock()
	defer c.mu.Unlock()

	if pn, found := c.pending[h]; found {
		pn.refs += 1
		return pn
	}

	pn := &pendingNode{
		done:  make(chan struct{}),
		refs:  1,
		hash:  h,
		depth: depth,
	}

	c.pending[h] = pn

	return pn
}

func (c *Coordinator) finishWork(pn *pendingNode) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if pn.node != nil {
		pn.node = c.dedup.AddMany(pn.node, pn.refs)
		for i := 0; i < 2; i++ {
			c.dedup.Remove(pn.node.Children[i])
		}
	}

	close(pn.done)
	delete(c.pending, pn.hash)
}

func (c *Coordinator) Fetch(ctx context.Context, conn *wire.KeyTreeClient, parallelism int, hash crypto.Hash, old *trie.Node) (*trie.Node, error) {
	ctx, cancel := context.WithCancel(ctx)

	fetcher := &fetcher{
		ctx:         ctx,
		conn:        conn,
		coordinator: c,
		old:         make(map[*pendingNode]*trie.Node),
	}
	fetcher.cond = sync.NewCond(&fetcher.mu)

	for i := 0; i < parallelism; i++ {
		go fetcher.run()
	}

	node, err := fetcher.get(hash, 0, old)

	fetcher.mu.Lock()
	cancel()
	fetcher.cond.Broadcast()
	fetcher.mu.Unlock()

	return node, err
}

// A fetcher represents an anti-entropy client session. Pending work is tracked q,
// which sorts work items by depth, preferring nodes further from the root.
//
// To speed up downloads, fetcher runs multiple goroutines that each take work
// from q. A fetcher keeps running even after q is empty. To stop fetcher, set
// done to true and broadcast cond.
//
// Even if an inner get fails, we still store the partially fetched
// children so we can dedup the children and reuse them during future
// attempts!
type fetcher struct {
	ctx context.Context

	// read-only
	conn        *wire.KeyTreeClient
	coordinator *Coordinator

	// work queue protected by mu
	mu   sync.Mutex
	cond *sync.Cond
	q    queue
	old  map[*pendingNode]*trie.Node
}

func (fetcher *fetcher) getWork() (*pendingNode, *trie.Node, bool) {
	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()

	for len(fetcher.q) == 0 {
		if fetcher.ctx.Err() != nil {
			return nil, nil, false
		}

		fetcher.cond.Wait()
	}

	pn := heap.Pop(&fetcher.q).(*pendingNode)
	old := fetcher.old[pn]
	delete(fetcher.old, pn)
	return pn, old, true
}

func (fetcher *fetcher) postWork(pn *pendingNode, old *trie.Node) {
	fetcher.mu.Lock()
	defer fetcher.mu.Unlock()

	heap.Push(&fetcher.q, pn)
	fetcher.old[pn] = old

	fetcher.cond.Signal()
}

// invariant: nodes returned from get have a dedup counted against them for this fetcher
// invariant: nodes returned in work have a dedup counted against them for every reference to the work

func (fetcher *fetcher) get(hash crypto.Hash, depth int, old *trie.Node) (*trie.Node, error) {
	if hash == crypto.EmptyHash {
		fetcher.coordinator.dedup.Add(old)
		return old, nil
	}

	if depth > crypto.HashBits {
		fetcher.coordinator.dedup.Add(old)
		return old, errors.New("too deep")
	}

	if node := fetcher.coordinator.dedup.FindAndAdd(hash); node != nil {
		return node, nil
	}

	for {
		pn := fetcher.coordinator.findWork(hash, depth)
		fetcher.postWork(pn, old)

		select {
		case <-pn.done:
		case <-fetcher.ctx.Done():
			fetcher.coordinator.dedup.Add(old)
			return old, fetcher.ctx.Err()
		}

		// Invariant: we now have a ref on the node in pn. This ref will
		// transfer to pn.node in dedup, and we either pass that to our caller,
		// or clean it up ourselves.

		// Either return pn.node, or remove the dedup ref.

		if pn.err == nil {
			return pn.node, nil
		} else if pn.claimed != fetcher {
			// Lookup failed. We'll try again, because some other client
			// failed, and our server might still have the data.
			fetcher.coordinator.dedup.Remove(pn.node)
			continue
		} else {
			// Lookup failed from our server. We'll return the (partial) result
			// so it can be reused.
			return pn.node, pn.err
		}
	}
}

func (fetcher *fetcher) run() {
	for fetcher.ctx.Err() == nil {
		pn, old, ok := fetcher.getWork()
		if !ok {
			break
		}
		if pn.claim(fetcher) {
			pn.node, pn.err = fetcher.do(pn, old)
			fetcher.coordinator.finishWork(pn)
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

func (fetcher *fetcher) do(pn *pendingNode, old *trie.Node) (*trie.Node, error) {
	node, err := fetcher.conn.TrieNode(pn.hash)
	if err != nil {
		return old, err
	}

	if hashWireTrieNode(node) != pn.hash {
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

	oldChildren := old.Split(pn.depth)
	var errs [2]error
	var children [2]*trie.Node

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			children[i], errs[i] = fetcher.get(hashes[i], pn.depth+1, oldChildren[i])
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
