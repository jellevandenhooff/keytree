package mirror

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/trie/dedup"
	"github.com/jellevandenhooff/keytree/wire"
	"golang.org/x/net/context"
)

// A Coordinator tracks nodes being fetched across multiple anti-entropy
// clients. Each such node is represented by a work item in pending. After
// fetching, it is removed from pending and stored in dedup.
// A Coordinator is thread-safe.
//
// The basic coordination strategy is first-come, first-serve. Each anti-entropy
// client prioritizes work as it sees fit, and no two clients download a work
// item at the same time. To ensure this, clients "claim" work items.
//
// If some client claims a work item, but fails to download it, other clients
// interested in the item re-add it to the Coordinator. The client that failed
// to download it gives up.
type Coordinator struct {
	// read-only
	dedup *dedup.Dedup

	// pending work protected by mu
	mu      sync.Mutex
	pending map[crypto.Hash]*work
}

func NewCoordinator(dedup *dedup.Dedup) *Coordinator {
	return &Coordinator{
		dedup:   dedup,
		pending: make(map[crypto.Hash]*work),
	}
}

func (c *Coordinator) findWork(h crypto.Hash, depth int) *work {
	c.mu.Lock()
	defer c.mu.Unlock()

	if w, found := c.pending[h]; found {
		w.refs += 1
		return w
	}

	w := &work{
		done:  make(chan struct{}),
		refs:  1,
		hash:  h,
		depth: depth,
	}

	c.pending[h] = w

	return w
}

func (c *Coordinator) finishWork(w *work) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if w.node != nil {
		w.node = c.dedup.AddMany(w.node, w.refs)
		for i := 0; i < 2; i++ {
			c.dedup.Remove(w.node.Children[i])
		}
	}

	close(w.done)
	delete(c.pending, w.hash)
}

func (c *Coordinator) Fetch(ctx context.Context, conn *wire.KeyTreeClient, parallelism int, hash crypto.Hash, old *trie.Node) (*trie.Node, error) {
	ctx, cancel := context.WithCancel(ctx)

	worker := &worker{
		ctx:         ctx,
		conn:        conn,
		coordinator: c,
		old:         make(map[*work]*trie.Node),
	}
	worker.cond = sync.NewCond(&worker.mu)

	for i := 0; i < parallelism; i++ {
		go worker.run()
	}

	node, err := worker.get(hash, 0, old)

	worker.mu.Lock()
	cancel()
	worker.cond.Broadcast()
	worker.mu.Unlock()

	return node, err
}
