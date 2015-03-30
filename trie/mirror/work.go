package mirror

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
)

// A work represents a node to be fetched. Each node is uniquely identified by
// its hash.
//
// The depth is used to prioritize nodes further from the root.
//
// The result of the work item is stored in node and err, visible once done is
// closed.
//
// Only one anti-entropy client downloads a given node. A client claims a work
// piece by storing its client in claimed.
type work struct {
	// read-only
	hash  crypto.Hash
	depth int

	// information accessed only by coordinator
	refs int

	// claim information protected with mu
	mu      sync.Mutex
	claimed *worker

	// results protected by waiting for done
	done chan struct{}
	node *trie.Node
	err  error
}

func (w *work) claim(worker *worker) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.claimed != nil {
		return false
	}
	w.claimed = worker

	return true
}

// priority queue order: deeper nodes get resolved first
type workQueue []*work

func (wq workQueue) Len() int           { return len(wq) }
func (wq workQueue) Less(a, b int) bool { return wq[a].depth > wq[b].depth }
func (wq workQueue) Swap(a, b int)      { wq[a], wq[b] = wq[b], wq[a] }

func (wq *workQueue) Push(x interface{}) {
	*wq = append(*wq, x.(*work))
}

func (wq *workQueue) Pop() interface{} {
	old := *wq
	n := len(old)
	x := old[n-1]
	*wq = old[0 : n-1]
	return x
}
