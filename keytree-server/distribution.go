package main

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
)

type updateCache struct {
	mu   sync.RWMutex
	cond *sync.Cond

	current crypto.Hash
	batches map[crypto.Hash]*wire.UpdateBatch

	hashes []crypto.Hash
	index  int
}

func newUpdateCache(current crypto.Hash) *updateCache {
	cache := &updateCache{
		current: current,
		batches: make(map[crypto.Hash]*wire.UpdateBatch),
		hashes:  make([]crypto.Hash, updateBatchBacklog),
		index:   0,
	}
	cache.cond = sync.NewCond(cache.mu.RLocker())
	return cache
}

func (ub *updateCache) get(hash crypto.Hash) (*wire.UpdateBatch, bool) {
	ub.mu.RLock()
	defer ub.mu.RUnlock()

	if ub.current == hash {
		ub.cond.Wait()
	}

	batch, found := ub.batches[hash]
	if !found {
		return nil, false
	}

	return batch, true
}

func (ub *updateCache) add(hash crypto.Hash, batch *wire.UpdateBatch) {
	ub.mu.Lock()
	defer ub.mu.Unlock()

	delete(ub.batches, ub.hashes[ub.index])
	ub.batches[ub.current] = batch
	ub.hashes[ub.index] = ub.current

	if hash != ub.current {
		ub.index = (ub.index + 1) % len(ub.hashes)
		ub.current = hash
	}

	ub.cond.Broadcast()
}

// A trieCache keeps dedup references on a set of recent tries. This helps
// other servers download snapshots of tries by keeping their snapshot in
// memory. A trieCache is not threadsafe.
//
// The tries are stored in a last-in first-out circular queue.
type trieCache struct {
	// Backing dedup.
	dedup *trie.Dedup

	// Recent tries. Initially, all tries are nil.
	recentTries []*trie.Node

	// Index points to the last added trie.
	index int
}

// Construct a new trieCache using dedup with given capacity.
func newTrieCache(dedup *trie.Dedup, capacity int) *trieCache {
	return &trieCache{
		dedup:       dedup,
		recentTries: make([]*trie.Node, capacity),
		index:       0,
	}
}

// Add a new trie to the trieCache and remove the oldest trie. Returns the
// dedup'd trie.
func (t *trieCache) setCurrentTrie(root *trie.Node) *trie.Node {
	// If the trie is the same the current trie, do not add it.
	if t.recentTries[t.index].Hash() == root.Hash() {
		return t.recentTries[t.index]
	}

	// Add the root to dedup before removing the old trie, so that if they are
	// mostly the same we keep the shared nodes in dedup.
	root = t.dedup.Add(root)

	// Find spot for new trie, remove the old one, and store the new trie.
	t.index = (t.index + 1) % len(t.recentTries)
	t.dedup.Remove(t.recentTries[t.index])
	t.recentTries[t.index] = root

	return root
}
