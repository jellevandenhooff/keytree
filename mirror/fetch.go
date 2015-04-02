package mirror

import (
	"errors"
	"sync"

	"golang.org/x/net/context"

	"github.com/jellevandenhooff/keytree/concurrency"
	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
)

type fetcher struct {
	ctx   context.Context
	p     *concurrency.PrioritySemaphore
	h     *concurrency.HashLocker
	dedup *trie.Dedup
	conn  *wire.KeyTreeClient
}

func hashWireTrieNode(node *wire.TrieNode) crypto.Hash {
	if node.Leaf != nil {
		return crypto.CombineHashes(node.Leaf.NameHash, node.Leaf.EntryHash)
	} else {
		return crypto.CombineHashes(node.ChildHashes[0], node.ChildHashes[1])
	}
}

func (f *fetcher) fetch(hash crypto.Hash, depth int, old *trie.Node) (*trie.Node, error) {
	if hash == crypto.EmptyHash {
		return nil, nil
	}

	concurrency.LockBoth(f.p.LockFor(depth), f.h.LockFor(hash))
	defer f.h.Unlock(hash)

	if err := f.ctx.Err(); err != nil {
		f.p.Release()
		return nil, err
	}

	if node := f.dedup.FindAndAdd(hash); node != nil {
		f.p.Release()
		return node, nil
	}

	node, err := f.conn.TrieNode(hash)
	f.p.Release()
	if err != nil {
		return old, err
	}

	if hashWireTrieNode(node) != hash {
		// TODO: don't recompute hash later on?
		return old, errors.New("bad hash")
	}

	if node.Leaf != nil {
		return f.dedup.Add(&trie.Node{
			Entry: node.Leaf,
		}), nil
	}

	hashes := node.ChildHashes

	oldChildren := old.Split(depth)
	var errs [2]error
	var children [2]*trie.Node

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			children[i], errs[i] = f.fetch(hashes[i], depth+1, oldChildren[i])
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

	return f.dedup.AddWithChildrenAlreadyAdded(trie.Merge(children)), err
}

type Coordinator struct {
	// read-only
	dedup *trie.Dedup
	h     *concurrency.HashLocker
}

func NewCoordinator(dedup *trie.Dedup) *Coordinator {
	return &Coordinator{
		dedup: dedup,
		h:     concurrency.NewHashLocker(),
	}
}

func (c *Coordinator) Fetch(ctx context.Context, conn *wire.KeyTreeClient, parallelism int, hash crypto.Hash, old *trie.Node) (*trie.Node, error) {
	fetcher := &fetcher{
		ctx:   ctx,
		conn:  conn,
		dedup: c.dedup,
		p:     concurrency.NewPrioritySemaphore(parallelism),
		h:     c.h,
	}

	return fetcher.fetch(hash, 0, old)
}
