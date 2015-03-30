//go:generate stringer -type=TrackingMode

package main

import (
	"errors"
	"log"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
	"golang.org/x/net/context"
)

type tracker struct {
	ctx    context.Context
	cancel context.CancelFunc
	// read-only
	conn               *wire.KeyTreeClient
	server             *Server
	address, publicKey string

	// resolve queue
	queue chan crypto.Hash
}

type TrackingMode int

const (
	AntiEntropy TrackingMode = iota
	Reconciling
	Following
)

type TrackingStatus struct {
	Mode TrackingMode

	Nodes             int
	ReconcilePosition crypto.Hash
}

func (t *tracker) fixer() error {
	for t.ctx.Err() == nil {
		select {
		case h := <-t.queue:
			t.fixup(h)
		case <-t.ctx.Done():
		}
	}
	return t.ctx.Err()
}

func (t *tracker) fixup(h crypto.Hash) {
	t.server.reconcileLocks.Lock(h)
	defer t.server.reconcileLocks.Unlock(h)

	localEntry, err := t.server.db.Read(h)
	if err != nil {
		log.Println(err)
		return
	}

	var since uint64
	if localEntry != nil {
		since = localEntry.Entry.Timestamp + 1
	}

	for {
		reply, err := t.conn.History(&wire.HistoryRequest{
			Hash:  h,
			Since: since,
		})
		if err != nil {
			log.Println(err)
			return
		}

		if reply.Update == nil {
			break
		}

		// Try applying all updates in order. If it doesn't work, keep trying
		// anyway!
		if err := t.server.doUpdate(reply.Update); err != nil {
			log.Println(err)
		}
		since = reply.Update.Entry.Timestamp + 1
	}
}

func areSameEntry(local, remote *trie.Node) bool {
	if local == nil && remote.Entry != nil {
		return true
	}

	if remote == nil && local.Entry != nil {
		return true
	}

	return local != nil && local.Entry != nil &&
		remote != nil && remote.Entry != nil &&
		local.Entry.NameHash == remote.Entry.NameHash
}

func (t *tracker) reconcile(local, remote *trie.Node, depth int) error {
	if err := t.ctx.Err(); err != nil {
		return err
	}

	if remote == nil || local.Hash() == remote.Hash() {
		return nil
	}

	if areSameEntry(local, remote) {
		select {
		case t.queue <- remote.Entry.NameHash:
		case <-t.ctx.Done():
		}
	} else {
		localChildren := local.Split(depth)
		remoteChildren := remote.Split(depth)
		for i := 0; i < 2; i++ {
			if err := t.reconcile(localChildren[i], remoteChildren[i], depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *tracker) track() error {
	for t.ctx.Err() == nil {
		root := t.server.getRootFor(t.publicKey)

		stream, err := t.conn.UpdateBatch(&wire.UpdateBatchRequest{
			RootHash: root.Hash(),
		})
		if err != nil {
			return err
		}

		batch := stream.UpdateBatch

		if err := crypto.Verify(t.publicKey, batch.NewRoot.Root, batch.NewRoot.Signature); err != nil {
			return err
		}

		newRoot := root
		for _, leaf := range batch.Updates {
			newRoot = newRoot.Set(leaf.NameHash, leaf)
		}
		newRoot = t.server.dedup.Add(newRoot)

		if newRoot.Hash() != batch.NewRoot.Root.RootHash {
			return errors.New("hash did not match NewRoot")
		}

		t.server.considerTrie(t.publicKey, newRoot, batch.NewRoot)

		for _, leaf := range batch.Updates {
			t.queue <- leaf.NameHash
		}
	}

	return t.ctx.Err()
}

func (t *tracker) fetchAntiEntropy() (*trie.Node, error) {
	reply, err := t.conn.Root(&wire.RootRequest{})
	if err != nil {
		return nil, err
	}

	if err := crypto.Verify(t.publicKey, reply.SignedRoot.Root, reply.SignedRoot.Signature); err != nil {
		return nil, err
	}

	// Extract hash and perform anti-entropy.
	rootHash := reply.SignedRoot.Root.RootHash

	// If we failed to completely download the trie, try to keep as much
	// data by merging in the old stored data.
	oldRoot := t.server.getRootFor(t.publicKey)

	root, err := t.server.coordinator.Fetch(t.ctx, t.conn, antiEntropyParallelism, rootHash, oldRoot)

	// Keep signature iff hash matches signature.
	var signedRoot *wire.SignedRoot
	if root.Hash() == rootHash {
		signedRoot = reply.SignedRoot
	}

	// Switch to the new root.
	t.server.considerTrie(t.publicKey, root, signedRoot)

	return root, err
}

func (t *tracker) run() error {
	for i := 0; i < fixerParallelism; i++ {
		go t.fixer()
	}

	for t.ctx.Err() == nil {
		err := t.track()
		if err.Error() == "not found" {
			log.Printf("performing anti-entropy for %s at %s\n", t.publicKey, t.address)
			for t.ctx.Err() == nil {
				root, err := t.fetchAntiEntropy()
				if err == nil {
					log.Printf("anti-entropy successful for %s at %s\n", t.publicKey, t.address)
					log.Printf("performing reconcile for %s at %s\n", t.publicKey, t.address)
					if err := t.reconcile(t.server.localTrie.root, root, 0); err != nil {
						log.Println("failed to reconcile for %s at %s: %s\n", t.publicKey, t.address, err)
					}
					break
				}

				if err.Error() == "not found" {
					continue // anti-entropy did not finish yet; try again
				} else if err != nil {
					log.Printf("anti-entropy failed with error %s for %s at %s\n", err, t.publicKey, t.address)
				}
			}
		} else if err != nil {
			log.Printf("tracking failed with error %s for %s at %s\n", err, t.publicKey, t.address)
		}
	}
	return t.ctx.Err()
}
