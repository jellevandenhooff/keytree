package mirror

import (
	"errors"
	"log"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
	"golang.org/x/net/context"
)

const fetchParallelism = 100

type TrieFollower interface {
	FullSync(*wire.SignedRoot, *trie.Node)
	Updated(*wire.SignedRoot, *trie.Node, []*wire.TrieLeaf)
}

type Mirror struct {
	ctx context.Context
	// read-only
	conn               *wire.KeyTreeClient
	address, publicKey string

	coordinator *Coordinator

	root *trie.Node

	follower TrieFollower
}

func (m *Mirror) track() error {
	for m.ctx.Err() == nil {
		root := m.root

		batch, err := m.conn.UpdateBatch(root.Hash())
		if err != nil {
			return err
		}

		if err := crypto.Verify(m.publicKey, batch.NewRoot.Root, batch.NewRoot.Signature); err != nil {
			return err
		}

		newRoot := root
		for _, leaf := range batch.Updates {
			newRoot = newRoot.Set(leaf.NameHash, leaf)
		}
		newRoot = m.coordinator.dedup.Add(newRoot)

		if newRoot.Hash() != batch.NewRoot.Root.RootHash {
			return errors.New("hash did not match NewRoot")
		}

		m.follower.Updated(batch.NewRoot, newRoot, batch.Updates)
		m.root = newRoot
	}

	return m.ctx.Err()
}

func (m *Mirror) fetch() error {
	signedRoot, err := m.conn.Root()
	if err != nil {
		return err
	}

	if err := crypto.Verify(m.publicKey, signedRoot.Root, signedRoot.Signature); err != nil {
		return err
	}

	// Extract hash and perform anti-entropy.
	rootHash := signedRoot.Root.RootHash

	// If we failed to completely download the trie, try to keep as much
	// data by merging in the old stored data.
	oldRoot := m.root
	root, err := m.coordinator.Fetch(m.ctx, m.conn, fetchParallelism, rootHash, oldRoot)

	// Keep signature iff hash matches signature.
	if root.Hash() == rootHash {
		m.follower.FullSync(signedRoot, root)
	}

	// Store root even if fetch did not succeed.
	m.root = root

	return err
}

func (m *Mirror) Run() error {
	for m.ctx.Err() == nil {
		err := m.track()
		if err == wire.ErrNotFound {
			log.Printf("performing anti-entropy for %s at %s\n", m.publicKey, m.address)
			for m.ctx.Err() == nil {
				err := m.fetch()
				if err == nil {
					log.Printf("anti-entropy successful for %s at %s\n", m.publicKey, m.address)
					log.Printf("performing reconcile for %s at %s\n", m.publicKey, m.address)
					break
				}

				if err == wire.ErrNotFound {
					continue // anti-entropy did not finish yet; try again
				} else if err != nil {
					log.Printf("anti-entropy failed with error %s for %s at %s\n", err, m.publicKey, m.address)
				}
			}
		} else if err != nil {
			log.Printf("tracking failed with error %s for %s at %s\n", err, m.publicKey, m.address)
		}
	}
	return m.ctx.Err()
}

func NewMirror(ctx context.Context, coordinator *Coordinator, conn *wire.KeyTreeClient, address, publicKey string, initial *trie.Node, follower TrieFollower) *Mirror {
	// Add refs?

	return &Mirror{
		ctx: ctx,

		conn:      conn,
		address:   address,
		publicKey: publicKey,

		coordinator: coordinator,

		root: initial,

		follower: follower,
	}
}
