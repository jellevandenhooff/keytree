//go:generate stringer -type=TrackingMode

package main

import (
	"log"
	"net/rpc"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/mirror"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
	"golang.org/x/net/context"
)

type tracker struct {
	ctx context.Context

	mirror *mirror.Mirror

	conn               *wire.KeyTreeClient
	server             *Server
	address, publicKey string

	// resolve queue
	queue chan crypto.Hash
}

func (t *tracker) FullSync(s *wire.SignedRoot, n *trie.Node) {
	t.server.considerTrie(t.publicKey, n, s)

	t.server.mu.Lock()
	localRoot := t.server.localTrie.root
	t.server.mu.Unlock()

	_ = t.reconcile(localRoot, n, 0)
}

func (t *tracker) Updated(s *wire.SignedRoot, n *trie.Node, u []*wire.TrieLeaf) {
	t.server.considerTrie(t.publicKey, n, s)

	for _, leaf := range u {
		t.queue <- leaf.NameHash
	}
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

func runTracker(ctx context.Context, s *Server, address string, publicKey string) (*tracker, error) {
	log.Printf("spawning tracker for %s at %s", publicKey, address)

	client, err := rpc.DialHTTP("tcp", address)
	if err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		client.Close()
	}()

	conn := wire.NewKeyTreeClient(client)

	t := &tracker{
		ctx:       ctx,
		conn:      conn,
		server:    s,
		address:   address,
		publicKey: publicKey,
		queue:     make(chan crypto.Hash, reconcileQueueSize),
	}

	t.mirror = mirror.NewMirror(ctx, s.coordinator, conn, address, publicKey,
		nil, t)

	for i := 0; i < fixerParallelism; i++ {
		go t.fixer()
	}
	go t.mirror.Run()

	return t, nil
}
