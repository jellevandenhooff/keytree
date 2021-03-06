package main

import (
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/jellevandenhooff/keytree/concurrency"
	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/mirror"
	"github.com/jellevandenhooff/keytree/rules"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/unixtime"
	"github.com/jellevandenhooff/keytree/wire"

	"golang.org/x/net/context"
)

type lookupTrie struct {
	root       *trie.Node
	signedRoot *wire.SignedRoot
}

type updateRequest struct {
	update *wire.SignedEntry
	result chan error
}

type Server struct {
	// configuration
	config *Config
	signer *crypto.Signer

	// global instances
	dedup       *trie.Dedup
	coordinator *mirror.Coordinator // anti-entropy coordinator
	verifier    *rules.Verifier     // update verifier
	db          DB                  // stores all data for the current local trie, thread-safe

	// updates and distribution
	updateCache    *updateCache       // provides channels with updates
	trieCache      *trieCache         // local recent trie tracker
	updateRequests chan updateRequest // channel to the update thread

	reconcileLocks *concurrency.HashLocker

	mu        sync.Mutex
	localTrie *lookupTrie            // latest version of data, not thread-safe
	allTries  map[string]*lookupTrie // combination of all tries
	trackers  map[string]*tracker    // tracking remote servers
}

func (s *Server) doUpdate(update *wire.SignedEntry) error {
	c := make(chan error, 1)
	s.updateRequests <- updateRequest{update: update, result: c}
	return <-c
}

func (s *Server) setAndSignRoot(newRoot *trie.Node) {
	// s must be locked

	newRoot = s.trieCache.setCurrentTrie(newRoot)

	timestampedRoot := &wire.Root{
		RootHash:  newRoot.Hash(),
		Timestamp: unixtime.Now(),
	}

	s.localTrie = &lookupTrie{
		root: newRoot,
		signedRoot: &wire.SignedRoot{
			Root:      timestampedRoot,
			Signature: s.signer.Sign(timestampedRoot),
		},
	}

	s.allTries[s.config.PublicKey] = s.localTrie
}

func (s *Server) processUpdates() {
	newRoot := s.localTrie.root
	pendingUpdates := make([]*wire.SignedEntry, 0)
	pending := make(map[crypto.Hash]*wire.Entry)

	flushTimer := time.After(noFlushUpdateInterval)

	for {
		select {
		case req := <-s.updateRequests:
			update := req.update

			if err := rules.CheckUpdate(update); err != nil {
				req.result <- err
				break
			}

			var oldEntry *wire.Entry
			leaf := update.Entry.ToLeaf()

			if pendingEntry, found := pending[leaf.NameHash]; found {
				oldEntry = pendingEntry
			} else {
				oldUpdate, err := s.db.Read(leaf.NameHash)
				if err != nil {
					req.result <- err
					break
				}
				if oldUpdate != nil {
					oldEntry = oldUpdate.Entry
				}
			}

			var window rules.Window
			now := unixtime.Now()
			if catchUpRecoveryEnabled {
				window = rules.Window{
					Start: catchUpRecoveryCutoff - 15*60,
					End:   now + 15*60,
				}
			} else {
				window = rules.Window{
					Start: now - 15*60,
					End:   now + 15*60,
				}
			}

			if err := s.verifier.VerifyUpdate(oldEntry, update, window); err != nil {
				req.result <- err
				break
			}

			if len(pendingUpdates) == 0 {
				flushTimer = time.After(updateFlushInterval)
			}

			newRoot = newRoot.Set(leaf.NameHash, leaf)
			pendingUpdates = append(pendingUpdates, update)
			pending[leaf.NameHash] = update.Entry
			req.result <- nil

		case _ = <-flushTimer:
			newRoot.ParallelHash(runtime.NumCPU())
			if err := s.db.PerformUpdates(pendingUpdates); err != nil {
				log.Printf("flushing failed: %s\n", err)
				newRoot = s.localTrie.root
				pendingUpdates = nil
			}

			leaves := make([]*wire.TrieLeaf, len(pendingUpdates))
			for i, update := range pendingUpdates {
				leaves[i] = update.Entry.ToLeaf()
			}

			s.mu.Lock()
			s.setAndSignRoot(newRoot)
			batch := &wire.UpdateBatch{
				NewRoot: s.localTrie.signedRoot,
				Updates: leaves,
			}
			s.updateCache.add(newRoot.Hash(), batch)
			s.mu.Unlock()

			newRoot = s.localTrie.root
			pendingUpdates = nil
			pending = make(map[crypto.Hash]*wire.Entry)

			flushTimer = time.After(noFlushUpdateInterval)
		}
	}
}

func (s *Server) getRootFor(publicKey string) *trie.Node {
	s.mu.Lock()
	defer s.mu.Unlock()

	if trie, found := s.allTries[publicKey]; found {
		return trie.root
	}
	return nil
}

func (s *Server) considerTrie(publicKey string, root *trie.Node, signedRoot *wire.SignedRoot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	root = s.dedup.Add(root)

	if trie, found := s.allTries[publicKey]; found {
		s.dedup.Remove(trie.root)
	}

	s.allTries[publicKey] = &lookupTrie{
		root:       root,
		signedRoot: signedRoot,
	}
}

func (s *Server) cleanOldTries() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := unixtime.Now() - 60*10

	for publicKey, trie := range s.allTries {
		if trie.signedRoot.Root.Timestamp < cutoff && s.trackers[publicKey] == nil {
			s.dedup.Remove(trie.root)
			delete(s.allTries, publicKey)
		}
	}
}

func (s *Server) spawnTrackers(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, serverInfo := range s.config.Upstream {
		s.trackers[serverInfo.PublicKey] = runTracker(ctx, s, serverInfo.Address, serverInfo.PublicKey)
	}
}

func (s *Server) follow(ctx context.Context) error {
	s.spawnTrackers(ctx)
	for ctx.Err() == nil {
		s.cleanOldTries()
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
		}
	}
	return ctx.Err()
}
