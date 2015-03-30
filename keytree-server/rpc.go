package main

import (
	"errors"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/wire"
)

func (s *Server) TrieNode(req *wire.TrieNodeRequest, reply *wire.TrieNodeReply) error {
	if err := req.Check(); err != nil {
		return err
	}

	node := s.dedup.FindAndDoNotAdd(req.Hash)

	if node == nil {
		return errors.New("not found")
	}

	if node.Entry != nil {
		reply.Node = &wire.TrieNode{
			Leaf: node.Entry,
		}
	} else {
		reply.Node = &wire.TrieNode{
			ChildHashes: &[2]crypto.Hash{node.Children[0].Hash(), node.Children[1].Hash()},
		}
	}
	return nil
}

func (s *Server) UpdateBatch(req *wire.UpdateBatchRequest, reply *wire.UpdateBatchReply) error {
	if err := req.Check(); err != nil {
		return err
	}

	batch, err := s.updateCache.get(req.RootHash)
	if err != nil {
		return err
	}

	reply.UpdateBatch = batch
	return nil
}

func (s *Server) Lookup(req *wire.LookupRequest, reply *wire.LookupReply) error {
	if err := req.Check(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Lookup the entry locally. Then perform the lookup in all requested
	// tries, and return all those that agree.

	// For all known requested tries, perform this lookup. Return the majority entry.

	update, err := s.db.Read(req.Hash)
	if err != nil {
		return err
	}
	var entry *wire.Entry
	if update != nil {
		entry = update.Entry
	}

	lookups := make(map[string]*wire.SignedTrieLookup)

	for _, publicKey := range req.PublicKeys {
		trie, found := s.allTries[publicKey]
		if !found || trie.signedRoot == nil {
			continue
		}

		lookup, leaf := trie.root.Lookup(req.Hash)
		var leafHash crypto.Hash
		if leaf != nil {
			leafHash = leaf.EntryHash
		}

		if leafHash == entry.Hash() {
			lookups[publicKey] = &wire.SignedTrieLookup{
				SignedRoot: trie.signedRoot,
				TrieLookup: lookup,
			}
		}
	}

	reply.Entry = entry
	reply.SignedTrieLookups = lookups
	return nil
}

func (s *Server) Update(req *wire.UpdateRequest, reply *wire.UpdateReply) error {
	if err := req.Check(); err != nil {
		return err
	}

	return s.doUpdate(req.SignedEntry)
}

func (s *Server) History(req *wire.HistoryRequest, reply *wire.HistoryReply) error {
	if err := req.Check(); err != nil {
		return err
	}

	update, err := s.db.ReadSince(req.Hash, req.Since)
	if err != nil {
		return err
	}

	reply.Update = update
	return nil
}

func (s *Server) Root(req *wire.RootRequest, reply *wire.RootReply) error {
	if err := req.Check(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	reply.SignedRoot = s.localTrie.signedRoot
	return nil
}
