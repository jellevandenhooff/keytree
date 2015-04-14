package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
	"github.com/jellevandenhooff/keytree/wire"
)

var ErrExpectedNameOrHash = errors.New("expected name or hash in query")

func parseNameOrHash(r *http.Request) (crypto.Hash, error) {
	hashString := r.URL.Query().Get("hash")
	nameString := r.URL.Query().Get("name")

	if hashString != "" && nameString != "" {
		return crypto.EmptyHash, errors.New("expected either name or hash in query; not both")
	}

	if hashString == "" && nameString == "" {
		return crypto.EmptyHash, ErrExpectedNameOrHash
	}

	if hashString != "" {
		return crypto.HashFromString(hashString)
	}
	return crypto.HashString(nameString), nil
}

func fetch(node *trie.Node, depth int) *wire.TrieNode {
	if node == nil {
		return nil
	}

	if node.Entry != nil {
		return &wire.TrieNode{
			Leaf: node.Entry,
		}
	}

	if depth == 0 {
		return &wire.TrieNode{
			ChildHashes: &[2]crypto.Hash{node.Children[0].Hash(), node.Children[1].Hash()},
		}
	} else {
		return &wire.TrieNode{
			Children: &[2]*wire.TrieNode{fetch(node.Children[0], depth-1), fetch(node.Children[1], depth-1)},
		}
	}
}

func (s *Server) handleTrieNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := crypto.HashFromString(r.URL.Query().Get("hash"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	depthString := r.URL.Query().Get("depth")
	var depth int
	if depthString == "" {
		depth = 0
	} else {
		var err error
		depth, err = strconv.Atoi(depthString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if depth < 0 || depth > 4 {
		http.Error(w, "depth out of range", http.StatusBadRequest)
		return
	}

	node := s.dedup.FindAndDoNotAdd(hash)
	wire.ReplyJSON(w, fetch(node, depth))
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := parseNameOrHash(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	update, err := s.db.Read(hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var entry *wire.Entry
	if update != nil {
		entry = update.Entry
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	lookups := make(map[string]*wire.SignedTrieLookup)

	for publicKey, trie := range s.allTries {
		lookup, leaf := trie.root.Lookup(hash)
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

	wire.ReplyJSON(w, &wire.LookupReply{
		Entry:             entry,
		SignedTrieLookups: lookups,
	})
}

func (s *Server) handleBrowse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := parseNameOrHash(r)
	if err == ErrExpectedNameOrHash {
		hash = crypto.EmptyHash
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var entries []*wire.Entry

	s.mu.Lock()
	root := s.localTrie.root
	s.mu.Unlock()

	for i := 0; i < 10; i++ {
		leaf := root.NextLeaf(hash)
		if leaf == nil {
			break
		}

		update, err := s.db.Read(leaf.NameHash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		entries = append(entries, update.Entry)
		hash = leaf.NameHash
	}

	wire.ReplyJSON(w, entries)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := parseNameOrHash(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sinceString := r.URL.Query().Get("since")
	var since uint64
	if sinceString != "" {
		sinceInt, err := strconv.Atoi(sinceString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		since = uint64(sinceInt)
	} else {
		since = 0
	}

	update, err := s.db.ReadSince(hash, since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wire.ReplyJSON(w, update)
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	var update *wire.SignedEntry
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := update.Check(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := s.doUpdate(update)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wire.ReplyJSON(w, err)
}

func (s *Server) handleUpdateBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := crypto.HashFromString(r.URL.Query().Get("hash"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	batch, ok := s.updateCache.get(hash)
	if !ok {
		wire.ReplyJSON(w, nil)
		return
	}

	wire.ReplyJSON(w, batch)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	s.mu.Lock()
	defer s.mu.Unlock()

	wire.ReplyJSON(w, s.localTrie.signedRoot)
}

func (s *Server) addHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/keytree/lookup", func(w http.ResponseWriter, r *http.Request) {
		s.handleLookup(w, r)
	})

	mux.HandleFunc("/keytree/updatebatch", func(w http.ResponseWriter, r *http.Request) {
		s.handleUpdateBatch(w, r)
	})

	mux.HandleFunc("/keytree/root", func(w http.ResponseWriter, r *http.Request) {
		s.handleRoot(w, r)
	})

	mux.HandleFunc("/keytree/trienode", func(w http.ResponseWriter, r *http.Request) {
		s.handleTrieNode(w, r)
	})

	mux.HandleFunc("/keytree/history", func(w http.ResponseWriter, r *http.Request) {
		s.handleHistory(w, r)
	})

	mux.HandleFunc("/keytree/browse", func(w http.ResponseWriter, r *http.Request) {
		s.handleBrowse(w, r)
	})

	mux.HandleFunc("/keytree/submit", func(w http.ResponseWriter, r *http.Request) {
		s.handleSubmit(w, r)
	})
}
