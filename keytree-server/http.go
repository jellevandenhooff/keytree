package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/jellevandenhooff/keytree/crypto"
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

func replyJSON(w http.ResponseWriter, v interface{}) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
}

func (s *Server) handleTrieNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := crypto.HashFromString(r.URL.Query().Get("hash"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	node := s.dedup.FindAndDoNotAdd(hash)

	if node == nil {
		http.NotFound(w, r)
		return
	}

	if node.Entry != nil {
		replyJSON(w, &wire.TrieNode{
			Leaf: node.Entry,
		})
	} else {
		replyJSON(w, &wire.TrieNode{
			ChildHashes: &[2]crypto.Hash{node.Children[0].Hash(), node.Children[1].Hash()},
		})
	}
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

	replyJSON(w, &wire.LookupReply{
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

	replyJSON(w, entries)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	hash, err := parseNameOrHash(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Println(hash)

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

	replyJSON(w, update)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
	}

	/*
		replyJSON(w, &Status{
			PublicKey:  s.config.PublicKey,
			Upstream:   s.config.Upstream,
			TotalNodes: s.dedup.NumNodes(),
		})
	*/
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

	replyJSON(w, err)
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
		http.NotFound(w, r)
		return
	}

	replyJSON(w, batch)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	s.mu.Lock()
	defer s.mu.Unlock()

	replyJSON(w, s.localTrie.signedRoot)
}

func (s *Server) addHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.handleIndex(w, r)
	})

	mux.HandleFunc("/lookup", func(w http.ResponseWriter, r *http.Request) {
		s.handleLookup(w, r)
	})

	mux.HandleFunc("/updatebatch", func(w http.ResponseWriter, r *http.Request) {
		s.handleUpdateBatch(w, r)
	})

	mux.HandleFunc("/root", func(w http.ResponseWriter, r *http.Request) {
		s.handleRoot(w, r)
	})

	mux.HandleFunc("/trienode", func(w http.ResponseWriter, r *http.Request) {
		s.handleTrieNode(w, r)
	})

	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		s.handleHistory(w, r)
	})

	mux.HandleFunc("/browse", func(w http.ResponseWriter, r *http.Request) {
		s.handleBrowse(w, r)
	})

	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		s.handleSubmit(w, r)
	})
}
