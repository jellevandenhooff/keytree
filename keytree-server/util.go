package main

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
)

type hashLock struct {
	mu   sync.Mutex
	refs int
}

type hashLocker struct {
	mu    sync.Mutex
	locks map[crypto.Hash]*hashLock
}

func newHashLocker() *hashLocker {
	return &hashLocker{
		locks: make(map[crypto.Hash]*hashLock),
	}
}

func (h *hashLocker) Lock(hash crypto.Hash) {
	h.mu.Lock()
	l := h.locks[hash]
	if l == nil {
		l = new(hashLock)
		h.locks[hash] = l
	}
	l.refs += 1
	h.mu.Unlock()

	l.mu.Lock()
}

func (h *hashLocker) Unlock(hash crypto.Hash) {
	h.mu.Lock()
	defer h.mu.Unlock()

	l := h.locks[hash]
	l.mu.Unlock()

	l.refs -= 1
	if l.refs == 0 {
		delete(h.locks, hash)
	}
}
