package concurrency

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
)

type hashLock struct {
	mu   sync.Mutex
	refs int
}

type HashLocker struct {
	mu    sync.Mutex
	locks map[crypto.Hash]*hashLock
}

func NewHashLocker() *HashLocker {
	return &HashLocker{
		locks: make(map[crypto.Hash]*hashLock),
	}
}

func (h *HashLocker) Lock(hash crypto.Hash) {
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

func (h *HashLocker) Unlock(hash crypto.Hash) {
	h.mu.Lock()
	defer h.mu.Unlock()

	l := h.locks[hash]
	l.mu.Unlock()

	l.refs -= 1
	if l.refs == 0 {
		delete(h.locks, hash)
	}
}

func (h *HashLocker) TryLock(hash crypto.Hash) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, found := h.locks[hash]; found {
		return false
	}

	l := new(hashLock)
	h.locks[hash] = l
	l.refs += 1
	l.mu.Lock()

	return true
}

type hashLockerLock struct {
	h    *HashLocker
	hash crypto.Hash
}

func (l *hashLockerLock) Lock() {
	l.h.Lock(l.hash)
}

func (l *hashLockerLock) Unlock() {
	l.h.Unlock(l.hash)
}

func (l *hashLockerLock) TryLock() bool {
	return l.h.TryLock(l.hash)
}

func (h *HashLocker) LockFor(hash crypto.Hash) TryLock {
	return &hashLockerLock{
		h:    h,
		hash: hash,
	}
}
