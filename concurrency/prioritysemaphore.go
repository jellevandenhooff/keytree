package concurrency

import (
	"container/heap"
	"sync"
)

type pending struct {
	priority int
	c        chan struct{}
}

type queue []*pending

func (q queue) Len() int           { return len(q) }
func (q queue) Less(a, b int) bool { return q[a].priority > q[b].priority }
func (q queue) Swap(a, b int)      { q[a], q[b] = q[b], q[a] }

func (q *queue) Push(x interface{}) {
	*q = append(*q, x.(*pending))
}

func (q *queue) Pop() interface{} {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

type PrioritySemaphore struct {
	mu sync.Mutex

	capacity int
	waiting  queue
}

func NewPrioritySemaphore(capacity int) *PrioritySemaphore {
	return &PrioritySemaphore{
		capacity: capacity,
	}
}

func (p *PrioritySemaphore) Acquire(priority int) {
	p.mu.Lock()
	if p.capacity > 0 {
		p.capacity -= 1
		p.mu.Unlock()
		return
	}

	c := make(chan struct{})
	heap.Push(&p.waiting, &pending{priority: priority, c: c})
	p.mu.Unlock()

	<-c
}

func (p *PrioritySemaphore) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.waiting) > 0 {
		pending := heap.Pop(&p.waiting).(*pending)
		close(pending.c)
	} else {
		p.capacity += 1
	}
}

func (p *PrioritySemaphore) TryAcquire() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.capacity > 0 {
		p.capacity -= 1
		return true
	}
	return false
}

type prioritySemaphoreLock struct {
	p        *PrioritySemaphore
	priority int
}

func (l *prioritySemaphoreLock) Lock() {
	l.p.Acquire(l.priority)
}

func (l *prioritySemaphoreLock) Unlock() {
	l.p.Release()
}

func (l *prioritySemaphoreLock) TryLock() bool {
	return l.p.TryAcquire()
}

func (p *PrioritySemaphore) LockFor(priority int) TryLock {
	return &prioritySemaphoreLock{
		p:        p,
		priority: priority,
	}
}
