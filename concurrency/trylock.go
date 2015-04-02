package concurrency

type TryLock interface {
	Lock()
	Unlock()
	TryLock() bool
}

func LockBoth(a, b TryLock) {
	for {
		a.Lock()
		if b.TryLock() {
			return
		}
		a.Unlock()
		b.Lock()
		if a.TryLock() {
			return
		}
		b.Unlock()
	}
}
