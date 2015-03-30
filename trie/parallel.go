package trie

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
)

func (n *Node) ParallelHash(m int) crypto.Hash {
	if n == nil {
		return crypto.EmptyHash
	}

	work := []*Node{n}
	for len(work) < m {
		if work[0].Children[0] == nil || work[0].Children[1] == nil {
			break
		}
		work = append(work[1:], work[0].Children[0], work[0].Children[1])
	}
	m = len(work)

	var wg sync.WaitGroup
	wg.Add(m)

	for i := 0; i < m; i++ {
		go func(i int) {
			work[i].Hash()
			wg.Done()
		}(i)
	}

	wg.Wait()

	return n.Hash()
}
