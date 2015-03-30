package trie

import (
	"fmt"
	"math/rand"

	"github.com/jellevandenhooff/keytree"
	"github.com/jellevandenhooff/keytree/crypto"
)
import "testing"

func makeEntries(n int) []*keytree.Entry {
	l := make([]*keytree.Entry, n)

	for i := 0; i < n; i += 1 {
		name := fmt.Sprintf("%d", rand.Int63())

		entry := &keytree.Entry{
			Name: name,
		}

		l[i] = entry
	}

	return l
}

func testLookup(t *testing.T, r *Node, k crypto.Hash, e *keytree.Entry, o *keytree.Entry) {
	if r.Get(k) != e {
		t.Errorf("uh oh get is broken")
	}

	l, f := r.Lookup(k)
	if l.CompleteLookup(k, e.Hash()) != r.Hash() {
		t.Errorf("uh oh lookup is broken (bad lookup)")
	}
	if f != e {
		t.Errorf("uh oh lookup is broken (bad entry)")
	}

	if l.CompleteLookup(k, o.Hash()) != r.Set(k, o).Hash() {
		t.Errorf("uh oh lookup is broken (bad adjust)")
	}
}

func TestStressTrieRandomly(t *testing.T) {
	n := 100
	m := 1000

	if testing.Short() {
		n = 10
		m = 100
	}

	l := makeEntries(n)

	var root *Node
	rep := make(map[crypto.Hash]*keytree.Entry)

	for i := 0; i < m; i++ {
		if rand.Intn(2) == 0 {
			e := l[rand.Intn(len(l))]
			root = root.Set(e.NameHash(), e)
			rep[e.NameHash()] = e
		} else {
			e := l[rand.Intn(len(l))]
			root = root.Set(e.NameHash(), nil)
			delete(rep, e.NameHash())
		}

		root.Hash()

		if i%n == 0 {
			var root2 *Node
			for k, v := range rep {
				root2 = root2.Set(k, v)
			}

			if root.Hash() != root2.Hash() {
				t.Errorf("uh oh hashes are wrong")
			}
		}

		e := l[rand.Intn(len(l))]
		r := rep[e.NameHash()]
		var o *keytree.Entry
		if r == nil {
			o = e
		} else {
			o = nil
		}

		testLookup(t, root, e.NameHash(), rep[e.NameHash()], o)
	}
}
