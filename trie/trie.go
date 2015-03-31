package trie

import (
	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/wire"
)

type Node struct {
	Children [2]*Node
	Entry    *wire.TrieLeaf

	cachedHash crypto.Hash
}

func (n *Node) Hash() crypto.Hash {
	if n == nil {
		return crypto.EmptyHash
	}

	if n.cachedHash != crypto.EmptyHash {
		return n.cachedHash
	}

	if n.Entry != nil {
		n.cachedHash = crypto.CombineHashes(n.Entry.NameHash, n.Entry.EntryHash)
	} else {
		n.cachedHash = crypto.CombineHashes(n.Children[0].Hash(), n.Children[1].Hash())
	}

	return n.cachedHash
}

func Merge(children [2]*Node) *Node {
	if children[0] == nil && children[1] == nil {
		return nil
	} else if children[0] == nil && children[1].Entry != nil {
		return children[1]
	} else if children[1] == nil && children[0].Entry != nil {
		return children[0]
	} else {
		return &Node{
			Children: children,
		}
	}
}

func (n *Node) Split(idx int) (children [2]*Node) {
	if n != nil {
		children = n.Children
		if n.Entry != nil {
			children[n.Entry.NameHash.GetBit(idx)] = n
		}
	}
	return
}

func (n *Node) set(key crypto.Hash, idx int, value *wire.TrieLeaf) *Node {
	if n == nil || (n.Entry != nil && n.Entry.NameHash == key) {
		if value == nil {
			return nil
		} else {
			return &Node{
				Entry: value,
			}
		}
	}

	children := n.Split(idx)

	bit := key.GetBit(idx)
	children[bit] = children[bit].set(key, idx+1, value)

	return Merge(children)
}

func (n *Node) Set(key crypto.Hash, value *wire.TrieLeaf) *Node {
	return n.set(key, 0, value)
}

func (n *Node) get(key crypto.Hash, idx int) *wire.TrieLeaf {
	if n == nil {
		return nil
	}

	if n.Entry != nil {
		if n.Entry.NameHash == key {
			return n.Entry
		} else {
			return nil
		}
	}

	return n.Children[key.GetBit(idx)].get(key, idx+1)
}

func (n *Node) Get(key crypto.Hash) *wire.TrieLeaf {
	return n.get(key, 0)
}

func (n *Node) lookup(key crypto.Hash, idx int, lookup *wire.TrieLookup) *wire.TrieLeaf {
	if n == nil {
		return nil
	}

	if n.Entry != nil {
		if n.Entry.NameHash == key {
			return n.Entry
		}
		lookup.LeafKey = n.Entry.NameHash
		lookup.Hashes[crypto.FirstDifference(n.Entry.NameHash, key)] = n.Entry.EntryHash
		return nil
	}

	bit := key.GetBit(idx)
	o := n.Children[1-bit]
	lookup.Hashes[idx] = o.Hash()

	r := n.Children[bit].lookup(key, idx+1, lookup)
	if lookup.LeafKey == key && o != nil && o.Entry != nil {
		lookup.LeafKey = o.Entry.NameHash
		lookup.Hashes[idx] = o.Entry.EntryHash
	}
	return r
}

func (n *Node) Lookup(key crypto.Hash) (*wire.TrieLookup, *wire.TrieLeaf) {
	lookup := new(wire.TrieLookup)
	lookup.LeafKey = key
	return lookup, n.lookup(key, 0, lookup)
}

func (n *Node) Nodes() int {
	if n == nil {
		return 0
	}
	return 1 + n.Children[0].Nodes() + n.Children[1].Nodes()
}

func (n *Node) Leaves() int {
	if n == nil {
		return 0
	}
	if n.Entry != nil {
		return 1
	}
	return n.Children[0].Leaves() + n.Children[1].Leaves()
}

func (n *Node) leftmostLeaf() *wire.TrieLeaf {
	if n == nil {
		return nil
	}

	if n.Entry != nil {
		return n.Entry
	}

	if leaf := n.Children[0].leftmostLeaf(); leaf != nil {
		return leaf
	}
	return n.Children[1].leftmostLeaf()
}

func (n *Node) nextLeaf(key crypto.Hash, idx int) *wire.TrieLeaf {
	if n == nil {
		return nil
	}

	if n.Entry != nil {
		if crypto.IsSmaller(key, n.Entry.NameHash) {
			return n.Entry
		}
		return nil
	}

	if key.GetBit(idx) == 0 {
		if leaf := n.Children[0].nextLeaf(key, idx+1); leaf != nil {
			return leaf
		}
		return n.Children[1].leftmostLeaf()
	}

	return n.Children[1].nextLeaf(key, idx+1)
}

func (n *Node) NextLeaf(key crypto.Hash) *wire.TrieLeaf {
	return n.nextLeaf(key, 0)
}
