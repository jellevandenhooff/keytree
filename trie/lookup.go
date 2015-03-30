package trie

import (
	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/wire"
)

func CompleteLookup(l *wire.TrieLookup, key crypto.Hash, value crypto.Hash) crypto.Hash {
	var current crypto.Hash
	var isLeaf bool

	if value == crypto.EmptyHash {
		current = crypto.EmptyHash
		isLeaf = false
	} else {
		current = crypto.CombineHashes(key, value)
		isLeaf = true
	}

	leafIdx := crypto.FirstDifference(key, l.LeafKey)

	for i := crypto.HashBits - 1; i >= 0; i-- {
		h := l.Hashes[i]

		if i == leafIdx {
			h = crypto.CombineHashes(l.LeafKey, h)

			if current == crypto.EmptyHash {
				current = h
				isLeaf = true
				continue
			}
		}

		if h == crypto.EmptyHash && isLeaf {
			continue
		}

		if key.GetBit(i) == 0 {
			current = crypto.CombineHashes(current, h)
		} else {
			current = crypto.CombineHashes(h, current)
		}
		isLeaf = false
	}

	return current
}
