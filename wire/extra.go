package wire

import (
	"sort"

	"github.com/jellevandenhooff/keytree/crypto"
)

func (e *Entry) SigningTypeName() string {
	return "github.com/jellevandenhooff/keytree.Entry-0.4"
}

func (e *Entry) ToLeaf() *TrieLeaf {
	return &TrieLeaf{
		NameHash:  crypto.HashString(e.Name),
		EntryHash: e.Hash(),
	}
}

func (e *Entry) Hash() crypto.Hash {
	if e == nil {
		return crypto.EmptyHash
	}

	h := crypto.NewHasher()
	h.WriteString(e.Name)

	names := make([]string, 0, len(e.Keys))
	for name := range e.Keys {
		names = append(names, name)
	}
	sort.Strings(names) // String values are comparable and ordered, lexically byte-wise.
	h.WriteUint64(uint64(len(names)))
	for _, name := range names {
		key := e.Keys[name]
		h.WriteString(name)
		h.WriteString(key)
	}

	h.WriteUint64(e.Timestamp)
	h.WriteBool(e.InRecovery)

	return h.Sum()
}

func (r *Root) SigningTypeName() string {
	return "github.com/jellevandenhooff/keytree.Root-0.1"
}

func (r *Root) Hash() crypto.Hash {
	h := crypto.NewHasher()
	h.Write(r.RootHash.Bytes())
	h.WriteUint64(r.Timestamp)
	return h.Sum()
}
