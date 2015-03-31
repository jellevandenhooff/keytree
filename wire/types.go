package wire

import "github.com/jellevandenhooff/keytree/crypto"

type Entry struct {
	Name       string
	Keys       map[string]string
	Timestamp  uint64
	InRecovery bool
}

type SignedEntry struct {
	Entry      *Entry
	Signatures map[string]string
}

type TrieLeaf struct {
	NameHash  crypto.Hash
	EntryHash crypto.Hash
}

type TrieNode struct {
	ChildHashes *[2]crypto.Hash `json:",omitempty"`
	Leaf        *TrieLeaf       `json:",omitempty"`
}

type Root struct {
	RootHash  crypto.Hash
	Timestamp uint64
}

type SignedRoot struct {
	Root      *Root
	Signature string
}

type UpdateBatch struct {
	Updates []*TrieLeaf
	NewRoot *SignedRoot
}

type TrieLookup struct {
	Hashes  Hashes
	LeafKey crypto.Hash
}

type SignedTrieLookup struct {
	SignedRoot *SignedRoot
	TrieLookup *TrieLookup
}

type LookupReply struct {
	SignedTrieLookups map[string]*SignedTrieLookup
	Entry             *Entry
}

type DKIMStatement struct {
	Sender string
	Token  string
}

type DKIMUpdate struct {
	Statement  *DKIMStatement
	Proof      string
	Status     []string
	Expiration uint64
}

type DKIMStatus struct {
	Proof      string
	Status     []string
	Expiration uint64
}
