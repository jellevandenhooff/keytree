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

type UpdateRequest struct {
	SignedEntry *SignedEntry
}

type UpdateReply struct {
}

type TrieNode struct {
	ChildHashes *[2]crypto.Hash
	Leaf        *TrieLeaf
}

type TrieNodeRequest struct {
	Hash crypto.Hash
}

type TrieNodeReply struct {
	Node *TrieNode
}

type Root struct {
	RootHash  crypto.Hash
	Timestamp uint64
}

type SignedRoot struct {
	Root      *Root
	Signature string
}

type RootRequest struct {
}

type RootReply struct {
	SignedRoot *SignedRoot
}

type UpdateBatchRequest struct {
	RootHash crypto.Hash
}

type UpdateBatchReply struct {
	UpdateBatch *UpdateBatch
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

type LookupRequest struct {
	Hash       crypto.Hash
	PublicKeys []string
}

type LookupReply struct {
	SignedTrieLookups map[string]*SignedTrieLookup
	Entry             *Entry
}

type HistoryRequest struct {
	Hash  crypto.Hash
	Since uint64
}

type HistoryReply struct {
	Update *SignedEntry
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

type DKIMPrepareRequest struct {
	Statement *DKIMStatement
}

type DKIMPrepareReply struct {
	Email string
}

type DKIMPollRequest struct {
	Email string
}

type DKIMPollReply struct {
	Proof      string
	Status     []string
	Expiration uint64
}
