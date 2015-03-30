package wire

import "errors"

func (e *Entry) Check() error {
	if e == nil {
		return errors.New("missing entry")
	}
	return nil
}

func (e *SignedEntry) Check() error {
	if e == nil {
		return errors.New("missing signed entry")
	}
	if err := e.Entry.Check(); err != nil {
		return err
	}
	return nil
}

func (l *TrieLeaf) Check() error {
	if l == nil {
		return errors.New("missing trie leaf")
	}
	return nil
}

func (req *UpdateRequest) Check() error {
	if req == nil {
		return errors.New("missing update request")
	}
	if err := req.SignedEntry.Check(); err != nil {
		return err
	}
	return nil
}

func (reply *UpdateReply) Check() error {
	if reply == nil {
		return errors.New("missing update reply")
	}
	return nil
}

func (n *TrieNode) Check() error {
	if n == nil {
		return errors.New("missing trie node")
	}
	if (n.ChildHashes == nil) == (n.Leaf == nil) {
		return errors.New("trie node must have either leaf or child hashes")
	}

	if n.Leaf != nil {
		if err := n.Leaf.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (req *TrieNodeRequest) Check() error {
	if req == nil {
		return errors.New("missing trie node request")
	}
	return nil
}

func (reply *TrieNodeReply) Check() error {
	if reply == nil {
		return errors.New("missing trie node reply")
	}
	if err := reply.Node.Check(); err != nil {
		return err
	}
	return nil
}

func (r *Root) Check() error {
	if r == nil {
		return errors.New("missing root")
	}
	return nil
}

func (r *SignedRoot) Check() error {
	if r == nil {
		return errors.New("missing signed root")
	}
	if err := r.Root.Check(); err != nil {
		return err
	}
	return nil
}

func (req *RootRequest) Check() error {
	if req == nil {
		return errors.New("missing root request")
	}
	return nil
}

func (reply *RootReply) Check() error {
	if reply == nil {
		return errors.New("missing root reply")
	}
	if err := reply.SignedRoot.Check(); err != nil {
		return err
	}
	return nil
}

func (req *UpdateBatchRequest) Check() error {
	if req == nil {
		return errors.New("missing update batch request")
	}
	return nil
}

func (reply *UpdateBatchReply) Check() error {
	if reply == nil {
		return errors.New("missing update batch reply")
	}
	if err := reply.UpdateBatch.Check(); err != nil {
		return err
	}
	return nil
}

func (b *UpdateBatch) Check() error {
	if b == nil {
		return errors.New("missing update batch")
	}

	for _, leaf := range b.Updates {
		if err := leaf.Check(); err != nil {
			return err
		}
	}

	if err := b.NewRoot.Check(); err != nil {
		return err
	}
	return nil
}

func (tl *TrieLookup) Check() error {
	if tl == nil {
		return errors.New("missing trie lookup")
	}

	return nil
}

func (tl *SignedTrieLookup) Check() error {
	if tl == nil {
		return errors.New("missing signed trie lookup")
	}

	if err := tl.TrieLookup.Check(); err != nil {
		return err
	}

	if err := tl.SignedRoot.Check(); err != nil {
		return err
	}

	return nil
}

func (req *LookupRequest) Check() error {
	if req == nil {
		return errors.New("missing signed trie lookup")
	}

	return nil
}

func (reply *LookupReply) Check() error {
	if reply == nil {
		return errors.New("missing signed trie lookup")
	}

	for _, tl := range reply.SignedTrieLookups {
		if err := tl.Check(); err != nil {
			return err
		}
	}

	// Allow nil entries
	if reply.Entry != nil {
		if err := reply.Entry.Check(); err != nil {
			return err
		}
	}

	return nil
}

func (req *HistoryRequest) Check() error {
	if req == nil {
		return errors.New("missing history request")
	}

	return nil
}

func (reply *HistoryReply) Check() error {
	if reply == nil {
		return errors.New("missing history reply")
	}

	// Allow nil entries
	if reply.Update != nil {
		if err := reply.Update.Check(); err != nil {
			return err
		}
	}

	return nil
}

func (s *DKIMStatement) Check() error {
	if s == nil {
		return errors.New("missing dkim statement")
	}

	return nil
}

func (u *DKIMUpdate) Check() error {
	if u == nil {
		return errors.New("missing dkim update")
	}

	if err := u.Statement.Check(); err != nil {
		return err
	}

	return nil
}

func (req *DKIMPrepareRequest) Check() error {
	if req == nil {
		return errors.New("missing dkim prepare request")
	}

	if err := req.Statement.Check(); err != nil {
		return err
	}

	return nil
}

func (reply *DKIMPrepareReply) Check() error {
	if reply == nil {
		return errors.New("missing dkim prepare reply")
	}

	return nil
}

func (req *DKIMPollRequest) Check() error {
	if req == nil {
		return errors.New("missing dkim poll request")
	}

	return nil
}

func (reply *DKIMPollReply) Check() error {
	if reply == nil {
		return errors.New("missing dkim poll reply")
	}

	return nil
}
