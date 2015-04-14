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

func (n *TrieNode) Check() error {
	if n == nil {
		return errors.New("missing trie node")
	}
	var count = 0
	if n.ChildHashes != nil {
		count += 1
	}
	if n.Children != nil {
		count += 1
		for i := 0; i < 2; i++ {
			if n.Children[i] != nil {
				if err := n.Children[i].Check(); err != nil {
					return err
				}
			}
		}
	}
	if n.Leaf != nil {
		count += 1
		if err := n.Leaf.Check(); err != nil {
			return err
		}
	}
	if count != 1 {
		return errors.New("trie node must have exactly one kind of node type")
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

func (req *DKIMStatus) Check() error {
	if req == nil {
		return errors.New("missing dkim status")
	}

	return nil
}
