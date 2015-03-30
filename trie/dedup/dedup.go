package dedup

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
	"github.com/jellevandenhooff/keytree/trie"
)

// A Dedup helps store only one of multiple identical trie nodes.  A Dedup is
// threadsafe.
type Dedup struct {
	mu    sync.Mutex
	nodes map[crypto.Hash]dedupInfo
}

func New() *Dedup {
	return &Dedup{
		nodes: make(map[crypto.Hash]dedupInfo),
	}
}

type dedupInfo struct {
	refs int
	node *trie.Node
}

func (d *Dedup) add(node *trie.Node, count int) *trie.Node {
	if node == nil {
		return node
	}

	entry, found := d.nodes[node.Hash()]
	if found {
		entry.refs += count
		return entry.node
	}

	node.Children[0] = d.add(node.Children[0], 1)
	node.Children[1] = d.add(node.Children[1], 1)
	d.nodes[node.Hash()] = dedupInfo{
		refs: count,
		node: node,
	}
	return node
}

func (d *Dedup) Add(node *trie.Node) *trie.Node {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.add(node, 1)
}

func (d *Dedup) AddMany(node *trie.Node, count int) *trie.Node {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.add(node, count)
}

func (d *Dedup) findAndAdd(hash crypto.Hash, count int) *trie.Node {
	d.mu.Lock()
	defer d.mu.Unlock()

	info, found := d.nodes[hash]
	if found {
		info.refs += count
		return info.node
	} else {
		return nil
	}
}

func (d *Dedup) FindAndAdd(hash crypto.Hash) *trie.Node {
	return d.findAndAdd(hash, 1)
}

func (d *Dedup) FindAndDoNotAdd(hash crypto.Hash) *trie.Node {
	return d.findAndAdd(hash, 0)
}

func (d *Dedup) remove(node *trie.Node) {
	if node == nil {
		return
	}

	entry := d.nodes[node.Hash()]
	entry.refs -= 1

	if entry.refs == 0 {
		delete(d.nodes, node.Hash())
		d.remove(node.Children[0])
		d.remove(node.Children[1])
	}
}

func (d *Dedup) Remove(node *trie.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.remove(node)
}

func (d *Dedup) NumNodes() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.nodes)
}