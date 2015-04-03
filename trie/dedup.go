package trie

import (
	"sync"

	"github.com/jellevandenhooff/keytree/crypto"
)

// A Dedup helps store only one of multiple identical trie nodes.  A Dedup is
// threadsafe.
type Dedup struct {
	mu    sync.Mutex
	nodes map[crypto.Hash]dedupInfo
}

func NewDedup() *Dedup {
	return &Dedup{
		nodes: make(map[crypto.Hash]dedupInfo),
	}
}

type dedupInfo struct {
	refs int
	node *Node
}

func (d *Dedup) add(node *Node) *Node {
	if node == nil {
		return node
	}

	entry, found := d.nodes[node.Hash()]
	if found {
		entry.refs += 1
		return entry.node
	}

	node.Children[0] = d.add(node.Children[0])
	node.Children[1] = d.add(node.Children[1])
	d.nodes[node.Hash()] = dedupInfo{
		refs: 1,
		node: node,
	}
	return node
}

func (d *Dedup) Add(node *Node) *Node {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.add(node)
}

func (d *Dedup) AddWithChildrenAlreadyAdded(node *Node) *Node {
	if node == nil {
		return node
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	entry, found := d.nodes[node.Hash()]
	if found {
		d.remove(node.Children[0])
		d.remove(node.Children[1])
		entry.refs += 1
		return entry.node
	}

	d.nodes[node.Hash()] = dedupInfo{
		refs: 1,
		node: node,
	}
	return node
}

func (d *Dedup) findAndAdd(hash crypto.Hash, count int) *Node {
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

func (d *Dedup) FindAndAdd(hash crypto.Hash) *Node {
	return d.findAndAdd(hash, 1)
}

func (d *Dedup) FindAndDoNotAdd(hash crypto.Hash) *Node {
	return d.findAndAdd(hash, 0)
}

func (d *Dedup) remove(node *Node) {
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

func (d *Dedup) Remove(node *Node) {
	return

	d.mu.Lock()
	defer d.mu.Unlock()

	d.remove(node)
}

func (d *Dedup) NumNodes() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.nodes)
}
