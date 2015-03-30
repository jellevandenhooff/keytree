package wire

import "net/rpc"

type KeyTreeClient struct {
	client *rpc.Client
}

func NewKeyTreeClient(client *rpc.Client) *KeyTreeClient {
	return &KeyTreeClient{
		client: client,
	}
}

func (c *KeyTreeClient) Update(req *UpdateRequest) (*UpdateReply, error) {
	var reply UpdateReply
	if err := c.client.Call("KeyTree.Update", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) TrieNode(req *TrieNodeRequest) (*TrieNodeReply, error) {
	var reply TrieNodeReply
	if err := c.client.Call("KeyTree.TrieNode", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) Root(req *RootRequest) (*RootReply, error) {
	var reply RootReply
	if err := c.client.Call("KeyTree.Root", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) UpdateBatch(req *UpdateBatchRequest) (*UpdateBatchReply, error) {
	var reply UpdateBatchReply
	if err := c.client.Call("KeyTree.UpdateBatch", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) Lookup(req *LookupRequest) (*LookupReply, error) {
	var reply LookupReply
	if err := c.client.Call("KeyTree.Lookup", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) History(req *HistoryRequest) (*HistoryReply, error) {
	var reply HistoryReply
	if err := c.client.Call("KeyTree.History", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

type DKIMClient struct {
	client *rpc.Client
}

func NewDKIMClient(client *rpc.Client) *DKIMClient {
	return &DKIMClient{
		client: client,
	}
}

func (c *DKIMClient) DKIMPrepare(req *DKIMPrepareRequest) (*DKIMPrepareReply, error) {
	var reply DKIMPrepareReply
	if err := c.client.Call("DKIM.DKIMPrepare", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *DKIMClient) DKIMPoll(req *DKIMPollRequest) (*DKIMPollReply, error) {
	var reply DKIMPollReply
	if err := c.client.Call("DKIM.DKIMPoll", req, &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}
