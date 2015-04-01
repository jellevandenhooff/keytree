package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/jellevandenhooff/keytree/crypto"
)

var ErrNotFound = errors.New("not found")

func backoff(retries int) time.Duration {
	backoff := 1 * time.Second
	max := 60 * time.Second

	for i := 0; i < retries && backoff < max; i++ {
		backoff = backoff * 2
	}
	if backoff > max {
		backoff = max
	}

	backoff -= time.Duration(float64(backoff) * 0.4 * rand.Float64())
	if backoff < 0 {
		return 0
	}

	return backoff
}

type client struct {
	host       string
	httpClient *http.Client

	mu      sync.Mutex
	retries int
	waiting chan struct{}
}

func (c *client) success() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.retries = 0
}

func (c *client) failure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.waiting != nil {
		return
	}

	c.waiting = make(chan struct{})
	time.AfterFunc(backoff(c.retries), func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		close(c.waiting)
		c.waiting = nil
	})
	c.retries += 1
}

func (c *client) await() {
	c.mu.Lock()
	w := c.waiting
	c.mu.Unlock()

	if w != nil {
		<-w
	}
}

func (c *client) process(err *error) {
	if *err != nil {
		c.failure()
	} else {
		c.success()
	}
}

func decode(resp *http.Response, reply interface{}) error {
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	reader := io.LimitReader(resp.Body, 32*1024)
	dec := json.NewDecoder(reader)
	return dec.Decode(reply)
}

func (c *client) get(path string, reply interface{}) (err error) {
	c.await()
	defer c.process(&err)

	resp, err := c.httpClient.Get(c.host + path)
	if err != nil {
		return err
	}

	return decode(resp, reply)
}

func (c *client) post(path string, request, reply interface{}) (err error) {
	c.await()
	defer c.process(&err)

	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(request); err != nil {
		return err
	}

	resp, err := c.httpClient.Post(c.host+path, "text/json; charset=utf8", buffer)
	if err != nil {
		return err
	}

	return decode(resp, reply)
}

func newClient(host string) *client {
	return &client{
		host: host,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

type KeyTreeClient struct {
	client *client
}

func NewKeyTreeClient(host string) *KeyTreeClient {
	return &KeyTreeClient{client: newClient(host)}
}

func (c *KeyTreeClient) Submit(update *SignedEntry) error {
	var reply interface{}
	return c.client.post("/keytree/submit", update, &reply)
}

func (c *KeyTreeClient) TrieNode(h crypto.Hash) (*TrieNode, error) {
	var reply *TrieNode
	if err := c.client.get(fmt.Sprintf("/keytree/trienode?hash=%s", h), &reply); err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, ErrNotFound
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *KeyTreeClient) Root() (*SignedRoot, error) {
	var reply SignedRoot
	if err := c.client.get("/keytree/root", &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) UpdateBatch(h crypto.Hash) (*UpdateBatch, error) {
	var reply *UpdateBatch
	if err := c.client.get(fmt.Sprintf("/keytree/updatebatch?hash=%s", h), &reply); err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, ErrNotFound
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *KeyTreeClient) Lookup(h crypto.Hash) (*LookupReply, error) {
	var reply LookupReply
	if err := c.client.get(fmt.Sprintf("/keytree/lookup?hash=%s", h), &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}

func (c *KeyTreeClient) History(h crypto.Hash, since uint64) (*SignedEntry, error) {
	var reply *SignedEntry
	if err := c.client.get(fmt.Sprintf("/keytree/history?hash=%s&since=%d", h, since), &reply); err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, ErrNotFound
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return reply, nil
}

type DKIMClient struct {
	client *client
}

func NewDKIMClient(host string) *DKIMClient {
	return &DKIMClient{client: newClient(host)}
}

func (c *DKIMClient) Prepare(req *DKIMStatement) (string, error) {
	var reply string
	if err := c.client.post("/dkim/prepare", req, &reply); err != nil {
		return "", err
	}
	return reply, nil
}

func (c *DKIMClient) Poll(req string) (*DKIMStatus, error) {
	var reply DKIMStatus
	if err := c.client.get(fmt.Sprintf("/dkim/poll?email=%s", req), &reply); err != nil {
		return nil, err
	}
	if err := reply.Check(); err != nil {
		return nil, err
	}
	return &reply, nil
}
