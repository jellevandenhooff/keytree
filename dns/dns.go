package dns

import (
	"errors"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
)

// SimpleDNSClient uses miekg/dns to look up TXT records, and supports falling
// back to TCP for big records.
//
// Exists because Go's built-in DNS client has problems with some TXT records.
type SimpleDNSClient struct {
	Server string
}

// LookupTxt queries the underlying server for TXT records for the given
// hostname.
func (s *SimpleDNSClient) LookupTxt(hostname string) ([]string, error) {
	// build the DNS query
	m := new(dns.Msg)
	m.SetQuestion(hostname, dns.TypeTXT)

	// try getting over UDP
	c := new(dns.Client)
	r, _, e := c.Exchange(m, s.Server)
	if e != nil {
		return nil, e
	}

	if r.Truncated {
		// try again with TCP for large messages
		c.Net = "tcp"
		r, _, e = c.Exchange(m, s.Server)
		if e != nil {
			return nil, e
		}
	}

	// parse TXT answers into strings
	var res []string
	for _, answer := range r.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok {
			return nil, errors.New("expected TXT")
		}
		// concatenate each multi-part answer into a single string
		res = append(res, strings.Join(txt.Txt, ""))
	}
	return res, nil
}

type CachingDNSClient struct {
	underlying *SimpleDNSClient
	cache      *lru.Cache
}

const cacheSize = 8192
const lifetime = 1 * time.Hour

type cacheItem struct {
	result  []string
	expires time.Time
}

func NewCachingDNSClient(server string) *CachingDNSClient {
	cache, _ := lru.New(cacheSize)

	return &CachingDNSClient{
		underlying: &SimpleDNSClient{Server: server},
		cache:      cache,
	}
}

func (c *CachingDNSClient) LookupTxt(hostname string) ([]string, error) {
	value, ok := c.cache.Get(hostname)
	if ok {
		item := value.(*cacheItem)
		if time.Now().Before(item.expires) {
			return item.result, nil
		}
	}

	result, err := c.underlying.LookupTxt(hostname)
	if err != nil {
		return nil, err
	}

	c.cache.Add(hostname, &cacheItem{
		result:  result,
		expires: time.Now().Add(lifetime),
	})
	return result, nil
}
