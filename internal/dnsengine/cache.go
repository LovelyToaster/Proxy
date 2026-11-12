package dnsengine

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const cacheByteLimit = 16 << 20

type cacheKey struct {
	policy   string
	question dns.Question
	flags    uint8
}

type cacheValue struct {
	key      cacheKey
	response *dns.Msg
	stored   time.Time
	ttl      uint32
	size     int
}

type cache struct {
	mu    sync.Mutex
	max   int
	bytes int
	items map[cacheKey]*list.Element
	lru   list.List
}

func newCache(maximum int) *cache {
	return &cache{max: maximum, items: make(map[cacheKey]*list.Element)}
}

func makeKey(policy string, query *dns.Msg) (cacheKey, bool) {
	// Other flags and sections can affect the response. Treat options such as ECS
	// and cookies as uncacheable, while separating DO and EDNS presence.
	if len(query.Answer) != 0 || len(query.Ns) != 0 || len(query.Extra) > 1 {
		return cacheKey{}, false
	}
	var flags uint8
	if query.RecursionDesired {
		flags |= 1
	}
	if query.CheckingDisabled {
		flags |= 2
	}
	if query.AuthenticatedData {
		flags |= 4
	}
	if len(query.Extra) == 1 {
		opt, ok := query.Extra[0].(*dns.OPT)
		if !ok || opt.Version() != 0 || len(opt.Option) != 0 || opt.Z() != 0 {
			return cacheKey{}, false
		}
		flags |= 8
		if opt.Do() {
			flags |= 16
		}
	}
	question := query.Question[0]
	question.Name = dns.CanonicalName(question.Name)
	return cacheKey{policy, question, flags}, true
}

func (c *cache) get(key cacheKey, query *dns.Msg, now time.Time) *dns.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.items[key]
	if entry == nil {
		return nil
	}
	value := entry.Value.(*cacheValue)
	age := uint32(now.Sub(value.stored) / time.Second)
	if age >= value.ttl {
		c.remove(entry)
		return nil
	}
	c.lru.MoveToFront(entry)
	result := value.response.Copy()
	result.Id = query.Id
	result.Question = append(result.Question[:0], query.Question...)
	eachRR(result, func(rr dns.RR) { rr.Header().Ttl -= min(age, rr.Header().Ttl) })
	return result
}

func (c *cache) put(key cacheKey, response *dns.Msg, now time.Time) {
	size := response.Len()
	if size > 16384 || c.max == 0 {
		return
	}
	ttl := cacheTTL(response, key.question.Qtype)
	if ttl == 0 {
		return
	}
	copy := response.Copy()
	if response.Rcode == dns.RcodeNameError || !hasAnswerType(response, key.question.Qtype) {
		eachRR(copy, func(rr dns.RR) { rr.Header().Ttl = min(ttl, rr.Header().Ttl) })
	}
	value := &cacheValue{key, copy, now, ttl, size}
	c.mu.Lock()
	defer c.mu.Unlock()
	if previous := c.items[key]; previous != nil {
		c.remove(previous)
	}
	c.items[key] = c.lru.PushFront(value)
	c.bytes += size
	for len(c.items) > c.max || c.bytes > cacheByteLimit {
		c.remove(c.lru.Back())
	}
}

func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.items)
	c.lru.Init()
	c.bytes = 0
}

func (c *cache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *cache) remove(item *list.Element) {
	value := item.Value.(*cacheValue)
	delete(c.items, value.key)
	c.bytes -= value.size
	c.lru.Remove(item)
}

func cacheTTL(response *dns.Msg, qtype uint16) uint32 {
	if response.Truncated || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError) {
		return 0
	}
	// Cached responses must not carry per-client EDNS data or transaction authentication.
	for _, rr := range response.Extra {
		if opt, ok := rr.(*dns.OPT); ok && len(opt.Option) != 0 {
			return 0
		}
		if rr.Header().Rrtype == dns.TypeTSIG || rr.Header().Rrtype == dns.TypeSIG {
			return 0
		}
	}
	ttl := uint32(86400)
	if response.Rcode == dns.RcodeNameError || !hasAnswerType(response, qtype) {
		var negative uint32
		for _, rr := range response.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				negative = min(soa.Hdr.Ttl, soa.Minttl)
				break
			}
		}
		if negative == 0 {
			return 0
		}
		ttl = min(ttl, negative)
	}
	eachRR(response, func(rr dns.RR) { ttl = min(ttl, rr.Header().Ttl) })
	return ttl
}

func hasAnswerType(response *dns.Msg, qtype uint16) bool {
	for _, rr := range response.Answer {
		if qtype == dns.TypeANY || rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func eachRR(msg *dns.Msg, apply func(dns.RR)) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				apply(rr)
			}
		}
	}
}
