package dnsengine

import (
	"container/list"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type lruCache struct {
	mu    sync.Mutex
	max   int
	bytes int
	stale staleOptions
	items map[cacheKey]*list.Element
	lru   list.List
}

func newLRUCache(maximum int, stale staleOptions) *lruCache {
	return &lruCache{
		max:   maximum,
		stale: stale,
		items: make(map[cacheKey]*list.Element),
	}
}

func (c *lruCache) capacity() int {
	return c.max
}

func (c *lruCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *lruCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.items)
	c.lru.Init()
	c.bytes = 0
}

func (c *lruCache) get(key cacheKey, query *dns.Msg, now time.Time) (*dns.Msg, entryState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.items[key]
	if entry == nil {
		return nil, entryMiss
	}
	value := entry.Value.(*cacheValue)
	msg, state := value.evaluate(query, now, c.stale)
	if state == entryMiss {
		c.remove(entry)
		return nil, entryMiss
	}
	c.lru.MoveToFront(entry)
	return msg, state
}

func (c *lruCache) put(key cacheKey, response *dns.Msg, now time.Time) {
	size := response.Len()
	if size > 16384 || c.max <= 0 {
		return
	}
	ttl := cacheTTL(response, key.question.Qtype)
	if ttl == 0 {
		return
	}
	copyMsg := response.Copy()
	if response.Rcode == dns.RcodeNameError || !hasAnswerType(response, key.question.Qtype) {
		eachRR(copyMsg, func(rr dns.RR) { rr.Header().Ttl = min(ttl, rr.Header().Ttl) })
	}
	value := &cacheValue{key, copyMsg, now, ttl, size}
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

func (c *lruCache) remove(item *list.Element) {
	value := item.Value.(*cacheValue)
	delete(c.items, value.key)
	c.bytes -= value.size
	c.lru.Remove(item)
}

func (c *lruCache) snapshot() []cacheSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := make([]cacheSnapshot, 0, len(c.items))
	for e := c.lru.Front(); e != nil; e = e.Next() {
		val := e.Value.(*cacheValue)
		res = append(res, cacheSnapshot{
			Key:      val.key,
			Response: val.response.Copy(),
			Stored:   val.stored,
			TTL:      val.ttl,
			Frequent: false,
		})
	}
	return res
}

func (c *lruCache) restore(items []cacheSnapshot, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, item := range items {
		if item.Response == nil {
			continue
		}
		age := uint32(now.Sub(item.Stored) / time.Second)
		staleLimit := item.TTL
		if c.stale.enabled {
			staleLimit += uint32(math.Ceil(c.stale.staleTTL.Seconds()))
		}
		if age >= staleLimit {
			continue
		}
		size := item.Response.Len()
		if size > 16384 || c.max <= 0 {
			continue
		}
		if previous := c.items[item.Key]; previous != nil {
			c.remove(previous)
		}
		val := &cacheValue{
			key:      item.Key,
			response: item.Response,
			stored:   item.Stored,
			ttl:      item.TTL,
			size:     size,
		}
		c.items[item.Key] = c.lru.PushFront(val)
		c.bytes += size
		for len(c.items) > c.max || c.bytes > cacheByteLimit {
			c.remove(c.lru.Back())
		}
	}
}
