package dnsengine

import (
	"container/list"
	"math"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type arcLocation int

const (
	locT1 arcLocation = iota + 1
	locT2
	locB1
	locB2
)

type arcEntry struct {
	key   cacheKey
	loc   arcLocation
	value *cacheValue // non-nil for T1/T2, nil for B1/B2
}

type arcCache struct {
	mu          sync.Mutex
	c           int     // maximum capacity
	p           float64 // adaptive target size of T1
	bytes       int     // total cached bytes in memory (T1 + T2)
	negativeTTL uint32
	stale       staleOptions

	t1 list.List
	t2 list.List
	b1 list.List
	b2 list.List

	items map[cacheKey]*list.Element
}

func newARCCache(capacity int, stale staleOptions) *arcCache {
	return &arcCache{
		c:     capacity,
		stale: stale,
		items: make(map[cacheKey]*list.Element),
	}
}

func (c *arcCache) capacity() int {
	return c.c
}

func (c *arcCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t1.Len() + c.t2.Len()
}

func (c *arcCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.items)
	c.t1.Init()
	c.t2.Init()
	c.b1.Init()
	c.b2.Init()
	c.bytes = 0
	c.p = 0
}

func (c *arcCache) get(key cacheKey, query *dns.Msg, now time.Time) (*dns.Msg, entryState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, entryMiss
	}
	entry := elem.Value.(*arcEntry)
	if entry.loc == locB1 || entry.loc == locB2 {
		return nil, entryMiss
	}

	val := entry.value
	msg, state := val.evaluate(query, now, c.stale)
	if state == entryMiss {
		c.removeCachedElement(elem)
		return nil, entryMiss
	}

	// Hits on T1 or T2 move the entry to MRU of T2
	if entry.loc == locT1 {
		c.t1.Remove(elem)
		entry.loc = locT2
		c.items[key] = c.t2.PushFront(entry)
	} else if entry.loc == locT2 {
		c.t2.MoveToFront(elem)
	}

	return msg, state
}

func (c *arcCache) put(key cacheKey, response *dns.Msg, now time.Time) putRejectReason {
	if c.c <= 0 {
		return rejectUncacheable
	}
	val, reason := prepareCacheValue(key, response, now, c.negativeTTL)
	if val == nil {
		return reason
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, exists := c.items[key]
	if exists {
		entry := elem.Value.(*arcEntry)
		switch entry.loc {
		case locT1, locT2:
			// Case 1: entry already in memory cache
			if entry.value != nil {
				c.bytes -= entry.value.size
			}
			entry.value = val
			c.bytes += val.size
			if entry.loc == locT1 {
				c.t1.Remove(elem)
				entry.loc = locT2
				c.items[key] = c.t2.PushFront(entry)
			} else {
				c.t2.MoveToFront(elem)
			}
			c.enforceByteLimit()
			return rejectNone

		case locB1:
			// Case 2: Ghost hit in B1
			b1Len := c.b1.Len()
			b2Len := c.b2.Len()
			delta := 1.0
			if b1Len < b2Len && b1Len > 0 {
				delta = float64(b2Len) / float64(b1Len)
			}
			c.p = math.Min(float64(c.c), c.p+delta)
			c.replace(false, c.p)

			c.b1.Remove(elem)
			entry.loc = locT2
			entry.value = val
			c.items[key] = c.t2.PushFront(entry)
			c.bytes += val.size
			c.enforceByteLimit()
			return rejectNone

		case locB2:
			// Case 3: Ghost hit in B2
			b1Len := c.b1.Len()
			b2Len := c.b2.Len()
			delta := 1.0
			if b2Len < b1Len && b2Len > 0 {
				delta = float64(b1Len) / float64(b2Len)
			}
			c.p = math.Max(0.0, c.p-delta)
			c.replace(true, c.p)

			c.b2.Remove(elem)
			entry.loc = locT2
			entry.value = val
			c.items[key] = c.t2.PushFront(entry)
			c.bytes += val.size
			c.enforceByteLimit()
			return rejectNone
		}
	}

	// Case 4: Complete miss
	l1Len := c.t1.Len() + c.b1.Len()
	if l1Len == c.c {
		if c.t1.Len() < c.c {
			c.removeGhost(c.b1.Back())
			c.replace(false, c.p)
		} else {
			c.removeCachedElement(c.t1.Back())
		}
	} else if l1Len < c.c {
		total := c.t1.Len() + c.t2.Len() + c.b1.Len() + c.b2.Len()
		if total >= c.c {
			if total >= 2*c.c {
				c.removeGhost(c.b2.Back())
			}
			c.replace(false, c.p)
		}
	}

	entry := &arcEntry{
		key:   key,
		loc:   locT1,
		value: val,
	}
	c.items[key] = c.t1.PushFront(entry)
	c.bytes += val.size
	c.enforceByteLimit()
	return rejectNone
}

func (c *arcCache) replace(inB2 bool, p float64) {
	t1Len := c.t1.Len()
	if t1Len > 0 && ((inB2 && float64(t1Len) == p) || float64(t1Len) > p) {
		// Evict LRU of T1 to MRU of B1
		back := c.t1.Back()
		entry := back.Value.(*arcEntry)
		c.t1.Remove(back)
		if entry.value != nil {
			c.bytes -= entry.value.size
		}
		entry.value = nil
		entry.loc = locB1
		c.items[entry.key] = c.b1.PushFront(entry)
	} else if c.t2.Len() > 0 {
		// Evict LRU of T2 to MRU of B2
		back := c.t2.Back()
		entry := back.Value.(*arcEntry)
		c.t2.Remove(back)
		if entry.value != nil {
			c.bytes -= entry.value.size
		}
		entry.value = nil
		entry.loc = locB2
		c.items[entry.key] = c.b2.PushFront(entry)
	}
}

func (c *arcCache) removeCachedElement(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*arcEntry)
	delete(c.items, entry.key)
	if entry.value != nil {
		c.bytes -= entry.value.size
	}
	if entry.loc == locT1 {
		c.t1.Remove(elem)
	} else if entry.loc == locT2 {
		c.t2.Remove(elem)
	}
}

func (c *arcCache) removeGhost(elem *list.Element) {
	if elem == nil {
		return
	}
	entry := elem.Value.(*arcEntry)
	delete(c.items, entry.key)
	if entry.loc == locB1 {
		c.b1.Remove(elem)
	} else if entry.loc == locB2 {
		c.b2.Remove(elem)
	}
}

func (c *arcCache) enforceByteLimit() {
	for c.bytes > cacheByteLimit && (c.t1.Len() > 0 || c.t2.Len() > 0) {
		c.replace(false, c.p)
	}
	for c.b1.Len()+c.b2.Len() > c.c {
		if c.b1.Len() > int(c.p) && c.b1.Len() > 0 {
			c.removeGhost(c.b1.Back())
		} else if c.b2.Len() > 0 {
			c.removeGhost(c.b2.Back())
		} else if c.b1.Len() > 0 {
			c.removeGhost(c.b1.Back())
		} else {
			break
		}
	}
}

func (c *arcCache) snapshot() []cacheSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := make([]cacheSnapshot, 0, c.t1.Len()+c.t2.Len())
	for e := c.t2.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*arcEntry)
		if entry.value != nil && entry.value.response != nil && !entry.value.negative {
			res = append(res, cacheSnapshot{
				Key:      entry.key,
				Response: entry.value.response.Copy(),
				Stored:   entry.value.stored,
				TTL:      entry.value.ttl,
				Frequent: true,
			})
		}
	}
	for e := c.t1.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*arcEntry)
		if entry.value != nil && entry.value.response != nil && !entry.value.negative {
			res = append(res, cacheSnapshot{
				Key:      entry.key,
				Response: entry.value.response.Copy(),
				Stored:   entry.value.stored,
				TTL:      entry.value.ttl,
				Frequent: false,
			})
		}
	}
	return res
}

func (c *arcCache) restore(items []cacheSnapshot, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, item := range items {
		if item.Response == nil || isNegativeResponse(item.Response, item.Key.question.Qtype) {
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
		if size > 16384 || c.c <= 0 {
			continue
		}
		if elem, ok := c.items[item.Key]; ok {
			c.removeCachedElement(elem)
		}
		val := &cacheValue{
			key:      item.Key,
			response: item.Response,
			stored:   item.Stored,
			ttl:      item.TTL,
			size:     size,
		}
		entry := &arcEntry{
			key:   item.Key,
			value: val,
		}
		if item.Frequent {
			entry.loc = locT2
			c.items[item.Key] = c.t2.PushFront(entry)
		} else {
			entry.loc = locT1
			c.items[item.Key] = c.t1.PushFront(entry)
		}
		c.bytes += size
		for c.t1.Len()+c.t2.Len() > c.c || c.bytes > cacheByteLimit {
			c.replace(false, c.p)
		}
	}
}
