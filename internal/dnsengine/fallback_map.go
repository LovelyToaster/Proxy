package dnsengine

import (
	"container/list"
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	fallbackMapCapacity     = 4096
	fallbackNegativeATTL    = 30 * time.Second
	fallbackMinV6DomainTTL  = 30 * time.Second
	fallbackMinV4RecordTTL  = 5 * time.Second
	fallbackMaxRecordTTL    = time.Hour
	fallbackLookupWaitLimit = 2 * time.Second
)

type lruValue[V any] struct {
	val     V
	expires time.Time
}

type lruItem[K comparable, V any] struct {
	key   K
	entry lruValue[V]
}

type boundedLRU[K comparable, V any] struct {
	capacity int
	items    map[K]*list.Element
	order    *list.List
}

func newBoundedLRU[K comparable, V any](capacity int) *boundedLRU[K, V] {
	return &boundedLRU[K, V]{
		capacity: capacity,
		items:    make(map[K]*list.Element, min(capacity, 64)),
		order:    list.New(),
	}
}

func (l *boundedLRU[K, V]) get(key K, now time.Time) (V, bool) {
	var zero V
	elem, ok := l.items[key]
	if !ok {
		return zero, false
	}
	item := elem.Value.(*lruItem[K, V])
	if !item.entry.expires.After(now) {
		l.order.Remove(elem)
		delete(l.items, key)
		return zero, false
	}
	l.order.MoveToFront(elem)
	return item.entry.val, true
}

func (l *boundedLRU[K, V]) put(key K, val V, expires time.Time) {
	if l.capacity <= 0 {
		return
	}
	if elem, ok := l.items[key]; ok {
		item := elem.Value.(*lruItem[K, V])
		item.entry = lruValue[V]{val: val, expires: expires}
		l.order.MoveToFront(elem)
		return
	}
	item := &lruItem[K, V]{
		key:   key,
		entry: lruValue[V]{val: val, expires: expires},
	}
	elem := l.order.PushFront(item)
	l.items[key] = elem
	for l.order.Len() > l.capacity {
		oldest := l.order.Back()
		if oldest == nil {
			break
		}
		l.order.Remove(oldest)
		delete(l.items, oldest.Value.(*lruItem[K, V]).key)
	}
}

func (l *boundedLRU[K, V]) clear() {
	l.items = make(map[K]*list.Element, min(l.capacity, 64))
	l.order.Init()
}

// fallbackRegistry tracks bounded IPv6->domain and domain->IPv4 associations
// learned from DNS answers so direct TCP connections can race IPv4 fallbacks.
type fallbackRegistry struct {
	mu         sync.Mutex
	v6ToDomain *boundedLRU[netip.Addr, string]
	domainToV4 *boundedLRU[string, []netip.Addr]
}

func newFallbackRegistry(capacity int) *fallbackRegistry {
	return &fallbackRegistry{
		v6ToDomain: newBoundedLRU[netip.Addr, string](capacity),
		domainToV4: newBoundedLRU[string, []netip.Addr](capacity),
	}
}

func (r *fallbackRegistry) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.v6ToDomain.clear()
	r.domainToV4.clear()
}

func (r *fallbackRegistry) record(qname string, answers []dns.RR, now time.Time) {
	domain := normalizeFallbackDomain(qname)
	if domain == "" || len(answers) == 0 {
		return
	}
	var (
		v6s      []netip.Addr
		minV6TTL time.Duration
		v4s      []netip.Addr
		minV4TTL time.Duration
	)
	for _, rr := range answers {
		switch rec := rr.(type) {
		case *dns.AAAA:
			addr, ok := netip.AddrFromSlice(rec.AAAA)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is6() {
				continue
			}
			v6s = append(v6s, addr)
			ttl := time.Duration(rec.Hdr.Ttl) * time.Second
			if minV6TTL == 0 || (ttl > 0 && ttl < minV6TTL) {
				minV6TTL = ttl
			}
		case *dns.A:
			addr, ok := netip.AddrFromSlice(rec.A)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is4() {
				continue
			}
			v4s = append(v4s, addr)
			ttl := time.Duration(rec.Hdr.Ttl) * time.Second
			if minV4TTL == 0 || (ttl > 0 && ttl < minV4TTL) {
				minV4TTL = ttl
			}
		}
	}
	if len(v6s) == 0 && len(v4s) == 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(v6s) > 0 {
		expires := now.Add(clampFallbackTTL(minV6TTL, fallbackMinV6DomainTTL, fallbackMaxRecordTTL))
		for _, addr := range v6s {
			r.v6ToDomain.put(addr, domain, expires)
		}
	}
	if len(v4s) > 0 {
		expires := now.Add(clampFallbackTTL(minV4TTL, fallbackMinV4RecordTTL, fallbackMaxRecordTTL))
		r.domainToV4.put(domain, dedupeAddrs(v4s), expires)
	}
}

func (r *fallbackRegistry) recordEmptyA(domain string, ttl time.Duration, now time.Time) {
	domain = normalizeFallbackDomain(domain)
	if domain == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domainToV4.put(domain, nil, now.Add(ttl))
}

func (r *fallbackRegistry) lookup(ip netip.Addr, now time.Time) (domain string, v4s []netip.Addr, domainKnown, hasV4Entry bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	domain, domainKnown = r.v6ToDomain.get(ip, now)
	if !domainKnown {
		return "", nil, false, false
	}
	v4s, hasV4Entry = r.domainToV4.get(domain, now)
	if len(v4s) > 0 {
		copied := make([]netip.Addr, len(v4s))
		copy(copied, v4s)
		v4s = copied
	}
	return domain, v4s, true, hasV4Entry
}

// FallbackIPv4s returns sanitized IPv4 candidates associated with a previously resolved IPv6 target.
// If only AAAA was queried earlier, it performs an on-demand bounded TypeA lookup via the DNS engine.
func (e *Engine) FallbackIPv4s(ctx context.Context, ip netip.Addr) []netip.Addr {
	if e == nil || e.fallbackMap == nil {
		return nil
	}
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.Is6() {
		return nil
	}
	domain, v4s, domainKnown, hasV4Entry := e.fallbackMap.lookup(ip, time.Now())
	if !domainKnown {
		return nil
	}
	if hasV4Entry {
		return filterFallbackIPv4s(ip, v4s)
	}

	lookupCtx, cancel := context.WithTimeout(ctx, fallbackLookupWaitLimit)
	defer cancel()
	ch := e.fallbackLookupGroup.DoChan(domain, func() (any, error) {
		if _, cached, _, ok := e.fallbackMap.lookup(ip, time.Now()); ok {
			return cached, nil
		}
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.RecursionDesired = true
		req.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		resp := e.answer(req)
		if resp == nil || (resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError) {
			return []netip.Addr(nil), nil
		}
		resolved := extractIPv4Answers(resp.Answer)
		if len(resolved) == 0 {
			e.fallbackMap.recordEmptyA(domain, fallbackNegativeATTL, time.Now())
		}
		return resolved, nil
	})

	select {
	case res := <-ch:
		resolved, _ := res.Val.([]netip.Addr)
		return filterFallbackIPv4s(ip, resolved)
	case <-lookupCtx.Done():
		return nil
	}
}

func normalizeFallbackDomain(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func clampFallbackTTL(ttl, minTTL, maxTTL time.Duration) time.Duration {
	if ttl < minTTL {
		return minTTL
	}
	if ttl > maxTTL {
		return maxTTL
	}
	return ttl
}

func extractIPv4Answers(answers []dns.RR) []netip.Addr {
	var out []netip.Addr
	for _, rr := range answers {
		rec, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(rec.A)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() {
			out = append(out, addr)
		}
	}
	return dedupeAddrs(out)
}

func dedupeAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) <= 1 {
		return addrs
	}
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}

func filterFallbackIPv4s(v6Target netip.Addr, candidates []netip.Addr) []netip.Addr {
	if len(candidates) == 0 {
		return nil
	}
	v6Local := v6Target.IsLoopback() || v6Target.IsUnspecified() || v6Target.IsLinkLocalUnicast() || v6Target.IsLinkLocalMulticast() || v6Target.IsMulticast() || v6Target.IsPrivate()
	out := make([]netip.Addr, 0, len(candidates))
	for _, addr := range dedupeAddrs(candidates) {
		addr = addr.Unmap()
		if !addr.IsValid() || !addr.Is4() {
			continue
		}
		if !v6Local && (addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast()) {
			continue
		}
		out = append(out, addr)
	}
	return out
}
