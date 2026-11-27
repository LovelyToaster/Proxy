package dnsengine

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeTestMsg(domain string, ttl uint32) *dns.Msg {
	msg := new(dns.Msg).SetQuestion(dns.Fqdn(domain), dns.TypeA)
	rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A 1.2.3.4", dns.Fqdn(domain), ttl))
	msg.Answer = []dns.RR{rr}
	return msg
}

func TestARCBasic(t *testing.T) {
	cache := newARCCache(3, staleOptions{})
	now := time.Now()

	// 1. Put domain1 (into T1)
	req1 := new(dns.Msg).SetQuestion("d1.test.", dns.TypeA)
	key1, _ := makeKey("p", req1)
	cache.put(key1, makeTestMsg("d1.test.", 60), now)
	if cache.size() != 1 {
		t.Fatalf("expected size 1, got %d", cache.size())
	}

	// 2. Query domain1 (moves from T1 to T2)
	got, state := cache.get(key1, req1, now.Add(time.Second))
	if state != entryFresh || got == nil {
		t.Fatalf("expected fresh hit, got state %v", state)
	}

	// 3. Put domain2, domain3
	req2 := new(dns.Msg).SetQuestion("d2.test.", dns.TypeA)
	key2, _ := makeKey("p", req2)
	cache.put(key2, makeTestMsg("d2.test.", 60), now)

	req3 := new(dns.Msg).SetQuestion("d3.test.", dns.TypeA)
	key3, _ := makeKey("p", req3)
	cache.put(key3, makeTestMsg("d3.test.", 60), now)

	if cache.size() != 3 {
		t.Fatalf("expected size 3, got %d", cache.size())
	}

	// 4. Put domain4 (causes eviction). Since d1 is in T2 and d2, d3 are in T1,
	// T1 size > p (initially p=0), so LRU of T1 (d2) should be evicted to B1.
	req4 := new(dns.Msg).SetQuestion("d4.test.", dns.TypeA)
	key4, _ := makeKey("p", req4)
	cache.put(key4, makeTestMsg("d4.test.", 60), now)

	if cache.size() != 3 {
		t.Fatalf("expected size 3 after eviction, got %d", cache.size())
	}

	// d1 (frequent) must still be in cache!
	if msg, state := cache.get(key1, req1, now.Add(2*time.Second)); state != entryFresh || msg == nil {
		t.Fatal("frequent item d1 was unexpectedly evicted")
	}

	// d2 should be evicted (miss)
	if _, state := cache.get(key2, req2, now.Add(2*time.Second)); state != entryMiss {
		t.Fatalf("expected d2 to be evicted, got state %v", state)
	}

	// 5. Query d2 again (it was in B1 ghost list, so this is a ghost hit on put)
	cache.put(key2, makeTestMsg("d2.test.", 60), now)
	// After ghost hit on B1, p should have increased from 0!
	if cache.p <= 0 {
		t.Fatalf("expected p to adaptively increase from 0, got %f", cache.p)
	}

	// 6. Test Clear
	cache.clear()
	if cache.size() != 0 || cache.bytes != 0 || cache.p != 0 {
		t.Fatalf("cache clear failed: size=%d, bytes=%d, p=%f", cache.size(), cache.bytes, cache.p)
	}
}

func TestARCvsLRUScanResistance(t *testing.T) {
	// Compare ARC and LRU under a scan workload:
	// Hot working set of 5 items, cache size 10.
	// Then a scan of 20 one-hit-wonder items.
	// ARC should keep hot items; LRU will completely flush hot items!
	cSize := 10
	arc := newARCCache(cSize, staleOptions{})
	lru := newLRUCache(cSize, staleOptions{})
	now := time.Now()

	// Warm up hot items (accessed twice each so they are marked frequent)
	for i := range 5 {
		name := fmt.Sprintf("hot%d.test.", i)
		req := new(dns.Msg).SetQuestion(name, dns.TypeA)
		key, _ := makeKey("p", req)
		msg := makeTestMsg(name, 300)

		arc.put(key, msg, now)
		arc.get(key, req, now) // 2nd access -> moves to T2 in ARC

		lru.put(key, msg, now)
		lru.get(key, req, now)
	}

	// Perform a scan of 20 sequential items (each accessed once)
	for i := range 20 {
		name := fmt.Sprintf("scan%d.test.", i)
		req := new(dns.Msg).SetQuestion(name, dns.TypeA)
		key, _ := makeKey("p", req)
		msg := makeTestMsg(name, 300)

		arc.put(key, msg, now)
		lru.put(key, msg, now)
	}

	// Check how many hot items survived
	arcHotSurvivors := 0
	lruHotSurvivors := 0

	for i := range 5 {
		name := fmt.Sprintf("hot%d.test.", i)
		req := new(dns.Msg).SetQuestion(name, dns.TypeA)
		key, _ := makeKey("p", req)

		if _, state := arc.get(key, req, now); state == entryFresh {
			arcHotSurvivors++
		}
		if _, state := lru.get(key, req, now); state == entryFresh {
			lruHotSurvivors++
		}
	}

	// In LRU, all 5 hot items are evicted because scan size (20) > cache capacity (10).
	if lruHotSurvivors != 0 {
		t.Fatalf("expected LRU to evict all hot items under scan, but %d survived", lruHotSurvivors)
	}

	// In ARC, hot items in T2 are protected against T1 scan pollution!
	if arcHotSurvivors != 5 {
		t.Fatalf("expected ARC to retain all 5 hot items, but got %d", arcHotSurvivors)
	}
}

func TestStaleWhileRevalidateEvaluation(t *testing.T) {
	stale := staleOptions{
		enabled:  true,
		staleTTL: 3600 * time.Second,
		serveTTL: 5,
	}
	cache := newARCCache(5, stale)
	now := time.Now()

	req := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	key, _ := makeKey("p", req)
	// Entry with 10s TTL
	cache.put(key, makeTestMsg("example.com.", 10), now)

	// 1. Query at +3s -> Fresh
	got, state := cache.get(key, req, now.Add(3*time.Second))
	if state != entryFresh || got == nil {
		t.Fatalf("expected fresh hit, got state %v", state)
	}
	if got.Answer[0].Header().Ttl != 7 {
		t.Fatalf("expected decremented TTL 7, got %d", got.Answer[0].Header().Ttl)
	}

	// 2. Query at +15s -> Stale (TTL expired, but within 3600s stale window)
	got, state = cache.get(key, req, now.Add(15*time.Second))
	if state != entryStale || got == nil {
		t.Fatalf("expected stale hit, got state %v", state)
	}
	if got.Answer[0].Header().Ttl != 5 {
		t.Fatalf("expected rewritten serveTTL 5, got %d", got.Answer[0].Header().Ttl)
	}

	// 3. Query at +4000s -> Expired (Miss)
	got, state = cache.get(key, req, now.Add(4000*time.Second))
	if state != entryMiss || got != nil {
		t.Fatalf("expected miss for expired entry, got state %v", state)
	}
}

func TestARCCapacityOne(t *testing.T) {
	cache := newARCCache(1, staleOptions{})
	now := time.Now()

	req1 := new(dns.Msg).SetQuestion("one.test.", dns.TypeA)
	key1, _ := makeKey("p", req1)
	cache.put(key1, makeTestMsg("one.test.", 60), now)

	if cache.size() != 1 {
		t.Fatalf("expected size 1, got %d", cache.size())
	}

	req2 := new(dns.Msg).SetQuestion("two.test.", dns.TypeA)
	key2, _ := makeKey("p", req2)
	cache.put(key2, makeTestMsg("two.test.", 60), now)

	if cache.size() != 1 {
		t.Fatalf("expected size 1, got %d", cache.size())
	}
	if _, state := cache.get(key1, req1, now); state != entryMiss {
		t.Fatal("expected key1 to be evicted")
	}
	if _, state := cache.get(key2, req2, now); state != entryFresh {
		t.Fatal("expected key2 to be fresh")
	}
}

func TestLRUStaleEvaluation(t *testing.T) {
	stale := staleOptions{
		enabled:  true,
		staleTTL: 60 * time.Second,
		serveTTL: 3,
	}
	cache := newLRUCache(2, stale)
	now := time.Now()

	req := new(dns.Msg).SetQuestion("lru.test.", dns.TypeA)
	key, _ := makeKey("p", req)
	cache.put(key, makeTestMsg("lru.test.", 10), now)

	// Fresh
	got, state := cache.get(key, req, now.Add(2*time.Second))
	if state != entryFresh || got.Answer[0].Header().Ttl != 8 {
		t.Fatalf("unexpected fresh: state=%v, got=%v", state, got)
	}

	// Stale
	got, state = cache.get(key, req, now.Add(20*time.Second))
	if state != entryStale || got.Answer[0].Header().Ttl != 3 {
		t.Fatalf("unexpected stale: state=%v, got=%v", state, got)
	}

	// Expired
	got, state = cache.get(key, req, now.Add(100*time.Second))
	if state != entryMiss || got != nil {
		t.Fatalf("unexpected miss: state=%v, got=%v", state, got)
	}
}

func TestNegativeCacheNeverServesStale(t *testing.T) {
	stale := staleOptions{
		enabled:  true,
		staleTTL: 24 * time.Hour,
		serveTTL: 5,
	}
	now := time.Now()

	for _, tc := range []struct {
		name  string
		cache dnsCache
	}{
		{"arc", newCacheWithOptions(cacheOptions{algorithm: "arc", maxEntries: 8, negativeTTL: 10, stale: stale})},
		{"lru", newCacheWithOptions(cacheOptions{algorithm: "lru", maxEntries: 8, negativeTTL: 10, stale: stale})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 1. NXDOMAIN
			nxReq := new(dns.Msg).SetQuestion("missing.test.", dns.TypeA)
			nxKey, _ := makeKey("p", nxReq)
			nxResp := new(dns.Msg).SetRcode(nxReq, dns.RcodeNameError)
			if reason := tc.cache.put(nxKey, nxResp, now); reason != rejectNone {
				t.Fatalf("expected NXDOMAIN to cache, got %v", reason)
			}
			if got, state := tc.cache.get(nxKey, nxReq, now.Add(5*time.Second)); state != entryFresh || got == nil {
				t.Fatalf("expected fresh NXDOMAIN hit, got state=%v", state)
			}
			if got, state := tc.cache.get(nxKey, nxReq, now.Add(10*time.Second)); state != entryMiss || got != nil {
				t.Fatalf("expected expired NXDOMAIN to miss (no stale), got state=%v msg=%v", state, got)
			}

			// 2. NODATA
			ndReq := new(dns.Msg).SetQuestion("nodata.test.", dns.TypeAAAA)
			ndKey, _ := makeKey("p", ndReq)
			ndResp := new(dns.Msg).SetReply(ndReq)
			if reason := tc.cache.put(ndKey, ndResp, now); reason != rejectNone {
				t.Fatalf("expected NODATA to cache, got %v", reason)
			}
			if got, state := tc.cache.get(ndKey, ndReq, now.Add(5*time.Second)); state != entryFresh || got == nil {
				t.Fatalf("expected fresh NODATA hit, got state=%v", state)
			}
			if got, state := tc.cache.get(ndKey, ndReq, now.Add(10*time.Second)); state != entryMiss || got != nil {
				t.Fatalf("expected expired NODATA to miss (no stale), got state=%v msg=%v", state, got)
			}
		})
	}
}
