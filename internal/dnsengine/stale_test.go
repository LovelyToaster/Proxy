package dnsengine

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
)

type mockUpstream struct {
	fn func(*dns.Msg) (*dns.Msg, error)
}

func (m *mockUpstream) Exchange(req *dns.Msg) (*dns.Msg, error) {
	return m.fn(req)
}

func (m *mockUpstream) Address() string {
	return "mock://127.0.0.1"
}

func (m *mockUpstream) Close() error {
	return nil
}

func newTestEngine(mock upstream.Upstream, stale staleOptions) *Engine {
	cache := newARCCache(64, stale)
	e := &Engine{
		upstreams: map[string]upstream.Upstream{
			"default": mock,
		},
		rules: []config.DNSRule{
			{Upstream: "default"},
		},
		cache:   cache,
		workers: make(chan struct{}, 128),
	}
	return e
}

func TestEngineServeStaleAsyncRefresh(t *testing.T) {
	var upstreamCalls atomic.Uint64
	var currentIP atomic.Pointer[string]
	ip1 := "1.1.1.1"
	ip2 := "2.2.2.2"
	currentIP.Store(&ip1)

	mock := &mockUpstream{
		fn: func(req *dns.Msg) (*dns.Msg, error) {
			upstreamCalls.Add(1)
			resp := new(dns.Msg)
			resp.SetReply(req)
			ip := *currentIP.Load()
			rr, _ := dns.NewRR(fmt.Sprintf("%s 10 IN A %s", req.Question[0].Name, ip))
			resp.Answer = []dns.RR{rr}
			return resp, nil
		},
	}

	staleOpts := staleOptions{
		enabled:  true,
		staleTTL: 3600 * time.Second,
		serveTTL: 5,
	}
	e := newTestEngine(mock, staleOpts)

	req := new(dns.Msg).SetQuestion("stale.test.", dns.TypeA)
	key, _ := makeKey("default", req)

	// Pre-populate cache with an entry that was stored 20s ago (TTL was 10s, so it is stale)
	storedTime := time.Now().Add(-20 * time.Second)
	resp1 := new(dns.Msg).SetReply(req)
	rr1, _ := dns.NewRR("stale.test. 10 IN A 1.1.1.1")
	resp1.Answer = []dns.RR{rr1}
	e.cache.put(key, resp1, storedTime)

	// Now current upstream IP changes to 2.2.2.2
	currentIP.Store(&ip2)

	// 1. Query: Cache is stale!
	// It should immediately return the stale answer (1.1.1.1) with serve_ttl=5,
	// and record a cache hit and stale hit.
	answer := e.handle(req)
	if len(answer.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %v", answer)
	}
	aRecord := answer.Answer[0].(*dns.A)
	if aRecord.A.String() != "1.1.1.1" {
		t.Fatalf("expected stale response 1.1.1.1, got %s", aRecord.A.String())
	}
	if aRecord.Hdr.Ttl != 5 {
		t.Fatalf("expected rewritten serve_ttl 5, got %d", aRecord.Hdr.Ttl)
	}

	status := e.Status()
	if status.CacheHits != 1 || status.StaleHits != 1 {
		t.Fatalf("expected 1 hit and 1 stale hit, got hits=%d, staleHits=%d", status.CacheHits, status.StaleHits)
	}

	// 2. Wait for async refresh in background to complete
	deadline := time.Now().Add(2 * time.Second)
	refreshed := false
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if upstreamCalls.Load() > 0 {
			refreshed = true
			break
		}
	}
	if !refreshed {
		t.Fatal("background refresh was not triggered")
	}

	// Allow a moment for cache.put in background to settle
	time.Sleep(50 * time.Millisecond)

	// 3. Next query should hit the fresh cache updated with 2.2.2.2!
	answer2 := e.handle(req)
	aRecord2 := answer2.Answer[0].(*dns.A)
	if aRecord2.A.String() != "2.2.2.2" {
		t.Fatalf("expected fresh response 2.2.2.2 after async refresh, got %s", aRecord2.A.String())
	}
	if aRecord2.Hdr.Ttl != 10 {
		t.Fatalf("expected full TTL 10 on fresh cache, got %d", aRecord2.Hdr.Ttl)
	}
}

func TestEngineServeStaleSingleFlight(t *testing.T) {
	var upstreamCalls atomic.Uint64
	blockUpstream := make(chan struct{})

	mock := &mockUpstream{
		fn: func(req *dns.Msg) (*dns.Msg, error) {
			upstreamCalls.Add(1)
			<-blockUpstream // delay upstream response
			resp := new(dns.Msg).SetReply(req)
			rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 9.9.9.9", req.Question[0].Name))
			resp.Answer = []dns.RR{rr}
			return resp, nil
		},
	}

	staleOpts := staleOptions{
		enabled:  true,
		staleTTL: 3600 * time.Second,
		serveTTL: 5,
	}
	e := newTestEngine(mock, staleOpts)

	req := new(dns.Msg).SetQuestion("singleflight.test.", dns.TypeA)
	key, _ := makeKey("default", req)

	// Seed stale entry
	storedTime := time.Now().Add(-20 * time.Second)
	resp1 := new(dns.Msg).SetReply(req)
	rr1, _ := dns.NewRR("singleflight.test. 10 IN A 1.2.3.4")
	resp1.Answer = []dns.RR{rr1}
	e.cache.put(key, resp1, storedTime)

	// Launch 50 concurrent requests
	const concurrent = 50
	var wg sync.WaitGroup
	wg.Add(concurrent)

	for range concurrent {
		go func() {
			defer wg.Done()
			ans := e.handle(req)
			if len(ans.Answer) != 1 || ans.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
				t.Errorf("expected immediate stale answer, got %v", ans)
			}
		}()
	}

	// All 50 queries should return almost instantly with the stale answer
	wg.Wait()

	// Wait a moment to ensure async calls have reached singleflight
	time.Sleep(50 * time.Millisecond)

	// Verify upstream was invoked at most ONCE
	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("expected singleflight to allow only 1 upstream call, got %d", calls)
	}

	// Unblock upstream
	close(blockUpstream)
}

func TestEngineUpstreamFailureReturnsStale(t *testing.T) {
	// RFC 8767: If upstream fails (returns error or SERVFAIL), return stale cache if available
	mock := &mockUpstream{
		fn: func(req *dns.Msg) (*dns.Msg, error) {
			return nil, errors.New("upstream network timeout")
		},
	}

	staleOpts := staleOptions{
		enabled:  true,
		staleTTL: 3600 * time.Second,
		serveTTL: 5,
	}
	e := newTestEngine(mock, staleOpts)

	req := new(dns.Msg).SetQuestion("failover.test.", dns.TypeA)
	key, _ := makeKey("default", req)

	// Put stale entry in cache
	storedTime := time.Now().Add(-20 * time.Second)
	resp := new(dns.Msg).SetReply(req)
	rr, _ := dns.NewRR("failover.test. 10 IN A 5.5.5.5")
	resp.Answer = []dns.RR{rr}
	e.cache.put(key, resp, storedTime)

	// Query: Since it's stale, it serves stale immediately.
	ans := e.handle(req)
	if len(ans.Answer) != 1 || ans.Answer[0].(*dns.A).A.String() != "5.5.5.5" {
		t.Fatalf("expected stale response on upstream failure, got %v", ans)
	}

	status := e.Status()
	if status.StaleHits < 1 {
		t.Fatalf("expected stale hits recorded, got %d", status.StaleHits)
	}
}

func TestEngineExpiredNegativeRefreshesSynchronously(t *testing.T) {
	var upstreamCalls atomic.Uint64
	mock := &mockUpstream{
		fn: func(req *dns.Msg) (*dns.Msg, error) {
			upstreamCalls.Add(1)
			resp := new(dns.Msg).SetReply(req)
			rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 3.3.3.3", req.Question[0].Name))
			resp.Answer = []dns.RR{rr}
			return resp, nil
		},
	}

	staleOpts := staleOptions{
		enabled:  true,
		staleTTL: 24 * time.Hour,
		serveTTL: 5,
	}
	e := newTestEngine(mock, staleOpts)
	e.cache.(*arcCache).negativeTTL = 10

	req := new(dns.Msg).SetQuestion("newly-created.test.", dns.TypeA)
	key, _ := makeKey("default", req)

	// Seed an expired NXDOMAIN (stored 20s ago, negativeTTL=10s)
	nxResp := new(dns.Msg).SetRcode(req, dns.RcodeNameError)
	if reason := e.cache.put(key, nxResp, time.Now().Add(-20*time.Second)); reason != rejectNone {
		t.Fatalf("expected NXDOMAIN to cache, got %v", reason)
	}

	// Next query must NOT serve stale NXDOMAIN; it must synchronously fetch 3.3.3.3
	ans := e.handle(req)
	if ans.Rcode != dns.RcodeSuccess || len(ans.Answer) != 1 {
		t.Fatalf("expected fresh A record after negative TTL expiry, got rcode=%s answers=%d", dns.RcodeToString[ans.Rcode], len(ans.Answer))
	}
	if ip := ans.Answer[0].(*dns.A).A.String(); ip != "3.3.3.3" {
		t.Fatalf("expected 3.3.3.3, got %s", ip)
	}
	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 synchronous upstream call, got %d", calls)
	}
	status := e.Status()
	if status.StaleHits != 0 {
		t.Fatalf("expected 0 stale hits for expired negative entry, got %d", status.StaleHits)
	}
}
