package dnsengine

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/systemdns"
)

func TestCacheKeyEDNS0AndECS(t *testing.T) {
	plain := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	ednsPlain := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	ednsPlain.SetEdns0(1232, false)

	ednsPadding := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	ednsPadding.SetEdns0(1232, false)
	ednsPadding.IsEdns0().Option = append(ednsPadding.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 32)})

	k1, ok1 := makeKey("default", plain)
	k2, ok2 := makeKey("default", ednsPlain)
	k3, ok3 := makeKey("default", ednsPadding)
	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("expected all non-ECS queries to be cacheable: %v %v %v", ok1, ok2, ok3)
	}
	if k1 != k2 || k2 != k3 {
		t.Fatalf("expected plain, EDNS0, and EDNS0+Padding to share key: %+v vs %+v vs %+v", k1, k2, k3)
	}

	ednsDO := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	ednsDO.SetEdns0(1232, true)
	kDO, okDO := makeKey("default", ednsDO)
	if !okDO || kDO == k1 {
		t.Fatalf("expected DO=true to have distinct cacheable key, ok=%v key=%+v", okDO, kDO)
	}

	ednsECS := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	ednsECS.SetEdns0(1232, false)
	ednsECS.IsEdns0().Option = append(ednsECS.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("1.2.3.0").To4(),
	})
	if _, ok := makeKey("default", ednsECS); ok {
		t.Fatal("expected ECS query to be uncacheable")
	}
}

func TestNegativeTTLAndResponseEDNS0(t *testing.T) {
	now := time.Now()
	req := new(dns.Msg).SetQuestion("nodata.example.com.", dns.TypeHTTPS)
	key, ok := makeKey("default", req)
	if !ok {
		t.Fatal("expected query to be cacheable")
	}

	// NODATA without SOA
	nodata := new(dns.Msg).SetReply(req)
	cDisabled := newARCCache(16, staleOptions{})
	if reason := cDisabled.put(key, nodata, now); reason != rejectNoSOA {
		t.Fatalf("expected rejectNoSOA when negativeTTL=0, got %v", reason)
	}

	cEnabled := newARCCache(16, staleOptions{})
	cEnabled.negativeTTL = 60
	if reason := cEnabled.put(key, nodata, now); reason != rejectNone {
		t.Fatalf("expected NODATA without SOA to cache when negativeTTL=60, got %v", reason)
	}
	if msg, state := cEnabled.get(key, req, now.Add(10*time.Second)); state != entryFresh || msg == nil {
		t.Fatalf("expected fresh hit for NODATA, got state=%v", state)
	}

	// Response with EDNS0 Padding should cache and strip OPT
	reqA := new(dns.Msg).SetQuestion("pad.example.com.", dns.TypeA)
	keyA, _ := makeKey("default", reqA)
	respPad := new(dns.Msg).SetReply(reqA)
	respPad.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "pad.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   net.ParseIP("93.184.216.34").To4(),
	}}
	respPad.SetEdns0(1232, false)
	respPad.IsEdns0().Option = append(respPad.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 16)})

	if reason := cEnabled.put(keyA, respPad, now); reason != rejectNone {
		t.Fatalf("expected response with EDNS0 Padding to cache, got %v", reason)
	}
	got, state := cEnabled.get(keyA, reqA, now)
	if state != entryFresh || got == nil || len(got.Answer) != 1 {
		t.Fatalf("expected fresh hit for padded response, got state=%v", state)
	}
	if got.IsEdns0() != nil {
		t.Fatal("expected cached response to strip upstream OPT record")
	}
}

func TestNegativeTTLCapsLargeSOA(t *testing.T) {
	now := time.Now()
	req := new(dns.Msg).SetQuestion("big-soa.example.com.", dns.TypeA)
	key, _ := makeKey("default", req)

	// Large SOA Minttl=3600s should be capped by negativeTTL=60s
	nxLarge := new(dns.Msg).SetRcode(req, dns.RcodeNameError)
	soaLarge, _ := dns.NewRR("example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 30 30 30 3600")
	nxLarge.Ns = []dns.RR{soaLarge}

	c := newARCCache(16, staleOptions{})
	c.negativeTTL = 60
	if reason := c.put(key, nxLarge, now); reason != rejectNone {
		t.Fatalf("expected NXDOMAIN with large SOA to cache, got %v", reason)
	}
	got, state := c.get(key, req, now.Add(10*time.Second))
	if state != entryFresh || got == nil || len(got.Ns) != 1 || got.Ns[0].Header().Ttl != 50 {
		t.Fatalf("expected capped SOA TTL 50 at +10s, got state=%v ns=%v", state, got)
	}
	if got, state := c.get(key, req, now.Add(60*time.Second)); state != entryMiss || got != nil {
		t.Fatalf("expected capped negative entry to expire at +60s, got state=%v", state)
	}

	// Smaller SOA Minttl=10s should be preserved (< negativeTTL=60s)
	nxSmall := new(dns.Msg).SetRcode(req, dns.RcodeNameError)
	soaSmall, _ := dns.NewRR("example.com. 300 IN SOA ns.example.com. admin.example.com. 1 30 30 30 10")
	nxSmall.Ns = []dns.RR{soaSmall}

	if reason := c.put(key, nxSmall, now); reason != rejectNone {
		t.Fatalf("expected NXDOMAIN with small SOA to cache, got %v", reason)
	}
	got, state = c.get(key, req, now.Add(3*time.Second))
	if state != entryFresh || got == nil || got.Ns[0].Header().Ttl != 7 {
		t.Fatalf("expected preserved SOA TTL 7 at +3s, got state=%v ns=%v", state, got)
	}
	if got, state := c.get(key, req, now.Add(10*time.Second)); state != entryMiss || got != nil {
		t.Fatalf("expected small SOA negative entry to expire at +10s, got state=%v", state)
	}
}

func TestEngineMissSingleFlightAndMetrics(t *testing.T) {
	var upstreamCalls atomic.Int32
	gate := make(chan struct{})
	mock := &mockUpstream{
		fn: func(m *dns.Msg) (*dns.Msg, error) {
			upstreamCalls.Add(1)
			<-gate
			resp := new(dns.Msg).SetReply(m)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   netip.MustParseAddr("192.0.2.1").AsSlice(),
			}}
			return resp, nil
		},
	}

	e := newTestEngine(mock, staleOptions{})
	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	results := make([]*dns.Msg, workers)
	for i := range workers {
		go func(idx int) {
			defer wg.Done()
			q := new(dns.Msg).SetQuestion("sf.example.com.", dns.TypeA)
			q.Id = uint16(1000 + idx)
			results[idx] = e.answer(q)
		}(i)
	}

	// Wait briefly so goroutines enter singleflight, then release upstream
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()

	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 upstream call due to miss singleflight, got %d", calls)
	}
	for i, res := range results {
		if res == nil || res.Id != uint16(1000+i) || len(res.Answer) != 1 {
			t.Fatalf("worker %d got invalid response: %+v", i, res)
		}
	}

	// Uncacheable ECS query should increment UncacheableQueries
	ecsQ := new(dns.Msg).SetQuestion("ecs.example.com.", dns.TypeA)
	ecsQ.SetEdns0(1232, false)
	ecsQ.IsEdns0().Option = append(ecsQ.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.ParseIP("10.0.0.0").To4(),
	})
	_ = e.answer(ecsQ)
	st := e.Status()
	if st.UncacheableQueries != 1 {
		t.Fatalf("expected UncacheableQueries=1, got %d", st.UncacheableQueries)
	}
}

func TestSystemUpstreamCachePolicyAcrossRestart(t *testing.T) {
	var currentDNS atomic.Value
	currentDNS.Store("192.0.2.53:53")

	newSys := func() *systemUpstream {
		return &systemUpstream{
			discover: func(ctx context.Context) ([]systemdns.Server, error) {
				addr := netip.MustParseAddrPort(currentDNS.Load().(string))
				return []systemdns.Server{{Address: addr, Default: true}}, nil
			},
		}
	}

	sys1 := newSys()
	p1 := sys1.cacheKeyPolicy("main", "example.com.")
	p1Again := sys1.cacheKeyPolicy("main", "example.com.")
	if p1 == "main" || p1 != p1Again {
		t.Fatalf("expected stable scoped policy, got %q and %q", p1, p1Again)
	}

	// Persist cache entry under p1
	now := time.Now()
	req := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	key1, ok := makeKey(p1, req)
	if !ok {
		t.Fatal("expected cacheable key")
	}
	resp := new(dns.Msg).SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
		A:   netip.MustParseAddr("93.184.216.34").AsSlice(),
	}}

	c1 := newARCCache(16, staleOptions{})
	c1.put(key1, resp, now)
	cacheFile := filepath.Join(t.TempDir(), "dns_cache.dat")
	if err := saveToFile(cacheFile, c1.snapshot()); err != nil {
		t.Fatal(err)
	}

	// Simulate restart on the SAME network: restored cache hits
	loaded, err := loadFromFile(cacheFile, now, staleOptions{})
	if err != nil {
		t.Fatal(err)
	}
	c2 := newARCCache(16, staleOptions{})
	c2.restore(loaded, now)

	sysRestartSame := newSys()
	keySame, _ := makeKey(sysRestartSame.cacheKeyPolicy("main", "example.com."), req)
	if _, state := c2.get(keySame, req, now); state != entryFresh {
		t.Fatalf("expected fresh hit after restart on same DNS, got %v", state)
	}

	// Simulate restart on a DIFFERENT network: restored cache misses
	currentDNS.Store("198.51.100.53:53")
	sysRestartChanged := newSys()
	keyChanged, _ := makeKey(sysRestartChanged.cacheKeyPolicy("main", "example.com."), req)
	if keyChanged == keySame {
		t.Fatal("expected different cache key when system DNS changed")
	}
	if _, state := c2.get(keyChanged, req, now); state != entryMiss {
		t.Fatalf("expected miss after restart on changed DNS, got %v", state)
	}
}
