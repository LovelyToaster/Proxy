package dnsengine

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
)

func TestFallbackRegistryLRUAndExpiry(t *testing.T) {
	reg := newFallbackRegistry(2)
	now := time.Unix(1_700_000_000, 0)

	rr1, _ := dns.NewRR("a.example.com. 60 IN AAAA 2001:db8::1")
	rr2, _ := dns.NewRR("b.example.com. 60 IN AAAA 2001:db8::2")
	rr3, _ := dns.NewRR("c.example.com. 60 IN AAAA 2001:db8::3")
	a1, _ := dns.NewRR("a.example.com. 10 IN A 198.51.100.1")

	reg.record("a.example.com.", []dns.RR{rr1, a1}, now)
	reg.record("b.example.com.", []dns.RR{rr2}, now)
	// Touch a.example.com so b becomes LRU.
	if dom, v4s, ok, hasV4 := reg.lookup(netip.MustParseAddr("2001:db8::1"), now.Add(time.Second)); !ok || !hasV4 || dom != "a.example.com" || len(v4s) != 1 || v4s[0] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("unexpected lookup for a.example.com: dom=%q v4=%v ok=%v hasV4=%v", dom, v4s, ok, hasV4)
	}
	// Inserting c evicts b (2001:db8::2).
	reg.record("c.example.com.", []dns.RR{rr3}, now)
	if _, _, ok, _ := reg.lookup(netip.MustParseAddr("2001:db8::2"), now.Add(time.Second)); ok {
		t.Fatal("expected b.example.com to be evicted from bounded LRU")
	}
	// A record expires at +10s while AAAA->domain lives >=30s.
	if _, _, ok, hasV4 := reg.lookup(netip.MustParseAddr("2001:db8::1"), now.Add(15*time.Second)); !ok || hasV4 {
		t.Fatalf("expected domain known with expired A entry at +15s: ok=%v hasV4=%v", ok, hasV4)
	}

	reg.clear()
	if _, _, ok, _ := reg.lookup(netip.MustParseAddr("2001:db8::1"), now.Add(time.Second)); ok {
		t.Fatal("expected clear() to empty registry")
	}
}

func TestFilterFallbackIPv4sRejectsPoisonedAddresses(t *testing.T) {
	v6Public := netip.MustParseAddr("2409:8c4c:c00:9::24")
	got := filterFallbackIPv4s(v6Public, []netip.Addr{
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("169.254.1.2"),
		netip.MustParseAddr("224.0.0.1"),
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("198.51.100.11"),
	})
	if len(got) != 2 || got[0] != netip.MustParseAddr("198.51.100.10") || got[1] != netip.MustParseAddr("198.51.100.11") {
		t.Fatalf("unexpected filtered candidates: %v", got)
	}
}

func TestEngineFallbackIPv4sLazyTypeALookupAndReplace(t *testing.T) {
	var aLookups atomic.Int32
	var v6OnlyLookups atomic.Int32

	upAddr := udpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		resp := new(dns.Msg).SetReply(q)
		name := q.Question[0].Name
		qtype := q.Question[0].Qtype
		switch name {
		case "dual.example.test.":
			if qtype == dns.TypeAAAA {
				rr, _ := dns.NewRR(name + " 60 IN AAAA 2001:db8::cafe")
				resp.Answer = []dns.RR{rr}
			} else if qtype == dns.TypeA {
				aLookups.Add(1)
				// Slight pause so concurrent callers share SingleFlight.
				time.Sleep(20 * time.Millisecond)
				rrBad, _ := dns.NewRR(name + " 60 IN A 127.0.0.1")
				rrGood, _ := dns.NewRR(name + " 60 IN A 203.0.113.8")
				resp.Answer = []dns.RR{rrBad, rrGood}
			}
		case "v6only.example.test.":
			if qtype == dns.TypeAAAA {
				rr, _ := dns.NewRR(name + " 60 IN AAAA 2001:db8::6666")
				resp.Answer = []dns.RR{rr}
			} else if qtype == dns.TypeA {
				v6OnlyLookups.Add(1)
			}
		}
		w.WriteMsg(resp)
	}))

	cfg := config.DNS{
		Enabled:  true,
		Timeout:  2 * time.Second,
		Fallback: "up",
		Cache: config.DNSCache{
			Enabled:    true,
			MaxEntries: 64,
			Algorithm:  "lru",
		},
		Upstreams: map[string]config.DNSUpstream{
			"up": {Type: "udp", Address: upAddr.String()},
		},
		Rules: []config.DNSRule{{Upstream: "up"}},
	}
	eng, err := New(cfg, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Unseen literal IPv6 returns nil without touching upstream.
	if got := eng.FallbackIPv4s(context.Background(), netip.MustParseAddr("2001:db8::9999")); len(got) != 0 {
		t.Fatalf("expected nil for unseen IPv6, got %v", got)
	}

	// Client queries only AAAA via handle (same path as ServeDNS / SubmitPacket / HandleStream).
	q := new(dns.Msg)
	q.SetQuestion("dual.example.test.", dns.TypeAAAA)
	if resp := eng.handle(q); resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected AAAA lookup success, got %v", resp)
	}

	// Concurrent FallbackIPv4s calls should trigger only 1 on-demand TypeA upstream query.
	const callers = 6
	var wg sync.WaitGroup
	results := make([][]netip.Addr, callers)
	for i := range callers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = eng.FallbackIPv4s(context.Background(), netip.MustParseAddr("2001:db8::cafe"))
		}(i)
	}
	wg.Wait()

	for i, res := range results {
		if len(res) != 1 || res[0] != netip.MustParseAddr("203.0.113.8") {
			t.Fatalf("caller %d got unexpected fallback IPv4s: %v", i, res)
		}
	}
	if aLookups.Load() != 1 {
		t.Fatalf("expected singleflight to coalesce TypeA lookups to 1, got %d", aLookups.Load())
	}

	// Subsequent call hits cached domainToV4 without another upstream query.
	if res := eng.FallbackIPv4s(context.Background(), netip.MustParseAddr("2001:db8::cafe")); len(res) != 1 || res[0] != netip.MustParseAddr("203.0.113.8") {
		t.Fatalf("unexpected cached fallback IPv4s: %v", res)
	}
	if aLookups.Load() != 1 {
		t.Fatalf("expected cached TypeA hit, got %d upstream lookups", aLookups.Load())
	}

	// IPv6-only domain without SOA negative answer is still suppressed in fallbackMap.
	qOnly := new(dns.Msg)
	qOnly.SetQuestion("v6only.example.test.", dns.TypeAAAA)
	_ = eng.handle(qOnly)
	if got := eng.FallbackIPv4s(context.Background(), netip.MustParseAddr("2001:db8::6666")); len(got) != 0 {
		t.Fatalf("expected no fallback for IPv6-only domain, got %v", got)
	}
	if got := eng.FallbackIPv4s(context.Background(), netip.MustParseAddr("2001:db8::6666")); len(got) != 0 {
		t.Fatalf("expected no fallback on second call, got %v", got)
	}
	if v6OnlyLookups.Load() != 1 {
		t.Fatalf("expected IPv6-only negative A cache to avoid repeat lookups, got %d", v6OnlyLookups.Load())
	}

	// Engine.Replace clears previously learned fallback mappings.
	nextEng, err := New(cfg, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	eng.Replace(nextEng)
	if got := eng.FallbackIPv4s(context.Background(), netip.MustParseAddr("2001:db8::cafe")); len(got) != 0 {
		t.Fatalf("expected Replace() to clear fallback registry, got %v", got)
	}
}
