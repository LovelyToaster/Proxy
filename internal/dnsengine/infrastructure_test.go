package dnsengine

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
)

func TestInfrastructureRulesAndCycles(t *testing.T) {
	endpoint := udpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		res := new(dns.Msg).SetReply(q)
		if q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.19")
			res.Answer = []dns.RR{rr}
		}
		w.WriteMsg(res)
	}))
	cfg := config.DNS{Enabled: true, Timeout: time.Second, Upstreams: map[string]config.DNSUpstream{"local": {Type: "udp", Address: endpoint.String()}, "remote": {Type: "doh", Address: "https://resolver.test/dns-query"}}, Rules: []config.DNSRule{{Domain: "resolver.test", Upstream: "local"}, {DomainSuffix: "internal.test", Upstream: "local"}, {Upstream: "remote"}}}
	e, err := New(cfg, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	d := e.Dialer(net.Dialer{})
	for range 3 {
		addresses, err := d.Resolver.LookupNetIP(context.Background(), "ip4", "nas.internal.test")
		if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.19" {
			t.Fatalf("internal rule resolution: %v %v", addresses, err)
		}
	}
	cfg.Rules = []config.DNSRule{{Upstream: "remote"}}
	if _, err := New(cfg, net.Dialer{}); err == nil || !strings.Contains(err.Error(), "remote -> remote") {
		t.Fatalf("self cycle: %v", err)
	}
	cfg.Upstreams["local"] = config.DNSUpstream{Type: "udp", Address: "resolver2.test:53"}
	cfg.Rules = []config.DNSRule{{Domain: "resolver.test", Upstream: "local"}, {Upstream: "remote"}}
	if _, err := New(cfg, net.Dialer{}); err == nil || !strings.Contains(err.Error(), "DNS dependency cycle") {
		t.Fatalf("two-node cycle: %v", err)
	}
	cfg.Upstreams["remote"] = config.DNSUpstream{Type: "doh", Address: "https://resolver.test/dns-query", Bootstrap: []netip.AddrPort{endpoint}}
	if valid, err := New(cfg, net.Dialer{}); err != nil {
		t.Fatalf("explicit bootstrap did not break cycle: %v", err)
	} else {
		valid.Close()
	}
}

func TestInfrastructureProxyCycle(t *testing.T) {
	cfg := config.DNS{Enabled: true, Timeout: time.Second, Upstreams: map[string]config.DNSUpstream{"remote": {Type: "doh", Address: "https://192.0.2.1/dns-query", Outbound: "proxy"}}, Rules: []config.DNSRule{{Upstream: "remote"}}}
	proxies := map[string]config.Outbound{"proxy": {Type: "socks5", Address: "proxy.test:1080"}}
	if _, err := New(cfg, net.Dialer{}, proxies); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("SOCKS5 dependency cycle: %v", err)
	}
}
