package dnsengine

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
)

func TestDomainDNSPriorityWireAndReload(t *testing.T) {
	fixture := func(ip string) string {
		return udpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			res := new(dns.Msg).SetReply(q)
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A " + ip)
			res.Answer = []dns.RR{rr}
			w.WriteMsg(res)
		})).String()
	}
	cfg := config.DNS{Enabled: true, Timeout: time.Second, GeoSiteFile: geositeFixture(t), Cache: config.DNSCache{Enabled: true, MaxEntries: 16},
		Upstreams: map[string]config.DNSUpstream{"specific": {Type: "udp", Address: fixture("192.0.2.1")}, "regional": {Type: "udp", Address: fixture("192.0.2.2")}, "default": {Type: "udp", Address: fixture("192.0.2.3")}},
		Rules:     []config.DNSRule{{Domain: "API.LAB.TEST.", Upstream: "specific"}, {DomainSuffix: "special.test", Upstream: "specific"}, {GeoSite: "local", Upstream: "regional"}, {Upstream: "default"}},
	}
	e, err := New(cfg, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for name, ip := range map[string]string{
		"api.lab.test.": "192.0.2.1", "child.api.lab.test.": "192.0.2.2", "SPECIAL.test.": "192.0.2.1", "a.special.test.": "192.0.2.1", "notspecial.test.": "192.0.2.3", "api.lab.test.evil.": "192.0.2.3",
	} {
		for range 2 {
			res := e.handle(new(dns.Msg).SetQuestion(name, dns.TypeA))
			if len(res.Answer) != 1 || res.Answer[0].(*dns.A).A.String() != ip {
				t.Fatalf("%s: %v", name, res)
			}
		}
	}
	if e.Status().CacheHits != 6 {
		t.Fatal("domain policy cache not reused")
	}
	cfg.Rules = []config.DNSRule{{Domain: "api.lab.test", Upstream: "default"}, {Upstream: "regional"}}
	next, err := New(cfg, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	e.Replace(next)
	res := e.handle(new(dns.Msg).SetQuestion("api.lab.test.", dns.TypeA))
	if len(res.Answer) != 1 || res.Answer[0].(*dns.A).A.String() != "192.0.2.3" {
		t.Fatal("old DNS policy/cache survived reload")
	}
}
