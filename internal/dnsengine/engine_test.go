package dnsengine

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
	"proxy.local/m0/internal/config"
)

func serveFixture(t *testing.T, server *dns.Server) {
	t.Helper()
	ready := make(chan struct{})
	done := make(chan error, 1)
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("DNS fixture failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("DNS fixture not ready")
	}
	t.Cleanup(func() { server.Shutdown(); <-done })
}

func udpFixture(t *testing.T, handler dns.Handler) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serveFixture(t, &dns.Server{PacketConn: conn, Handler: handler, UDPSize: 4096})
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func tcpFixture(t *testing.T, handler dns.Handler) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveFixture(t, &dns.Server{Listener: ln, Handler: handler})
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

func geositeFixture(t *testing.T) string {
	t.Helper()
	appendBytes := func(data []byte, n protowire.Number, value []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(data, n, protowire.BytesType), value)
	}
	category := appendBytes(nil, 1, []byte("LOCAL"))
	for kind, value := range []string{"key-lab", "^rx[0-9]+[.]test$", "lab.test", "full.test"} {
		domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), uint64(kind))
		domain = appendBytes(domain, 2, []byte(value))
		category = appendBytes(category, 2, domain)
	}
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, appendBytes(nil, 1, category), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDNSPolicyWireAndCache(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) { testDNSPolicy(t, "127.0.0.1:0") })
	if os.Getenv("PROXY_TEST_IPV6") == "1" {
		t.Run("IPv6", func(t *testing.T) { testDNSPolicy(t, "[::1]:0") })
	}
}

func testDNSPolicy(t *testing.T, bind string) {
	var regionalCalls, defaultCalls atomic.Uint64
	regional := udpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		regionalCalls.Add(1)
		answer := new(dns.Msg).SetReply(q)
		rr, err := dns.NewRR(q.Question[0].Name + " 60 IN HTTPS 1 svc.lab.test. alpn=\"h3\" ech=\"AAECAw==\"")
		if err != nil {
			t.Error(err)
			return
		}
		answer.Answer = []dns.RR{rr}
		w.WriteMsg(answer)
	}))
	fallback := udpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg).SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.30")
		answer.Answer = []dns.RR{rr}
		w.WriteMsg(answer)
	}))
	primary := tcpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		defaultCalls.Add(1)
		answer := new(dns.Msg).SetReply(q)
		if q.Question[0].Name == "retry.test." {
			answer.Rcode = dns.RcodeServerFailure
		} else {
			answer.Rcode = dns.RcodeNameError
			rr, _ := dns.NewRR("test. 60 IN SOA ns.test. hostmaster.test. 1 30 30 30 15")
			answer.Ns = []dns.RR{rr}
		}
		w.WriteMsg(answer)
	}))
	socket, err := net.Listen("tcp", bind)
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().(*net.TCPAddr).AddrPort()
	socket.Close()
	e, err := New(config.DNS{Enabled: true, Listen: []netip.AddrPort{address}, GeoSiteFile: geositeFixture(t),
		Timeout: time.Second, Cache: config.DNSCache{Enabled: true, MaxEntries: 16}, Fallback: "fallback",
		Upstreams: map[string]config.DNSUpstream{
			"regional": {Type: "udp", Address: regional.String()},
			"default":  {Type: "tcp", Address: primary.String()},
			"fallback": {Type: "udp", Address: fallback.String()},
		}, Rules: []config.DNSRule{{GeoSite: "local", Upstream: "regional"}, {Upstream: "default"}},
	}, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	servers, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer servers.Close()
	for _, name := range []string{"lab.test.", "a.LAB.test.", "full.test.", "a-key-lab.other.", "rx3.test."} {
		if e.policy(name) != "regional" {
			t.Errorf("expected GEOSITE match for %s", name)
		}
	}
	for _, name := range []string{"notlab.test.", "child.full.test.", "rx.test."} {
		if e.policy(name) != "default" {
			t.Errorf("unexpected GEOSITE match for %s", name)
		}
	}

	query := new(dns.Msg).SetQuestion("api.lab.test.", dns.TypeHTTPS)
	query.SetEdns0(1232, false)
	probe := func(network string, q *dns.Msg) *dns.Msg {
		t.Helper()
		result, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(q, address.String())
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for _, network := range []string{"udp", "tcp"} {
		res := probe(network, query)
		if len(res.Answer) != 1 || !strings.Contains(res.Answer[0].String(), `ech="AAECAw=="`) ||
			!strings.Contains(res.Answer[0].String(), `alpn="h3"`) {
			t.Fatalf("HTTPS/SVCB parameters lost over %s: %s", network, res)
		}
	}
	if regionalCalls.Load() != 1 {
		t.Fatalf("expected one regional upstream query, got %d", regionalCalls.Load())
	}
	query.IsEdns0().SetDo()
	probe("udp", query)
	if regionalCalls.Load() != 2 {
		t.Fatal("DNSSEC DO query reused a different cache policy")
	}

	missing := new(dns.Msg).SetQuestion("missing.test.", dns.TypeA)
	for range 2 {
		if response := probe("tcp", missing); response.Rcode != dns.RcodeNameError {
			t.Fatal(response)
		}
	}
	if defaultCalls.Load() != 1 {
		t.Fatal("NXDOMAIN was not cached")
	}
	retry := new(dns.Msg).SetQuestion("retry.test.", dns.TypeA)
	for range 2 {
		if response := probe("tcp", retry); len(response.Answer) != 1 {
			t.Fatal(response)
		}
	}
	if status := e.Status(); status.CacheHits != 2 || status.Fallbacks != 2 || defaultCalls.Load() != 3 {
		t.Fatalf("unexpected DNS statistics: %+v", status)
	}
	if err := e.Flush(); err != nil || e.Status().Cached != 0 {
		t.Fatal("cache flush failed")
	}
}

func TestNegativeTTL(t *testing.T) {
	cache := newCache(1)
	request := new(dns.Msg).SetQuestion("missing.test.", dns.TypeA)
	answer := new(dns.Msg).SetRcode(request, dns.RcodeNameError)
	soa, _ := dns.NewRR("test. 60 IN SOA ns.test. admin.test. 1 30 30 30 10")
	answer.Ns = []dns.RR{soa}
	key, _ := makeKey("primary", request)
	now := time.Now()
	cache.put(key, answer, now)
	got, _ := cache.get(key, request, now.Add(3*time.Second))
	if got == nil || got.Ns[0].Header().Ttl != 7 {
		t.Fatalf("unexpected aged negative TTL: %v", got)
	}
	if got, _ := cache.get(key, request, now.Add(10*time.Second)); got != nil {
		t.Fatal("negative entry did not expire")
	}
}

func TestM3LabUpstream(t *testing.T) {
	address := os.Getenv("PROXY_M3_DNS_FIXTURE")
	if address == "" {
		t.Skip("isolated DNS lab fixture")
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg).SetReply(q)
		if len(q.Question) == 1 {
			answer.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 15}, Txt: []string{address}}}
		}
		w.WriteMsg(answer)
	})
	serveFixture(t, &dns.Server{Listener: tcp, Handler: handler})
	serveFixture(t, &dns.Server{PacketConn: udp, Handler: handler})
	t.Log("DNS fixture ready")
	select {}
}
