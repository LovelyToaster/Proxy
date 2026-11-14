package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/dnsengine"
	"proxy.local/m0/internal/routing"
)

func reservePort(t *testing.T, network, addr string) netip.AddrPort {
	t.Helper()
	if network == "udp" || network == "udp4" || network == "udp6" {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			t.Fatal(err)
		}
		ap := netip.MustParseAddrPort(pc.LocalAddr().String())
		pc.Close()
		return ap
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	return ap
}

func startEchoIPv4(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

func startMockDNSUDP(t *testing.T, handler dns.Handler) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler, UDPSize: 4096}
	ready := make(chan struct{})
	done := make(chan error, 1)
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- srv.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("mock DNS failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("mock DNS start timeout")
	}
	t.Cleanup(func() { srv.Shutdown(); <-done })
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestCoreServeTCPIPv6FallbackEndToEnd(t *testing.T) {
	echoAddr := startEchoIPv4(t)
	upDNS := startMockDNSUDP(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		resp := new(dns.Msg).SetReply(q)
		name := q.Question[0].Name
		switch q.Question[0].Qtype {
		case dns.TypeAAAA:
			rr, _ := dns.NewRR(name + " 60 IN AAAA ::1")
			resp.Answer = []dns.RR{rr}
		case dns.TypeA:
			rr, _ := dns.NewRR(name + " 60 IN A 127.0.0.1")
			resp.Answer = []dns.RR{rr}
		}
		w.WriteMsg(resp)
	}))

	listenTCP := reservePort(t, "tcp4", "127.0.0.1:0")
	dnsListen := reservePort(t, "udp4", "127.0.0.1:0")
	dir := filepath.Join(t.TempDir(), "run")
	cfgPath := filepath.Join(t.TempDir(), "proxy.yaml")
	cfgText := fmt.Sprintf(`version: 1
network:
  connect_timeout: 2s
  ipv6_fallback: true
  ipv6_fallback_delay: 30ms
listeners:
  - address: %s
    target: "[::1]:%d"
    network: tcp
outbounds:
  direct:
    type: direct
routing:
  rules:
    - outbound: direct
dns:
  enabled: true
  listen: [%s]
  upstreams:
    up: {type: udp, address: %s}
  rules:
    - upstream: up
`, listenTCP, echoAddr.Port(), dnsListen, upDNS)
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- ServeReady(ctx, cfgPath, dir, func() { close(ready) }) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("ServeReady exited early: %v", err)
	case <-ctx.Done():
		t.Fatal("ServeReady timed out")
	}

	// Step 1: Query AAAA via the proxy DNS server so [::1] -> fallback.test is recorded (without A queried yet).
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	q := new(dns.Msg)
	q.SetQuestion("fallback.test.", dns.TypeAAAA)
	resp, _, err := client.Exchange(q, dnsListen.String())
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("DNS AAAA query failed: resp=%v err=%v", resp, err)
	}

	// Step 2: Connect to the proxy listener targeting [::1]:<echoPort>.
	// Because nothing listens on [::1]:<echoPort>, direct fallback should lazy-resolve A (127.0.0.1),
	// connect to 127.0.0.1:<echoPort>, and echo data.
	conn, err := net.DialTimeout("tcp4", listenTCP.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy listener failed: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("happy-eyeballs-ok")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("expected echoed payload via IPv4 fallback: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, payload)
	}
}

func TestDialTCPOutboundRespectsRouteConsistencyAndOutboundType(t *testing.T) {
	echoAddr := startEchoIPv4(t)
	upDNS := startMockDNSUDP(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		resp := new(dns.Msg).SetReply(q)
		name := q.Question[0].Name
		switch q.Question[0].Qtype {
		case dns.TypeAAAA:
			rr, _ := dns.NewRR(name + " 60 IN AAAA ::1")
			resp.Answer = []dns.RR{rr}
		case dns.TypeA:
			rr, _ := dns.NewRR(name + " 60 IN A 127.0.0.1")
			resp.Answer = []dns.RR{rr}
		}
		w.WriteMsg(resp)
	}))

	dnsCfg := config.DNS{
		Enabled:   true,
		Timeout:   time.Second,
		Cache:     config.DNSCache{Enabled: true, MaxEntries: 32, Algorithm: "lru"},
		Upstreams: map[string]config.DNSUpstream{"up": {Type: "udp", Address: upDNS.String()}},
		Rules:     []config.DNSRule{{Upstream: "up"}},
	}
	eng, err := dnsengine.New(dnsCfg, net.Dialer{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Seed ::1 -> route-split.test -> 127.0.0.1.
	q := new(dns.Msg)
	q.SetQuestion("route-split.test.", dns.TypeAAAA)
	eng.ServeDNS(nopResponseWriter{}, q)

	// Routing table: IPv6 [::1] goes to direct, while 127.0.0.1/32 goes to proxy_out.
	table, err := routing.Open(config.Routing{
		Rules: []config.Rule{
			{CIDR: netip.MustParsePrefix("127.0.0.1/32"), Outbound: "proxy_out"},
			{Outbound: "direct"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer table.Close()

	st := &state{dns: eng}
	st.snap.Store(&routeSnapshot{routes: table})

	netCfg := config.Network{
		ConnectTimeout:    500 * time.Millisecond,
		IPv6FallbackDelay: 20 * time.Millisecond,
	}
	deadV6 := netip.AddrPortFrom(netip.IPv6Loopback(), echoAddr.Port())

	// 1. Route consistency check must reject 127.0.0.1 because it routes to proxy_out, not direct.
	if conn, _, err := st.dialTCPOutbound(context.Background(), net.Dialer{}, "direct", config.Outbound{Type: "direct"}, deadV6, netCfg); err == nil {
		conn.Close()
		t.Fatal("expected route-mismatch IPv4 fallback to be rejected")
	}

	// 2. Non-direct outbound (socks5) must never trigger IPv4 fallback even if routing matches.
	sameTable, err := routing.Open(config.Routing{
		Rules: []config.Rule{{Outbound: "socks_out"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sameTable.Close()
	st.snap.Store(&routeSnapshot{routes: sameTable})
	if conn, _, err := st.dialTCPOutbound(context.Background(), net.Dialer{}, "socks_out", config.Outbound{Type: "socks5", Address: "127.0.0.1:1"}, deadV6, netCfg); err == nil {
		conn.Close()
		t.Fatal("expected socks5 outbound not to fall back to direct IPv4")
	}
}

type nopResponseWriter struct{}

func (nopResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (nopResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (nopResponseWriter) WriteMsg(*dns.Msg) error     { return nil }
func (nopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (nopResponseWriter) Close() error                { return nil }
func (nopResponseWriter) TsigStatus() error           { return nil }
func (nopResponseWriter) TsigTimersOnly(bool)         {}
func (nopResponseWriter) Hijack()                     {}
