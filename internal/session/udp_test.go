package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"proxy.local/m0/internal/capture"
	"proxy.local/m0/internal/config"
)

func TestQUICThroughUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	tlsFixture := httptest.NewTLSServer(nil)
	cert := tlsFixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(tlsFixture.Certificate())
	tlsFixture.Close()
	const alpn = "proxy-m2-test"
	server, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{alpn}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	finished := make(chan error, 1)
	go func() {
		connection, err := server.Accept(ctx)
		if err != nil {
			finished <- err
			return
		}
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			finished <- err
			return
		}
		packet, err := io.ReadAll(stream)
		if err == nil {
			_, err = stream.Write(packet)
		}
		stream.Close()
		finished <- err
	}()

	listener, err := capture.ListenExplicitUDP(netip.MustParseAddrPort("127.0.0.1:0"), server.Addr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	manager := NewUDP(func(netip.AddrPort) (Route, error) {
		return Route{Name: "direct", Outbound: config.Outbound{Type: "direct"},
			Network: config.Network{MaxUDPSessions: 4, ConnectTimeout: time.Second, UDPTimeout: time.Second}}, nil
	})
	stopped := make(chan struct{})
	go func() { defer close(stopped); manager.Serve(listener, nil) }()
	defer func() { listener.Close(); <-stopped; manager.Close() }()
	conn, err := quic.DialAddr(ctx, listener.LocalAddr().String(), &tls.Config{RootCAs: roots, NextProtos: []string{alpn}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(stream, "QUIC through Proxy"); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	response, err := io.ReadAll(stream)
	if err != nil || string(response) != "QUIC through Proxy" {
		t.Fatalf("unexpected QUIC echo %q, %v", response, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if stats := manager.Stats(); stats.Opened["direct"] != 1 {
		t.Fatalf("unexpected UDP sessions: %+v", stats)
	}
}

func BenchmarkUDPRelay(b *testing.B) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = server.WriteTo(buf[:n], addr)
		}
	}()

	listener, err := capture.ListenExplicitUDP(netip.MustParseAddrPort("127.0.0.1:0"), server.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		b.Fatal(err)
	}
	manager := NewUDP(func(netip.AddrPort) (Route, error) {
		return Route{Name: "direct", Outbound: config.Outbound{Type: "direct"},
			Network: config.Network{MaxUDPSessions: 4, ConnectTimeout: time.Second, UDPTimeout: 5 * time.Second}}, nil
	})
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = manager.Serve(listener, nil) }()
	defer func() { listener.Close(); <-stopped; manager.Close() }()

	client, err := net.Dial("udp", listener.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	payload := make([]byte, 1200)
	buf := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for range b.N {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := client.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
}
