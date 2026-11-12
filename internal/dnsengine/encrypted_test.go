package dnsengine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"proxy.local/m0/internal/config"
)

func encryptedAnswer(q *dns.Msg) *dns.Msg {
	response := new(dns.Msg).SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.25")
	response.Answer = []dns.RR{rr}
	return response
}

func TestDoHUsesSystemResolverWithoutBootstrap(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire []byte
		var err error
		if r.Method == http.MethodGet {
			wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		} else {
			wire, err = io.ReadAll(r.Body)
		}
		query := new(dns.Msg)
		if err != nil || query.Unpack(wire) != nil {
			http.Error(w, "bad DNS query", http.StatusBadRequest)
			return
		}
		answer, _ := encryptedAnswer(query).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	resolverAddress := udpFixture(t, dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg).SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Name == "example.com." && q.Question[0].Qtype == dns.TypeA {
			record, _ := dns.NewRR("example.com. 60 IN A 127.0.0.1")
			answer.Answer = []dns.RR{record}
		}
		w.WriteMsg(answer)
	}))
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, resolverAddress.String())
	}}
	defer func() { net.DefaultResolver = previous }()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	up, closers, err := buildUpstream(config.DNSUpstream{
		Type: "doh", Address: "https://example.com:" + port + "/dns-query",
	}, nil, 3*time.Second, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer closeAll(closers)
	defer up.Close()
	answer, err := exchange(up, new(dns.Msg).SetQuestion("encrypted.test.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 1 || answer.Answer[0].String() != "encrypted.test.\t60\tIN\tA\t192.0.2.25" {
		t.Fatalf("unexpected DoH answer: %v", answer)
	}
}

func TestEncryptedDNSUpstreams(t *testing.T) {
	tlsFixture := httptest.NewTLSServer(nil)
	cert := tlsFixture.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(tlsFixture.Certificate())
	tlsFixture.Close()
	baseTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	check := func(t *testing.T, kind, address string) {
		t.Helper()
		up, closers, err := buildUpstream(config.DNSUpstream{Type: kind, Address: address}, nil, 3*time.Second, roots)
		if err != nil {
			t.Fatal(err)
		}
		defer closeAll(closers)
		defer up.Close()
		query := new(dns.Msg).SetQuestion("encrypted.test.", dns.TypeA)
		res, err := exchange(up, query)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Answer) != 1 || res.Answer[0].String() != encryptedAnswer(query).Answer[0].String() {
			t.Fatal(res)
		}
	}
	handler := func(expectH3 bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if (r.ProtoMajor == 3) != expectH3 {
				http.Error(w, "unexpected HTTP version", 400)
				return
			}
			var wire []byte
			var err error
			if r.Method == http.MethodGet {
				wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			} else {
				wire, err = io.ReadAll(io.LimitReader(r.Body, 65536))
			}
			q := new(dns.Msg)
			if err != nil || q.Unpack(wire) != nil || len(q.Question) != 1 {
				http.Error(w, "bad query", 400)
				return
			}
			wire, err = encryptedAnswer(q).Pack()
			if err != nil {
				http.Error(w, "pack response", 500)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(wire)
		}
	}

	t.Run("DoH", func(t *testing.T) {
		server := httptest.NewTLSServer(handler(false))
		defer server.Close()
		check(t, "doh", server.URL+"/dns-query")
	})
	t.Run("DoT", func(t *testing.T) {
		ln, err := tls.Listen("tcp4", "127.0.0.1:0", baseTLS)
		if err != nil {
			t.Fatal(err)
		}
		serveFixture(t, &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
			w.WriteMsg(encryptedAnswer(q))
		})})
		check(t, "dot", ln.Addr().String())
	})
	t.Run("DoH3", func(t *testing.T) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		server := &http3.Server{TLSConfig: baseTLS, Handler: handler(true)}
		done := make(chan struct{})
		go func() { defer close(done); server.Serve(conn) }()
		defer func() { server.Close(); <-done }()
		check(t, "doh3", "https://"+conn.LocalAddr().String()+"/dns-query")
	})
	t.Run("DoQ", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cfg := baseTLS.Clone()
		cfg.NextProtos = []string{"doq"}
		server, err := quic.ListenAddr("127.0.0.1:0", cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		done := make(chan error, 1)
		go func() {
			conn, err := server.Accept(ctx)
			if err == nil {
				err = serveDoQ(ctx, conn)
			}
			done <- err
		}()
		check(t, "doq", server.Addr().String())
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func serveDoQ(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	var size uint16
	if err := binary.Read(stream, binary.BigEndian, &size); err != nil {
		return err
	}
	wire := make([]byte, size)
	if _, err := io.ReadFull(stream, wire); err != nil {
		return err
	}
	q := new(dns.Msg)
	if err := q.Unpack(wire); err != nil {
		return err
	}
	if q.Id != 0 || len(q.Question) != 1 {
		return fmt.Errorf("invalid DoQ query")
	}
	answer, err := encryptedAnswer(q).Pack()
	if err != nil {
		return err
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(answer)))
	_, err = stream.Write(append(framed, answer...))
	return err
}
