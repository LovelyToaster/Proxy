package dnsengine

import (
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/config"
)

func TestDoHViaSOCKS5(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if q.Unpack(wire) != nil {
			http.Error(w, "invalid DNS", 400)
			return
		}
		answer, _ := encryptedAnswer(q).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(answer)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan netip.AddrPort, 1)
	go func() {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(5 * time.Second))
		var greeting [3]byte
		if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			return
		}
		client.Write([]byte{5, 0})
		var request [10]byte
		if _, err := io.ReadFull(client, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[3] != 1 {
			return
		}
		target := netip.AddrPortFrom(netip.AddrFrom4([4]byte(request[4:8])), binary.BigEndian.Uint16(request[8:]))
		observed <- target
		upstream, err := net.DialTimeout("tcp", target.String(), time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		done := make(chan struct{})
		go func() { io.Copy(upstream, client); close(done) }()
		io.Copy(client, upstream)
		client.Close()
		<-done
	}()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	up, err := newProxiedDoH(config.DNSUpstream{Type: "doh", Address: server.URL + "/dns-query"}, nil,
		3*time.Second, net.Dialer{}, config.Outbound{Type: "socks5", Address: listener.Addr().String()}, roots)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	q := new(dns.Msg).SetQuestion("encrypted.test.", dns.TypeA)
	answer, err := exchange(up, q)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Id != q.Id || len(answer.Answer) != 1 {
		t.Fatal(answer)
	}
	select {
	case target := <-observed:
		if target.String() != server.Listener.Addr().String() {
			t.Fatalf("unexpected proxy target %s", target)
		}
	default:
		t.Fatal("DoH did not use SOCKS5")
	}
}
