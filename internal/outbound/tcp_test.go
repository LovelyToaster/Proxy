package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"proxy.local/m0/internal/config"
)

func fixture(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		serve(conn)
	}()
	t.Cleanup(func() { listener.Close(); <-finished })
	return listener.Addr().String()
}

func expect(t *testing.T, conn io.Reader, want string) bool {
	t.Helper()
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != want {
		t.Errorf("read %q, want %q: %v", buf, want, err)
		return false
	}
	return true
}

func TestHTTPConnectBufferedIPv6(t *testing.T) {
	target := netip.MustParseAddrPort("[2001:db8::42]:443")
	addr := fixture(t, func(conn net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Error(err)
			return
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if req.Method != "CONNECT" || req.Host != target.String() || req.Header.Get("Proxy-Authorization") != wantAuth {
			t.Errorf("incorrect HTTP CONNECT request: %s %s", req.Method, req.Host)
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nbuffered")
		if expect(t, conn, "ping") {
			io.WriteString(conn, "pong")
		}
	})
	conn, err := Dial(context.Background(), net.Dialer{}, config.Outbound{Type: "http", Address: addr, Username: "user", Password: "pass"}, target, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if !expect(t, conn, "buffered") {
		return
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	expect(t, conn, "pong")
}

func TestSOCKS5ConnectAuth(t *testing.T) {
	for _, target := range []netip.AddrPort{netip.MustParseAddrPort("192.0.2.6:443"), netip.MustParseAddrPort("[2001:db8::42]:443")} {
		t.Run(target.String(), func(t *testing.T) {
			addr := fixture(t, func(conn net.Conn) {
				if !expect(t, conn, "\x05\x01\x02") {
					return
				}
				io.WriteString(conn, "\x05\x02")
				if !expect(t, conn, "\x01\x04user\x04pass") {
					return
				}
				io.WriteString(conn, "\x01\x00")
				kind := byte(1)
				if target.Addr().Is6() {
					kind = 4
				}
				request := string([]byte{5, 1, 0, kind}) + string(target.Addr().AsSlice()) + "\x01\xbb"
				if !expect(t, conn, request) {
					return
				}
				io.WriteString(conn, "\x05\x00\x00\x03\x03lab\x01\xbb")
				if expect(t, conn, "ping") {
					io.WriteString(conn, "pong")
				}
			})
			conn, err := Dial(context.Background(), net.Dialer{}, config.Outbound{Type: "socks5", Address: addr, Username: "user", Password: "pass"}, target, 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := io.WriteString(conn, "ping"); err != nil {
				t.Fatal(err)
			}
			expect(t, conn, "pong")
		})
	}
}
