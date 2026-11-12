package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"proxy.local/m0/internal/config"
)

func TestSOCKS5UDPAssociation(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	controlClosed := make(chan struct{})
	var once sync.Once
	closeControl := func() { once.Do(func() { close(controlClosed) }) }
	defer closeControl()
	addr := fixture(t, func(conn net.Conn) {
		if !expect(t, conn, "\x05\x01\x00") {
			return
		}
		io.WriteString(conn, "\x05\x00")
		if !expect(t, conn, "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00") {
			return
		}
		reply := appendSocksAddress([]byte{5, 0, 0}, netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(relay.LocalAddr().(*net.UDPAddr).Port)))
		conn.Write(reply)
		select {
		case <-controlClosed:
		case <-time.After(4 * time.Second):
		}
	})
	target := netip.MustParseAddrPort("[2001:db8::7]:443")
	conn, err := DialUDP(context.Background(), net.Dialer{}, config.Outbound{Type: "socks5", Address: addr, UDP: true}, target, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	relay.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 128)
	n, peer, err := relay.ReadFromUDPAddrPort(wire)
	if err != nil {
		t.Fatal(err)
	}
	expected := appendSocksAddress([]byte{0, 0, 0}, target)
	if string(wire[:n]) != string(expected)+"ping" {
		t.Fatalf("unexpected SOCKS5 datagram: %x", wire[:n])
	}
	wire[2] = 1
	if _, err := relay.WriteToUDPAddrPort(wire[:n], peer); err != nil {
		t.Fatal(err)
	}
	copy(wire, expected)
	copy(wire[len(expected):], "pong")
	if _, err := relay.WriteToUDPAddrPort(wire[:n], peer); err != nil {
		t.Fatal(err)
	}
	expect(t, conn, "pong")
	closeControl()
	if _, err := conn.Read(wire); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP relay stayed open after TCP control closed: %v", err)
	}
}
