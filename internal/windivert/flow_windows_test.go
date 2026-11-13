//go:build windows

package windivert

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestCaptureDestinationAndSource(t *testing.T) {
	client := netip.MustParseAddrPort("192.168.1.100:54321")
	target := netip.MustParseAddrPort("150.171.27.11:443")
	alias := netip.MustParseAddrPort("150.171.27.11:10708")

	flow := &tcpFlow{
		key:   flowKey{source: client, target: target},
		alias: alias,
	}
	flow.seen.Store(time.Now().UnixNano())

	cap := &Capture{
		reverse: map[netip.AddrPort]*tcpFlow{
			alias: flow,
		},
	}

	// Create a dummy in-memory TCP pipe or loopback listener to get a *net.TCPConn
	// Wait, conn.RemoteAddr() in Destination and Source is (*net.TCPAddr).AddrPort()
	// Let's test using a net.Pipe or local TCP pair
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("local socket not permitted in sandbox")
	}
	defer l.Close()

	// If local socket works, we can connect; otherwise, we can test flow lookup logic
	connCh := make(chan *net.TCPConn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			connCh <- c.(*net.TCPConn)
		}
	}()

	clientConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Skip("local socket not permitted in sandbox")
	}
	defer clientConn.Close()

	accepted := <-connCh
	defer accepted.Close()

	// Populate reverse map with accepted.RemoteAddr()
	acceptedPeer := accepted.RemoteAddr().(*net.TCPAddr).AddrPort()
	cap.reverse[acceptedPeer] = flow

	gotTarget, err := cap.Destination(accepted)
	if err != nil {
		t.Fatalf("Destination failed: %v", err)
	}
	if gotTarget != target {
		t.Fatalf("got target %v, want %v", gotTarget, target)
	}

	gotSource, err := cap.Source(accepted)
	if err != nil {
		t.Fatalf("Source failed: %v", err)
	}
	if gotSource != client {
		t.Fatalf("got source %v, want %v (client real address)", gotSource, client)
	}
}
