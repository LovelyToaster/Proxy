package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxy.local/m0/internal/config"
)

type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newTrackedPipe() (*trackedConn, net.Conn) {
	a, b := net.Pipe()
	return &trackedConn{Conn: a}, b
}

func TestHappyEyeballsPrimaryWinsFastWithoutDialingFallback(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::1]:443")
	v4 := netip.MustParseAddrPort("198.51.100.1:443")

	var fallbackCalls atomic.Int32
	clientConn, serverConn := newTrackedPipe()
	defer serverConn.Close()

	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == v6.String() {
			return clientConn, nil
		}
		fallbackCalls.Add(1)
		return nil, errors.New("unexpected fallback dial")
	}

	conn, target, err := dialHappyEyeballs(context.Background(), dialFn, v6, []netip.AddrPort{v4}, 250*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()
	if target != v6 {
		t.Fatalf("expected target %v, got %v", v6, target)
	}
	if fallbackCalls.Load() != 0 {
		t.Fatalf("expected 0 fallback dials, got %d", fallbackCalls.Load())
	}
}

func TestHappyEyeballsPrimaryTimeoutFallsBackAndClosesLateWinner(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::2]:443")
	v4 := netip.MustParseAddrPort("198.51.100.2:443")

	v4Client, v4Server := newTrackedPipe()
	defer v4Server.Close()

	var v6Canceled atomic.Bool
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == v6.String() {
			<-ctx.Done()
			v6Canceled.Store(true)
			return nil, ctx.Err()
		}
		return v4Client, nil
	}

	start := time.Now()
	conn, target, err := dialHappyEyeballs(context.Background(), dialFn, v6, []netip.AddrPort{v4}, 60*time.Millisecond, 2*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()
	if target != v4 {
		t.Fatalf("expected fallback %v, got %v", v4, target)
	}
	if elapsed < 40*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("unexpected fallback duration %v", elapsed)
	}

	deadline := time.Now().Add(time.Second)
	for !v6Canceled.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !v6Canceled.Load() {
		t.Fatal("expected primary dial context to be canceled after fallback win")
	}
}

func TestHappyEyeballsPrimaryFastFailureTriggersFallbackImmediately(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::3]:443")
	v4 := netip.MustParseAddrPort("198.51.100.3:443")

	v4Client, v4Server := newTrackedPipe()
	defer v4Server.Close()

	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == v6.String() {
			return nil, errors.New("connect: network is unreachable")
		}
		return v4Client, nil
	}

	start := time.Now()
	conn, target, err := dialHappyEyeballs(context.Background(), dialFn, v6, []netip.AddrPort{v4}, 500*time.Millisecond, 2*time.Second)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()
	if target != v4 {
		t.Fatalf("expected fallback %v, got %v", v4, target)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("expected immediate fallback on primary failure, took %v", elapsed)
	}
}

func TestHappyEyeballsLateLoserConnIsClosed(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::4]:443")
	v4 := netip.MustParseAddrPort("198.51.100.4:443")

	v6Late, v6Server := newTrackedPipe()
	defer v6Server.Close()
	v4Client, v4Server := newTrackedPipe()
	defer v4Server.Close()

	releaseV6 := make(chan struct{})
	v6Returned := make(chan struct{})
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == v6.String() {
			<-releaseV6
			close(v6Returned)
			return v6Late, nil
		}
		return v4Client, nil
	}

	conn, target, err := dialHappyEyeballs(context.Background(), dialFn, v6, []netip.AddrPort{v4}, 30*time.Millisecond, 2*time.Second)
	if err != nil || target != v4 {
		t.Fatalf("expected v4 win, got target=%v err=%v", target, err)
	}
	defer conn.Close()

	close(releaseV6)
	<-v6Returned
	deadline := time.Now().Add(time.Second)
	for !v6Late.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !v6Late.closed.Load() {
		t.Fatal("expected late loser connection to be closed")
	}
}

func TestHappyEyeballsMultipleFallbacksAndFailure(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::5]:443")
	v4Bad := netip.MustParseAddrPort("198.51.100.5:443")
	v4Good := netip.MustParseAddrPort("198.51.100.6:443")

	v4Client, v4Server := newTrackedPipe()
	defer v4Server.Close()

	var attempts []string
	var mu sync.Mutex
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		attempts = append(attempts, addr)
		mu.Unlock()
		switch addr {
		case v6.String():
			return nil, errors.New("v6 refused")
		case v4Bad.String():
			return nil, errors.New("v4 bad refused")
		case v4Good.String():
			return v4Client, nil
		default:
			return nil, errors.New("unexpected")
		}
	}

	conn, target, err := dialHappyEyeballs(context.Background(), dialFn, v6, []netip.AddrPort{v4Bad, v4Good, v4Bad}, 50*time.Millisecond, 2*time.Second)
	if err != nil || target != v4Good {
		t.Fatalf("expected %v, got target=%v err=%v", v4Good, target, err)
	}
	conn.Close()

	// Both fail case.
	_, _, err = dialHappyEyeballs(
		context.Background(),
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("failed: " + addr)
		},
		v6,
		[]netip.AddrPort{v4Bad},
		20*time.Millisecond,
		time.Second,
	)
	if err == nil {
		t.Fatal("expected error when all targets fail")
	}
}

func TestDialWithFallbackDirectVsProxyTCPListeners(t *testing.T) {
	v4Listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v4Listener.Close()
	go func() {
		for {
			c, err := v4Listener.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	v4Addr := netip.MustParseAddrPort(v4Listener.Addr().String())

	// Non-direct outbound must NOT race fallback.
	proxyCfg := config.Outbound{Type: "socks5", Address: "127.0.0.1:1"}
	v6Dead := netip.MustParseAddrPort("[::1]:1")
	if _, _, err := DialWithFallback(context.Background(), net.Dialer{}, proxyCfg, v6Dead, []netip.AddrPort{v4Addr}, 20*time.Millisecond, 500*time.Millisecond); err == nil {
		t.Fatal("expected socks5 outbound not to fall back to direct IPv4 listener")
	}

	// Direct outbound should fall back to local IPv4 listener when IPv6 target fails/unreachable.
	directCfg := config.Outbound{Type: "direct"}
	// RFC 3849 / documentation IPv6 or closed loopback port: use an unopen loopback port on [::1] if available or 2001:db8::1.
	conn, dialed, err := DialWithFallback(context.Background(), net.Dialer{}, directCfg, v6Dead, []netip.AddrPort{v4Addr}, 30*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("expected direct fallback to succeed on %v: %v", v4Addr, err)
	}
	conn.Close()
	if dialed != v4Addr {
		t.Fatalf("expected dialed target %v, got %v", v4Addr, dialed)
	}
}
