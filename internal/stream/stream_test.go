package stream

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type closeWriteConn struct {
	net.Conn
}

func (c closeWriteConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func tcpLoopbackPair(t testing.TB) (Conn, Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-ch
	if server == nil {
		client.Close()
		t.Fatal("accept failed")
	}
	return closeWriteConn{client}, closeWriteConn{server}
}

func TestRelayBidirectionalAndIdle(t *testing.T) {
	c1, s1 := tcpLoopbackPair(t)
	c2, s2 := tcpLoopbackPair(t)
	defer c1.Close()
	defer s2.Close()

	done := make(chan error, 1)
	go func() {
		done <- Relay(s1, c2, 2*time.Second)
	}()

	msg := bytes.Repeat([]byte("hello-proxy-"), 1024)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := c1.Write(msg); err != nil {
			t.Error(err)
		}
		_ = c1.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		got, err := io.ReadAll(s2)
		if err != nil || !bytes.Equal(got, msg) {
			t.Errorf("got len=%d err=%v", len(got), err)
		}
		_ = s2.CloseWrite()
	}()
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatalf("Relay: %v", err)
	}
}

func TestRelayIdleTimeout(t *testing.T) {
	c1, s1 := tcpLoopbackPair(t)
	c2, s2 := tcpLoopbackPair(t)
	defer c1.Close()
	defer s2.Close()

	start := time.Now()
	err := Relay(s1, c2, 80*time.Millisecond)
	if err == nil {
		t.Fatal("expected idle timeout error")
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("closed too early: %v", elapsed)
	}
}

func BenchmarkRelay(b *testing.B) {
	const chunk = 64 * 1024
	payload := bytes.Repeat([]byte("a"), chunk)
	buf := make([]byte, chunk)

	c1, s1 := tcpLoopbackPair(b)
	c2, s2 := tcpLoopbackPair(b)
	defer c1.Close()
	defer s2.Close()

	done := make(chan error, 1)
	go func() {
		done <- Relay(s1, c2, 10*time.Second)
	}()

	b.ReportAllocs()
	b.SetBytes(chunk)
	b.ResetTimer()
	for range b.N {
		if _, err := c1.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(s2, buf); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = c1.CloseWrite()
	_ = s2.CloseWrite()
	<-done
}
