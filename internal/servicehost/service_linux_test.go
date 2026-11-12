package servicehost

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestSystemdNotifications(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "notify")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("WATCHDOG_USEC", "200000")
	t.Setenv("WATCHDOG_PID", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); notifyLifecycle(ctx, socket) }()
	expect := func(want string) {
		t.Helper()
		var buffer [128]byte
		listener.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			n, _, err := listener.ReadFromUnix(buffer[:])
			if err != nil {
				t.Fatal(err)
			}
			if string(buffer[:n]) == want {
				return
			}
		}
	}
	expect("READY=1")
	expect("WATCHDOG=1")
	cancel()
	expect("STOPPING=1")
	<-done
}
