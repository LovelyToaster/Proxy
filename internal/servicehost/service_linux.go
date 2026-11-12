package servicehost

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"proxy.local/m0/internal/core"
)

func Run(parent context.Context, path, runtime string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return core.Serve(parent, path, runtime)
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	ready := false
	result := core.ServeReady(ctx, path, runtime, func() {
		ready = true
		go func() { defer close(done); notifyLifecycle(ctx, socket) }()
	})
	cancel()
	if ready {
		<-done
	}
	return result
}

func notifyLifecycle(ctx context.Context, socket string) {
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	notify := func(text string) {
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
		if err != nil {
			log.Printf("systemd notification: %v", err)
			return
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte(text)); err != nil {
			log.Printf("systemd notification: %v", err)
		}
	}
	notify("READY=1")
	defer notify("STOPPING=1")
	micros, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	watchdogPID := os.Getenv("WATCHDOG_PID")
	if err != nil || micros < 2 || micros > int64((24*time.Hour)/time.Microsecond) ||
		watchdogPID != "" && watchdogPID != strconv.Itoa(os.Getpid()) {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(time.Duration(micros/2) * time.Microsecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			notify("WATCHDOG=1")
		}
	}
}

func Control(ctx context.Context, operation string) error {
	switch operation {
	case "start", "stop", "restart", "status", "enable", "disable":
		cmd := exec.CommandContext(ctx, "systemctl", operation, "proxyd.service")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported systemd operation %q", operation)
	}
}
