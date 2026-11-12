package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"proxy.local/m0/internal/dnsengine"
	"proxy.local/m0/internal/ipc"
)

func TestManagementLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	directory := filepath.Join(t.TempDir(), "run")
	config := filepath.Join(t.TempDir(), "proxy.yaml")
	const valid = "version: 1\noutbounds:\n  direct:\n    type: direct\nrouting:\n  rules:\n    - outbound: direct\n"
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(config, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(valid)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, config, directory) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	for {
		attempt, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := ipc.Call(attempt, directory, "status")
		stop()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("IPC unavailable: %v", err)
		case <-time.After(25 * time.Millisecond):
		}
	}
	write(valid + "unknown: true\n")
	if _, err := ipc.Call(ctx, directory, "reload"); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	write(valid)
	if result, err := ipc.Call(ctx, directory, "reload"); err != nil || string(result) != "{\"generation\":2}" {
		t.Fatalf("reload returned %s, %v", result, err)
	}
	if _, err := ipc.Call(ctx, directory, "stop"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		done <- err
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("daemon did not stop")
	}
}

func TestStandaloneDNSControl(t *testing.T) {
	upstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	started := make(chan struct{})
	server := &dns.Server{PacketConn: upstream, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg).SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.40")
		answer.Answer = []dns.RR{rr}
		w.WriteMsg(answer)
	})}
	dnsDone := make(chan error, 1)
	go func() { dnsDone <- server.ActivateAndServe() }()
	select {
	case <-started:
		defer server.Shutdown()
	case err := <-dnsDone:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("DNS upstream did not start")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().(*net.TCPAddr).AddrPort()
	listener.Close()
	configPath := filepath.Join(t.TempDir(), "proxy.yaml")
	if err := os.WriteFile(configPath, fmt.Appendf(nil, `version: 1
outbounds:
  direct:
    type: direct
routing:
  rules:
    - outbound: direct
dns:
  enabled: true
  listen: ["%s"]
  timeout: 1s
  upstreams:
    lab:
      type: udp
      address: "%s"
  rules:
    - upstream: lab
`, address, upstream.LocalAddr()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Check(configPath); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	directory := filepath.Join(t.TempDir(), "run")
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, configPath, directory) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("service did not stop")
		}
	}()
	for {
		attempt, stop := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := ipc.Call(attempt, directory, "dns-status")
		stop()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(err)
		case <-time.After(25 * time.Millisecond):
		}
	}
	for _, protocol := range []string{"udp", "tcp"} {
		msg, err := dnsengine.Probe(ctx, address, protocol, "lab.test", dns.TypeA)
		if err != nil || msg == nil || len(msg.Answer) != 1 {
			t.Fatalf("DNS service over %s: %v, %v", protocol, msg, err)
		}
		if answer, ok := msg.Answer[0].(*dns.A); !ok || answer.A.String() != "192.0.2.40" {
			t.Fatalf("unexpected DNS answer over %s: %v", protocol, msg.Answer[0])
		}
	}
	if _, err := ipc.Call(ctx, directory, "dns-flush"); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Call(ctx, directory, "stop"); err != nil {
		t.Fatal(err)
	}
}
