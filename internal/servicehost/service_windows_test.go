package servicehost

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestSCMHandlerLifecycle(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "proxy.yaml")
	const text = "version: 1\noutbounds:\n  direct:\n    type: direct\nrouting:\n  rules:\n    - outbound: direct\n"
	if err := os.WriteFile(cfg, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	updates := make(chan svc.Status, 16)
	requests := make(chan svc.ChangeRequest, 1)
	done := make(chan uint32, 1)
	runtime := filepath.Join(t.TempDir(), "run")
	go func() {
		_, code := (handler{parent: ctx, path: cfg, runtime: runtime}).Execute(nil, requests, updates)
		done <- code
	}()
	expect := func(want svc.State) {
		t.Helper()
		for {
			select {
			case status := <-updates:
				if status.State == want {
					return
				}
			case <-ctx.Done():
				t.Fatalf("service did not report %v", want)
			}
		}
	}
	expect(svc.StartPending)
	expect(svc.Running)
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	expect(svc.StopPending)
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d", code)
		}
	case <-ctx.Done():
		t.Fatal("service did not stop")
	}
}
