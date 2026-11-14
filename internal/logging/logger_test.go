package logging

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"proxy.local/m0/internal/logbuffer"
)

func TestLevelFilteringAndTemporaryOverride(t *testing.T) {
	var out bytes.Buffer
	buf := &logbuffer.Buffer{}
	logger := New(&out, buf)

	status, err := logger.SetConfiguredLevel("info")
	if err != nil {
		t.Fatal(err)
	}
	if status.Configured != "info" || status.Current != "info" || status.Temporary {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	logger.Debugf("hidden debug")
	logger.Infof("visible info")
	logger.Warnf("visible warn")
	logger.Errorf("visible error")

	snap := buf.Read(0)
	if len(snap.Entries) != 3 {
		t.Fatalf("expected 3 entries at info level, got %d: %+v", len(snap.Entries), snap.Entries)
	}
	if snap.Entries[0].Level != "info" || snap.Entries[1].Level != "warn" || snap.Entries[2].Level != "error" {
		t.Fatalf("unexpected entry levels: %+v", snap.Entries)
	}
	if strings.Contains(out.String(), "hidden debug") {
		t.Fatalf("debug log leaked into writer: %s", out.String())
	}

	// Temporary switch to debug
	status, err = logger.SetTemporaryLevel("DEBUG")
	if err != nil {
		t.Fatal(err)
	}
	if status.Configured != "info" || status.Current != "debug" || !status.Temporary {
		t.Fatalf("unexpected temporary status: %+v", status)
	}
	logger.Debugf("visible debug %d", 42)
	snap = buf.Read(snap.Next)
	if len(snap.Entries) != 1 || snap.Entries[0].Level != "debug" || snap.Entries[0].Text != "visible debug 42" {
		t.Fatalf("expected debug entry after temporary switch, got %+v", snap.Entries)
	}

	// Invalid temporary level returns error and keeps current level
	if _, err := logger.SetTemporaryLevel("trace"); err == nil {
		t.Fatal("expected error for invalid level")
	}
	if got := logger.Status(); got.Current != "debug" || !got.Temporary {
		t.Fatalf("invalid level mutated state: %+v", got)
	}

	// Reset via "reset" restores configured level
	status, err = logger.SetTemporaryLevel("reset")
	if err != nil {
		t.Fatal(err)
	}
	if status.Configured != "info" || status.Current != "info" || status.Temporary {
		t.Fatalf("unexpected reset status: %+v", status)
	}

	logger.Debugf("hidden again")
	if len(buf.Read(snap.Next).Entries) != 0 {
		t.Fatal("expected debug to be filtered after reset")
	}
}

func TestStdBridgeAndSlogHandler(t *testing.T) {
	var out bytes.Buffer
	buf := &logbuffer.Buffer{}
	logger := New(&out, buf)

	std := log.New(logger.StdBridgeWriter(slog.LevelInfo), "", log.LstdFlags)
	std.Printf("plain std message")
	std.Printf("[WARN] helper warning")
	std.Printf("[DEBUG] helper debug")

	snap := buf.Read(0)
	if len(snap.Entries) != 2 {
		t.Fatalf("expected 2 bridged entries at info level, got %d: %+v", len(snap.Entries), snap.Entries)
	}
	if snap.Entries[0].Level != "info" || snap.Entries[0].Text != "plain std message" {
		t.Fatalf("unexpected bridged info entry: %+v", snap.Entries[0])
	}
	if snap.Entries[1].Level != "warn" || snap.Entries[1].Text != "helper warning" {
		t.Fatalf("unexpected bridged warn entry: %+v", snap.Entries[1])
	}

	slogger := slog.New(logger).With("comp", "dns")
	slogger.Warn("cache miss", "qname", "example.com")
	snap = buf.Read(snap.Next)
	if len(snap.Entries) != 1 || snap.Entries[0].Level != "warn" || !strings.Contains(snap.Entries[0].Text, "comp=dns") || !strings.Contains(snap.Entries[0].Text, "qname=example.com") {
		t.Fatalf("unexpected slog handler entry: %+v", snap.Entries)
	}
}

func TestConcurrentLoggingAndLevelSwitching(t *testing.T) {
	buf := &logbuffer.Buffer{}
	logger := New(nil, buf)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				logger.Debugf("d %d %d", id, i)
				logger.Infof("i %d %d", id, i)
				logger.Warnf("w %d %d", id, i)
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		levels := []string{"debug", "info", "warn", "error", "reset"}
		for i := 0; i < 50; i++ {
			_, _ = logger.SetTemporaryLevel(levels[i%len(levels)])
			_ = logger.Status()
		}
	}()
	wg.Wait()
	_ = fmt.Sprintf("next=%d", buf.Read(0).Next)
}
