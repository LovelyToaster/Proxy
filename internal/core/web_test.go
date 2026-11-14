package core

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/geodata"
	"proxy.local/m0/internal/routing"
	"proxy.local/m0/internal/session"
)

func TestStateWebProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.yaml")
	base := "outbounds:\n  direct: {type: direct}\nrouting:\n  rules:\n    - outbound: direct\n"
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := routing.Open(cfg.Routing)
	if err != nil {
		t.Fatal(err)
	}
	defer routes.Close()

	s := &state{
		cfg:              cfg,
		routes:           routes,
		generation:       1,
		active:           make(map[uint64]connection),
		connected:        map[string]uint64{"direct": 10},
		store:            geodata.ForConfig(path),
		geoTimer:         make(chan struct{}, 1),
		udp:              session.NewUDP(nil),
		configPath:       path,
	}
	defer s.udp.Close()

	overview, err := s.Overview()
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	if overview.Generation != 1 || overview.Connected["direct"] != 10 || overview.ActiveTCP != 0 {
		t.Fatalf("unexpected overview: %+v", overview)
	}

	targetAddr := netip.MustParseAddrPort("150.171.27.11:443")
	s.active[1] = connection{
		ID:          1,
		Source:      "127.0.0.1:58473",
		Destination: targetAddr,
		Outbound:    "direct",
		Started:     time.Now().Add(-65 * time.Second),
	}

	overview, err = s.Overview()
	if err != nil {
		t.Fatalf("Overview failed: %v", err)
	}
	if overview.ActiveTCP != 1 || len(overview.ActiveConns) != 1 {
		t.Fatalf("expected 1 active conn, got %+v", overview)
	}
	conn0 := overview.ActiveConns[0]
	if conn0.Source != "127.0.0.1:58473" || conn0.Destination != "150.171.27.11:443" {
		t.Fatalf("unexpected conn info: %+v", conn0)
	}
	if conn0.Duration != "1分5秒" {
		t.Fatalf("unexpected duration format: %s", conn0.Duration)
	}

	snapshot := s.Logs(0)
	if snapshot.Next == 0 && len(snapshot.Entries) > 0 {
		t.Fatalf("unexpected log snapshot: %+v", snapshot)
	}

	// FlushDNS when nil should return error
	if err := s.FlushDNS(); err == nil {
		t.Fatal("expected error when DNS is nil")
	}

	// Verify drop callbacks run without holding s.mu and concurrent Overview calls remain safe.
	s.kernelUDPDrops = func() (uint64, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return 7, nil
	}
	s.captureUDPDrops = func() (uint64, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return 3, nil
	}

	overview, err = s.Overview()
	if err != nil {
		t.Fatalf("Overview with drop callbacks failed: %v", err)
	}
	if overview.UDPStats.KernelDropped == nil || *overview.UDPStats.KernelDropped != 7 {
		t.Fatalf("unexpected kernel drops: %+v", overview.UDPStats.KernelDropped)
	}
	if overview.UDPStats.CaptureDropped == nil || *overview.UDPStats.CaptureDropped != 3 {
		t.Fatalf("unexpected capture drops: %+v", overview.UDPStats.CaptureDropped)
	}

	// Reload should succeed
	if err := s.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if s.generation != 2 {
		t.Fatalf("expected generation 2, got %d", s.generation)
	}
}
