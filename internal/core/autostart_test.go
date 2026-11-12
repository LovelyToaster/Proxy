package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/geodata"
	"proxy.local/m0/internal/routing"
)

func TestReloadSynchronizesAutostart(t *testing.T) {
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
	enabled := false
	s := &state{cfg: cfg, routes: routes, store: geodata.ForConfig(path), geoTimer: make(chan struct{}, 1), applyAutostart: func(value bool) error { enabled = value; return nil }}
	defer func() { s.routes.Close() }()
	if err := os.WriteFile(path, []byte(base+"service: {autostart: true}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reload(path); err != nil || !enabled || !s.cfg.Service.Autostart {
		t.Fatalf("autostart reload: %v", err)
	}
	s.applyAutostart = func(bool) error { return errors.New("SCM denied") }
	if err := os.WriteFile(path, []byte(base+"service: {autostart: false}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reload(path); err == nil || !s.cfg.Service.Autostart {
		t.Fatal("failed SCM update published config")
	}
}
