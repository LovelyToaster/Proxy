package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func loadText(t *testing.T, text string) (Config, string, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	return cfg, dir, err
}

const minimalDNS = `outbounds:
  direct: {type: direct}
routing:
  rules:
    - outbound: direct
dns:
  enabled: true
  upstreams:
    local: {type: system}
  rules:
    - upstream: local
`

func TestImplicitNativeCaptureAndDNSHijack(t *testing.T) {
	text := "capture: {scope: global, port: 15090}\n" + strings.Replace(minimalDNS, "dns:\n", "dns:\n  hijack: true\n", 1)
	cfg, _, err := loadText(t, text)
	expected, resolveErr := nativeCaptureMode(Capture{Scope: "global"}, runtime.GOOS)
	if resolveErr != nil {
		t.Skip(resolveErr)
	}
	if err != nil || cfg.Capture.Mode != expected || !cfg.Capture.DNSHijack {
		t.Fatalf("implicit backend/hijack: %+v %v", cfg.Capture, err)
	}
	for _, invalid := range []string{
		strings.Replace(text, "scope: global", "mode: off, scope: global", 1),
		strings.Replace(text, "hijack: true", "hijack: false", 1),
		strings.Replace(text, "scope: global", "scope: global, typo: true", 1),
		"capture: {scope: global, dns_hijack: true}\n" + minimalDNS,
	} {
		if _, _, err := loadText(t, invalid); err == nil {
			t.Fatal("explicit disable or unknown field ignored")
		}
	}
}

func TestLoadDefaultsAndOverrides(t *testing.T) {
	cfg, _, err := loadText(t, minimalDNS)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 || cfg.DNS.Timeout != 4*time.Second || len(cfg.DNS.Listen) != 2 || cfg.DNS.Listen[0].String() != "127.0.0.1:15353" || !cfg.DNS.Cache.Enabled || cfg.DNS.Cache.MaxEntries != 4096 {
		t.Fatalf("defaults: %+v", cfg.DNS)
	}
	if cfg.Routing.GeoIPDB != "" || cfg.DNS.GeoSiteFile != "" {
		t.Fatal("unused geo database required")
	}
	text := strings.Replace(minimalDNS, "dns:\n", "dns:\n  timeout: 7s\n  listen: ['127.0.0.1:15555']\n  cache: {enabled: false, max_entries: 12}\n", 1)
	cfg, _, err = loadText(t, text)
	if err != nil || cfg.DNS.Timeout != 7*time.Second || cfg.DNS.Cache.Enabled || cfg.DNS.Cache.MaxEntries != 12 || len(cfg.DNS.Listen) != 1 || cfg.DNS.Listen[0].Port() != 15555 {
		t.Fatalf("overrides: %+v %v", cfg.DNS, err)
	}
	text = strings.Replace(minimalDNS, "outbounds:", "capture: {mode: windivert, scope: global}\noutbounds:", 1)
	text = strings.Replace(text, "dns:\n", "dns:\n  hijack: true\n  listen: []\n", 1)
	cfg, _, err = loadText(t, text)
	if err != nil || len(cfg.DNS.Listen) != 0 {
		t.Fatalf("explicit empty listeners: %+v %v", cfg.DNS.Listen, err)
	}
	text = strings.Replace(minimalDNS, "    - outbound: direct", "    - geoip: CN\n      outbound: direct\n    - outbound: direct", 1)
	text = strings.Replace(text, "    - upstream: local", "    - geosite: cn\n      upstream: local\n    - upstream: local", 1)
	cfg, dir, err := loadText(t, text)
	if err != nil || cfg.Routing.GeoIPDB != filepath.Join(dir, "data", "geoip.dat") || cfg.DNS.GeoSiteFile != filepath.Join(dir, "data", "geosite.dat") {
		t.Fatalf("relative geo defaults: %+v %v", cfg, err)
	}
}

func TestDNSDomainRuleValidation(t *testing.T) {
	for _, rule := range []string{
		"domain: example.com", "domain_suffix: Example.COM.", "domain: xn--fsqu00a.xn--0zwm56d",
	} {
		text := strings.Replace(minimalDNS, "    - upstream: local", "    - "+rule+"\n      upstream: local\n    - upstream: local", 1)
		if _, _, err := loadText(t, text); err != nil {
			t.Fatalf("valid %s: %v", rule, err)
		}
	}
	for _, rule := range []string{
		"domain: '*.test'", "domain: example..com", "domain_suffix: .example.com", "domain: https://example.com", "domain: -bad.test", "domain: '.'", "domain: example.com\n      domain_suffix: example.com",
	} {
		text := strings.Replace(minimalDNS, "    - upstream: local", "    - "+rule+"\n      upstream: local\n    - upstream: local", 1)
		if _, _, err := loadText(t, text); err == nil {
			t.Fatalf("accepted invalid %s", rule)
		}
	}
	if _, _, err := loadText(t, strings.Replace(minimalDNS, "    - upstream: local", "    - domain: example.com\n      upstream: local", 1)); err == nil {
		t.Fatal("missing final default accepted")
	}
}

func TestDNSCacheConfig(t *testing.T) {
	cfg, _, err := loadText(t, minimalDNS)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Cache.Algorithm != "arc" || !cfg.DNS.Cache.Stale.IsEnabled() || cfg.DNS.Cache.Stale.StaleTTL != time.Hour || cfg.DNS.Cache.Stale.ServeTTL != 5*time.Second {
		t.Fatalf("unexpected cache defaults: %+v", cfg.DNS.Cache)
	}

	valid := strings.Replace(minimalDNS, "dns:\n", "dns:\n  cache:\n    enabled: true\n    max_entries: 512\n    algorithm: lru\n    stale:\n      enabled: false\n      stale_ttl: 15m\n      serve_ttl: 3s\n", 1)
	cfg, _, err = loadText(t, valid)
	if err != nil {
		t.Fatalf("valid custom cache config failed: %v", err)
	}
	if cfg.DNS.Cache.Algorithm != "lru" || cfg.DNS.Cache.Stale.IsEnabled() || cfg.DNS.Cache.Stale.StaleTTL != 15*time.Minute || cfg.DNS.Cache.Stale.ServeTTL != 3*time.Second {
		t.Fatalf("unexpected custom cache: %+v", cfg.DNS.Cache)
	}

	for _, invalid := range []string{
		"algorithm: random",
		"stale:\n      stale_ttl: 48h",
		"stale:\n      serve_ttl: 2m",
	} {
		bad := strings.Replace(minimalDNS, "dns:\n", "dns:\n  cache:\n    enabled: true\n    max_entries: 512\n    "+invalid+"\n", 1)
		if _, _, err := loadText(t, bad); err == nil {
			t.Fatalf("expected error for bad cache config %s", invalid)
		}
	}
}
