package config

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestNativeCaptureMode(t *testing.T) {
	for _, tc := range []struct {
		name, platform string
		capture        Capture
		want           string
		invalid        bool
	}{
		{name: "Windows global", platform: "windows", capture: Capture{Scope: "global"}, want: "windivert"},
		{name: "Linux global", platform: "linux", capture: Capture{Scope: "global"}, want: "local"},
		{name: "Linux gateway", platform: "linux", capture: Capture{Scope: "global", Interfaces: []string{"eth0"}}, want: "gateway"},
		{name: "Linux application", platform: "linux", capture: Capture{Scope: "application"}, invalid: true},
		{name: "Linux excludes", platform: "linux", capture: Capture{ExcludeApplications: []string{`C:\app.exe`}}, invalid: true},
		{name: "Windows gateway", platform: "windows", capture: Capture{Interfaces: []string{"eth0"}}, invalid: true},
		{name: "unsupported", platform: "darwin", capture: Capture{Scope: "global"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nativeCaptureMode(tc.capture, tc.platform)
			if (err != nil) != tc.invalid || got != tc.want {
				t.Fatalf("got %q %v, want %q invalid=%v", got, err, tc.want, tc.invalid)
			}
		})
	}
}

func TestCaptureModeOverrides(t *testing.T) {
	for _, mode := range []string{"off", "local", "gateway", "windivert"} {
		// Decode only: explicit foreign backends remain available to config tooling.
		var c Capture
		if err := yaml.Unmarshal([]byte("mode: "+mode+"\nscope: global\n"), &c); err != nil {
			t.Fatal(err)
		}
		if c.Mode != mode {
			t.Fatalf("explicit %s became %s", mode, c.Mode)
		}
	}
	for _, header := range []string{"scope: global\n", "mode: auto\nscope: global\n"} {
		captureYAML := "capture:\n  " + strings.ReplaceAll(strings.TrimSpace(header), "\n", "\n  ") + "\n"
		dnsText := strings.Replace(minimalDNS, "dns:\n", "dns:\n  hijack: true\n", 1)
		cfg, _, err := loadText(t, captureYAML+dnsText)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Capture.Mode == "off" || cfg.Capture.Mode == "auto" {
			t.Fatal("backend unresolved")
		}
	}
	cfg, _, err := loadText(t, minimalDNS)
	if err != nil || cfg.Capture.Mode != "off" {
		t.Fatalf("absent capture enabled: %+v %v", cfg.Capture, err)
	}
}
