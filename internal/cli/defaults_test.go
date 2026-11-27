package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"proxy.local/m0/internal/buildinfo"
)

func TestUserConfigurationDefaultAndOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".proxy")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	valid := []byte("outbounds:\n  direct: {type: direct}\nrouting:\n  rules:\n    - outbound: direct\n")
	if err := os.WriteFile(filepath.Join(dir, "proxy.yaml"), valid, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	args := []string{"config", "check"}
	if runtime.GOOS == "linux" {
		args = append([]string{"--config", filepath.Join(dir, "proxy.yaml")}, args...)
	}
	if err := Run(args, &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := Run([]string{"--config", filepath.Join(dir, "proxy.yaml"), "web"}, &output); err != nil {
		t.Fatalf("proxy web failed: %v", err)
	}
	if !strings.Contains(output.String(), "http://127.0.0.1:9100") {
		t.Fatalf("unexpected proxy web output: %s", output.String())
	}

	invalid := filepath.Join(home, "invalid.yaml")
	if err := os.WriteFile(invalid, []byte("unknown: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"--config", invalid, "config", "check"}, &output); err == nil {
		t.Fatal("explicit config did not override user default")
	}
	if err := Run([]string{"--service-run", "--config", invalid}, &output); err == nil || !strings.Contains(err.Error(), "unknown") && !strings.Contains(err.Error(), "field") {
		t.Fatalf("merged service entry did not load configuration: %v", err)
	}
}

func TestDefaultConfigPathByPlatform(t *testing.T) {
	home := t.TempDir()
	userPath := filepath.Join(home, ".proxy", "proxy.yaml")
	for _, tc := range []struct {
		platform string
		exists   bool
		want     string
	}{
		{"linux", true, "/etc/proxy/proxy.yaml"},
		{"linux", false, "/etc/proxy/proxy.yaml"},
		{"windows", true, userPath},
		{"windows", false, "proxy.yaml"},
		{"foreground", true, userPath},
		{"foreground", false, "proxy.yaml"},
	} {
		got := defaultConfigPath(tc.platform, home, func(path string) bool {
			if path != userPath {
				t.Fatal(path)
			}
			return tc.exists
		})
		if got != tc.want {
			t.Fatalf("%s exists=%v: got %q want %q", tc.platform, tc.exists, got, tc.want)
		}
	}
	// sudo's private HOME must never become the service configuration path.
	if got := defaultConfigPath("linux", "/root", func(string) bool { t.Fatal("Linux probed HOME"); return true }); got != "/etc/proxy/proxy.yaml" {
		t.Fatal(got)
	}
}

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"version"}, &out); err != nil {
		t.Fatalf("proxy version failed: %v", err)
	}
	if strings.TrimSpace(out.String()) != buildinfo.Version {
		t.Fatalf("unexpected version text: %q", out.String())
	}

	out.Reset()
	if err := Run([]string{"version", "--json"}, &out); err != nil {
		t.Fatalf("proxy version --json failed: %v", err)
	}
	var info buildinfo.Info
	if err := json.Unmarshal(out.Bytes(), &info); err != nil {
		t.Fatalf("invalid version json: %v (%s)", err, out.String())
	}
	if info.Version != buildinfo.Version || info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH {
		t.Fatalf("unexpected version json payload: %+v", info)
	}
}
