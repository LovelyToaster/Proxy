package updater

import (
	"strings"
	"testing"
)

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.1.0", 0},
		{"0.1.0", "v0.1.0", 0},
		{"v0.1.0", "v0.2.0", -1},
		{"v0.2.0", "v0.1.9", 1},
		{"v1.0.0-rc.1", "v1.0.0", -1},
		{"v1.0.0", "v1.0.0-rc.1", 1},
		{"v1.0.0-rc.1", "v1.0.0-rc.2", -1},
		{"v1.0.0-rc.2", "v1.0.0-rc.10", -1},
		{"v1.0.0-alpha.1", "v1.0.0-beta.1", -1},
		{"v1.0.0+build1", "v1.0.0+build2", 0},
	}
	for _, tc := range cases {
		got, err := CompareVersion(tc.a, tc.b)
		if err != nil {
			t.Fatalf("CompareVersion(%q, %q) unexpected error: %v", tc.a, tc.b, err)
		}
		if got != tc.want {
			t.Fatalf("CompareVersion(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNeedsUpdate(t *testing.T) {
	cases := []struct {
		current, target string
		force           bool
		want            bool
	}{
		{"0.1.0-dev", "v0.1.0", false, true},
		{"dev", "v0.1.0", false, true},
		{"0.1.0-m3", "v0.1.0", false, true},
		{"v0.2.0", "v0.2.0", false, false},
		{"v0.2.0", "v0.2.0", true, true},
		{"v0.2.0", "v0.2.1", false, true},
		{"v0.3.0", "v0.2.1", false, false},
	}
	for _, tc := range cases {
		got, err := NeedsUpdate(tc.current, tc.target, tc.force)
		if err != nil {
			t.Fatalf("NeedsUpdate(%q, %q, %v) error: %v", tc.current, tc.target, tc.force, err)
		}
		if got != tc.want {
			t.Fatalf("NeedsUpdate(%q, %q, %v) = %v, want %v", tc.current, tc.target, tc.force, got, tc.want)
		}
	}
}

func TestParseManifestAndChecksums(t *testing.T) {
	sum := strings.Repeat("a", 64)
	rawManifest := `{
  "version": "v0.2.0",
  "artifacts": {
    "windows-amd64": {
      "archive": "proxy-windows-amd64.zip",
      "archive_sha256": "` + sum + `",
      "installer": "Proxy-Setup-v0.2.0-x64.exe",
      "installer_sha256": "` + sum + `",
      "files": {
        "proxy.exe": "` + sum + `",
        "WinDivert.dll": "` + sum + `",
        "WinDivert64.sys": "` + sum + `",
        "data/geoip.dat": "` + sum + `"
      }
    },
    "linux-amd64": {
      "archive": "proxy-linux-amd64.tar.gz",
      "archive_sha256": "` + sum + `",
      "deb": "proxy_0.2.0_amd64.deb",
      "deb_sha256": "` + sum + `",
      "files": {
        "proxy": "` + sum + `"
      }
    }
  }
}`
	m, err := ParseManifest(strings.NewReader(rawManifest))
	if err != nil {
		t.Fatalf("ParseManifest valid failed: %v", err)
	}
	if m.Version != "v0.2.0" || m.Artifacts["linux-amd64"].Deb != "proxy_0.2.0_amd64.deb" {
		t.Fatalf("unexpected manifest: %+v", m)
	}

	badManifest := strings.Replace(rawManifest, "data/geoip.dat", "../escape.dat", 1)
	if _, err := ParseManifest(strings.NewReader(badManifest)); err == nil {
		t.Fatal("expected traversal path in manifest to be rejected")
	}

	checksums, err := ParseChecksums(strings.NewReader(sum + "  proxy-windows-amd64.zip\n" + sum + " *proxy-linux-amd64.tar.gz\n"))
	if err != nil {
		t.Fatalf("ParseChecksums failed: %v", err)
	}
	if checksums["proxy-windows-amd64.zip"] != sum || checksums["proxy-linux-amd64.tar.gz"] != sum {
		t.Fatalf("unexpected checksums: %+v", checksums)
	}
}
