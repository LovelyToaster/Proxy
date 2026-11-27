package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildTestTarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEndToEndLinuxTarGzAndDebStage(t *testing.T) {
	files := map[string][]byte{
		"proxy":            []byte("linux-proxy-v0.2.0"),
		"data/geoip.dat":   []byte("geoip-v2"),
		"data/geosite.dat": []byte("geosite-v2"),
	}
	tarBytes := buildTestTarGz(t, files)
	tarSum := sha256HexBytes(tarBytes)
	debBytes := []byte("fake-deb-package-v0.2.0")
	debSum := sha256HexBytes(debBytes)

	inner := map[string]string{
		"proxy":            sha256HexBytes(files["proxy"]),
		"data/geoip.dat":   sha256HexBytes(files["data/geoip.dat"]),
		"data/geosite.dat": sha256HexBytes(files["data/geosite.dat"]),
	}
	manifest := ReleaseManifest{
		Version: "v0.2.0",
		Artifacts: map[string]Artifact{
			"linux-arm64": {
				Archive:       "proxy-linux-arm64.tar.gz",
				ArchiveSHA256: tarSum,
				Deb:           "proxy_0.2.0_arm64.deb",
				DebSHA256:     debSum,
				Files:         inner,
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	checksums := strings.Join([]string{
		tarSum + "  proxy-linux-arm64.tar.gz",
		debSum + "  proxy_0.2.0_arm64.deb",
		sha256HexBytes(manifestBytes) + "  release-manifest.json",
	}, "\n") + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/checksums.txt":
			_, _ = w.Write([]byte(checksums))
		case "/proxy-linux-arm64.tar.gz":
			_, _ = w.Write(tarBytes)
		case "/proxy_0.2.0_arm64.deb":
			_, _ = w.Write(debBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := NewClient(srv.Client())
	opts := Options{
		BaseURL:        srv.URL,
		CurrentVersion: "v0.1.0",
		GOOS:           "linux",
		GOARCH:         "arm64",
		SkipPrecheck:   true,
	}

	check, err := client.Check(context.Background(), opts)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !check.UpdateAvailable || check.DriverUpdateNeeded {
		t.Fatalf("unexpected linux check result: %+v", check)
	}

	// Stage tar.gz mode
	stagedTar, err := client.Stage(context.Background(), opts, check, false)
	if err != nil {
		t.Fatalf("Stage tar.gz failed: %v", err)
	}
	defer stagedTar.Cleanup()
	if stagedTar.BinaryPath == "" || len(stagedTar.GeoFiles) != 2 {
		t.Fatalf("unexpected staged tar.gz: %+v", stagedTar)
	}

	// Stage deb mode
	stagedDeb, err := client.Stage(context.Background(), opts, check, true)
	if err != nil {
		t.Fatalf("Stage deb failed: %v", err)
	}
	defer stagedDeb.Cleanup()
	if stagedDeb.DebPath == "" || filepath.Base(stagedDeb.DebPath) != "proxy_0.2.0_arm64.deb" {
		t.Fatalf("unexpected staged deb: %+v", stagedDeb)
	}
}

func TestSyncBundledGeoRespectsManagedManifest(t *testing.T) {
	cfgDir := t.TempDir()
	stageDir := t.TempDir()
	stagedGeo := filepath.Join(stageDir, "geoip.dat")
	_ = os.WriteFile(stagedGeo, []byte("bundled-geoip"), 0644)

	cfgPath := filepath.Join(cfgDir, "proxy.yaml")
	dataDir := filepath.Join(cfgDir, "data")
	_ = os.MkdirAll(dataDir, 0755)
	_ = os.WriteFile(filepath.Join(dataDir, "manifest.json"), []byte(`{}`), 0644)

	synced := syncBundledGeo(cfgPath, map[string]string{"geoip.dat": stagedGeo})
	if len(synced) != 0 {
		t.Fatalf("expected managed geo directory to be left untouched, synced=%v", synced)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "geoip.dat")); !os.IsNotExist(err) {
		t.Fatal("should not write geoip.dat when manifest.json exists")
	}

	// Remove manifest.json -> should now copy missing geoip.dat.
	_ = os.Remove(filepath.Join(dataDir, "manifest.json"))
	synced = syncBundledGeo(cfgPath, map[string]string{"geoip.dat": stagedGeo})
	if len(synced) != 1 || synced[0] != "geoip.dat" {
		t.Fatalf("expected geoip.dat to be synced, got %v", synced)
	}
}

func TestCleanupStaleBackups(t *testing.T) {
	dir := t.TempDir()
	stale := []string{"proxy.exe.old", "WinDivert.dll.old", "proxy.old"}
	for _, name := range stale {
		_ = os.WriteFile(filepath.Join(dir, name), []byte("old"), 0644)
	}
	keep := filepath.Join(dir, "proxy.yaml")
	_ = os.WriteFile(keep, []byte("keep"), 0644)

	CleanupStaleBackups(dir)
	for _, name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed", name)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("unrelated file should remain intact: %v", err)
	}
}
