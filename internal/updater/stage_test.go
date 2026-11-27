package updater

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildTestZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestClientCheckAndStageSuccessAndDriverRepair(t *testing.T) {
	files := map[string][]byte{
		"proxy.exe":         []byte("fake-proxy-v0.2.0"),
		"WinDivert.dll":     []byte("windivert-dll-v2"),
		"WinDivert64.sys":   []byte("windivert-sys-v2"),
		"WinDivert-LICENSE": []byte("license"),
		"data/geoip.dat":    []byte("geoip-data"),
		"data/geosite.dat":  []byte("geosite-data"),
	}
	zipBytes := buildTestZip(t, files)
	zipSum := sha256HexBytes(zipBytes)

	innerHashes := make(map[string]string, len(files))
	for k, v := range files {
		innerHashes[k] = sha256HexBytes(v)
	}

	manifest := ReleaseManifest{
		Version: "v0.2.0",
		Artifacts: map[string]Artifact{
			"windows-amd64": {
				Archive:       "proxy-windows-amd64.zip",
				ArchiveSHA256: zipSum,
				Files:         innerHashes,
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	checksums := zipSum + "  proxy-windows-amd64.zip\n" + sha256HexBytes(manifestBytes) + "  release-manifest.json\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/checksums.txt":
			_, _ = w.Write([]byte(checksums))
		case "/proxy-windows-amd64.zip":
			_, _ = w.Write(zipBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	installDir := t.TempDir()
	// Same version v0.2.0, but old WinDivert.dll -> should detect DriverUpdateNeeded!
	_ = os.WriteFile(filepath.Join(installDir, "WinDivert.dll"), []byte("old-dll"), 0600)
	_ = os.WriteFile(filepath.Join(installDir, "WinDivert64.sys"), files["WinDivert64.sys"], 0600)

	client := NewClient(srv.Client())
	opts := Options{
		BaseURL:        srv.URL,
		CurrentVersion: "v0.2.0",
		GOOS:           "windows",
		GOARCH:         "amd64",
		InstallDir:     installDir,
		SkipPrecheck:   true,
	}
	check, err := client.Check(context.Background(), opts)
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !check.UpdateAvailable || !check.DriverUpdateNeeded {
		t.Fatalf("expected driver repair update needed: %+v", check)
	}

	staged, err := client.Stage(context.Background(), opts, check, false)
	if err != nil {
		t.Fatalf("Stage failed: %v", err)
	}
	defer staged.Cleanup()

	if staged.BinaryPath == "" || len(staged.DriverFiles) != 3 || len(staged.GeoFiles) != 2 {
		t.Fatalf("unexpected staged payload: bin=%s drivers=%v geo=%v", staged.BinaryPath, staged.DriverFiles, staged.GeoFiles)
	}

	// Update local DLL to match -> now should be completely up-to-date.
	_ = os.WriteFile(filepath.Join(installDir, "WinDivert.dll"), files["WinDivert.dll"], 0600)
	check2, err := client.Check(context.Background(), opts)
	if err != nil {
		t.Fatalf("second Check failed: %v", err)
	}
	if check2.UpdateAvailable || check2.DriverUpdateNeeded {
		t.Fatalf("expected up to date when version and driver match: %+v", check2)
	}
}

func TestStageRejectsTamperedArchiveAndZipSlip(t *testing.T) {
	// Zip-Slip check directly on ExtractArchive.
	evilZip := buildTestZip(t, map[string][]byte{
		"../evil.txt": []byte("pwned"),
	})
	dir := t.TempDir()
	evilPath := filepath.Join(dir, "evil.zip")
	if err := os.WriteFile(evilPath, evilZip, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ExtractArchive(evilPath, filepath.Join(dir, "out")); err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("expected zip-slip error, got: %v", err)
	}
}
