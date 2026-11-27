package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"proxy.local/m0/internal/updater"
)

func TestUpdateCheckCommandJSON(t *testing.T) {
	target := updater.TargetKey(runtime.GOOS, runtime.GOARCH)
	archiveName := "proxy-" + target + ".tar.gz"
	if runtime.GOOS == "windows" {
		archiveName = "proxy-" + target + ".zip"
	}
	dummySum := strings.Repeat("b", 64)
	manifest := updater.ReleaseManifest{
		Version: "v9.9.9",
		Artifacts: map[string]updater.Artifact{
			target: {
				Archive:       archiveName,
				ArchiveSHA256: dummySum,
				Files: map[string]string{
					"proxy": dummySum,
				},
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mSum := sha256.Sum256(manifestBytes)
	checksums := dummySum + "  " + archiveName + "\n" + hex.EncodeToString(mSum[:]) + "  release-manifest.json\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release-manifest.json":
			_, _ = w.Write(manifestBytes)
		case "/checksums.txt":
			_, _ = w.Write([]byte(checksums))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := Run([]string{"--config", t.TempDir() + "/nonexistent.yaml", "update", "--check", "--json", "--base-url", srv.URL}, &out); err != nil {
		t.Fatalf("proxy update --check --json failed: %v", err)
	}
	var res updater.CheckResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("decode update check json: %v (%s)", err, out.String())
	}
	if !res.UpdateAvailable || res.TargetVersion != "v9.9.9" || res.Target != target {
		t.Fatalf("unexpected update check result: %+v", res)
	}
}
