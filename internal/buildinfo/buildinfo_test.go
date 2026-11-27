package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentForDirWindows(t *testing.T) {
	dir := t.TempDir()
	dllData := []byte("fake-windivert-dll")
	sysData := []byte("fake-windivert-sys")
	if err := os.WriteFile(filepath.Join(dir, "WinDivert.dll"), dllData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "WinDivert64.sys"), sysData, 0600); err != nil {
		t.Fatal(err)
	}

	info := CurrentForDir(dir, "windows", "amd64")
	if info.GOOS != "windows" || info.GOARCH != "amd64" {
		t.Fatalf("unexpected target: %+v", info)
	}
	if info.WinDivert == nil || !info.WinDivert.DLLPresent || !info.WinDivert.SYSPresent {
		t.Fatalf("expected WinDivert files detected: %+v", info.WinDivert)
	}
	wantDLL := sha256Hex(dllData)
	wantSYS := sha256Hex(sysData)
	if info.WinDivert.DLLSHA256 != wantDLL || info.WinDivert.SYSSHA256 != wantSYS {
		t.Fatalf("hash mismatch: got (%s, %s), want (%s, %s)", info.WinDivert.DLLSHA256, info.WinDivert.SYSSHA256, wantDLL, wantSYS)
	}
}

func TestCurrentForDirMissingAndLinux(t *testing.T) {
	dir := t.TempDir()
	winInfo := CurrentForDir(dir, "windows", "amd64")
	if winInfo.WinDivert == nil || winInfo.WinDivert.DLLPresent || winInfo.WinDivert.SYSPresent {
		t.Fatalf("expected missing WinDivert files reported cleanly: %+v", winInfo.WinDivert)
	}

	linuxInfo := CurrentForDir(dir, "linux", "arm64")
	if linuxInfo.WinDivert != nil {
		t.Fatalf("expected nil WinDivert on linux: %+v", linuxInfo.WinDivert)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
