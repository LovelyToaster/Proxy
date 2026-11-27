package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// These variables are populated at build time via -ldflags "-X ...".
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = ""
)

type WinDivertInfo struct {
	DLLPresent bool   `json:"dll_present"`
	DLLSHA256  string `json:"dll_sha256,omitempty"`
	SYSPresent bool   `json:"sys_present"`
	SYSSHA256  string `json:"sys_sha256,omitempty"`
}

type Info struct {
	Version   string         `json:"version"`
	Commit    string         `json:"commit,omitempty"`
	BuildDate string         `json:"build_date,omitempty"`
	GOOS      string         `json:"goos"`
	GOARCH    string         `json:"goarch"`
	WinDivert *WinDivertInfo `json:"windivert,omitempty"`
}

func Current() Info {
	dir := ""
	if exe, err := os.Executable(); err == nil {
		dir = filepath.Dir(exe)
	}
	return CurrentForDir(dir, runtime.GOOS, runtime.GOARCH)
}

func CurrentForDir(dir, goos, goarch string) Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GOOS:      goos,
		GOARCH:    goarch,
	}
	if goos == "windows" && dir != "" {
		info.WinDivert = inspectWinDivert(dir)
	}
	return info
}

func inspectWinDivert(dir string) *WinDivertInfo {
	wd := &WinDivertInfo{}
	if hash, ok, err := FileSHA256(filepath.Join(dir, "WinDivert.dll")); err == nil && ok {
		wd.DLLPresent = true
		wd.DLLSHA256 = hash
	}
	if hash, ok, err := FileSHA256(filepath.Join(dir, "WinDivert64.sys")); err == nil && ok {
		wd.SYSPresent = true
		wd.SYSSHA256 = hash
	}
	return wd
}

func FileSHA256(path string) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", true, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), true, nil
}
