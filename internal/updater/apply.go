package updater

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

type ApplyOptions struct {
	InstallDir     string
	ExecutablePath string
	ConfigPath     string
	Progress       io.Writer
}

type ApplyResult struct {
	UpdatedVersion   string   `json:"updated_version"`
	DriverUpdated    bool     `json:"driver_updated"`
	DriverNote       string   `json:"driver_note,omitempty"`
	ServiceRestarted bool     `json:"service_restarted"`
	Method           string   `json:"method"`
	GeoSynced        []string `json:"geo_synced,omitempty"`
}

func normalizeApplyOptions(opts ApplyOptions) (ApplyOptions, error) {
	if opts.ExecutablePath == "" {
		exe, err := os.Executable()
		if err != nil {
			return opts, err
		}
		opts.ExecutablePath = exe
	}
	if opts.InstallDir == "" {
		opts.InstallDir = filepath.Dir(opts.ExecutablePath)
	}
	return opts, nil
}

// CleanupStaleBackups removes leftover *.old backup files from a previous update.
func CleanupStaleBackups(dir string) {
	if dir == "" {
		if exe, err := os.Executable(); err == nil {
			dir = filepath.Dir(exe)
		}
	}
	if dir == "" {
		return
	}
	for _, name := range []string{
		"proxy.exe.old",
		"WinDivert.dll.old",
		"WinDivert64.sys.old",
		"WinDivert-LICENSE.old",
		"proxy.old",
	} {
		_ = os.Remove(filepath.Join(dir, name))
	}
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if err := errors.Join(copyErr, syncErr, closeErr); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

// syncBundledGeo copies bundled geoip.dat / geosite.dat only when missing and
// not already managed by geodata's manifest.json (from `proxy geo update`).
func syncBundledGeo(configPath string, geoFiles map[string]string) []string {
	if configPath == "" || len(geoFiles) == 0 {
		return nil
	}
	dataDir := filepath.Join(filepath.Dir(configPath), "data")
	if _, err := os.Stat(filepath.Join(dataDir, "manifest.json")); err == nil {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil
	}
	var synced []string
	for name, src := range geoFiles {
		dst := filepath.Join(dataDir, name)
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		if err := copyFile(src, dst, 0644); err == nil {
			synced = append(synced, name)
		}
	}
	return synced
}
