package updater

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxy.local/m0/internal/buildinfo"
)

type StagedUpdate struct {
	Version            string
	StageDir           string
	ArchivePath        string
	DebPath            string
	BinaryPath         string
	DriverFiles        map[string]string // filename -> staged path
	GeoFiles           map[string]string // filename -> staged path
	DriverUpdateNeeded bool
}

func (s *StagedUpdate) Cleanup() {
	if s != nil && s.StageDir != "" {
		_ = os.RemoveAll(s.StageDir)
	}
}

func (c *Client) Stage(ctx context.Context, opts Options, check *CheckResult, preferDeb bool) (*StagedUpdate, error) {
	opts = normalizeOptions(opts)
	stageDir, err := os.MkdirTemp("", "proxy-update-*")
	if err != nil {
		return nil, fmt.Errorf("create staging directory: %w", err)
	}
	staged := &StagedUpdate{
		Version:            check.TargetVersion,
		StageDir:           stageDir,
		DriverFiles:        make(map[string]string),
		GeoFiles:           make(map[string]string),
		DriverUpdateNeeded: check.DriverUpdateNeeded,
	}
	cleanupOnErr := true
	defer func() {
		if cleanupOnErr {
			staged.Cleanup()
		}
	}()

	if preferDeb && opts.GOOS == "linux" && check.Artifact.Deb != "" {
		debURL, ok := check.AssetURLs[check.Artifact.Deb]
		if !ok {
			return nil, fmt.Errorf("missing download URL for %s", check.Artifact.Deb)
		}
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, "Downloading %s...\n", check.Artifact.Deb)
		}
		debPath := filepath.Join(stageDir, check.Artifact.Deb)
		actual, err := c.downloadToFile(ctx, debURL, debPath, maxArchiveBytes)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(actual, check.Artifact.DebSHA256) {
			return nil, fmt.Errorf("%s SHA-256 mismatch: got %s, expected %s", check.Artifact.Deb, actual, check.Artifact.DebSHA256)
		}
		staged.DebPath = debPath
		cleanupOnErr = false
		return staged, nil
	}

	archiveURL, ok := check.AssetURLs[check.Artifact.Archive]
	if !ok {
		return nil, fmt.Errorf("missing download URL for %s", check.Artifact.Archive)
	}
	if opts.Progress != nil {
		fmt.Fprintf(opts.Progress, "Downloading %s...\n", check.Artifact.Archive)
	}
	archivePath := filepath.Join(stageDir, check.Artifact.Archive)
	actualArchive, err := c.downloadToFile(ctx, archiveURL, archivePath, maxArchiveBytes)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(actualArchive, check.Artifact.ArchiveSHA256) {
		return nil, fmt.Errorf("%s SHA-256 mismatch: got %s, expected %s", check.Artifact.Archive, actualArchive, check.Artifact.ArchiveSHA256)
	}
	staged.ArchivePath = archivePath

	extractDir := filepath.Join(stageDir, "extracted")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return nil, err
	}
	if err := ExtractArchive(archivePath, extractDir); err != nil {
		return nil, fmt.Errorf("extract %s: %w", check.Artifact.Archive, err)
	}

	// Verify every file declared in the manifest.
	for rel, expectedHash := range check.Artifact.Files {
		full := filepath.Join(extractDir, filepath.FromSlash(rel))
		actual, present, err := buildinfo.FileSHA256(full)
		if err != nil {
			return nil, fmt.Errorf("hash staged file %s: %w", rel, err)
		}
		if !present {
			return nil, fmt.Errorf("staged archive missing expected file %s", rel)
		}
		if !strings.EqualFold(actual, expectedHash) {
			return nil, fmt.Errorf("staged file %s SHA-256 mismatch: got %s, expected %s", rel, actual, expectedHash)
		}
	}

	binName := "proxy"
	if opts.GOOS == "windows" {
		binName = "proxy.exe"
	}
	binPath := filepath.Join(extractDir, binName)
	if _, err := os.Stat(binPath); err != nil {
		return nil, fmt.Errorf("staged archive missing binary %s: %w", binName, err)
	}
	staged.BinaryPath = binPath

	if opts.GOOS == "windows" {
		for _, name := range []string{"WinDivert.dll", "WinDivert64.sys", "WinDivert-LICENSE"} {
			p := filepath.Join(extractDir, name)
			if _, err := os.Stat(p); err == nil {
				staged.DriverFiles[name] = p
			}
		}
	}

	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		p := filepath.Join(extractDir, "data", name)
		if _, err := os.Stat(p); err == nil {
			staged.GeoFiles[name] = p
		}
	}

	// Pre-flight check on native host binary before stopping any service.
	if !opts.SkipPrecheck && opts.GOOS == runtime.GOOS && opts.GOARCH == runtime.GOARCH {
		if err := precheckBinary(ctx, binPath, opts.ConfigPath); err != nil {
			return nil, err
		}
	}

	cleanupOnErr = false
	return staged, nil
}

func precheckBinary(ctx context.Context, binPath, configPath string) error {
	if runtime.GOOS != "windows" {
		_ = os.Chmod(binPath, 0755)
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(checkCtx, binPath, "version").CombinedOutput(); err != nil {
		return fmt.Errorf("staged binary failed version precheck: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if configPath != "" {
		if info, err := os.Stat(configPath); err == nil && info.Mode().IsRegular() {
			if out, err := exec.CommandContext(checkCtx, binPath, "--config", configPath, "config", "check").CombinedOutput(); err != nil {
				return fmt.Errorf("staged binary rejected existing config %s: %w (%s)", configPath, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}
