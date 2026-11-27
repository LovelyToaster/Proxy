//go:build windows

package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func PreferDeb(_ string) bool { return false }

func Apply(ctx context.Context, staged *StagedUpdate, opts ApplyOptions) (*ApplyResult, error) {
	return applyWindows(ctx, staged, opts, realWindowsOps{})
}

func applyWindows(ctx context.Context, staged *StagedUpdate, opts ApplyOptions, ops windowsOps) (*ApplyResult, error) {
	var err error
	opts, err = normalizeApplyOptions(opts)
	if err != nil {
		return nil, err
	}
	if staged == nil || staged.BinaryPath == "" {
		return nil, errors.New("missing staged Windows binary")
	}

	// Pre-flight check: verify write access to install directory before stopping any service.
	if err := checkDirWritable(opts.InstallDir); err != nil {
		if !ops.isElevated() {
			return nil, fmt.Errorf("administrator privileges required to update %s (re-run in an elevated terminal): %w", opts.InstallDir, err)
		}
		return nil, fmt.Errorf("installation directory %s is not writable: %w", opts.InstallDir, err)
	}

	if staged.DriverUpdateNeeded && !ops.isElevated() {
		return nil, errors.New("administrator privileges required to update WinDivert driver (re-run in an elevated terminal)")
	}

	wasRunning, err := ops.isServiceRunning()
	if err != nil {
		if !ops.isElevated() {
			return nil, fmt.Errorf("administrator privileges required to query ProxyD service: %w", err)
		}
		return nil, fmt.Errorf("query ProxyD service: %w", err)
	}

	if wasRunning {
		if opts.Progress != nil {
			fmt.Fprintln(opts.Progress, "Stopping ProxyD service...")
		}
		if err := ops.stopService(ctx); err != nil {
			return nil, fmt.Errorf("stop ProxyD service: %w", err)
		}
	}

	restartIfNeeded := func() error {
		if !wasRunning {
			return nil
		}
		if opts.Progress != nil {
			fmt.Fprintln(opts.Progress, "Starting ProxyD service...")
		}
		return ops.startService(ctx)
	}

	if staged.DriverUpdateNeeded && len(staged.DriverFiles) > 0 {
		if opts.Progress != nil {
			fmt.Fprintln(opts.Progress, "Unloading WinDivert driver for update...")
		}
		if err := ops.unloadWinDivert(ctx); err != nil {
			_ = restartIfNeeded()
			return nil, err
		}
	}

	// Build swap plan: always swap proxy.exe; swap WinDivert files when needed.
	type swapItem struct {
		stagedPath string
		targetPath string
		backupPath string
		tempPath   string
		swapped    bool
		hadBackup  bool
	}
	items := []*swapItem{
		{
			stagedPath: staged.BinaryPath,
			targetPath: opts.ExecutablePath,
			backupPath: opts.ExecutablePath + ".old",
			tempPath:   filepath.Join(opts.InstallDir, ".proxy.exe.new"),
		},
	}
	driverUpdated := false
	if staged.DriverUpdateNeeded {
		for _, name := range []string{"WinDivert.dll", "WinDivert64.sys", "WinDivert-LICENSE"} {
			if src, ok := staged.DriverFiles[name]; ok {
				dst := filepath.Join(opts.InstallDir, name)
				items = append(items, &swapItem{
					stagedPath: src,
					targetPath: dst,
					backupPath: dst + ".old",
					tempPath:   filepath.Join(opts.InstallDir, "."+name+".new"),
				})
				driverUpdated = true
			}
		}
	}

	rollback := func(cause error) error {
		var rbErrs []error
		for i := len(items) - 1; i >= 0; i-- {
			it := items[i]
			_ = os.Remove(it.tempPath)
			if !it.swapped {
				continue
			}
			if it.hadBackup {
				if err := moveFileWithRetry(it.backupPath, it.targetPath); err != nil {
					rbErrs = append(rbErrs, fmt.Errorf("restore %s: %w", filepath.Base(it.targetPath), err))
				}
			} else {
				_ = os.Remove(it.targetPath)
			}
		}
		if wasRunning {
			if startErr := ops.startService(ctx); startErr != nil {
				rbErrs = append(rbErrs, fmt.Errorf("restart original ProxyD: %w", startErr))
			}
		}
		if len(rbErrs) > 0 {
			return fmt.Errorf("%w (rollback warnings: %v)", cause, errors.Join(rbErrs...))
		}
		return fmt.Errorf("%w (rolled back to previous version)", cause)
	}

	// Copy staged files onto the same volume as installDir first.
	for _, it := range items {
		if err := copyFile(it.stagedPath, it.tempPath, 0755); err != nil {
			return nil, rollback(fmt.Errorf("prepare %s: %w", filepath.Base(it.targetPath), err))
		}
	}

	// Atomically move existing targets to .old and move new files into place.
	for _, it := range items {
		if _, err := os.Stat(it.targetPath); err == nil {
			_ = os.Remove(it.backupPath)
			if err := moveFileWithRetry(it.targetPath, it.backupPath); err != nil {
				return nil, rollback(fmt.Errorf("backup %s: %w", filepath.Base(it.targetPath), err))
			}
			it.hadBackup = true
		}
		if err := moveFileWithRetry(it.tempPath, it.targetPath); err != nil {
			// Restore backup immediately if moving new file failed.
			if it.hadBackup {
				_ = moveFileWithRetry(it.backupPath, it.targetPath)
			}
			return nil, rollback(fmt.Errorf("install %s: %w", filepath.Base(it.targetPath), err))
		}
		it.swapped = true
	}

	geoSynced := syncBundledGeo(opts.ConfigPath, staged.GeoFiles)
	ops.updateUninstallVersion(staged.Version)

	if err := restartIfNeeded(); err != nil {
		return nil, rollback(fmt.Errorf("start updated ProxyD service: %w", err))
	}

	// Best-effort remove non-locked backups; proxy.exe.old will be cleaned on next launch.
	for _, it := range items {
		if it.hadBackup {
			_ = os.Remove(it.backupPath)
		}
	}

	method := "binary"
	note := "WinDivert driver already up to date"
	if driverUpdated {
		method = "binary+windivert"
		note = "WinDivert driver updated"
	}
	return &ApplyResult{
		UpdatedVersion:   staged.Version,
		DriverUpdated:    driverUpdated,
		DriverNote:       note,
		ServiceRestarted: wasRunning,
		Method:           method,
		GeoSynced:        geoSynced,
	}, nil
}

func moveFileWithRetry(src, dst string) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if err := moveFileReplace(src, dst); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return lastErr
}

func checkDirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".proxy-update-perm-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
