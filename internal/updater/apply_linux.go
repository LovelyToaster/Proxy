//go:build linux

package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type linuxOps interface {
	isRoot() bool
	isServiceActive(ctx context.Context) bool
	restartService(ctx context.Context) error
	installDeb(ctx context.Context, debPath string) error
}

type realLinuxOps struct{}

func (realLinuxOps) isRoot() bool { return os.Geteuid() == 0 }

func (realLinuxOps) isServiceActive(ctx context.Context) bool {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", "proxyd.service").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func (realLinuxOps) restartService(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "proxyd.service")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart proxyd.service: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (realLinuxOps) installDeb(ctx context.Context, debPath string) error {
	cmd := exec.CommandContext(ctx, "dpkg", "-i", debPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dpkg -i %s: %w (%s)", filepath.Base(debPath), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PreferDeb returns true when the running executable belongs to the dpkg-managed "proxy" package.
func PreferDeb(exePath string) bool {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return false
		}
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	out, err := exec.Command("dpkg-query", "-S", exePath).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		pkg, _, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(pkg) == "proxy" {
			return true
		}
	}
	return false
}

func Apply(ctx context.Context, staged *StagedUpdate, opts ApplyOptions) (*ApplyResult, error) {
	return applyLinux(ctx, staged, opts, realLinuxOps{})
}

func applyLinux(ctx context.Context, staged *StagedUpdate, opts ApplyOptions, ops linuxOps) (*ApplyResult, error) {
	var err error
	opts, err = normalizeApplyOptions(opts)
	if err != nil {
		return nil, err
	}
	if staged == nil {
		return nil, errors.New("missing staged update")
	}

	const linuxDriverNote = "Linux uses built-in kernel TPROXY/nftables; no external driver update required"
	wasActive := ops.isServiceActive(ctx)

	if staged.DebPath != "" {
		if !ops.isRoot() {
			return nil, errors.New("root privileges required to upgrade Debian package (run sudo proxy update)")
		}
		if opts.Progress != nil {
			fmt.Fprintf(opts.Progress, "Installing %s via dpkg...\n", filepath.Base(staged.DebPath))
		}
		if err := ops.installDeb(ctx, staged.DebPath); err != nil {
			return nil, err
		}
		if wasActive && !ops.isServiceActive(ctx) {
			if err := ops.restartService(ctx); err != nil {
				return nil, err
			}
		}
		return &ApplyResult{
			UpdatedVersion:   staged.Version,
			DriverUpdated:    false,
			DriverNote:       linuxDriverNote,
			ServiceRestarted: wasActive,
			Method:           "deb",
		}, nil
	}

	if staged.BinaryPath == "" {
		return nil, errors.New("missing staged Linux binary")
	}
	if wasActive && !ops.isRoot() {
		return nil, errors.New("root privileges required to restart proxyd.service (run sudo proxy update)")
	}
	if err := checkLinuxDirWritable(opts.InstallDir); err != nil {
		if !ops.isRoot() {
			return nil, fmt.Errorf("root privileges required to update %s (run sudo proxy update): %w", opts.InstallDir, err)
		}
		return nil, fmt.Errorf("installation directory %s is not writable: %w", opts.InstallDir, err)
	}

	backupPath := opts.ExecutablePath + ".old"
	tempNewPath := filepath.Join(opts.InstallDir, ".proxy.new")
	hasBackup := false
	if _, err := os.Stat(opts.ExecutablePath); err == nil {
		if err := copyFile(opts.ExecutablePath, backupPath, 0755); err != nil {
			return nil, fmt.Errorf("backup existing binary: %w", err)
		}
		hasBackup = true
	}

	if err := copyFile(staged.BinaryPath, tempNewPath, 0755); err != nil {
		if hasBackup {
			_ = os.Remove(backupPath)
		}
		return nil, fmt.Errorf("stage binary in install directory: %w", err)
	}

	if err := os.Rename(tempNewPath, opts.ExecutablePath); err != nil {
		_ = os.Remove(tempNewPath)
		if hasBackup {
			_ = os.Remove(backupPath)
		}
		return nil, fmt.Errorf("replace binary: %w", err)
	}

	geoSynced := syncBundledGeo(opts.ConfigPath, staged.GeoFiles)

	if wasActive {
		if opts.Progress != nil {
			fmt.Fprintln(opts.Progress, "Restarting proxyd.service...")
		}
		if err := ops.restartService(ctx); err != nil {
			if hasBackup {
				_ = os.Rename(backupPath, opts.ExecutablePath)
				_ = ops.restartService(ctx)
			}
			return nil, fmt.Errorf("restart proxyd.service failed (rolled back to previous version): %w", err)
		}
	}

	if hasBackup {
		_ = os.Remove(backupPath)
	}

	return &ApplyResult{
		UpdatedVersion:   staged.Version,
		DriverUpdated:    false,
		DriverNote:       linuxDriverNote,
		ServiceRestarted: wasActive,
		Method:           "binary",
		GeoSynced:        geoSynced,
	}, nil
}

func checkLinuxDirWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".proxy-update-perm-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
