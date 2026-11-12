package servicehost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/core"
)

const linuxUnit = "/etc/systemd/system/proxyd.service"
const linuxOwner = "# proxy-managed-v1 "

type linuxRegistration struct {
	Binary  string
	Config  string
	Runtime string
}

// systemd has its own quoting and specifier expansion, independent of a shell.
func unitQuote(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	return strconv.Quote(value)
}

func execUnitQuote(value string) string { return unitQuote(strings.ReplaceAll(value, "$", "$$")) }

func renderLinuxUnit(r linuxRegistration, capture bool) string {
	metadata, _ := json.Marshal(r)
	args := execUnitQuote(r.Binary) + " --service-run --config " + execUnitQuote(r.Config) + " --runtime " + execUnitQuote(r.Runtime)
	capabilities := ""
	if capture {
		capabilities = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
	}
	return linuxOwner + string(metadata) + "\n" + fmt.Sprintf(`[Unit]
Description=Proxy TCP/UDP and DNS service
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
NotifyAccess=main
User=proxyd
Group=proxyd
Environment=%s
ExecStart=%s
ExecStopPost=%s --runtime %s capture-cleanup
Restart=on-failure
RestartSec=2
WatchdogSec=8
TimeoutStartSec=45
TimeoutStopSec=30
KillMode=mixed
NoNewPrivileges=yes
CapabilityBoundingSet=%s
AmbientCapabilities=%s

[Install]
WantedBy=multi-user.target
`, unitQuote("PROXY_CAPTURE_LOCK_DIR="+r.Runtime), args,
		execUnitQuote(r.Binary), execUnitQuote(r.Runtime), capabilities, capabilities)
}

func parseLinuxRegistration(data []byte) (linuxRegistration, error) {
	var r linuxRegistration
	line, _, _ := strings.Cut(string(data), "\n")
	if !strings.HasPrefix(line, linuxOwner) {
		return r, errors.New("proxyd.service is not managed by proxy; remove the old service explicitly before using start")
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, linuxOwner)), &r); err != nil {
		return r, err
	}
	for _, path := range []string{r.Binary, r.Config, r.Runtime} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return r, errors.New("invalid managed service metadata")
		}
	}
	return r, nil
}

func readLinuxRegistration() (linuxRegistration, error) {
	info, err := os.Lstat(linuxUnit)
	if err != nil {
		return linuxRegistration{}, err
	}
	if !info.Mode().IsRegular() {
		return linuxRegistration{}, errors.New("refusing non-regular proxyd.service")
	}
	data, err := os.ReadFile(linuxUnit)
	if err != nil {
		return linuxRegistration{}, err
	}
	return parseLinuxRegistration(data)
}

func systemCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func requireLinuxManager() error {
	if os.Geteuid() != 0 {
		return errors.New("service management requires root; run sudo proxy start/stop/restart")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("background service management requires a running systemd; use proxy run for foreground operation")
	}
	return nil
}

func sameLinuxBinary(r linuxRegistration, executable string) error {
	if filepath.Clean(r.Binary) != filepath.Clean(executable) {
		return errors.New("proxyd.service belongs to another executable; use the installed proxy command")
	}
	return nil
}

func SimpleControl(ctx context.Context, operation, path, directory string) error {
	if operation != "start" && operation != "stop" && operation != "restart" {
		return fmt.Errorf("unsupported service operation %q", operation)
	}
	if err := requireLinuxManager(); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	registration, err := readLinuxRegistration()
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if exists {
		if err := sameLinuxBinary(registration, executable); err != nil {
			return err
		}
	}
	if operation == "stop" {
		if !exists {
			return nil
		}
		if err := Control(ctx, "stop"); err != nil {
			return err
		}
		return Uninstall()
	}
	if !exists {
		if err := Install(executable, path, directory, false); err != nil {
			return err
		}
		if err := startLinuxService(ctx, "start"); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			stopErr := Control(cleanupCtx, "stop")
			return errors.Join(err, stopErr, Uninstall())
		}
		return nil
	}
	cfg, err := config.Load(registration.Config)
	if err != nil {
		return err
	}
	if err := setLinuxAutostart(ctx, cfg.Service.Autostart); err != nil {
		return err
	}
	return startLinuxService(ctx, operation)
}

func startLinuxService(ctx context.Context, operation string) error {
	// An explicit user start/restart should recover from a prior start limit.
	// Automatic systemd recovery remains bounded by StartLimitBurst.
	if err := systemCommand(ctx, "systemctl", "reset-failed", "proxyd.service"); err != nil {
		// Freshly installed inactive units may not yet be loaded by PID 1.
		state, inspectErr := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", "proxyd.service").Output()
		if inspectErr != nil || strings.TrimSpace(string(state)) != "inactive" {
			return errors.Join(err, inspectErr)
		}
	}
	return Control(ctx, operation)
}

func setLinuxAutostart(ctx context.Context, enabled bool) error {
	operation := "disable"
	if enabled {
		operation = "enable"
	}
	return systemCommand(ctx, "systemctl", operation, "proxyd.service")
}

func Install(executable, path, directory string, _ bool) error {
	if err := requireLinuxManager(); err != nil {
		return err
	}
	var err error
	r := linuxRegistration{}
	if r.Binary, err = filepath.Abs(executable); err != nil {
		return err
	}
	if r.Config, err = filepath.Abs(path); err != nil {
		return err
	}
	if r.Runtime, err = filepath.Abs(directory); err != nil {
		return err
	}
	for _, value := range []string{r.Binary, r.Config, r.Runtime} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("service paths must not contain control characters")
		}
	}
	if _, err := os.Lstat(linuxUnit); err == nil {
		return errors.New("proxyd.service already exists; refusing to replace it")
	} else if !os.IsNotExist(err) {
		return err
	}
	if entries, err := os.ReadDir(linuxUnit + ".d"); err == nil && len(entries) > 0 {
		return errors.New("existing proxyd.service drop-ins require explicit removal before automatic installation")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := core.Check(r.Config); err != nil {
		return err
	}
	cfg, err := config.Load(r.Config)
	if err != nil {
		return err
	}
	if cfg.Capture.Mode != "off" && cfg.Capture.Scope != "global" {
		return errors.New("automatic Linux capture service requires scope: global; use proxy run for isolated lab configurations")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for _, property := range []string{"FragmentPath", "DropInPaths"} {
		output, err := exec.CommandContext(ctx, "systemctl", "show", "--property="+property, "--value", "proxyd.service").Output()
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(output)) != "" {
			return errors.New("an existing proxyd systemd unit or drop-in must be removed explicitly before installation")
		}
	}
	account, err := user.Lookup("proxyd")
	if _, missing := err.(user.UnknownUserError); missing {
		if err := systemCommand(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "proxyd"); err != nil {
			return err
		}
		account, err = user.Lookup("proxyd")
	}
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil || uid == 0 {
		return errors.New("proxyd must be a dedicated non-root account")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	group, err := user.LookupGroup("proxyd")
	if err != nil || group.Gid != account.Gid {
		return errors.New("proxyd user must have primary group proxyd")
	}
	if err := systemCommand(ctx, "runuser", "--user", "proxyd", "--", r.Binary, "--config", r.Config, "config", "check"); err != nil {
		return fmt.Errorf("service account cannot execute proxy or read its configuration/data; use a service-readable installation directory: %w", err)
	}
	if err := prepareLinuxRuntime(r.Runtime, uid, gid); err != nil {
		return err
	}
	unit, err := os.OpenFile(linuxUnit, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, writeErr := unit.WriteString(renderLinuxUnit(r, cfg.Capture.Mode != "off"))
	closeErr := unit.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return errors.Join(err, os.Remove(linuxUnit))
	}
	if err := systemCommand(ctx, "systemd-analyze", "verify", linuxUnit); err != nil {
		return errors.Join(err, os.Remove(linuxUnit))
	}
	if err := systemCommand(ctx, "systemctl", "daemon-reload"); err != nil {
		return errors.Join(err, removeLinuxUnit(ctx))
	}
	if err := setLinuxAutostart(ctx, cfg.Service.Autostart); err != nil {
		return errors.Join(err, removeLinuxUnit(ctx))
	}
	return nil
}

func prepareLinuxRuntime(path string, uid, gid int) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("runtime must be a real private directory")
	}
	owner := info.Sys().(*syscall.Stat_t).Uid
	if owner != uint32(uid) {
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		if owner != 0 || len(entries) != 0 {
			return errors.New("runtime is owned by another account; select an empty dedicated runtime directory")
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, 0700)
}

func removeLinuxUnit(ctx context.Context) error {
	// Disable links before removing the owned unit. Keep configuration and data.
	if err := setLinuxAutostart(ctx, false); err != nil {
		return err
	}
	if err := os.Remove(linuxUnit); err != nil {
		return err
	}
	return systemCommand(ctx, "systemctl", "daemon-reload")
}

func Uninstall() error {
	if err := requireLinuxManager(); err != nil {
		return err
	}
	r, err := readLinuxRegistration()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := sameLinuxBinary(r, executable); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", "show", "--property=ActiveState", "--value", "proxyd.service").Output()
	if err != nil {
		return err
	}
	state := strings.TrimSpace(string(output))
	if state != "inactive" && state != "failed" {
		return errors.New("stop proxyd.service before uninstalling it")
	}
	return removeLinuxUnit(ctx)
}
