package servicehost

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"proxy.local/m0/internal/config"
	"strconv"
	"syscall"
)

func captureFirewall(executable string, cfg config.Config) error {
	if cfg.Capture.Mode != "windivert" {
		return nil
	}
	run := func(args ...string) error {
		command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe"), args...)
		command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("configure capture firewall: %w: %s", err, output)
		}
		return nil
	}
	// Scope to our executable, TCP and the actual redirect port; UDP replies are
	// injected directly and need no inbound socket exception.
	if err := run("advfirewall", "firewall", "delete", "rule", "name=ProxyTransparent-Capture", "program="+executable); err != nil {
		// netsh reports no matching rule as failure on first installation.
	}
	return run("advfirewall", "firewall", "add", "rule", "name=ProxyTransparent-Capture", "dir=in", "action=allow", "enable=yes", "profile=any", "program="+executable, "protocol=TCP", "localport="+strconv.Itoa(int(cfg.Capture.Port)))
}

func removeCaptureFirewall(executable string) error {
	// An empty match is success; permission/query failures must remain visible.
	script := `$ErrorActionPreference='Stop'; Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.DisplayName -eq 'ProxyTransparent-Capture' } | Get-NetFirewallApplicationFilter | Where-Object { $_.Program -eq $env:PROXY_FIREWALL_PROGRAM } | Get-NetFirewallRule | Remove-NetFirewallRule`
	command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	command.Env = append(os.Environ(), "PROXY_FIREWALL_PROGRAM="+executable)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("remove capture firewall: %w: %s", err, output)
	}
	return nil
}
