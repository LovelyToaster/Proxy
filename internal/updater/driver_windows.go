//go:build windows

package updater

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"proxy.local/m0/internal/servicehost"
)

const (
	proxyServiceName     = "ProxyD"
	winDivertServiceName = "WinDivert"
	uninstallRegPath     = `Software\Microsoft\Windows\CurrentVersion\Uninstall\ProxyTransparent`
)

type windowsOps interface {
	isElevated() bool
	isServiceRunning() (bool, error)
	stopService(ctx context.Context) error
	startService(ctx context.Context) error
	unloadWinDivert(ctx context.Context) error
	updateUninstallVersion(version string)
}

type realWindowsOps struct{}

func (realWindowsOps) isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func (realWindowsOps) isServiceRunning() (bool, error) {
	scm, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(proxyServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, err
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running || st.State == svc.StartPending, nil
}

func (realWindowsOps) stopService(ctx context.Context) error {
	return servicehost.Control(ctx, "stop")
}

func (realWindowsOps) startService(ctx context.Context) error {
	return servicehost.Control(ctx, "start")
}

func (realWindowsOps) unloadWinDivert(ctx context.Context) error {
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM to unload WinDivert: %w", err)
	}
	defer scm.Disconnect()

	s, err := scm.OpenService(winDivertServiceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return fmt.Errorf("open WinDivert service: %w", err)
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("query WinDivert service: %w", err)
	}
	if st.State != svc.Stopped {
		if st.State != svc.StopPending {
			if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
				return fmt.Errorf("stop WinDivert driver service: %w", err)
			}
		}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			st, err = s.Query()
			if err != nil {
				break
			}
			if st.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		if st.State != svc.Stopped {
			return errors.New("timed out waiting for WinDivert driver to stop (another process may still hold a handle)")
		}
	}

	if err := s.Delete(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return fmt.Errorf("delete WinDivert driver service: %w", err)
	}
	// Give Windows kernel a short moment to release the WinDivert64.sys file handle.
	time.Sleep(500 * time.Millisecond)
	return nil
}

func (realWindowsOps) updateUninstallVersion(version string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallRegPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return
	}
	defer key.Close()
	_ = key.SetStringValue("DisplayVersion", strings.TrimPrefix(version, "v"))
}

func moveFileReplace(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
