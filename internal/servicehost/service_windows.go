package servicehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"proxy.local/m0/internal/config"
	"proxy.local/m0/internal/core"
	"proxy.local/m0/internal/logging"
)

const serviceName = "ProxyD"

func Run(ctx context.Context, path, runtime string) error {
	service, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !service {
		return core.Serve(ctx, path, runtime)
	}
	return svc.Run(serviceName, handler{parent: ctx, path: path, runtime: runtime, apply: func(enabled bool) error {
		operation := "disable"
		if enabled {
			operation = "enable"
		}
		return Control(ctx, operation)
	}})
}

type handler struct {
	apply         func(bool) error
	parent        context.Context
	path, runtime string
}

func (h handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	current := svc.Status{State: svc.StartPending, WaitHint: 15000, CheckPoint: 1}
	status <- current
	go func() {
		done <- core.ServeReadyManaged(ctx, h.path, h.runtime, func() { close(ready) }, h.apply)
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ready:
			ready = nil
			if current.State == svc.StartPending {
				current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				status <- current
			}
		case request, open := <-requests:
			if !open {
				requests = nil
				cancel()
				continue
			}
			switch request.Cmd {
			case svc.Interrogate:
				status <- current
			case svc.Stop, svc.Shutdown:
				current = svc.Status{State: svc.StopPending, WaitHint: 30000, CheckPoint: 1}
				status <- current
				cancel()
			}
		case <-ticker.C:
			if current.State == svc.StartPending || current.State == svc.StopPending {
				current.CheckPoint++
				status <- current
			}
		case err := <-done:
			if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
				logging.Errorf("Windows service: %v", err)
				return true, 1
			}
			return false, 0
		}
	}
}

func Install(executable, path, runtime string, automatic bool) error {
	var err error
	if executable, err = filepath.Abs(executable); err != nil {
		return err
	}
	if path, err = filepath.Abs(path); err != nil {
		return err
	}
	if runtime, err = filepath.Abs(runtime); err != nil {
		return err
	}
	if info, err := os.Stat(executable); err != nil || !info.Mode().IsRegular() {
		return errors.New("service binary must be a regular file")
	}
	if !filepath.IsAbs(runtime) {
		return errors.New("runtime must be absolute")
	}
	if err := core.Check(path); err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	scm, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	options := mgr.Config{
		StartType: mgr.StartManual, ErrorControl: mgr.ErrorNormal, DisplayName: "ProxyD",
		Description: "Proxy TCP/UDP and DNS service", ServiceStartName: "NT AUTHORITY\\LocalService",
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	if cfg.Capture.Mode == "windivert" {
		// WinDivert requires an elevated token to open/install its driver.
		options.ServiceStartName = "LocalSystem"
	}
	if cfg.Service.Autostart {
		options.StartType = mgr.StartAutomatic
		options.DelayedAutoStart = true
	}
	service, err := scm.CreateService(serviceName, executable, options, "--service-run", "--config", path, "--runtime", runtime)
	if err != nil {
		return err
	}
	defer service.Close()
	if err := captureFirewall(executable, cfg); err != nil {
		return errors.Join(err, service.Delete())
	}
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.NoAction},
	}, 60); err != nil {
		return errors.Join(err, service.Delete())
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return errors.Join(err, service.Delete())
	}
	return nil
}

func Uninstall() error {
	scm, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	service, err := scm.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		return errors.New("stop ProxyD before uninstalling it")
	}
	settings, err := service.Config()
	if err != nil {
		return err
	}
	args, err := windows.DecomposeCommandLine(settings.BinaryPathName)
	if err != nil {
		return err
	}
	if len(args) > 0 {
		if err := removeCaptureFirewall(args[0]); err != nil {
			return err
		}
	}
	return service.Delete()
}

func Control(ctx context.Context, operation string) error {
	scm, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	service, err := scm.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if operation == "status" {
		fmt.Printf("ProxyD SCM state: %s\n", stateName(status.State))
		return nil
	}
	switch operation {
	case "enable", "disable":
		cfg, err := service.Config()
		if err != nil {
			return err
		}
		cfg.StartType = mgr.StartManual
		cfg.DelayedAutoStart = false
		if operation == "enable" {
			cfg.StartType = mgr.StartAutomatic
			cfg.DelayedAutoStart = true
		}
		return service.UpdateConfig(cfg)
	case "start", "stop", "restart":
	default:
		return fmt.Errorf("unsupported SCM operation %q", operation)
	}
	if operation != "start" && status.State != svc.Stopped {
		if status.State != svc.StopPending {
			if _, err := service.Control(svc.Stop); err != nil {
				return err
			}
		}
		if err := waitState(ctx, service, svc.Stopped); err != nil {
			return err
		}
		status.State = svc.Stopped
	}
	if operation == "start" || operation == "restart" {
		settings, err := service.Config()
		if err != nil {
			return err
		}
		args, err := windows.DecomposeCommandLine(settings.BinaryPathName)
		if err != nil {
			return err
		}
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "--config" {
				cfg, err := config.Load(args[i+1])
				if err != nil {
					return err
				}
				if err := captureFirewall(args[0], cfg); err != nil {
					return err
				}
				break
			}
		}
	}
	if operation == "stop" || status.State == svc.Running {
		return nil
	}
	if status.State != svc.StartPending {
		if err := service.Start(); err != nil {
			return err
		}
	}
	return waitState(ctx, service, svc.Running)
}

func stateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	default:
		return fmt.Sprint(state)
	}
}

func waitState(ctx context.Context, service *mgr.Service, target svc.State) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == target {
			return nil
		}
		if target == svc.Running && status.State == svc.Stopped {
			return fmt.Errorf("service stopped during start (exit=%d, specific=%d)", status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
