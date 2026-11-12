package servicehost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func SimpleControl(ctx context.Context, operation, path, directory string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	service, err := manager.OpenService(serviceName)
	exists := err == nil
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		manager.Disconnect()
		return err
	}
	if exists {
		settings, err := service.Config()
		service.Close()
		manager.Disconnect()
		if err != nil {
			return err
		}
		args, err := windows.DecomposeCommandLine(settings.BinaryPathName)
		if err != nil {
			return err
		}
		if len(args) == 0 || !strings.EqualFold(filepath.Clean(args[0]), filepath.Clean(executable)) {
			return errors.New("ProxyD belongs to a different executable; use the installed proxy command")
		}
	} else {
		manager.Disconnect()
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
		return Control(ctx, "start")
	}
	return Control(ctx, operation)
}
