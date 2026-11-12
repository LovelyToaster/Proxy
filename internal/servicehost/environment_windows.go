package servicehost

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func InstallerPath(action, directory string) error {
	if !filepath.IsAbs(directory) || (action != "add" && action != "remove") {
		return errors.New("invalid installer PATH operation")
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	owner, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\ProxyTransparent`, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer owner.Close()
	value, _, err := key.GetStringValue("Path")
	if err != nil {
		return err
	}
	parts := strings.Split(value, ";")
	same := func(p string) bool {
		return strings.EqualFold(filepath.Clean(strings.Trim(strings.TrimSpace(p), `"`)), filepath.Clean(directory))
	}
	present := false
	for _, p := range parts {
		if same(p) {
			present = true
		}
	}
	if action == "add" {
		if !present {
			updated := directory
			if value != "" {
				updated = value + ";" + directory
			}
			if err := key.SetExpandStringValue("Path", updated); err != nil {
				return err
			}
			if err := owner.SetDWordValue("PathAdded", 1); err != nil {
				return err
			}
		}
	} else if added, _, _ := owner.GetIntegerValue("PathAdded"); added == 1 {
		kept := parts[:0]
		for _, p := range parts {
			if !same(p) {
				kept = append(kept, p)
			}
		}
		if err := key.SetExpandStringValue("Path", strings.Join(kept, ";")); err != nil {
			return err
		}
		owner.DeleteValue("PathAdded")
	}
	text, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW").Call(0xffff, 0x1a, 0, uintptr(unsafe.Pointer(text)), 2, 2000, uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(text)
	return nil
}
