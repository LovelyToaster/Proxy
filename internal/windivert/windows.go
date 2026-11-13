//go:build windows

package windivert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	layerNetwork  = 0
	layerReflect  = 4
	flagSniff     = 1
	flagRecvOnly  = 4
	flagNoInstall = 16
)

type library struct {
	dll                                             *windows.DLL
	open, close, recv, shutdown, getParam, setParam *windows.Proc
	send, checksums                                 *windows.Proc
	parse                                           *windows.Proc
	recvEx, sendEx                                  *windows.Proc
}

func load() (*library, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(filepath.Dir(exe), "WinDivert.dll")
	if runtime.GOARCH != "amd64" {
		return nil, path, errors.New("WinDivert runtime currently supports Windows x64")
	}
	// Load only the runtime placed alongside our executable.
	dll, err := windows.LoadDLL(path)
	if err != nil {
		return nil, path, fmt.Errorf("load official x64 WinDivert.dll beside proxy.exe: %w", err)
	}
	lib := &library{dll: dll}
	for _, proc := range []struct {
		name   string
		target **windows.Proc
	}{
		{"WinDivertOpen", &lib.open}, {"WinDivertClose", &lib.close},
		{"WinDivertRecv", &lib.recv}, {"WinDivertShutdown", &lib.shutdown},
		{"WinDivertGetParam", &lib.getParam}, {"WinDivertSetParam", &lib.setParam},
		{"WinDivertSend", &lib.send}, {"WinDivertHelperCalcChecksums", &lib.checksums},
		{"WinDivertRecvEx", &lib.recvEx}, {"WinDivertSendEx", &lib.sendEx},
		{"WinDivertHelperParsePacket", &lib.parse},
	} {
		*proc.target, err = dll.FindProc(proc.name)
		if err != nil {
			dll.Release()
			return nil, path, err
		}
	}
	return lib, path, nil
}

func (l *library) openHandle(filter string, layer, flags uintptr) (uintptr, error) {
	text, err := windows.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	handle, _, callErr := l.open.Call(uintptr(unsafe.Pointer(text)), layer, 0, flags)
	runtime.KeepAlive(text)
	if handle == ^uintptr(0) {
		return 0, fmt.Errorf("WinDivertOpen (administrator privileges required): %w", callErr)
	}
	return handle, nil
}

func (l *library) tuneHandle(handle uintptr) {
	// 0 = WINDIVERT_PARAM_QUEUE_LENGTH, 1 = WINDIVERT_PARAM_QUEUE_TIME, 2 = WINDIVERT_PARAM_QUEUE_SIZE
	_, _, _ = l.setParam.Call(handle, 0, 16384)
	_, _, _ = l.setParam.Call(handle, 1, 4000)
	_, _, _ = l.setParam.Call(handle, 2, 16<<20)
}

func (l *library) closeHandle(handle uintptr) error {
	ok, _, err := l.close.Call(handle)
	if ok == 0 {
		return fmt.Errorf("WinDivertClose: %w", err)
	}
	return nil
}

func Inspect() (result Status, err error) {
	result.Backend = "windivert"
	lib, path, err := load()
	result.DLL = path
	if err != nil {
		return result, err
	}
	defer lib.dll.Release()
	handle, err := lib.openHandle("false", layerReflect, flagSniff|flagRecvOnly|flagNoInstall)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, lib.closeHandle(handle)) }()
	var major, minor uint64
	for _, param := range []struct {
		id    uintptr
		value *uint64
	}{{3, &major}, {4, &minor}} {
		ok, _, callErr := lib.getParam.Call(handle, param.id, uintptr(unsafe.Pointer(param.value)))
		if ok == 0 {
			return result, fmt.Errorf("WinDivertGetParam: %w", callErr)
		}
	}
	if major != 2 {
		return result, fmt.Errorf("unsupported WinDivert API major version %d", major)
	}
	result.DriverLoaded = true
	result.Version = fmt.Sprintf("%d.%d", major, minor)
	return result, nil
}

// Sniff only receives copies. Opening this explicit command may install the supplied driver.
func Sniff(ctx context.Context, filter string, ready func()) (counts Counts, err error) {
	if err := ctx.Err(); err != nil {
		return counts, err
	}
	lib, _, err := load()
	if err != nil {
		return counts, err
	}
	defer lib.dll.Release()
	handle, err := lib.openHandle(filter, layerNetwork, flagSniff|flagRecvOnly)
	if err != nil {
		return counts, err
	}
	defer func() { err = errors.Join(err, lib.closeHandle(handle)) }()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		ok, _, _ := lib.shutdown.Call(handle, 1) // WINDIVERT_SHUTDOWN_RECV
		if ok == 0 {
			windows.CancelIoEx(windows.Handle(handle), nil)
		}
	})
	defer func() {
		if !stop() {
			<-done
		}
	}()
	packet := make([]byte, 65575)
	// WINDIVERT_ADDRESS is an 80-byte structure aligned to 8 bytes.
	var address [10]uint64
	if ready != nil {
		ready()
	}
	for ctx.Err() == nil {
		var size uint32
		ok, _, callErr := lib.recv.Call(handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)),
			uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&address[0])))
		if ok == 0 {
			if ctx.Err() != nil {
				return counts, nil
			}
			return counts, fmt.Errorf("WinDivertRecv: %w", callErr)
		}
		if size == 0 || size > uint32(len(packet)) {
			return counts, errors.New("invalid WinDivert packet length")
		}
		counts.Packets++
		counts.Bytes += uint64(size)
		switch packet[0] >> 4 {
		case 4:
			counts.IPv4++
		case 6:
			counts.IPv6++
		}
	}
	return counts, nil
}
