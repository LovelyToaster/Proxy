package wfp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	deviceName     = `\\.\ProxyWfp`
	ioctlArm       = 0x22a000
	ioctlHeartbeat = 0x22a004
	ioctlDisarm    = 0x22a008
	ioctlReadUDP   = 0x22a00c
	ioctlReplyUDP  = 0x22a010
	ioctlUDPDrops  = 0x22a014
	// mstcpip.h and winsock2.h: _WSAIOR / _WSAIOW(IOC_VENDOR, ...).
	queryRecords = 0x580000dc
	queryContext = 0x580000dd
	setRecords   = 0x980000de
	maxRecords   = 64 << 10
)

type Guard struct {
	mu         sync.Mutex
	device     windows.Handle
	stop, done chan struct{}
	err        error
}

func Arm(application string, port uint16, targets []netip.AddrPort, udp, dns bool) (*Guard, error) {
	application = filepath.Clean(application)
	if !filepath.IsAbs(application) || !strings.HasSuffix(filepath.VolumeName(application), ":") ||
		!strings.EqualFold(filepath.Ext(application), ".exe") {
		return nil, errors.New("WFP application must be an absolute local .exe path")
	}
	app, err := os.Stat(application)
	if err != nil {
		return nil, err
	}
	if !app.Mode().IsRegular() {
		return nil, errors.New("WFP application must be a regular file")
	}
	current, err := os.Executable()
	if err != nil {
		return nil, err
	}
	self, err := os.Stat(current)
	if err != nil {
		return nil, err
	}
	if os.SameFile(app, self) {
		return nil, errors.New("WFP application must be separate from the proxy executable")
	}
	id, err := applicationID(application)
	if err != nil {
		return nil, err
	}
	data, err := registration(port, targets, id, udp, dns)
	if err != nil {
		return nil, err
	}

	path, err := windows.UTF16PtrFromString(deviceName)
	if err != nil {
		return nil, err
	}
	device, err := windows.CreateFile(path, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("open ProxyWfp device (driver must already be loaded): %w", err)
	}
	if err := control(device, ioctlArm, data); err != nil {
		windows.CloseHandle(device)
		return nil, fmt.Errorf("arm WFP capture: %w", err)
	}
	guard := &Guard{device: device, stop: make(chan struct{}), done: make(chan struct{})}
	go guard.renew()
	return guard, nil
}

func control(device windows.Handle, code uint32, input []byte) error {
	var returned uint32
	return windows.DeviceIoControl(device, code, &input[0], uint32(len(input)), nil, 0, &returned, nil)
}

func (g *Guard) renew() {
	defer close(g.done)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-g.stop:
			return
		case <-ticker.C:
			if err := control(g.device, ioctlHeartbeat, []byte{Version, 0, 0, 0}); err != nil {
				g.err = fmt.Errorf("WFP lease renewal: %w", err)
				return
			}
		}
	}
}

func (g *Guard) Done() <-chan struct{} { return g.done }

func (g *Guard) Close() error {
	close(g.stop)
	<-g.done
	g.mu.Lock()
	defer g.mu.Unlock()
	err := control(g.device, ioctlDisarm, []byte{Version, 0, 0, 0})
	closeErr := windows.CloseHandle(g.device)
	g.device = 0
	return errors.Join(g.err, err, closeErr)
}

func (g *Guard) packetIO(code uint32, input, output []byte) (uint32, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.device == 0 {
		return 0, net.ErrClosed
	}
	var n uint32
	err := windows.DeviceIoControl(g.device, code, unsafe.SliceData(input), uint32(len(input)),
		unsafe.SliceData(output), uint32(len(output)), &n, nil)
	return n, err
}

const udpHeader = 32

func (g *Guard) ReadPacket(payload []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	data := make([]byte, udpHeader+len(payload))
	for {
		n, err := g.packetIO(ioctlReadUDP, nil, data)
		if err != nil {
			return 0, netip.AddrPort{}, netip.AddrPort{}, err
		}
		if n != 0 {
			if n < udpHeader || n > uint32(len(data)) || binary.LittleEndian.Uint64(data) == 0 {
				return 0, netip.AddrPort{}, netip.AddrPort{}, errors.New("invalid WFP datagram result")
			}
			port := binary.LittleEndian.Uint32(data[12:])
			var target netip.Addr
			switch binary.LittleEndian.Uint32(data[8:]) {
			case 4:
				target = netip.AddrFrom4([4]byte(data[16:20]))
			case 6:
				target = netip.AddrFrom16([16]byte(data[16:32]))
			}
			if !target.IsLoopback() || port == 0 || port > 65535 {
				return 0, netip.AddrPort{}, netip.AddrPort{}, errors.New("invalid WFP datagram destination")
			}
			// Session identity comes from the driver flow cookie. This address stays in-process.
			peer := [16]byte{0xfd}
			copy(peer[8:], data[:8])
			return copy(payload, data[udpHeader:n]), netip.AddrPortFrom(netip.AddrFrom16(peer), 1),
				netip.AddrPortFrom(target, uint16(port)), nil
		}
		select {
		case <-g.stop:
			return 0, netip.AddrPort{}, netip.AddrPort{}, net.ErrClosed
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (g *Guard) ReplyPacket(peer netip.AddrPort, payload []byte) error {
	addr := peer.Addr().As16()
	data := make([]byte, 8+len(payload))
	copy(data, addr[8:])
	copy(data[8:], payload)
	_, err := g.packetIO(ioctlReplyUDP, data, nil)
	return err
}

func (g *Guard) UDPDrops() (uint64, error) {
	var data [8]byte
	n, err := g.packetIO(ioctlUDPDrops, nil, data[:])
	if err != nil {
		return 0, err
	}
	if n != uint32(len(data)) {
		return 0, errors.New("invalid WFP drop counter")
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

var (
	firewallDLL = windows.NewLazySystemDLL("fwpuclnt.dll")
	getAppID    = firewallDLL.NewProc("FwpmGetAppIdFromFileName0")
	freeMemory  = firewallDLL.NewProc("FwpmFreeMemory0")
)

func applicationID(path string) ([]byte, error) {
	type blob struct {
		Size uint32
		Data *byte
	}
	if err := getAppID.Find(); err != nil {
		return nil, err
	}
	if err := freeMemory.Find(); err != nil {
		return nil, err
	}
	input, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var value *blob
	result, _, _ := getAppID.Call(uintptr(unsafe.Pointer(input)), uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(input)
	if value != nil {
		defer func() { freeMemory.Call(uintptr(unsafe.Pointer(&value))) }()
	}
	if result != 0 {
		return nil, fmt.Errorf("resolve WFP application ID: %w", syscall.Errno(uint32(result)))
	}
	if value == nil || value.Data == nil || value.Size == 0 || value.Size > maxAppID {
		return nil, errors.New("invalid WFP application ID length")
	}
	return append([]byte(nil), unsafe.Slice(value.Data, value.Size)...), nil
}

func Destination(conn *net.TCPConn) (netip.AddrPort, error) {
	data, err := query(conn, queryContext, contextSize, contextSize)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("query WFP redirect context: %w", err)
	}
	return destination(data)
}

func PrepareDialer(conn *net.TCPConn, dialer net.Dialer) (net.Dialer, error) {
	records, err := query(conn, queryRecords, 4096, maxRecords)
	if err != nil {
		return dialer, err
	}
	oldControl, oldContext := dialer.Control, dialer.ControlContext
	dialer.ControlContext = func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if oldContext != nil {
			if err := oldContext(ctx, network, address, raw); err != nil {
				return err
			}
		} else if oldControl != nil {
			if err := oldControl(network, address, raw); err != nil {
				return err
			}
		}
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			var returned uint32
			socketErr = windows.WSAIoctl(windows.Handle(fd), setRecords, &records[0], uint32(len(records)), nil, 0, &returned, nil, 0)
		})
		return errors.Join(err, socketErr)
	}
	return dialer, nil
}

func query(conn *net.TCPConn, code uint32, initial, limit int) ([]byte, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	size := initial
	for {
		data := make([]byte, size)
		var returned uint32
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = windows.WSAIoctl(windows.Handle(fd), code, nil, 0, &data[0], uint32(len(data)), &returned, nil, 0)
		}); err != nil {
			return nil, err
		}
		if errors.Is(socketErr, windows.ERROR_INSUFFICIENT_BUFFER) && returned > uint32(size) && returned <= uint32(limit) {
			size = int(returned)
			continue
		}
		if socketErr != nil {
			return nil, socketErr
		}
		if returned == 0 || returned > uint32(size) {
			return nil, errors.New("invalid WFP socket result length")
		}
		return data[:returned], nil
	}
}
