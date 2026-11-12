package windivert

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var tcpTable = ipHelper.NewProc("GetExtendedTcpTable")
var udpTable = ipHelper.NewProc("GetExtendedUdpTable")

// Verify endpoint ownership at capture time. Ambiguous or unavailable ownership is bypassed.
func ownedBy(p packet, application string) bool {
	pid := endpointPID(p)
	return pid != 0 && pid != windows.GetCurrentProcessId() && strings.EqualFold(processPath(pid), filepath.Clean(application))
}

func endpointPID(p packet) uint32 {
	p.source = netip.AddrPortFrom(p.source.Addr().Unmap(), p.source.Port())
	if p.target.IsValid() {
		p.target = netip.AddrPortFrom(p.target.Addr().Unmap(), p.target.Port())
	}
	proc, class, rowSize := tcpTable, uintptr(5), 24
	localAddr, localPort, remoteAddr, remotePort, owner := 4, 8, 12, 16, 20
	stateOffset := 0
	family := uintptr(windows.AF_INET)
	if p.source.Addr().Is6() {
		family, rowSize = windows.AF_INET6, 56
		localAddr, localPort, remoteAddr, remotePort, owner = 0, 20, 24, 44, 52
		stateOffset = 48
	}
	if p.protocol == 17 {
		proc, class = udpTable, 1
		localAddr, localPort, owner, rowSize = 0, 4, 8, 12
		if family == windows.AF_INET6 {
			localPort, owner, rowSize = 20, 24, 28
		}
	}
	var size uint32 = 16 << 10
	var data []byte
	for attempt := 0; attempt < 3; attempt++ {
		if size < 4 || size > 8<<20 {
			return 0
		}
		data = make([]byte, size)
		result, _, _ := proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if result == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if result != 0 || size < 4 || size > uint32(len(data)) {
			return 0
		}
		data = data[:size]
		break
	}
	if len(data) < 4 {
		return 0
	}
	count := binary.LittleEndian.Uint32(data)
	if uint64(count)*uint64(rowSize)+4 > uint64(len(data)) {
		return 0
	}
	var pid uint32
	for i := 0; i < int(count); i++ {
		row := data[4+i*rowSize : 4+(i+1)*rowSize]
		if binary.BigEndian.Uint16(row[localPort:]) != p.source.Port() {
			continue
		}
		local := tableAddress(row[localAddr:], family)
		if local != p.source.Addr() && !((p.protocol == 17 || !p.target.IsValid()) && local.IsUnspecified()) {
			continue
		}
		if p.protocol == 6 && !p.target.IsValid() {
			state := binary.LittleEndian.Uint32(row[stateOffset:])
			// Some network providers report state zero for a bound listener.
			// Only accept it when the remote endpoint is entirely unspecified.
			if state != 2 && !(state == 0 && binary.BigEndian.Uint16(row[remotePort:]) == 0 && tableAddress(row[remoteAddr:], family).IsUnspecified()) {
				continue
			}
		}
		if p.protocol == 6 && p.target.IsValid() && (binary.BigEndian.Uint16(row[remotePort:]) != p.target.Port() ||
			tableAddress(row[remoteAddr:], family) != p.target.Addr()) {
			continue
		}
		candidate := binary.LittleEndian.Uint32(row[owner:])
		if candidate == 0 || pid != 0 && candidate != pid {
			return 0
		}
		pid = candidate
	}
	return pid
}

func processPath(pid uint32) string {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(process)
	var path [32768]uint16
	length := uint32(len(path))
	if windows.QueryFullProcessImageName(process, 0, &path[0], &length) != nil {
		return ""
	}
	return filepath.Clean(windows.UTF16ToString(path[:length]))
}

func tableAddress(data []byte, family uintptr) netip.Addr {
	if family == windows.AF_INET {
		return netip.AddrFrom4([4]byte(data[:4]))
	}
	return netip.AddrFrom16([16]byte(data[:16]))
}
