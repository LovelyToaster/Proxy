package linuxsocket

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	ipTransparent           = 19
	ipv6Transparent         = 75
	ipOriginalDestination   = 20
	ipv6OriginalDestination = 74
	soOriginalDestination   = 80
)

func MarkedDialer(mark int) net.Dialer {
	return net.Dialer{Control: socketControl(func(fd int, _ bool) error {
		return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	})}
}

func socketControl(apply func(int, bool) error) func(string, string, syscall.RawConn) error {
	return func(network, _ string, raw syscall.RawConn) error {
		var optionErr error
		err := raw.Control(func(fd uintptr) { optionErr = apply(int(fd), network[len(network)-1] == '6') })
		return errors.Join(err, optionErr)
	}
}

func TransparentControl(originalDestination bool, mark int) func(string, string, syscall.RawConn) error {
	return socketControl(func(fd int, ipv6 bool) error {
		level, transparent, original := syscall.IPPROTO_IP, ipTransparent, ipOriginalDestination
		if ipv6 {
			level, transparent, original = syscall.IPPROTO_IPV6, ipv6Transparent, ipv6OriginalDestination
		}
		if err := syscall.SetsockoptInt(fd, level, transparent, 1); err != nil {
			return err
		}
		if originalDestination {
			return syscall.SetsockoptInt(fd, level, original, 1)
		}
		if mark != 0 {
			return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		}
		return nil
	})
}

func RedirectTarget(conn *net.TCPConn, network string) (netip.AddrPort, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	ipv6 := network == "tcp6"
	level := uintptr(syscall.IPPROTO_IP)
	if ipv6 {
		level = syscall.IPPROTO_IPV6
	}
	var addr [28]byte
	length := uint32(len(addr))
	var sockErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		_, _, sockErr = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, level, soOriginalDestination,
			uintptr(unsafe.Pointer(&addr[0])), uintptr(unsafe.Pointer(&length)), 0)
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if sockErr != 0 {
		return netip.AddrPort{}, sockErr
	}
	if length > uint32(len(addr)) {
		return netip.AddrPort{}, errors.New("oversized original destination")
	}
	return DecodeDestination(addr[:length], ipv6)
}

func DecodeDestination(data []byte, ipv6 bool) (netip.AddrPort, error) {
	if ipv6 && len(data) >= 28 && binary.NativeEndian.Uint16(data) == syscall.AF_INET6 {
		addr := netip.AddrFrom16([16]byte(data[8:24]))
		if scope := binary.NativeEndian.Uint32(data[24:]); scope != 0 {
			addr = addr.WithZone(strconv.FormatUint(uint64(scope), 10))
		}
		return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(data[2:])), nil
	}
	if !ipv6 && len(data) >= 16 && binary.NativeEndian.Uint16(data) == syscall.AF_INET {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[4:8])), binary.BigEndian.Uint16(data[2:])), nil
	}
	return netip.AddrPort{}, errors.New("invalid original destination sockaddr")
}

func OriginalUDP(control []byte, ipv6 bool) (netip.AddrPort, error) {
	messages, err := syscall.ParseSocketControlMessage(control)
	if err != nil {
		return netip.AddrPort{}, err
	}
	level, kind := int32(syscall.IPPROTO_IP), int32(ipOriginalDestination)
	if ipv6 {
		level, kind = syscall.IPPROTO_IPV6, ipv6OriginalDestination
	}
	for _, message := range messages {
		if message.Header.Level == level && message.Header.Type == kind {
			return DecodeDestination(message.Data, ipv6)
		}
	}
	return netip.AddrPort{}, errors.New("missing UDP original destination")
}
