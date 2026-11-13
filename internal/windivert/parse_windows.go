package windivert

import (
	"runtime"
	"unsafe"
)

// WinDivert owns extension-header discovery. Go handles standard non-extended packets directly.
func (l *library) parseTransportPacket(data []byte) (packet, error) {
	n, err := parseNetwork(data)
	if err != nil {
		return packet{data: data}, err
	}
	if n.source.Is4() && n.data[6]&0x3f != 0 || n.source.Is4() && n.data[7] != 0 || n.protocol == 44 {
		return packet{}, errFragment
	}
	// Fast path: standard IPv4 or IPv6 without extension headers directly carrying TCP/UDP.
	if (n.protocol == 6 || n.protocol == 17) && (n.source.Is4() || n.offset == 40) {
		return parseTransport(n)
	}
	var tcp, udp uintptr
	protocol := n.protocol
	base := uintptr(unsafe.Pointer(&n.data[0]))
	ok, _, _ := l.parse.Call(base, uintptr(len(n.data)), 0, 0, uintptr(unsafe.Pointer(&protocol)), 0, 0,
		uintptr(unsafe.Pointer(&tcp)), uintptr(unsafe.Pointer(&udp)), 0, 0, 0, 0)
	runtime.KeepAlive(n.data)
	if ok == 0 {
		return packet{}, errPacket
	}
	if tcp != 0 && udp != 0 {
		return packet{}, errPacket
	}
	location := tcp
	if tcp != 0 {
		n.protocol = 6
	} else if udp != 0 {
		location = udp
		n.protocol = 17
	} else {
		n.protocol = protocol
		return parseTransport(n)
	}
	if location < base || location-base > uintptr(len(n.data)) {
		return packet{}, errPacket
	}
	n.offset = int(location - base)
	return parseTransport(n)
}
