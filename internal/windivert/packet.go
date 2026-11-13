package windivert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

var errPacket = errors.New("unsupported or malformed diverted packet")
var errFragment = errors.New("fragment requires reassembly")
var errProtected = errors.New("IPsec protected packet")
var errOtherProtocol = errors.New("non TCP/UDP protocol")

type unsupportedHeader byte

func (h unsupportedHeader) Error() string { return fmt.Sprintf("unsupported IPv6 next-header %d", h) }

type networkPacket struct {
	data             []byte
	offset, previous int
	protocol         byte
	source, target   netip.Addr
}

func parseNetwork(data []byte) (networkPacket, error) {
	n := networkPacket{data: data}
	if len(data) < 20 {
		return n, errPacket
	}
	switch data[0] >> 4 {
	case 4:
		n.offset = int(data[0]&15) * 4
		size := int(binary.BigEndian.Uint16(data[2:]))
		if n.offset < 20 || size < n.offset || size > len(data) {
			return n, errPacket
		}
		n.data = data[:size]
		n.protocol = data[9]
		n.source = netip.AddrFrom4([4]byte(data[12:16]))
		n.target = netip.AddrFrom4([4]byte(data[16:20]))
		if n.protocol == 50 || n.protocol == 51 {
			return n, errProtected
		}
	case 6:
		if len(data) < 40 {
			return n, errPacket
		}
		size := 40 + int(binary.BigEndian.Uint16(data[4:]))
		if size > len(data) {
			return n, errPacket
		}
		n.data = data[:size]
		n.offset, n.previous, n.protocol = 40, 6, data[6]
		n.source = netip.AddrFrom16([16]byte(data[8:24]))
		n.target = netip.AddrFrom16([16]byte(data[24:40]))
		for count := 0; count < 32; count++ {
			switch n.protocol {
			case 0, 43, 60, 135, 139, 140:
				if n.offset+2 > size {
					return n, errPacket
				}
				length := (int(data[n.offset+1]) + 1) * 8
				if n.offset+length > size {
					return n, errPacket
				}
				if n.protocol == 43 && data[n.offset+3] != 0 {
					return n, errPacket
				}
				n.protocol, n.previous, n.offset = data[n.offset], n.offset, n.offset+length
			case 51, 50:
				return n, errProtected
			default:
				return n, nil
			}
		}
		return n, errPacket
	default:
		return n, errPacket
	}
	return n, nil
}

type packet struct {
	data           []byte
	offset         int
	payload        int
	protocol       byte
	source, target netip.AddrPort
}

func parsePacket(data []byte) (packet, error) {
	n, err := parseNetwork(data)
	p := packet{data: n.data, offset: n.offset, protocol: n.protocol}
	if err != nil {
		return p, err
	}
	if n.source.Is4() && binary.BigEndian.Uint16(data[6:])&0x3fff != 0 || n.protocol == 44 {
		return p, errFragment
	}
	return parseTransport(n)
}

func parseTransport(n networkPacket) (packet, error) {
	p := packet{data: n.data, offset: n.offset, protocol: n.protocol}
	size := len(p.data) - p.offset
	switch p.protocol {
	case 6:
		if size < 20 {
			return p, errPacket
		}
		header := int(p.data[p.offset+12]>>4) * 4
		if header < 20 || header > size {
			return p, errPacket
		}
		p.payload = p.offset + header
	case 17:
		if size < 8 || int(binary.BigEndian.Uint16(p.data[p.offset+4:])) != size {
			return p, errPacket
		}
		p.payload = p.offset + 8
	case 1, 2, 58, 59, 132:
		return p, errOtherProtocol
	default:
		if n.source.Is6() {
			return p, unsupportedHeader(p.protocol)
		}
		return p, errOtherProtocol
	}
	p.source = netip.AddrPortFrom(n.source, binary.BigEndian.Uint16(p.data[p.offset:]))
	p.target = netip.AddrPortFrom(n.target, binary.BigEndian.Uint16(p.data[p.offset+2:]))
	if p.source.Port() == 0 || p.target.Port() == 0 {
		return p, errPacket
	}
	return p, nil
}

func udpResponse(template []byte, source, target netip.AddrPort, payload []byte) ([]byte, error) {
	header := 20
	if source.Addr().Is6() {
		header = 40
	}
	if len(payload) > 65507 || len(template) < header {
		return nil, errPacket
	}
	data := make([]byte, header+8+len(payload))
	if header == 20 {
		data[0], data[1], data[8], data[9] = 0x45, template[1], 64, 17
		binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
	} else {
		data[0], data[1], data[6], data[7] = 0x60|template[0]&15, template[1]&0xf0, 17, 64
		binary.BigEndian.PutUint16(data[4:], uint16(len(data)-40))
	}
	p := packet{data: data, offset: header}
	p.rewrite(source, target)
	binary.BigEndian.PutUint16(data[header+4:], uint16(8+len(payload)))
	copy(data[header+8:], payload)
	return data, nil
}

func (p packet) rewrite(source, target netip.AddrPort) {
	if source.Addr().Is4() {
		copy(p.data[12:16], source.Addr().AsSlice())
		copy(p.data[16:20], target.Addr().AsSlice())
	} else {
		copy(p.data[8:24], source.Addr().AsSlice())
		copy(p.data[24:40], target.Addr().AsSlice())
	}
	binary.BigEndian.PutUint16(p.data[p.offset:], source.Port())
	binary.BigEndian.PutUint16(p.data[p.offset+2:], target.Port())
}

// rewriteTCPIncremental rewrites endpoints and incrementally updates IPv4/TCP checksums (RFC 1624).
// Returns true if checksums were updated in Go and WinDivertHelperCalcChecksums can be skipped.
func (p packet) rewriteTCPIncremental(source, target netip.AddrPort) bool {
	if p.protocol != 6 || len(p.data) < p.offset+20 {
		p.rewrite(source, target)
		return false
	}
	oldTCPCsum := binary.BigEndian.Uint16(p.data[p.offset+16:])
	if oldTCPCsum == 0 {
		p.rewrite(source, target)
		return false
	}
	is4 := source.Addr().Is4()
	var oldIPCsum uint16
	if is4 {
		if p.data[0] != 0x45 {
			p.rewrite(source, target)
			return false
		}
		oldIPCsum = binary.BigEndian.Uint16(p.data[10:12])
		if oldIPCsum == 0 {
			p.rewrite(source, target)
			return false
		}
	} else if p.offset != 40 {
		p.rewrite(source, target)
		return false
	}

	var ipDelta, tcpDelta uint32
	if is4 {
		ipSub := sumSub16(p.data[12:20])
		ipDelta += ipSub
		tcpDelta += ipSub
	} else {
		tcpDelta += sumSub16(p.data[8:40])
	}
	tcpDelta += sumSub16(p.data[p.offset : p.offset+4])

	p.rewrite(source, target)

	if is4 {
		ipAdd := sumAdd16(p.data[12:20])
		ipDelta += ipAdd
		tcpDelta += ipAdd
		binary.BigEndian.PutUint16(p.data[10:12], csumUpdate(oldIPCsum, ipDelta))
	} else {
		tcpDelta += sumAdd16(p.data[8:40])
	}
	tcpDelta += sumAdd16(p.data[p.offset : p.offset+4])
	binary.BigEndian.PutUint16(p.data[p.offset+16:], csumUpdate(oldTCPCsum, tcpDelta))
	return true
}

func sumSub16(b []byte) uint32 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(^binary.BigEndian.Uint16(b[i:]))
	}
	return s
}

func sumAdd16(b []byte) uint32 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	return s
}

func csumUpdate(old uint16, delta uint32) uint16 {
	sum := uint32(^old) + delta
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
