package wfp

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	Version          = 2
	registrationSize = 48
	contextSize      = 36
	maxAppID         = 8192
	contextMagic     = 0x31504657 // WFP1
)

func registration(port uint16, targets []netip.AddrPort, appID []byte, udp, dns bool) ([]byte, error) {
	if port < 1024 || len(targets) == 0 || len(targets) > 2 || len(appID) < 2 || len(appID) > maxAppID || len(appID)%2 != 0 {
		return nil, errors.New("invalid WFP registration")
	}
	data := make([]byte, registrationSize+len(appID))
	binary.LittleEndian.PutUint32(data, Version)
	binary.LittleEndian.PutUint32(data[4:], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[8:], uint32(port))
	targetPort := targets[0].Port()
	if targetPort == 0 && (!dns || udp) {
		return nil, errors.New("WFP target port is required")
	}
	binary.LittleEndian.PutUint32(data[16:], uint32(targetPort))
	binary.LittleEndian.PutUint32(data[20:], uint32(len(appID)))
	var flags uint32
	if udp {
		flags |= 1
	}
	if dns {
		flags |= 2
	}
	binary.LittleEndian.PutUint32(data[44:], flags)
	var families uint32
	for _, target := range targets {
		ip := target.Addr()
		if !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" || target.Port() != targetPort ||
			targetPort != 0 && targetPort < 1024 || targetPort == port || flags != 0 && !ip.IsLoopback() {
			return nil, errors.New("invalid WFP target")
		}
		flag := uint32(1)
		if ip.Is4() {
			copy(data[24:28], ip.AsSlice())
		} else {
			flag = 2
			copy(data[28:44], ip.AsSlice())
		}
		if families&flag != 0 {
			return nil, errors.New("duplicate WFP target family")
		}
		families |= flag
	}
	binary.LittleEndian.PutUint32(data[12:], families)
	copy(data[registrationSize:], appID)
	return data, nil
}

func destination(data []byte) (netip.AddrPort, error) {
	if len(data) != contextSize || binary.LittleEndian.Uint32(data) != contextMagic ||
		binary.LittleEndian.Uint32(data[4:]) != contextSize {
		return netip.AddrPort{}, errors.New("unrecognized WFP redirect context")
	}
	family, port, scope := binary.LittleEndian.Uint32(data[8:]), binary.LittleEndian.Uint32(data[12:]), binary.LittleEndian.Uint32(data[16:])
	if port != 53 && port < 1024 || port > 65535 || scope != 0 {
		return netip.AddrPort{}, errors.New("invalid WFP redirect endpoint")
	}
	var ip netip.Addr
	switch family {
	case 4:
		ip = netip.AddrFrom4([4]byte(data[20:24]))
	case 6:
		ip = netip.AddrFrom16([16]byte(data[20:36]))
	default:
		return netip.AddrPort{}, errors.New("unknown WFP address family")
	}
	if ip.Is4In6() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return netip.AddrPort{}, errors.New("invalid WFP destination address")
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
