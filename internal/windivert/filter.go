package windivert

import (
	"fmt"
	"net/netip"
	"strings"

	"proxy.local/m0/internal/config"
)

func captureFilter(c config.Capture) string {
	var targets []string
	for _, prefix := range c.CIDRs {
		field := "ip.DstAddr"
		if prefix.Addr().Is6() {
			field = "ipv6.DstAddr"
		}
		last := append([]byte(nil), prefix.Addr().AsSlice()...)
		for bit := prefix.Bits(); bit < prefix.Addr().BitLen(); bit++ {
			last[bit/8] |= 1 << (7 - bit%8)
		}
		end, _ := netip.AddrFromSlice(last)
		targets = append(targets, fmt.Sprintf("(%s >= %s and %s <= %s)", field, prefix.Addr(), field, end))
	}
	if len(targets) == 0 {
		if c.IPv4 {
			targets = append(targets, "ip")
		}
		if c.IPv6 {
			targets = append(targets, "ipv6")
		}
	}
	var tcpPorts, udpPorts []string
	for _, port := range c.Ports {
		tcpPorts = append(tcpPorts, fmt.Sprintf("tcp.DstPort == %d", port))
		if c.UDP {
			udpPorts = append(udpPorts, fmt.Sprintf("udp.DstPort == %d", port))
		}
	}
	if len(c.Ports) == 0 && (c.Scope == "application" || c.Scope == "global") {
		tcpPorts = append(tcpPorts, fmt.Sprintf("(tcp.DstPort != 53 and tcp.DstPort != %d)", c.Port))
		if c.UDP {
			udpPorts = append(udpPorts, fmt.Sprintf("(udp.DstPort != 53 and udp.DstPort != %d)", c.Port))
		}
	}
	if c.DNSHijack {
		tcpPorts = append(tcpPorts, "tcp.DstPort == 53")
		udpPorts = append(udpPorts, "udp.DstPort == 53")
	}
	transport := "(tcp and (" + strings.Join(tcpPorts, " or ") + "))"
	if len(udpPorts) > 0 {
		transport += " or (udp and (" + strings.Join(udpPorts, " or ") + "))"
	}
	direction := "outbound and loopback"
	reply := "loopback and tcp"
	if c.Scope == "application" || c.Scope == "global" {
		direction = "outbound and !impostor"
		reply = "tcp"
	}
	if c.Scope == "global" {
		transport += " or ipv6"
	}
	return fmt.Sprintf("%s and ((%s and tcp.SrcPort == %d) or ((%s) and (fragment or %s)))",
		direction, reply, c.Port, strings.Join(targets, " or "), transport)
}

// Preserve the original interface, using the inbound path for non-local peers.
func returnAddress(original [10]uint64) [10]uint64 {
	if original[1]&(1<<18) == 0 {
		original[1] &^= 1 << 17
	}
	return original
}
