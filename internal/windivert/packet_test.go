package windivert

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"proxy.local/m0/internal/config"
)

func TestPacketRewriteAndBounds(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		header := 20
		source, target := netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.2:19090")
		if ipv6 {
			header = 40
			source = netip.MustParseAddrPort("[::1]:40000")
			target = netip.MustParseAddrPort("[::1]:19090")
		}
		data := make([]byte, header+11)
		if ipv6 {
			data[0], data[6] = 0x60, 17
			binary.BigEndian.PutUint16(data[4:], 11)
		} else {
			data[0], data[9] = 0x45, 17
			binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
		}
		binary.BigEndian.PutUint16(data[header:], source.Port())
		binary.BigEndian.PutUint16(data[header+2:], target.Port())
		binary.BigEndian.PutUint16(data[header+4:], 11)
		copy(data[header+8:], "abc")
		p, err := parsePacket(data)
		if err != nil {
			t.Fatal(err)
		}
		p.rewrite(source, target)
		p, err = parsePacket(data)
		if err != nil || p.source != source || p.target != target || string(p.data[p.payload:]) != "abc" {
			t.Fatalf("decode: %+v, %v", p, err)
		}
		p.rewrite(target, source)
		p, err = parsePacket(data)
		if err != nil || p.source != target || p.target != source {
			t.Fatalf("reverse: %+v, %v", p, err)
		}
		if _, err := parsePacket(data[:len(data)-1]); err == nil {
			t.Fatal("truncated packet accepted")
		}
		if ipv6 {
			data[6] = 44
		} else {
			data[6] = 0x20
		}
		if _, err := parsePacket(data); err == nil {
			t.Fatal("unsupported fragment accepted")
		}
	}
}

func TestApplicationFilterAndReturnDirection(t *testing.T) {
	c := config.Capture{Mode: "windivert", Scope: "application", IPv4: true, IPv6: true, Port: 15090, UDP: true, DNSHijack: true}
	filter := captureFilter(c)
	if strings.Contains(filter, "outbound and loopback") || !strings.Contains(filter, "udp.DstPort == 53") ||
		!strings.Contains(filter, "tcp.SrcPort == 15090") {
		t.Fatal(filter)
	}
	c.CIDRs = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	filter = captureFilter(c)
	if !strings.Contains(filter, "ip.DstAddr >= 192.0.2.0 and ip.DstAddr <= 192.0.2.255") {
		t.Fatal(filter)
	}
	address := [10]uint64{}
	address[1] = 1 << 17
	address[2] = 123
	inbound := returnAddress(address)
	if inbound[1]&(1<<17) != 0 || inbound[2] != 123 {
		t.Fatal("external return direction or interface incorrect")
	}
	address[1] |= 1 << 18
	if returnAddress(address) != address {
		t.Fatal("loopback direction changed")
	}
}
