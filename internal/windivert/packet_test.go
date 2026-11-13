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

func BenchmarkParseAndRewrite(b *testing.B) {
	data := make([]byte, 40)
	data[0], data[9] = 0x45, 6
	binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
	copy(data[12:16], netip.MustParseAddr("127.0.0.1").AsSlice())
	copy(data[16:20], netip.MustParseAddr("198.18.0.1").AsSlice())
	binary.BigEndian.PutUint16(data[20:], 40000)
	binary.BigEndian.PutUint16(data[22:], 443)
	data[32] = 0x50
	src := netip.MustParseAddrPort("127.0.0.1:50000")
	dst := netip.MustParseAddrPort("127.0.0.1:15090")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		p, err := parsePacket(data)
		if err != nil {
			b.Fatal(err)
		}
		p.rewrite(src, dst)
	}
}

func fullIPv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i < len(hdr); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func fullTCPChecksum(pkt []byte, offset int, ipv6 bool) uint16 {
	var sum uint32
	if ipv6 {
		for i := 8; i < 40; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
		}
		sum += uint32(len(pkt) - offset)
		sum += 6
	} else {
		for i := 12; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(pkt[i:]))
		}
		sum += uint32(len(pkt) - offset)
		sum += 6
	}
	seg := pkt[offset:]
	for i := 0; i+1 < len(seg); i += 2 {
		if i == 16 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(seg[i:]))
	}
	if len(seg)%2 == 1 {
		sum += uint32(seg[len(seg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestIncrementalTCPChecksum(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		hdr := 20
		oldSrc := netip.MustParseAddrPort("192.168.1.10:51234")
		oldDst := netip.MustParseAddrPort("93.184.216.34:443")
		newSrc := netip.MustParseAddrPort("127.0.0.1:49999")
		newDst := netip.MustParseAddrPort("127.0.0.1:15090")
		if ipv6 {
			hdr = 40
			oldSrc = netip.MustParseAddrPort("[2001:db8::10]:51234")
			oldDst = netip.MustParseAddrPort("[2606:2800:220:1::248]:443")
			newSrc = netip.MustParseAddrPort("[::1]:49999")
			newDst = netip.MustParseAddrPort("[::1]:15090")
		}
		payload := []byte("GET / HTTP/1.1\r\n")
		data := make([]byte, hdr+20+len(payload))
		if ipv6 {
			data[0], data[6] = 0x60, 6
			binary.BigEndian.PutUint16(data[4:], uint16(20+len(payload)))
			copy(data[8:24], oldSrc.Addr().AsSlice())
			copy(data[24:40], oldDst.Addr().AsSlice())
		} else {
			data[0], data[9] = 0x45, 6
			binary.BigEndian.PutUint16(data[2:], uint16(len(data)))
			copy(data[12:16], oldSrc.Addr().AsSlice())
			copy(data[16:20], oldDst.Addr().AsSlice())
		}
		binary.BigEndian.PutUint16(data[hdr:], oldSrc.Port())
		binary.BigEndian.PutUint16(data[hdr+2:], oldDst.Port())
		data[hdr+12] = 0x50
		copy(data[hdr+20:], payload)
		if !ipv6 {
			binary.BigEndian.PutUint16(data[10:], fullIPv4Checksum(data[:20]))
		}
		binary.BigEndian.PutUint16(data[hdr+16:], fullTCPChecksum(data, hdr, ipv6))

		p, err := parsePacket(data)
		if err != nil {
			t.Fatal(err)
		}
		if !p.rewriteTCPIncremental(newSrc, newDst) {
			t.Fatal("expected incremental checksum update")
		}
		if !ipv6 {
			gotIP := binary.BigEndian.Uint16(data[10:])
			wantIP := fullIPv4Checksum(data[:20])
			if gotIP != wantIP {
				t.Fatalf("IPv4 checksum mismatch: got %#x want %#x", gotIP, wantIP)
			}
		}
		gotTCP := binary.BigEndian.Uint16(data[hdr+16:])
		wantTCP := fullTCPChecksum(data, hdr, ipv6)
		if gotTCP != wantTCP {
			t.Fatalf("TCP checksum mismatch (ipv6=%v): got %#x want %#x", ipv6, gotTCP, wantTCP)
		}
	}
}
