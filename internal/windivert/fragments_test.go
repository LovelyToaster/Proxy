package windivert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func udpFixturePacket(ipv6 bool) []byte {
	source, target := netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.20:53")
	template := make([]byte, 20)
	if ipv6 {
		source, target = netip.MustParseAddrPort("[2001:db8::10]:40000"), netip.MustParseAddrPort("[2001:db8::20]:53")
		template = make([]byte, 40)
		template[0] = 0x60
	}
	data, _ := udpResponse(template, source, target, bytes.Repeat([]byte{'x'}, 32))
	return data
}

func fragmentPacket(data []byte, offset, length int, more bool, id uint32) []byte {
	ipv6 := data[0]>>4 == 6
	header := 20
	if ipv6 {
		header = 40
	}
	body := data[header+offset : header+offset+length]
	fragment := append([]byte(nil), data[:header]...)
	if ipv6 {
		fragment[6] = 44
		ext := make([]byte, 8)
		ext[0] = 17
		field := uint16(offset)
		if more {
			field |= 1
		}
		binary.BigEndian.PutUint16(ext[2:], field)
		binary.BigEndian.PutUint32(ext[4:], id)
		fragment = append(fragment, ext...)
		fragment = append(fragment, body...)
		binary.BigEndian.PutUint16(fragment[4:], uint16(len(fragment)-40))
	} else {
		binary.BigEndian.PutUint16(fragment[4:], uint16(id))
		field := uint16(offset / 8)
		if more {
			field |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:], field)
		fragment = append(fragment, body...)
		binary.BigEndian.PutUint16(fragment[2:], uint16(len(fragment)))
	}
	return fragment
}

func TestFragmentReassemblyOutOfOrder(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		original := udpFixturePacket(ipv6)
		fragments := [][]byte{fragmentPacket(original, 0, 16, true, 42), fragmentPacket(original, 16, 16, true, 42), fragmentPacket(original, 32, 8, false, 42)}
		cache := &fragmentCache{}
		now := time.Now()
		address := [10]uint64{0, 1 << 17, 7}
		for _, index := range []int{2, 1} {
			_, _, waiting, err := cache.Add(fragments[index], address, now)
			if err != nil || !waiting {
				t.Fatalf("fragment queue ipv6=%v: %v", ipv6, err)
			}
		}
		assembled, raw, waiting, err := cache.Add(fragments[0], address, now)
		if err != nil || waiting || len(raw) != 3 {
			t.Fatalf("reassembly ipv6=%v: %v", ipv6, err)
		}
		packet, err := parsePacket(assembled)
		if err != nil || !bytes.Equal(packet.data[packet.payload:], original[len(original)-32:]) {
			t.Fatalf("payload: %v", err)
		}
		if len(cache.sets) != 0 || cache.bytes != 0 {
			t.Fatal("completed fragments retained")
		}
		for i, index := range []int{2, 1, 0} {
			if !bytes.Equal(raw[i].data, fragments[index]) || raw[i].address != address {
				t.Fatal("original capture modified")
			}
		}
	}
}

func TestFragmentOverlapTimeoutAndLimits(t *testing.T) {
	cache := &fragmentCache{}
	data := udpFixturePacket(false)
	now := time.Now()
	first := fragmentPacket(data, 0, 16, true, 1)
	if _, _, _, err := cache.Add(first, [10]uint64{}, now); err != nil {
		t.Fatal(err)
	}
	overlap := fragmentPacket(data, 8, 16, true, 1)
	if _, _, _, err := cache.Add(overlap, [10]uint64{}, now); err == nil {
		t.Fatal("overlap accepted")
	}
	if _, _, _, err := cache.Add(first, [10]uint64{}, now); err == nil {
		t.Fatal("discarded datagram resumed")
	}
	cache.Expire(now.Add(fragmentLifetime))
	if len(cache.sets) != 0 || cache.bytes != 0 {
		t.Fatal("fragment state did not expire")
	}
	for i := 0; i < maxFragmentSets; i++ {
		p := fragmentPacket(data, 0, 16, true, uint32(i))
		if _, _, _, err := cache.Add(p, [10]uint64{}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := cache.Add(fragmentPacket(data, 0, 16, true, 9999), [10]uint64{}, now); err == nil {
		t.Fatal("fragment table overflow accepted")
	}
	if len(cache.Drain()) != maxFragmentSets || cache.bytes != 0 {
		t.Fatal("fragment drain failed")
	}
}

func TestIPv6ExtensionsAndAtomicFragment(t *testing.T) {
	data := udpFixturePacket(true)
	withOptions := append([]byte(nil), data[:40]...)
	withOptions[6] = 0
	withOptions = append(withOptions, []byte{60, 0, 0, 0, 0, 0, 0, 0}...)
	withOptions = append(withOptions, []byte{17, 0, 0, 0, 0, 0, 0, 0}...)
	withOptions = append(withOptions, data[40:]...)
	binary.BigEndian.PutUint16(withOptions[4:], uint16(len(withOptions)-40))
	p, err := parsePacket(withOptions)
	if err != nil || p.offset != 56 {
		t.Fatalf("extension traversal: %v", err)
	}
	response, err := udpResponse(withOptions, p.target, p.source, []byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := parsePacket(response)
	if err != nil || reply.offset != 40 || reply.source != p.target || string(reply.data[reply.payload:]) != "reply" {
		t.Fatal("reply copied request extension headers")
	}
	atomic := fragmentPacket(data, 0, len(data)-40, false, 2)
	assembled, _, waiting, err := (&fragmentCache{}).Add(atomic, [10]uint64{}, time.Now())
	if err != nil || waiting || !bytes.Equal(assembled, data) {
		t.Fatalf("atomic fragment: %v", err)
	}
	withOptions[48] = 253
	if _, err := parsePacket(withOptions); !errors.As(err, new(unsupportedHeader)) {
		t.Fatal("unknown extension was guessed")
	}
}

func TestFragmentAfterIPv6Extension(t *testing.T) {
	original := udpFixturePacket(true)
	cache := &fragmentCache{}
	for i, offset := range []int{0, 16, 32} {
		length := 16
		if i == 2 {
			length = 8
		}
		fragment := fragmentPacket(original, offset, length, i != 2, 99)
		wire := append([]byte(nil), fragment[:40]...)
		wire[6] = 0
		wire = append(wire, []byte{44, 0, 0, 0, 0, 0, 0, 0}...)
		wire = append(wire, fragment[40:]...)
		binary.BigEndian.PutUint16(wire[4:], uint16(len(wire)-40))
		assembled, _, waiting, err := cache.Add(wire, [10]uint64{}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if i != 2 {
			if !waiting {
				t.Fatal("early reassembly")
			}
			continue
		}
		p, err := parsePacket(assembled)
		if err != nil || p.offset != 48 || !bytes.Equal(assembled[48:], original[40:]) {
			t.Fatalf("extension fragment chain: %v", err)
		}
	}
}
