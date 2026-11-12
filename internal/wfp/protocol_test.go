package wfp

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestRegistrationABI(t *testing.T) {
	data, err := registration(15090, []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:19090"),
		netip.MustParseAddrPort("[::1]:19090"),
	}, []byte{'a', 0, 0, 0}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	const want = "0200000034000000f23a000003000000924a0000040000007f000001000000000000000000000000000000010000000061000000"
	if got := hex.EncodeToString(data); got != want {
		t.Fatalf("registration %s, want %s", got, want)
	}
}

func TestDecodeRedirectContext(t *testing.T) {
	for _, want := range []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:19090"),
		netip.MustParseAddrPort("127.0.0.1:53"),
		netip.MustParseAddrPort("[2001:db8::1]:19090"),
	} {
		family := uint32(6)
		if want.Addr().Is4() {
			family = 4
		}
		context := make([]byte, 36)
		binary.LittleEndian.PutUint32(context, 0x31504657)
		binary.LittleEndian.PutUint32(context[4:], 36)
		binary.LittleEndian.PutUint32(context[8:], family)
		binary.LittleEndian.PutUint32(context[12:], uint32(want.Port()))
		copy(context[20:], want.Addr().AsSlice())
		got, err := destination(context)
		if err != nil || got != want {
			t.Fatalf("destination %v, %v; want %v", got, err, want)
		}
		binary.LittleEndian.PutUint32(context[16:], 1)
		if _, err := destination(context); err == nil {
			t.Fatal("accepted an unsupported zone")
		}
		if _, err := destination(context[:35]); err == nil {
			t.Fatal("accepted a truncated context")
		}
	}
}

func TestDNSOnlyRegistrationABI(t *testing.T) {
	target := netip.AddrPortFrom(netip.IPv6Loopback(), 0)
	data, err := registration(15090, []netip.AddrPort{target}, []byte{'a', 0}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if port := binary.LittleEndian.Uint32(data[16:]); port != 0 {
		t.Fatalf("unexpected ordinary target port %d", port)
	}
	if flags := binary.LittleEndian.Uint32(data[44:]); flags != 2 {
		t.Fatalf("unexpected DNS-only flags %d", flags)
	}
}
