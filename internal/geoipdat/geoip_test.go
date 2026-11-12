package geoipdat

import (
	"google.golang.org/protobuf/encoding/protowire"
	"net/netip"
	"testing"
)

func bytesField(data []byte, n protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(data, n, protowire.BytesType), value)
}
func category(code string, prefixes ...string) []byte {
	entry := bytesField(nil, 1, []byte(code))
	for _, text := range prefixes {
		p := netip.MustParsePrefix(text)
		ip := p.Addr().AsSlice()
		cidr := bytesField(nil, 1, ip)
		cidr = protowire.AppendVarint(protowire.AppendTag(cidr, 2, protowire.VarintType), uint64(p.Bits()))
		entry = bytesField(entry, 2, cidr)
	}
	return bytesField(nil, 1, entry)
}
func TestDATBoundariesAndInverse(t *testing.T) {
	data := category("CN", "192.0.2.0/24", "2001:db8::/32")
	sets, err := parse(data, []string{"CN"})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"192.0.2.1": true, "192.0.3.1": false, "2001:db8:ffff::1": true, "2001:db9::1": false} {
		if sets["CN"].Match(netip.MustParseAddr(ip)) != want {
			t.Fatal(ip)
		}
	}
	inverse := bytesField(nil, 1, []byte("GB"))
	inverse = protowire.AppendVarint(protowire.AppendTag(inverse, 3, protowire.VarintType), 1)
	sets, err = parse(append(data, bytesField(nil, 1, inverse)...), []string{"GB"})
	if err != nil || !sets["GB"].Match(netip.MustParseAddr("198.51.100.1")) {
		t.Fatalf("inverse: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("MMDB is not DAT"), data[:len(data)-1], append(append([]byte(nil), data...), data...)} {
		if _, err := parse(bad, []string{"CN"}); err == nil {
			t.Fatal("invalid DAT accepted")
		}
	}
	if _, err := parse(data, []string{"US"}); err == nil {
		t.Fatal("missing country accepted")
	}
	cidr := bytesField(nil, 1, []byte{192, 0, 2, 0})
	cidr = protowire.AppendVarint(protowire.AppendTag(cidr, 2, protowire.VarintType), 129)
	bad := bytesField(nil, 1, bytesField(bytesField(nil, 1, []byte("CN")), 2, cidr))
	if _, err := parse(bad, []string{"CN"}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}
