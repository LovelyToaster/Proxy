package geoipdat

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

type trieNode struct {
	child    [2]uint32
	terminal bool
}

type Set struct {
	v4      []trieNode
	v6      []trieNode
	inverse bool
}

func insertTrie(nodes *[]trieNode, addr []byte, bits int) {
	if len(*nodes) == 0 {
		*nodes = append(*nodes, trieNode{})
	}
	idx := uint32(0)
	for bit := 0; bit < bits; bit++ {
		if (*nodes)[idx].terminal {
			return
		}
		b := (addr[bit/8] >> (7 - bit%8)) & 1
		next := (*nodes)[idx].child[b]
		if next == 0 {
			next = uint32(len(*nodes))
			*nodes = append(*nodes, trieNode{})
			(*nodes)[idx].child[b] = next
		}
		idx = next
	}
	(*nodes)[idx].terminal = true
}

func matchTrie(nodes []trieNode, addr []byte) bool {
	if len(nodes) == 0 {
		return false
	}
	idx := uint32(0)
	if nodes[0].terminal {
		return true
	}
	maxBits := len(addr) * 8
	for bit := 0; bit < maxBits; bit++ {
		b := (addr[bit/8] >> (7 - bit%8)) & 1
		next := nodes[idx].child[b]
		if next == 0 {
			return false
		}
		idx = next
		if nodes[idx].terminal {
			return true
		}
	}
	return false
}

func (s *Set) Match(ip netip.Addr) bool {
	ip = ip.Unmap()
	var found bool
	if ip.Is4() {
		a := ip.As4()
		found = matchTrie(s.v4, a[:])
	} else if ip.Is6() {
		a := ip.As16()
		found = matchTrie(s.v6, a[:])
	}
	return found != s.inverse
}

type field struct {
	num     protowire.Number
	kind    protowire.Type
	data    []byte
	integer uint64
}

func walk(data []byte, visit func(field) error) error {
	for len(data) > 0 {
		num, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			return protowire.ParseError(n)
		}
		data = data[n:]
		f := field{num: num, kind: kind}
		switch kind {
		case protowire.BytesType:
			f.data, n = protowire.ConsumeBytes(data)
		case protowire.VarintType:
			f.integer, n = protowire.ConsumeVarint(data)
		default:
			n = protowire.ConsumeFieldValue(num, kind, data)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		if err := visit(f); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
func Load(path string, codes []string) (map[string]*Set, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	const limit = 256 << 20
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("invalid GeoIP DAT file size/type")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("GeoIP DAT exceeds limit")
	}
	return parse(data, codes)
}
func Validate(path string) error { _, err := Load(path, nil); return err }
func parse(data []byte, codes []string) (map[string]*Set, error) {
	selected := map[string]*Set{}
	for _, code := range codes {
		selected[strings.ToUpper(code)] = nil
	}
	seen := map[string]bool{}
	total := 0
	err := walk(data, func(f field) error {
		if f.num != 1 {
			return nil
		}
		if f.kind != protowire.BytesType {
			return fmt.Errorf("invalid GeoIP DAT entry")
		}
		var code string
		var inverse bool
		if err := walk(f.data, func(x field) error {
			if x.num == 1 {
				if x.kind != protowire.BytesType {
					return fmt.Errorf("invalid GeoIP category")
				}
				code = strings.ToUpper(string(x.data))
			}
			if x.num == 3 {
				if x.kind != protowire.VarintType || x.integer > 1 {
					return fmt.Errorf("invalid GeoIP inverse flag")
				}
				inverse = x.integer == 1
			}
			return nil
		}); err != nil {
			return err
		}
		if code == "" || len(code) > 128 || seen[code] || len(seen) >= 4096 {
			return fmt.Errorf("invalid or duplicate GeoIP category %q", code)
		}
		seen[code] = true
		_, needed := selected[code]
		set := &Set{inverse: inverse}
		err := walk(f.data, func(x field) error {
			if x.num != 2 {
				return nil
			}
			if x.kind != protowire.BytesType {
				return fmt.Errorf("invalid GeoIP CIDR entry")
			}
			var ipBytes []byte
			var bits uint64
			if err := walk(x.data, func(y field) error {
				switch y.num {
				case 1:
					if y.kind != protowire.BytesType {
						return fmt.Errorf("invalid CIDR IP")
					}
					ipBytes = y.data
				case 2:
					if y.kind != protowire.VarintType {
						return fmt.Errorf("invalid CIDR prefix")
					}
					bits = y.integer
				}
				return nil
			}); err != nil {
				return err
			}
			ip, ok := netip.AddrFromSlice(ipBytes)
			if !ok || ip.Is4In6() || bits > uint64(ip.BitLen()) {
				return fmt.Errorf("invalid GeoIP CIDR")
			}
			total++
			if total > 5000000 {
				return fmt.Errorf("too many GeoIP CIDRs")
			}
			if needed {
				prefix := netip.PrefixFrom(ip, int(bits)).Masked()
				if ip.Is4() {
					a := prefix.Addr().As4()
					insertTrie(&set.v4, a[:], int(bits))
				} else {
					a := prefix.Addr().As16()
					insertTrie(&set.v6, a[:], int(bits))
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if needed {
			selected[code] = set
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("GeoIP DAT: %w", err)
	}
	if len(seen) == 0 || total == 0 {
		return nil, fmt.Errorf("empty GeoIP DAT")
	}
	for code, set := range selected {
		if set == nil {
			return nil, fmt.Errorf("GeoIP category %s not found", code)
		}
	}
	return selected, nil
}
