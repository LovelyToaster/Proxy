package windivert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const (
	maxFragmentBytes = 8 << 20
	maxFragmentSets  = 256
	fragmentLifetime = 15 * time.Second
)

type fragmentKey struct {
	source, target netip.Addr
	id             uint32
	protocol       byte
	iface          uint64
}

type capturedPacket struct {
	data    []byte
	address [10]uint64
}

type fragmentPart struct {
	packet  capturedPacket
	offset  int
	payload []byte
}

type fragmentSet struct {
	prefix                []byte
	previous              int
	protocol              byte
	parts                 []fragmentPart
	total, covered, bytes int
	first                 bool
	invalid               bool
	created               time.Time
}

type fragmentCache struct {
	mu    sync.Mutex
	sets  map[fragmentKey]*fragmentSet
	bytes int
}

type fragmentInfo struct {
	key                             fragmentKey
	prefix, payload                 []byte
	offset, previous, payloadOffset int
	more                            bool
}

func describeFragment(data []byte, address [10]uint64) (fragmentInfo, bool, error) {
	var info fragmentInfo
	n, err := parseNetwork(data)
	if err != nil {
		return info, false, err
	}
	info.key = fragmentKey{source: n.source, target: n.target, protocol: n.protocol, iface: address[2]}
	if n.source.Is4() {
		flags := binary.BigEndian.Uint16(data[6:])
		if flags&0x3fff == 0 {
			return info, false, nil
		}
		if flags&0xc000 != 0 {
			return info, true, errPacket
		}
		info.key.id = uint32(binary.BigEndian.Uint16(data[4:]))
		info.prefix = n.data[:n.offset]
		info.payload = n.data[n.offset:]
		info.payloadOffset = n.offset
		info.offset = int(flags&0x1fff) * 8
		info.more = flags&0x2000 != 0
	} else {
		if n.protocol != 44 {
			return info, false, nil
		}
		if n.offset+8 > len(n.data) {
			return info, true, errPacket
		}
		field := binary.BigEndian.Uint16(data[n.offset+2:])
		if field&6 != 0 || data[n.offset+1] != 0 {
			return info, true, errPacket
		}
		info.key.protocol = data[n.offset]
		info.key.id = binary.BigEndian.Uint32(data[n.offset+4:])
		info.prefix = n.data[:n.offset]
		info.payload = n.data[n.offset+8:]
		info.payloadOffset = n.offset + 8
		info.previous = n.previous
		info.offset = int(field & 0xfff8)
		info.more = field&1 != 0
	}
	limit := 65535 - len(info.prefix)
	if n.source.Is6() {
		limit += 40
	}
	if len(info.payload) == 0 || info.more && len(info.payload)%8 != 0 || info.offset+len(info.payload) > limit {
		return info, true, errPacket
	}
	return info, true, nil
}

// Add holds fragments until the full transport packet exists. Original captures are retained
// so traffic outside our scope can be reinjected without altering its fragmentation.
func (c *fragmentCache) Add(data []byte, address [10]uint64, now time.Time) ([]byte, []capturedPacket, bool, error) {
	info, fragment, err := describeFragment(data, address)
	if err != nil {
		return nil, nil, false, err
	}
	if !fragment {
		return data, nil, false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sets == nil {
		c.sets = make(map[fragmentKey]*fragmentSet)
	}
	set := c.sets[info.key]
	if set != nil && now.Sub(set.created) >= fragmentLifetime {
		c.remove(info.key, set)
		set = nil
	}
	if set == nil {
		if len(c.sets) >= maxFragmentSets {
			return nil, nil, true, errors.New("fragment set limit reached")
		}
		set = &fragmentSet{total: -1, previous: info.previous, protocol: info.key.protocol, created: now}
		c.sets[info.key] = set
	}
	if set.invalid {
		return nil, nil, true, errors.New("discarded fragment datagram")
	}
	fail := func(message string) ([]byte, []capturedPacket, bool, error) {
		c.bytes -= set.bytes
		set.parts = nil
		set.prefix = nil
		set.bytes = 0
		set.invalid = true
		return nil, nil, true, errors.New(message)
	}
	end := info.offset + len(info.payload)
	if set.total >= 0 && end > set.total {
		return fail("fragment exceeds final length")
	}
	if !info.more {
		if set.total >= 0 && set.total != end {
			return fail("conflicting final fragment")
		}
		for _, part := range set.parts {
			if part.offset+len(part.payload) > end {
				return fail("final fragment truncates prior data")
			}
		}
		set.total = end
	}
	for _, part := range set.parts {
		if info.offset < part.offset+len(part.payload) && part.offset < end {
			return fail("overlapping fragments")
		}
	}
	if len(set.parts) >= 8192 || c.bytes+len(data) > maxFragmentBytes {
		return fail("fragment memory limit reached")
	}
	if len(set.prefix) > 0 && info.key.source.Is6() && !sameIPv6Prefix(set.prefix, info.prefix) {
		return fail("conflicting IPv6 unfragmentable headers")
	}
	owned := append([]byte(nil), data...)
	set.parts = append(set.parts, fragmentPart{packet: capturedPacket{owned, address}, offset: info.offset, payload: owned[info.payloadOffset : info.payloadOffset+len(info.payload)]})
	set.bytes += len(owned)
	c.bytes += len(owned)
	set.covered += len(info.payload)
	if len(set.prefix) == 0 || info.offset == 0 {
		set.prefix = owned[:len(info.prefix)]
	}
	if info.offset == 0 {
		set.first = true
	}
	if !set.first || set.total < 0 || set.covered != set.total {
		return nil, nil, true, nil
	}
	if len(set.prefix)+set.total > 65535 && info.key.source.Is4() || len(set.prefix)+set.total > 65575 {
		return fail("reassembled IP packet too large")
	}
	assembled := make([]byte, len(set.prefix)+set.total)
	copy(assembled, set.prefix)
	originals := make([]capturedPacket, 0, len(set.parts))
	for _, part := range set.parts {
		copy(assembled[len(set.prefix)+part.offset:], part.payload)
		originals = append(originals, part.packet)
	}
	if info.key.source.Is4() {
		binary.BigEndian.PutUint16(assembled[2:], uint16(len(assembled)))
		binary.BigEndian.PutUint16(assembled[6:], 0)
		binary.BigEndian.PutUint16(assembled[10:], 0)
	} else {
		assembled[set.previous] = set.protocol
		binary.BigEndian.PutUint16(assembled[4:], uint16(len(assembled)-40))
	}
	c.remove(info.key, set)
	return assembled, originals, false, nil
}

func sameIPv6Prefix(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	// Payload length and hop limit may differ between fragments.
	return bytes.Equal(first[:4], second[:4]) && first[6] == second[6] && bytes.Equal(first[8:], second[8:])
}

func (c *fragmentCache) remove(key fragmentKey, set *fragmentSet) {
	delete(c.sets, key)
	c.bytes -= set.bytes
}

func (c *fragmentCache) Expire(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for key, set := range c.sets {
		if now.Sub(set.created) >= fragmentLifetime {
			count += len(set.parts)
			c.remove(key, set)
		}
	}
	return count
}

func (c *fragmentCache) Drain() []capturedPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []capturedPacket
	for key, set := range c.sets {
		for _, part := range set.parts {
			result = append(result, part.packet)
		}
		c.remove(key, set)
	}
	return result
}
