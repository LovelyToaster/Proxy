package windivert

import (
	"encoding/binary"
	"errors"
)

const batchMax = 64
const batchBytes = 256 << 10

// Split without transport decoding: fragments and unknown protocols still have
// an IP total length. A batch must match its address count exactly.
func splitBatch(data []byte, addresses [][10]uint64, packets []capturedPacket) ([]capturedPacket, error) {
	if len(addresses) == 0 || len(addresses) > batchMax {
		return nil, errors.New("invalid WinDivert batch address count")
	}
	packets = packets[:0]
	for _, address := range addresses {
		if len(data) < 20 {
			return nil, errors.New("truncated WinDivert batch")
		}
		var size int
		switch data[0] >> 4 {
		case 4:
			size = int(binary.BigEndian.Uint16(data[2:]))
			if header := int(data[0]&15) * 4; header < 20 || size < header {
				return nil, errors.New("invalid IPv4 batch length")
			}
		case 6:
			if len(data) < 40 {
				return nil, errors.New("truncated IPv6 batch")
			}
			size = 40 + int(binary.BigEndian.Uint16(data[4:]))
		default:
			return nil, errors.New("invalid batch IP version")
		}
		if size > len(data) {
			return nil, errors.New("truncated IP packet in batch")
		}
		packets = append(packets, capturedPacket{data: data[:size:size], address: address})
		data = data[size:]
	}
	if len(data) != 0 {
		return nil, errors.New("WinDivert batch address/packet mismatch")
	}
	return packets, nil
}

type packetBatch struct {
	data      []byte
	addresses [][10]uint64
	write     func([]byte, [][10]uint64) error
}

func newPacketBatch(write func([]byte, [][10]uint64) error) *packetBatch {
	return &packetBatch{data: make([]byte, 0, batchBytes), addresses: make([][10]uint64, 0, batchMax), write: write}
}

func (b *packetBatch) flush() error {
	if len(b.addresses) == 0 {
		return nil
	}
	if err := b.write(b.data, b.addresses); err != nil {
		return err // No retry: injection may already have partially succeeded.
	}
	b.data, b.addresses = b.data[:0], b.addresses[:0]
	return nil
}

func (b *packetBatch) add(data []byte, address [10]uint64) error {
	if len(data) == 0 || len(data) > batchBytes {
		return errors.New("invalid send batch packet length")
	}
	if len(b.addresses) == batchMax || len(b.data)+len(data) > batchBytes {
		if err := b.flush(); err != nil {
			return err
		}
	}
	// Own the bytes: reassembly buffers and the receive buffer can be reused.
	b.data = append(b.data, data...)
	b.addresses = append(b.addresses, address)
	return nil
}
