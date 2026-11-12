package windivert

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSplitBatchMixedAndBounds(t *testing.T) {
	v4, v6 := make([]byte, 28), make([]byte, 48)
	v4[0], v6[0] = 0x45, 0x60
	binary.BigEndian.PutUint16(v4[2:], uint16(len(v4)))
	binary.BigEndian.PutUint16(v6[4:], uint16(len(v6)-40))
	data := append(append([]byte(nil), v4...), v6...)
	addresses := [][10]uint64{{1, 2, 3}, {4, 5, 6}}
	packets, err := splitBatch(data, addresses, nil)
	if err != nil || len(packets) != 2 || !bytes.Equal(packets[0].data, v4) || !bytes.Equal(packets[1].data, v6) || packets[1].address != addresses[1] {
		t.Fatalf("mixed packet batch: %v %v", packets, err)
	}
	for _, test := range []struct {
		data      []byte
		addresses [][10]uint64
	}{
		{data[:len(data)-1], addresses}, {data, addresses[:1]}, {data, nil},
		{append(append([]byte(nil), data...), 0), addresses},
		{[]byte{0x60}, addresses[:1]},
		{data, make([][10]uint64, batchMax+1)},
	} {
		if _, err := splitBatch(test.data, test.addresses, nil); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
}

func TestPacketBatchOwnershipCapacityAndFlush(t *testing.T) {
	writes, count := 0, 0
	b := newPacketBatch(func(data []byte, addresses [][10]uint64) error {
		writes++
		count += len(addresses)
		if len(addresses) > batchMax || len(data) > batchBytes || data[0] != 7 || addresses[0][2] != 99 {
			t.Fatal("invalid buffered packet or metadata")
		}
		return nil
	})
	data := []byte{7}
	address := [10]uint64{0, 0, 99}
	if err := b.add(data, address); err != nil {
		t.Fatal(err)
	}
	data[0] = 0 // Sender must own bytes, not retain this mutable input.
	for i := 0; i < batchMax; i++ {
		if err := b.add([]byte{7}, address); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 1 || count != batchMax {
		t.Fatal("packet limit not flushed")
	}
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
	if writes != 2 || count != batchMax+1 {
		t.Fatal("last packet not flushed")
	}
	if err := b.flush(); err != nil || writes != 2 {
		t.Fatal("empty flush wrote data")
	}
	large := bytes.Repeat([]byte{7}, 65575)
	for i := 0; i < 4; i++ {
		if err := b.add(large, address); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 3 {
		t.Fatal("byte capacity not flushed")
	}
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketBatchFailureDoesNotRetry(t *testing.T) {
	failure := errors.New("partial injection")
	writes := 0
	b := newPacketBatch(func([]byte, [][10]uint64) error { writes++; return failure })
	if err := b.add([]byte{1}, [10]uint64{}); err != nil {
		t.Fatal(err)
	}
	if err := b.flush(); !errors.Is(err, failure) || writes != 1 {
		t.Fatal("send error lost or retried")
	}
}
