package dnsengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
)

const (
	persistMagic   uint32 = 0x50444331 // "PDC1"
	persistVersion uint16 = 1
)

type cacheSnapshot struct {
	Key      cacheKey
	Response *dns.Msg
	Stored   time.Time
	TTL      uint32
	Frequent bool
}

// savePersist writes the snapshot entries to the given writer with CRC32 checksum.
func savePersist(w io.Writer, entries []cacheSnapshot) error {
	crc := crc32.NewIEEE()
	mw := io.MultiWriter(w, crc)

	// Header: Magic (4) + Version (2) + Count (4)
	var header [10]byte
	binary.BigEndian.PutUint32(header[0:4], persistMagic)
	binary.BigEndian.PutUint16(header[4:6], persistVersion)
	binary.BigEndian.PutUint32(header[6:10], uint32(len(entries)))
	if _, err := mw.Write(header[:]); err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.Response == nil {
			continue
		}
		wire, err := entry.Response.Pack()
		if err != nil {
			continue
		}
		if len(wire) > 65535 {
			continue
		}

		// Write policy
		policyBytes := []byte(entry.Key.policy)
		if err := writeBytes16(mw, policyBytes); err != nil {
			return err
		}

		// Write question name
		nameBytes := []byte(entry.Key.question.Name)
		if err := writeBytes16(mw, nameBytes); err != nil {
			return err
		}

		// Write question type, class, flags, frequent, stored, ttl, wire
		var meta [18]byte
		binary.BigEndian.PutUint16(meta[0:2], entry.Key.question.Qtype)
		binary.BigEndian.PutUint16(meta[2:4], entry.Key.question.Qclass)
		meta[4] = entry.Key.flags
		if entry.Frequent {
			meta[5] = 1
		} else {
			meta[5] = 0
		}
		binary.BigEndian.PutUint64(meta[6:14], uint64(entry.Stored.Unix()))
		binary.BigEndian.PutUint32(meta[14:18], entry.TTL)
		if _, err := mw.Write(meta[:]); err != nil {
			return err
		}

		// Write wire bytes
		if err := writeBytes16(mw, wire); err != nil {
			return err
		}
	}

	// Footer: CRC32
	var footer [4]byte
	binary.BigEndian.PutUint32(footer[:], crc.Sum32())
	_, err := w.Write(footer[:])
	return err
}

// loadPersist reads and validates snapshot entries from the given reader.
func loadPersist(r io.Reader, now time.Time, stale staleOptions) ([]cacheSnapshot, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if len(data) < 14 { // 10 header + 4 footer
		return nil, errors.New("DNS cache persistence: file too small")
	}

	// Verify CRC32
	bodyLen := len(data) - 4
	expectedCRC := binary.BigEndian.Uint32(data[bodyLen:])
	actualCRC := crc32.ChecksumIEEE(data[:bodyLen])
	if expectedCRC != actualCRC {
		return nil, errors.New("DNS cache persistence: CRC32 checksum mismatch")
	}

	reader := bytes.NewReader(data[:bodyLen])

	// Read header
	var header [10]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	magic := binary.BigEndian.Uint32(header[0:4])
	if magic != persistMagic {
		return nil, errors.New("DNS cache persistence: invalid magic header")
	}
	version := binary.BigEndian.Uint16(header[4:6])
	if version != persistVersion {
		return nil, fmt.Errorf("DNS cache persistence: unsupported version %d", version)
	}
	count := binary.BigEndian.Uint32(header[6:10])

	snapshots := make([]cacheSnapshot, 0, count)

	for range count {
		policyBytes, err := readBytes16(reader)
		if err != nil {
			return nil, err
		}
		nameBytes, err := readBytes16(reader)
		if err != nil {
			return nil, err
		}

		var meta [18]byte
		if _, err := io.ReadFull(reader, meta[:]); err != nil {
			return nil, err
		}
		qtype := binary.BigEndian.Uint16(meta[0:2])
		qclass := binary.BigEndian.Uint16(meta[2:4])
		flags := meta[4]
		frequent := meta[5] == 1
		storedSec := int64(binary.BigEndian.Uint64(meta[6:14]))
		ttl := binary.BigEndian.Uint32(meta[14:18])
		stored := time.Unix(storedSec, 0)

		wire, err := readBytes16(reader)
		if err != nil {
			return nil, err
		}

		// Filter expired entries
		age := uint32(now.Sub(stored) / time.Second)
		staleLimit := ttl
		if stale.enabled {
			staleLimit += uint32(math.Ceil(stale.staleTTL.Seconds()))
		}
		if age >= staleLimit {
			continue
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(wire); err != nil {
			continue
		}

		key := cacheKey{
			policy: string(policyBytes),
			question: dns.Question{
				Name:   string(nameBytes),
				Qtype:  qtype,
				Qclass: qclass,
			},
			flags: flags,
		}

		snapshots = append(snapshots, cacheSnapshot{
			Key:      key,
			Response: msg,
			Stored:   stored,
			TTL:      ttl,
			Frequent: frequent,
		})
	}

	return snapshots, nil
}

// saveToFile writes snapshot entries atomically to the specified file path.
func saveToFile(path string, entries []cacheSnapshot) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, "dns_cache_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := savePersist(tmpFile, entries); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	return replaceFile(tmpPath, path)
}

// loadFromFile loads and filters snapshots from the specified file.
func loadFromFile(path string, now time.Time, stale staleOptions) ([]cacheSnapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	return loadPersist(file, now, stale)
}

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Fallback for Windows if destination exists
	_ = os.Remove(dst)
	return os.Rename(src, dst)
}

func writeBytes16(w io.Writer, b []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(b)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readBytes16(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
