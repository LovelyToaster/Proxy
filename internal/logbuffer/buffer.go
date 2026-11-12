package logbuffer

import (
	"strings"
	"sync"
)

const Capacity = 1000
const MaxLine = 4096

type Entry struct {
	ID   uint64 `json:"id"`
	Text string `json:"text"`
}
type Snapshot struct {
	Next    uint64  `json:"next"`
	Entries []Entry `json:"entries"`
}
type Buffer struct {
	mu      sync.Mutex
	next    uint64
	entries [Capacity]Entry
	count   int
}

var Default = &Buffer{}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Split without allocating a copy of an arbitrarily large log message.
	text := string(p)
	for len(text) > 0 {
		line, rest, found := strings.Cut(text, "\n")
		if len(line) > MaxLine {
			line = line[:MaxLine-3] + "..."
		}
		if line != "" {
			b.next++
			b.entries[(b.next-1)%Capacity] = Entry{b.next, strings.Clone(line)}
			if b.count < Capacity {
				b.count++
			}
		}
		if !found {
			break
		}
		text = rest
	}
	return len(p), nil
}
func (b *Buffer) Read(after uint64) Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := Snapshot{Next: b.next, Entries: []Entry{}}
	if after > b.next {
		after = 0
	} // A service restart resets sequence IDs.
	first := b.next - uint64(b.count) + 1
	for id := first; id <= b.next && b.count > 0; id++ {
		if id > after {
			result.Entries = append(result.Entries, b.entries[(id-1)%Capacity])
		}
	}
	return result
}
