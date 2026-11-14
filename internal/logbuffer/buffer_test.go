package logbuffer

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestBoundedHistoryAndCursor(t *testing.T) {
	b := &Buffer{}
	for i := 0; i < Capacity+25; i++ {
		fmt.Fprintf(b, "line %d\n", i)
	}
	snapshot := b.Read(0)
	if len(snapshot.Entries) != Capacity || snapshot.Entries[0].ID != 26 || snapshot.Next != Capacity+25 {
		t.Fatalf("history not bounded: %d %+v", len(snapshot.Entries), snapshot.Entries[0])
	}
	if len(b.Read(snapshot.Next).Entries) != 0 {
		t.Fatal("cursor repeated entries")
	}
	b.Write([]byte(strings.Repeat("x", MaxLine*10)))
	recent := b.Read(snapshot.Next)
	if len(recent.Entries) != 1 || len(recent.Entries[0].Text) > MaxLine {
		t.Fatal("oversize message retained")
	}
	if len(b.Read(snapshot.Next+100).Entries) != Capacity {
		t.Fatal("restart cursor not reset")
	}
}

func TestStructuredAppendAndJSON(t *testing.T) {
	b := &Buffer{}
	b.Append("warn", "09:30:00", "first line\nsecond line\r\n")
	b.Write([]byte("plain line\n"))

	snap := b.Read(0)
	if len(snap.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(snap.Entries))
	}
	if snap.Entries[0].Level != "warn" || snap.Entries[0].Time != "09:30:00" || snap.Entries[0].Text != "first line" {
		t.Fatalf("unexpected structured entry[0]: %+v", snap.Entries[0])
	}
	if snap.Entries[1].Level != "warn" || snap.Entries[1].Text != "second line" {
		t.Fatalf("unexpected structured entry[1]: %+v", snap.Entries[1])
	}
	if snap.Entries[2].Level != "" || snap.Entries[2].Time != "" || snap.Entries[2].Text != "plain line" {
		t.Fatalf("unexpected plain entry[2]: %+v", snap.Entries[2])
	}

	raw, err := json.Marshal(snap.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"level":"warn"`) || !strings.Contains(string(raw), `"time":"09:30:00"`) {
		t.Fatalf("unexpected json: %s", raw)
	}
}

func TestConcurrentAppendAndRead(t *testing.T) {
	b := &Buffer{}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				b.Append("info", "12:00:00", fmt.Sprintf("g=%d i=%d", id, i))
				_ = b.Read(0)
			}
		}(g)
	}
	wg.Wait()
	snap := b.Read(0)
	if snap.Next != 400 || len(snap.Entries) != 400 {
		t.Fatalf("unexpected concurrent count: next=%d len=%d", snap.Next, len(snap.Entries))
	}
}
