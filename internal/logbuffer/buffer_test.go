package logbuffer

import (
	"fmt"
	"strings"
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
