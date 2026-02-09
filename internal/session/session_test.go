package session

import (
	"bytes"
	"sync"
	"testing"
)

func TestRingBuffer_UnderCapacity(t *testing.T) {
	r := NewRingBuffer(1024)
	data := []byte("hello world")
	r.Write(data)

	snap := r.Snapshot()
	if !bytes.Equal(snap, data) {
		t.Errorf("got %q, want %q", snap, data)
	}
}

func TestRingBuffer_ExactCapacity(t *testing.T) {
	r := NewRingBuffer(5)
	r.Write([]byte("abcde"))

	snap := r.Snapshot()
	if !bytes.Equal(snap, []byte("abcde")) {
		t.Errorf("got %q, want %q", snap, "abcde")
	}
}

func TestRingBuffer_Wrap(t *testing.T) {
	r := NewRingBuffer(8)
	r.Write([]byte("12345678"))
	r.Write([]byte("AB"))

	snap := r.Snapshot()
	want := []byte("345678AB")
	if !bytes.Equal(snap, want) {
		t.Errorf("got %q, want %q", snap, want)
	}
}

func TestRingBuffer_WrapMultiple(t *testing.T) {
	r := NewRingBuffer(4)
	r.Write([]byte("abcdefghij"))

	snap := r.Snapshot()
	want := []byte("ghij")
	if !bytes.Equal(snap, want) {
		t.Errorf("got %q, want %q", snap, want)
	}
}

func TestRingBuffer_IncrementalWrites(t *testing.T) {
	r := NewRingBuffer(6)
	r.Write([]byte("abc"))
	r.Write([]byte("def"))
	r.Write([]byte("gh"))

	snap := r.Snapshot()
	want := []byte("cdefgh")
	if !bytes.Equal(snap, want) {
		t.Errorf("got %q, want %q", snap, want)
	}
}

func TestRingBuffer_Empty(t *testing.T) {
	r := NewRingBuffer(1024)
	snap := r.Snapshot()
	if len(snap) != 0 {
		t.Errorf("expected empty snapshot, got %d bytes", len(snap))
	}
}

func TestRingBuffer_LargeOverwrite(t *testing.T) {
	r := NewRingBuffer(4)
	r.Write([]byte("0123456789abcdef"))
	snap := r.Snapshot()
	want := []byte("cdef")
	if !bytes.Equal(snap, want) {
		t.Errorf("got %q, want %q", snap, want)
	}
}

func TestRingBuffer_ConcurrentWrites(t *testing.T) {
	r := NewRingBuffer(1024)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Write([]byte("hello world! "))
		}()
	}
	wg.Wait()

	snap := r.Snapshot()
	if len(snap) == 0 {
		t.Error("expected non-empty snapshot after concurrent writes")
	}
	if len(snap) > 1024 {
		t.Errorf("snapshot size %d exceeds capacity 1024", len(snap))
	}
}
