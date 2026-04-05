package main

import (
	"net"
	"testing"
)

func TestRegistry_AllocateAndFree(t *testing.T) {
	reg := NewRegistry()

	// Allocate 3 sessions.
	c1a, c1b := net.Pipe()
	defer c1a.Close()
	defer c1b.Close()
	c2a, c2b := net.Pipe()
	defer c2a.Close()
	defer c2b.Close()
	c3a, c3b := net.Pipe()
	defer c3a.Close()
	defer c3b.Close()

	s1 := reg.Allocate(c1a, false)
	s2 := reg.Allocate(c2a, false)
	s3 := reg.Allocate(c3a, false)

	if s1 == nil || s2 == nil || s3 == nil {
		t.Fatal("expected all 3 allocations to succeed")
	}
	if s1.ID != 1 || s2.ID != 2 || s3.ID != 3 {
		t.Fatalf("expected IDs 1,2,3 got %d,%d,%d", s1.ID, s2.ID, s3.ID)
	}

	// Remove session 2.
	reg.Remove(2)

	// All() should return 2 sessions.
	all := reg.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 sessions after remove, got %d", len(all))
	}

	// Next allocation should reuse ID 2 (nextID reset on remove).
	c4a, c4b := net.Pipe()
	defer c4a.Close()
	defer c4b.Close()
	s4 := reg.Allocate(c4a, false)
	if s4 == nil {
		t.Fatal("expected allocation to succeed after remove")
	}
	if s4.ID != 2 {
		t.Errorf("expected reused ID 2, got %d", s4.ID)
	}

	// Verify final count.
	if reg.Count() != 3 {
		t.Errorf("expected count 3, got %d", reg.Count())
	}
}

func TestRegistry_AllocateHTTP_IDsSequential(t *testing.T) {
	reg := NewRegistry()

	s1 := reg.AllocateHTTP("tok1", "10.0.0.1:80")
	s2 := reg.AllocateHTTP("tok2", "10.0.0.2:80")
	if s1 == nil || s2 == nil {
		t.Fatal("expected both allocations to succeed")
	}
	if s1.ID != 1 || s2.ID != 2 {
		t.Fatalf("expected IDs 1,2 got %d,%d", s1.ID, s2.ID)
	}

	// Remove and reallocate — should reuse.
	reg.Remove(1)
	s3 := reg.AllocateHTTP("tok3", "10.0.0.3:80")
	if s3 == nil {
		t.Fatal("expected allocation to succeed after remove")
	}
	if s3.ID != 1 {
		t.Errorf("expected reused ID 1, got %d", s3.ID)
	}
}

func TestRegistry_MixedAllocateAndAllocateHTTP(t *testing.T) {
	reg := NewRegistry()

	c1a, c1b := net.Pipe()
	defer c1a.Close()
	defer c1b.Close()

	s1 := reg.Allocate(c1a, false)
	s2 := reg.AllocateHTTP("tok1", "10.0.0.1:80")
	if s1 == nil || s2 == nil {
		t.Fatal("expected both allocations to succeed")
	}
	if s1.ID != 1 || s2.ID != 2 {
		t.Fatalf("expected IDs 1,2 got %d,%d", s1.ID, s2.ID)
	}
}
