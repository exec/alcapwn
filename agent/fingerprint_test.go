package main

import (
	"regexp"
	"testing"
)

var hexRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// TestMachineID_format verifies the returned value is exactly 16 lowercase hex chars.
func TestMachineID_format(t *testing.T) {
	id := machineID()
	if id == "" {
		t.Fatal("machineID returned empty string")
	}
	if !hexRE.MatchString(id) {
		t.Fatalf("machineID %q is not a 16-char lowercase hex string", id)
	}
}

// TestMachineID_deterministic verifies two consecutive calls return the same value.
func TestMachineID_deterministic(t *testing.T) {
	id1 := machineID()
	id2 := machineID()
	if id1 != id2 {
		t.Fatalf("machineID is not deterministic: first=%q second=%q", id1, id2)
	}
}

// TestMachineID_noPanic just verifies machineID does not panic in any environment
// (including minimal containers where /etc/machine-id may not exist).
func TestMachineID_noPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("machineID panicked: %v", r)
		}
	}()
	_ = machineID()
}

// TestMachineID_length verifies the exact byte length of the returned string.
func TestMachineID_length(t *testing.T) {
	id := machineID()
	if len(id) != 16 {
		t.Fatalf("machineID length: want 16, got %d (%q)", len(id), id)
	}
}
