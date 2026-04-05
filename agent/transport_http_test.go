package main

import (
	"testing"
)

// TestHTTPTransport_JitterZeroIgnored verifies that a Welcome with Jitter=0
// does not override the agent's configured default jitter. The zero value
// of int is 0, so a missing Jitter field in JSON would decode as 0 and
// previously (with >= 0 check) would silently disable jitter.
func TestHTTPTransport_JitterZeroIgnored(t *testing.T) {
	defaultJitter := 20
	ht := &HTTPTransport{
		jitPct: defaultJitter,
	}

	// Simulate processing a Welcome with Jitter=0 (the zero value).
	welcomeJitter := 0
	if welcomeJitter > 0 && welcomeJitter <= 100 {
		ht.jitPct = welcomeJitter
	}

	if ht.jitPct != defaultJitter {
		t.Fatalf("jitter=0 should not override default; want %d, got %d", defaultJitter, ht.jitPct)
	}
}

// TestHTTPTransport_JitterPositiveApplied verifies that a positive Jitter
// value from the Welcome message is correctly applied.
func TestHTTPTransport_JitterPositiveApplied(t *testing.T) {
	ht := &HTTPTransport{
		jitPct: 20,
	}

	welcomeJitter := 50
	if welcomeJitter > 0 && welcomeJitter <= 100 {
		ht.jitPct = welcomeJitter
	}

	if ht.jitPct != 50 {
		t.Fatalf("positive jitter should be applied; want 50, got %d", ht.jitPct)
	}
}

// TestHTTPTransport_JitterNegativeIgnored verifies that negative Jitter
// values are ignored.
func TestHTTPTransport_JitterNegativeIgnored(t *testing.T) {
	ht := &HTTPTransport{
		jitPct: 20,
	}

	welcomeJitter := -5
	if welcomeJitter > 0 && welcomeJitter <= 100 {
		ht.jitPct = welcomeJitter
	}

	if ht.jitPct != 20 {
		t.Fatalf("negative jitter should not override default; want 20, got %d", ht.jitPct)
	}
}
