package main

import (
	"testing"
)

func TestReconSectionCount(t *testing.T) {
	// The buildReconScript function must iterate over exactly len(reconSections)
	// sections. This test guards against the hardcoded count drifting from the
	// actual slice length.
	nonce := makeReconNonce()
	script := buildReconScript(nonce)

	// Verify that every section's placeholder was replaced (no leftover {{HASH_N}}).
	for i := 1; i <= len(reconSections); i++ {
		placeholder := "{{HASH_" + itoa(i) + "}}"
		if containsStr(script, placeholder) {
			t.Errorf("buildReconScript left placeholder %s unreplaced", placeholder)
		}
	}
}

// itoa is a minimal int-to-string for test use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
