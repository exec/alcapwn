package main

import (
	"testing"
)

// ── TestSanitizeLabel ────────────────────────────────────────────────────────

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean label",
			input: "web-server_01",
			want:  "web-server_01",
		},
		{
			name:  "path traversal stripped",
			input: "../../../etc/passwd",
			want:  "......etcpasswd",
		},
		{
			name:  "spaces removed",
			input: "my session name",
			want:  "mysessionname",
		},
		{
			name:  "special characters stripped",
			input: "session@host:8080/path?q=1&x=2",
			want:  "sessionhost8080pathq1x2",
		},
		{
			name:  "dots and hyphens preserved",
			input: "host.example.com",
			want:  "host.example.com",
		},
		{
			name:  "underscores preserved",
			input: "test_session_123",
			want:  "test_session_123",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "only special chars",
			input: "!@#$%^&*()",
			want:  "",
		},
		{
			name:  "unicode stripped",
			input: "session\u2603name",
			want:  "sessionname",
		},
		{
			name:  "mixed alphanumeric and special",
			input: "A1-B2_C3.D4/E5",
			want:  "A1-B2_C3.D4E5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeLabel(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeLabel(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── TestSanitizeLabel_NoPathTraversal ─────────────────────────────────────────

func TestSanitizeLabel_NoPathTraversal(t *testing.T) {
	// Ensure that no sanitized output can be used for path traversal.
	dangerous := []string{
		"../../../etc/shadow",
		"/etc/passwd",
		"..\\..\\windows\\system32",
		"foo/bar/baz",
	}

	for _, input := range dangerous {
		got := sanitizeLabel(input)
		// The result must not contain path separators
		for _, ch := range got {
			if ch == '/' || ch == '\\' {
				t.Errorf("sanitizeLabel(%q) = %q, contains path separator %q", input, got, string(ch))
			}
		}
	}
}

// ── TestStringPtr ────────────────────────────────────────────────────────────

func TestStringPtr(t *testing.T) {
	s := "hello"
	ptr := stringPtr(s)
	if ptr == nil {
		t.Fatal("stringPtr returned nil")
	}
	if *ptr != s {
		t.Errorf("*stringPtr(%q) = %q, want %q", s, *ptr, s)
	}

	// Verify it's a new pointer, not pointing to the original
	s = "changed"
	if *ptr == s {
		t.Error("stringPtr should return a new copy, not a reference to the original")
	}
}
