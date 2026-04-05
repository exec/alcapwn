package main

import (
	"strings"
	"testing"
)

// ── Fix 1: C1 control code bypass tests ─────────────────────────────────────

// TestStripDangerousAnsi_C1Codes verifies that single-byte C1 control codes
// (0x80-0x9F), which many terminals accept as equivalents to 2-byte ESC
// sequences, are stripped from output.
func TestStripDangerousAnsi_C1Codes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "C1 OSC clipboard hijack via 0x9D",
			input: "before\x9D52;c;cGF5bG9hZA==\x07after",
			want:  "beforeafter",
		},
		{
			name:  "C1 CSI cursor report via 0x9B",
			input: "before\x9B6nafter",
			want:  "beforeafter",
		},
		{
			name:  "C1 APC via 0x9F",
			input: "before\x9Fpayload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "C1 PM via 0x9E",
			input: "before\x9Epayload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "C1 DCS via 0x90",
			input: "before\x90payload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "non-sequence C1 bytes stripped",
			input: "a\x80b\x81c\x82d",
			want:  "abcd",
		},
		{
			name:  "legitimate UTF-8 not stripped",
			input: "caf\xc3\xa9", // "café" in UTF-8
			want:  "caf\xc3\xa9",
		},
		{
			name:  "UTF-8 multibyte preserved",
			input: "\xe2\x9c\x93 check", // "✓ check" in UTF-8
			want:  "\xe2\x9c\x93 check",
		},
		{
			name:  "UTF-8 CJK preserved",
			input: "\xe4\xb8\xad\xe6\x96\x87", // "中文" in UTF-8
			want:  "\xe4\xb8\xad\xe6\x96\x87",
		},
		{
			name:  "plain ASCII unchanged",
			input: "hello world",
			want:  "hello world",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripDangerousAnsi(tc.input)
			if got != tc.want {
				t.Errorf("stripDangerousAnsi(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestInteractiveFilter_C1Codes verifies that the interactive filter strips
// C1 control codes while preserving legitimate UTF-8 content.
func TestInteractiveFilter_C1Codes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "C1 CSI cursor report via 0x9B",
			input: []byte("before\x9B6nafter"),
			want:  "beforeafter",
		},
		{
			name:  "C1 OSC clipboard hijack via 0x9D",
			input: []byte("before\x9D52;c;payload\x07after"),
			want:  "beforeafter",
		},
		{
			name:  "C1 APC via 0x9F",
			input: []byte("before\x9Fpayload\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "C1 PM via 0x9E with ST",
			input: []byte("before\x9Epayload\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "C1 DCS via 0x90 with ST",
			input: []byte("before\x90payload\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "non-sequence C1 bytes stripped",
			input: []byte("a\x80b\x81c\x82d"),
			want:  "abcd",
		},
		{
			name:  "legitimate UTF-8 not stripped",
			input: []byte("caf\xc3\xa9"),
			want:  "caf\xc3\xa9",
		},
		{
			name:  "UTF-8 multibyte preserved",
			input: []byte("\xe2\x9c\x93 check"),
			want:  "\xe2\x9c\x93 check",
		},
		{
			name:  "plain ASCII unchanged",
			input: []byte("hello world"),
			want:  "hello world",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &interactiveFilter{}
			got, _ := f.process(tc.input)
			if string(got) != tc.want {
				t.Errorf("interactiveFilter.process(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestANSIStateParse_C1Codes verifies that ANSIState.Parse strips C1 control
// codes while preserving legitimate UTF-8 content.
func TestANSIStateParse_C1Codes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "C1 CSI cursor report via 0x9B",
			input: []byte("before\x9B6nafter"),
			want:  "beforeafter",
		},
		{
			name:  "C1 OSC clipboard hijack via 0x9D",
			input: []byte("before\x9D52;c;payload\x07after"),
			want:  "beforeafter",
		},
		{
			name:  "C1 DCS via 0x90",
			input: []byte("before\x90payload\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "non-sequence C1 bytes stripped",
			input: []byte("a\x80b\x81c\x82d"),
			want:  "abcd",
		},
		{
			name:  "legitimate UTF-8 not stripped",
			input: []byte("caf\xc3\xa9"),
			want:  "caf\xc3\xa9",
		},
		{
			name:  "plain ASCII unchanged",
			input: []byte("hello world"),
			want:  "hello world",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewANSIState()
			got := s.Parse(tc.input)
			if string(got) != tc.want {
				t.Errorf("ANSIState.Parse(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── Fix 2: APC/PM/SOS body content leak tests ──────────────────────────────

// TestStripDangerousAnsi_APCBody verifies that APC/PM/SOS body content
// (everything between the introducer and ST terminator) is stripped.
func TestStripDangerousAnsi_APCBody(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "APC body stripped with ST terminator",
			input: "before\x1b_PAYLOAD\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "PM body stripped with ST terminator",
			input: "before\x1b^PAYLOAD\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "SOS body stripped with ST terminator",
			input: "before\x1bXPAYLOAD\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "DCS body preserved (already handled)",
			input: "before\x1bPPAYLOAD\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "APC body stripped at end of string",
			input: "before\x1b_PAYLOAD",
			want:  "before",
		},
		{
			name:  "PM body stripped at end of string",
			input: "before\x1b^PAYLOAD",
			want:  "before",
		},
		{
			name:  "multiple APC sequences stripped",
			input: "a\x1b_P1\x1b\\b\x1b_P2\x1b\\c",
			want:  "abc",
		},
		{
			name:  "APC with dangerous shell commands in body",
			input: "ok\x1b_rm -rf /\x1b\\done",
			want:  "okdone",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripDangerousAnsi(tc.input)
			// Verify PAYLOAD does not appear in output
			if strings.Contains(got, "PAYLOAD") {
				t.Errorf("stripDangerousAnsi(%q) = %q, still contains PAYLOAD", tc.input, got)
			}
			if got != tc.want {
				t.Errorf("stripDangerousAnsi(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── Fix 3: PM/SOS handling in pty_upgrader.go ───────────────────────────────

// TestANSIStateParse_PMBodyConsumed verifies that PM body content is consumed
// up to the ST terminator, not just the 2-byte introducer.
func TestANSIStateParse_PMBodyConsumed(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "PM body consumed with ST",
			input: []byte("before\x1b^PAYLOAD\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "PM body consumed at end of string",
			input: []byte("before\x1b^PAYLOAD"),
			want:  "before",
		},
		{
			name:  "SOS body consumed with ST (correct \x1bX)",
			input: []byte("before\x1bXPAYLOAD\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "SOS body consumed at end of string",
			input: []byte("before\x1bXPAYLOAD"),
			want:  "before",
		},
		{
			name:  "APC body consumed (for completeness)",
			input: []byte("before\x1b_PAYLOAD\x1b\\after"),
			want:  "beforeafter",
		},
		{
			name:  "standalone ST not misidentified as SOS",
			input: []byte("before\x1b\\after"),
			want:  "before\x1b\\after",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewANSIState()
			got := s.Parse(tc.input)
			if strings.Contains(string(got), "PAYLOAD") {
				t.Errorf("ANSIState.Parse(%q) = %q, still contains PAYLOAD", tc.input, got)
			}
			if string(got) != tc.want {
				t.Errorf("ANSIState.Parse(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
