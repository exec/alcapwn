package main

import (
	"testing"
	"time"
)

// ── TestStripDangerousAnsi ──────────────────────────────────────────────────

func TestStripDangerousAnsi(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Normal text
		{
			name:  "plain text unchanged",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},

		// Simple CSI colors — safe, should be preserved
		{
			name:  "CSI color red preserved",
			input: "\x1b[31mred text\x1b[0m",
			want:  "\x1b[31mred text\x1b[0m",
		},
		{
			name:  "CSI bold preserved",
			input: "\x1b[1mbold\x1b[0m",
			want:  "\x1b[1mbold\x1b[0m",
		},
		{
			name:  "CSI 256-color preserved",
			input: "\x1b[38;5;196mcolor\x1b[0m",
			want:  "\x1b[38;5;196mcolor\x1b[0m",
		},

		// Cursor movement — dangerous, should be stripped
		{
			name:  "CSI cursor home stripped",
			input: "before\x1b[Hafter",
			want:  "beforeafter",
		},
		{
			name:  "CSI clear screen stripped",
			input: "before\x1b[2Jafter",
			want:  "beforeafter",
		},
		{
			name:  "CSI cursor up stripped",
			input: "before\x1b[Aafter",
			want:  "beforeafter",
		},
		{
			name:  "CSI cursor down stripped",
			input: "before\x1b[Bafter",
			want:  "beforeafter",
		},
		{
			name:  "CSI cursor forward stripped",
			input: "before\x1b[Cafter",
			want:  "beforeafter",
		},
		{
			name:  "CSI cursor backward stripped",
			input: "before\x1b[Dafter",
			want:  "beforeafter",
		},
		{
			name:  "CSI erase line stripped",
			input: "before\x1b[Kafter",
			want:  "beforeafter",
		},

		// OSC sequences — dangerous, should be stripped entirely
		{
			name:  "OSC 52 clipboard hijack stripped (BEL terminated)",
			input: "before\x1b]52;c;cGF5bG9hZA==\x07after",
			want:  "beforeafter",
		},
		{
			name:  "OSC 52 clipboard hijack stripped (ST terminated)",
			input: "before\x1b]52;c;cGF5bG9hZA==\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "OSC title set stripped",
			input: "before\x1b]0;Evil Title\x07after",
			want:  "beforeafter",
		},

		// APC sequences — body must be fully stripped
		{
			name:  "APC body stripped with ST",
			input: "before\x1b_payload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "APC body stripped at end of string",
			input: "before\x1b_payload",
			want:  "before",
		},

		// PM sequences — body must be fully stripped
		{
			name:  "PM body stripped with ST",
			input: "before\x1b^payload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "PM body stripped at end of string",
			input: "before\x1b^payload",
			want:  "before",
		},

		// SOS sequences — body must be fully stripped
		{
			name:  "SOS body stripped with ST",
			input: "before\x1bXpayload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "SOS body stripped at end of string",
			input: "before\x1bXpayload",
			want:  "before",
		},

		// DCS sequences — stripped
		{
			name:  "DCS body stripped with ST",
			input: "before\x1bPpayload\x1b\\after",
			want:  "beforeafter",
		},

		// C1 control codes (single-byte equivalents)
		{
			name:  "C1 CSI 0x9B stripped",
			input: "before\x9B6nafter",
			want:  "beforeafter",
		},
		{
			name:  "C1 OSC 0x9D stripped",
			input: "before\x9D52;c;payload\x07after",
			want:  "beforeafter",
		},
		{
			name:  "C1 APC 0x9F stripped",
			input: "before\x9Fpayload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "C1 DCS 0x90 stripped",
			input: "before\x90payload\x1b\\after",
			want:  "beforeafter",
		},
		{
			name:  "non-sequence C1 bytes stripped",
			input: "a\x80b\x81c\x82d",
			want:  "abcd",
		},

		// Nested and chained sequences
		{
			name:  "chained color then cursor movement",
			input: "\x1b[31mred\x1b[Hmoved\x1b[0m",
			want:  "\x1b[31mredmoved\x1b[0m",
		},
		{
			name:  "multiple OSC sequences stripped",
			input: "a\x1b]52;c;AAAA\x07b\x1b]0;title\x07c",
			want:  "abc",
		},
		{
			name:  "multiple APC sequences stripped",
			input: "a\x1b_P1\x1b\\b\x1b_P2\x1b\\c",
			want:  "abc",
		},

		// Mixed safe and dangerous
		{
			name:  "safe color around dangerous cursor move",
			input: "\x1b[32msafe\x1b[Hunsafe\x1b[0m",
			want:  "\x1b[32msafeunsafe\x1b[0m",
		},

		// String that is all escape sequences
		{
			name:  "all dangerous sequences",
			input: "\x1b[H\x1b[2J\x1b]0;title\x07",
			want:  "",
		},

		// Private mode sequences — stripped
		{
			name:  "private mode CSI stripped",
			input: "before\x1b[?25hafter",
			want:  "beforeafter",
		},

		// UTF-8 preservation
		{
			name:  "UTF-8 cafe preserved",
			input: "caf\xc3\xa9",
			want:  "caf\xc3\xa9",
		},
		{
			name:  "UTF-8 CJK preserved",
			input: "\xe4\xb8\xad\xe6\x96\x87",
			want:  "\xe4\xb8\xad\xe6\x96\x87",
		},
		{
			name:  "UTF-8 emoji preserved",
			input: "\xf0\x9f\x98\x80 smile",
			want:  "\xf0\x9f\x98\x80 smile",
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

// ── TestContainsAnsiSequences ───────────────────────────────────────────────

func TestContainsAnsiSequences(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "no ANSI sequences",
			input: "plain text",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "simple CSI color — not detected as TUI",
			input: "\x1b[31mred\x1b[0m",
			want:  false,
		},
		{
			name:  "OSC title set detected",
			input: "\x1b]0;window title\x07",
			want:  true,
		},
		{
			name:  "OSC 52 clipboard detected",
			input: "\x1b]52;c;payload\x07",
			want:  true,
		},
		{
			name:  "private mode CSI detected",
			input: "\x1b[?25h",
			want:  true,
		},
		{
			name:  "APC detected via OSC check",
			input: "\x1b]_payload\x1b\\",
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containsAnsiSequences(tc.input)
			if got != tc.want {
				t.Errorf("containsAnsiSequences(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// ── TestFmtAge ──────────────────────────────────────────────────────────────

func TestFmtAge(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{
			name: "zero duration",
			d:    0,
			want: "0s",
		},
		{
			name: "seconds",
			d:    45 * time.Second,
			want: "45s",
		},
		{
			name: "just under a minute",
			d:    59 * time.Second,
			want: "59s",
		},
		{
			name: "exactly one minute",
			d:    time.Minute,
			want: "1m",
		},
		{
			name: "minutes",
			d:    30 * time.Minute,
			want: "30m",
		},
		{
			name: "just under an hour",
			d:    59 * time.Minute,
			want: "59m",
		},
		{
			name: "exactly one hour",
			d:    time.Hour,
			want: "1h",
		},
		{
			name: "multiple hours",
			d:    5 * time.Hour,
			want: "5h",
		},
		{
			name: "large duration (days worth of hours)",
			d:    72 * time.Hour,
			want: "72h",
		},
		{
			name: "1 second",
			d:    time.Second,
			want: "1s",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fmtAge(tc.d)
			if got != tc.want {
				t.Errorf("fmtAge(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}

// ── TestMatchesFilter ───────────────────────────────────────────────────────

func TestMatchesFilter(t *testing.T) {
	mkOS := func(s string) *string { return &s }
	mkHostname := func(s string) *string { return &s }

	tests := []struct {
		name           string
		sess           *Session
		osFilter       string
		hostnameFilter string
		ipFilter       string
		cveFilter      string
		want           bool
	}{
		{
			name: "empty filter matches all",
			sess: &Session{
				RemoteAddr: "10.0.0.5:4444",
				Findings:   &Findings{OS: mkOS("Ubuntu 22.04")},
			},
			want: true,
		},
		{
			name: "IP filter matches remote addr",
			sess: &Session{
				RemoteAddr: "10.0.0.5:4444",
			},
			ipFilter: "10.0.0.5",
			want:     true,
		},
		{
			name: "IP filter no match",
			sess: &Session{
				RemoteAddr: "10.0.0.5:4444",
			},
			ipFilter: "192.168.1.1",
			want:     false,
		},
		{
			name: "hostname filter matches",
			sess: &Session{
				Findings: &Findings{Hostname: mkHostname("webserver01")},
			},
			hostnameFilter: "webserver",
			want:           true,
		},
		{
			name: "hostname filter case insensitive",
			sess: &Session{
				Findings: &Findings{Hostname: mkHostname("WebServer01")},
			},
			hostnameFilter: "webserver",
			want:           true,
		},
		{
			name: "hostname filter no match",
			sess: &Session{
				Findings: &Findings{Hostname: mkHostname("dbserver")},
			},
			hostnameFilter: "webserver",
			want:           false,
		},
		{
			name: "hostname filter with nil Findings",
			sess: &Session{},
			hostnameFilter: "webserver",
			want:           false,
		},
		{
			name: "OS filter matches",
			sess: &Session{
				Findings: &Findings{OS: mkOS("Ubuntu 22.04")},
			},
			osFilter: "ubuntu",
			want:     true,
		},
		{
			name: "OS filter no match",
			sess: &Session{
				Findings: &Findings{OS: mkOS("CentOS 7")},
			},
			osFilter: "ubuntu",
			want:     false,
		},
		{
			name: "OS filter with nil Findings",
			sess: &Session{},
			osFilter: "ubuntu",
			want:     false,
		},
		{
			name: "OS filter with nil OS field",
			sess: &Session{
				Findings: &Findings{},
			},
			osFilter: "ubuntu",
			want:     false,
		},
		{
			name: "CVE filter matches when candidates exist",
			sess: &Session{
				Findings: &Findings{
					CveCandidates: []CveCandidate{
						{CVE: "CVE-2021-4034", Severity: "critical"},
					},
				},
			},
			cveFilter: "cve",
			want:      true,
		},
		{
			name: "CVE filter no match when no candidates",
			sess: &Session{
				Findings: &Findings{
					CveCandidates: []CveCandidate{},
				},
			},
			cveFilter: "cve",
			want:      false,
		},
		{
			name: "CVE severity filter critical",
			sess: &Session{
				Findings: &Findings{
					CveCandidates: []CveCandidate{
						{CVE: "CVE-2021-4034", Severity: "critical"},
					},
				},
			},
			cveFilter: "critical",
			want:      true,
		},
		{
			name: "CVE severity filter critical when only high",
			sess: &Session{
				Findings: &Findings{
					CveCandidates: []CveCandidate{
						{CVE: "CVE-2023-1234", Severity: "high"},
					},
				},
			},
			cveFilter: "critical",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFilter(tc.sess, tc.osFilter, tc.hostnameFilter, tc.ipFilter, tc.cveFilter)
			if got != tc.want {
				t.Errorf("matchesFilter() = %v, want %v", got, tc.want)
			}
		})
	}
}
