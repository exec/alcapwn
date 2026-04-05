package main

import (
	"testing"
)

// ── TestVersionBefore ────────────────────────────────────────────────────────

func TestVersionBefore(t *testing.T) {
	tests := []struct {
		name                               string
		maj, min, pat, pnum                int
		tMaj, tMin, tPat, tPnum            int
		want                               bool
	}{
		{
			name: "1.8.0 before 1.9.0",
			maj: 1, min: 8, pat: 0, pnum: 0,
			tMaj: 1, tMin: 9, tPat: 0, tPnum: 0,
			want: true,
		},
		{
			name: "1.9.5 not before 1.9.5 (equal)",
			maj: 1, min: 9, pat: 5, pnum: 0,
			tMaj: 1, tMin: 9, tPat: 5, tPnum: 0,
			want: false,
		},
		{
			name: "1.9.5p2 before 1.9.5p3",
			maj: 1, min: 9, pat: 5, pnum: 2,
			tMaj: 1, tMin: 9, tPat: 5, tPnum: 3,
			want: true,
		},
		{
			name: "2.0.0 not before 1.9.9",
			maj: 2, min: 0, pat: 0, pnum: 0,
			tMaj: 1, tMin: 9, tPat: 9, tPnum: 0,
			want: false,
		},
		{
			name: "1.8.0 before 1.8.1 (fewer components as zero)",
			maj: 1, min: 8, pat: 0, pnum: 0,
			tMaj: 1, tMin: 8, tPat: 1, tPnum: 0,
			want: true,
		},
		{
			name: "major less",
			maj: 0, min: 105, pat: 0, pnum: 0,
			tMaj: 0, tMin: 120, tPat: 0, tPnum: 0,
			want: true,
		},
		{
			name: "major greater",
			maj: 0, min: 120, pat: 0, pnum: 0,
			tMaj: 0, tMin: 105, tPat: 0, tPnum: 0,
			want: false,
		},
		{
			name: "pnum only diff, less",
			maj: 1, min: 9, pat: 5, pnum: 1,
			tMaj: 1, tMin: 9, tPat: 5, tPnum: 2,
			want: true,
		},
		{
			name: "pnum only diff, greater",
			maj: 1, min: 9, pat: 5, pnum: 3,
			tMaj: 1, tMin: 9, tPat: 5, tPnum: 2,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := versionBefore(tc.maj, tc.min, tc.pat, tc.pnum, tc.tMaj, tc.tMin, tc.tPat, tc.tPnum)
			if got != tc.want {
				t.Errorf("versionBefore(%d.%d.%dp%d, %d.%d.%dp%d) = %v, want %v",
					tc.maj, tc.min, tc.pat, tc.pnum,
					tc.tMaj, tc.tMin, tc.tPat, tc.tPnum,
					got, tc.want)
			}
		})
	}
}

// ── TestParseSudoNopasswd ────────────────────────────────────────────────────

func TestParseSudoNopasswd(t *testing.T) {
	t.Run("basic NOPASSWD ALL", func(t *testing.T) {
		output := `User testuser may run the following commands on host:
    (ALL) NOPASSWD: ALL
`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].User != "testuser" {
			t.Errorf("user = %q, want %q", entries[0].User, "testuser")
		}
		if entries[0].Command != "ALL" {
			t.Errorf("command = %q, want %q", entries[0].Command, "ALL")
		}
		if !entries[0].Nopasswd {
			t.Error("expected Nopasswd to be true")
		}
		if entries[0].NegatedRoot {
			t.Error("expected NegatedRoot to be false")
		}
	})

	t.Run("constrained command", func(t *testing.T) {
		output := `User admin may run the following commands on host:
    (root) NOPASSWD: /usr/bin/vim
`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].Command != "/usr/bin/vim" {
			t.Errorf("command = %q, want %q", entries[0].Command, "/usr/bin/vim")
		}
	})

	t.Run("negated root", func(t *testing.T) {
		output := `User deploy may run the following commands on host:
    (ALL, !root) NOPASSWD: /bin/bash
`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if !entries[0].NegatedRoot {
			t.Error("expected NegatedRoot to be true for (ALL, !root)")
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		output := `User admin may run the following commands on host:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /usr/bin/vim
`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 1 {
			t.Fatalf("expected 1 entry after deduplication, got %d", len(entries))
		}
	})

	t.Run("multiple distinct commands", func(t *testing.T) {
		output := `User ops may run the following commands on host:
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/vim
`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 2 {
			t.Fatalf("expected 2 entries, got %d", len(entries))
		}
	})

	t.Run("empty output", func(t *testing.T) {
		p := &ReconParser{}
		entries := p.parseSudoNopasswd("")

		if len(entries) != 0 {
			t.Fatalf("expected 0 entries for empty output, got %d", len(entries))
		}
	})

	t.Run("SUDO_REQUIRES_PASSWORD without NOPASSWD", func(t *testing.T) {
		output := `SUDO_REQUIRES_PASSWORD`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 0 {
			t.Fatalf("expected 0 entries when no NOPASSWD lines, got %d", len(entries))
		}
	})

	t.Run("username at start of line", func(t *testing.T) {
		output := `admin ALL=(ALL) NOPASSWD: ALL
`
		p := &ReconParser{}
		entries := p.parseSudoNopasswd(output)

		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].User != "admin" {
			t.Errorf("user = %q, want %q", entries[0].User, "admin")
		}
	})
}

// ── TestParseSuidSgid ────────────────────────────────────────────────────────

func TestParseSuidSgid(t *testing.T) {
	t.Run("find output format", func(t *testing.T) {
		output := `SUID binaries:
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgrp
SGID binaries:
/usr/bin/wall
/usr/bin/ssh-agent
`
		p := &ReconParser{}
		result := p.parseSuidSgid(output)

		if len(result.suid) != 3 {
			t.Fatalf("expected 3 SUID binaries, got %d: %v", len(result.suid), result.suid)
		}
		if len(result.sgid) != 2 {
			t.Fatalf("expected 2 SGID binaries, got %d: %v", len(result.sgid), result.sgid)
		}
		if result.suid[0] != "/usr/bin/passwd" {
			t.Errorf("suid[0] = %q, want %q", result.suid[0], "/usr/bin/passwd")
		}
		if result.sgid[0] != "/usr/bin/wall" {
			t.Errorf("sgid[0] = %q, want %q", result.sgid[0], "/usr/bin/wall")
		}
	})

	t.Run("empty output", func(t *testing.T) {
		p := &ReconParser{}
		result := p.parseSuidSgid("")

		if len(result.suid) != 0 {
			t.Fatalf("expected 0 SUID for empty, got %d", len(result.suid))
		}
		if len(result.sgid) != 0 {
			t.Fatalf("expected 0 SGID for empty, got %d", len(result.sgid))
		}
	})

	t.Run("ls -l format with SUID bit", func(t *testing.T) {
		output := `SUID binaries:
-rwsr-xr-x 1 root root 12345 Jan 1 00:00 /usr/bin/passwd
`
		p := &ReconParser{}
		result := p.parseSuidSgid(output)

		if len(result.suid) != 1 {
			t.Fatalf("expected 1 SUID binary from ls -l format, got %d: %v", len(result.suid), result.suid)
		}
		if result.suid[0] != "/usr/bin/passwd" {
			t.Errorf("suid[0] = %q, want %q", result.suid[0], "/usr/bin/passwd")
		}
	})

	t.Run("skips comments and blank lines", func(t *testing.T) {
		output := `SUID binaries:
# comment line
/usr/bin/su

/usr/bin/sudo
`
		p := &ReconParser{}
		result := p.parseSuidSgid(output)

		if len(result.suid) != 2 {
			t.Fatalf("expected 2 SUID binaries (skipping comments/blanks), got %d: %v", len(result.suid), result.suid)
		}
	})

	t.Run("custom paths in /opt and /home", func(t *testing.T) {
		output := `SUID binaries:
/opt/custom_tool
/home/user/my_suid_binary
`
		p := &ReconParser{}
		result := p.parseSuidSgid(output)

		if len(result.suid) != 2 {
			t.Fatalf("expected 2 SUID binaries from custom paths, got %d", len(result.suid))
		}
	})
}

// ── TestCheckCVECandidates ───────────────────────────────────────────────────

func TestCheckCVECandidates(t *testing.T) {
	t.Run("Baron Samedit detected for sudo below 1.9.5p2", func(t *testing.T) {
		p := &ReconParser{}
		f := newFindings()

		// Note: checkCVECandidates checks strings.Contains(sudoOutput, "sudo")
		// with lowercase "sudo". Real `sudo -l` output includes "Sudo version"
		// (capital S, parsed by reSudoVersion) plus lines containing "sudo"
		// in lowercase (e.g., the user privileges line).
		sections := map[string]string{
			"SUDO ACCESS":              "User sudo privileges:\nSudo version 1.8.31\nUser test may run the following commands:\n    (ALL) NOPASSWD: ALL",
			"SUID/SGID BINARIES":       "",
			"CAPABILITIES":             "",
			"ENVIRONMENT & TOOLS":      "",
			"WRITABLE PATHS":           "",
		}

		// Parse sudo first to populate SudoNopasswd
		f.SudoNopasswd = p.parseSudoNopasswd(sections["SUDO ACCESS"])
		f.SudoRequiresPassword = false

		candidates := p.checkCVECandidates(f, sections)

		foundBaronSamedit := false
		for _, c := range candidates {
			if c.CVE == "CVE-2021-3156" {
				foundBaronSamedit = true
				if c.Confidence != "high" {
					t.Errorf("expected high confidence, got %q", c.Confidence)
				}
				break
			}
		}
		if !foundBaronSamedit {
			t.Error("expected CVE-2021-3156 (Baron Samedit) to be detected for sudo 1.8.31")
		}
	})

	t.Run("Baron Samedit not detected for sudo above 1.9.5p2", func(t *testing.T) {
		p := &ReconParser{}
		f := newFindings()

		sections := map[string]string{
			"SUDO ACCESS":              "User sudo privileges:\nSudo version 1.9.12p1\nUser test may run the following commands:\n    (ALL) NOPASSWD: ALL",
			"SUID/SGID BINARIES":       "",
			"CAPABILITIES":             "",
			"ENVIRONMENT & TOOLS":      "",
			"WRITABLE PATHS":           "",
		}

		f.SudoNopasswd = p.parseSudoNopasswd(sections["SUDO ACCESS"])
		f.SudoRequiresPassword = false

		candidates := p.checkCVECandidates(f, sections)

		for _, c := range candidates {
			if c.CVE == "CVE-2021-3156" {
				t.Error("did not expect CVE-2021-3156 to be detected for sudo 1.9.12p1")
			}
		}
	})

	t.Run("Baron Samedit skipped when sudo requires password", func(t *testing.T) {
		p := &ReconParser{}
		f := newFindings()
		f.SudoRequiresPassword = true

		sections := map[string]string{
			"SUDO ACCESS":              "sudo version 1.8.0\nSUDO_REQUIRES_PASSWORD",
			"SUID/SGID BINARIES":       "",
			"CAPABILITIES":             "",
			"ENVIRONMENT & TOOLS":      "",
			"WRITABLE PATHS":           "",
		}

		candidates := p.checkCVECandidates(f, sections)

		for _, c := range candidates {
			if c.CVE == "CVE-2021-3156" {
				t.Error("did not expect CVE-2021-3156 when sudo requires password")
			}
		}
	})

	t.Run("PwnKit detected for pkexec in SUID", func(t *testing.T) {
		p := &ReconParser{}
		f := newFindings()

		sections := map[string]string{
			"SUDO ACCESS":              "",
			"SUID/SGID BINARIES":       "/usr/bin/pkexec",
			"CAPABILITIES":             "",
			"ENVIRONMENT & TOOLS":      "",
			"WRITABLE PATHS":           "",
		}

		candidates := p.checkCVECandidates(f, sections)

		foundPwnKit := false
		for _, c := range candidates {
			if c.CVE == "CVE-2021-4034" {
				foundPwnKit = true
				break
			}
		}
		if !foundPwnKit {
			t.Error("expected CVE-2021-4034 (PwnKit) when pkexec is SUID and version undetected")
		}
	})

	t.Run("writable /etc/passwd detected", func(t *testing.T) {
		p := &ReconParser{}
		f := newFindings()

		sections := map[string]string{
			"SUDO ACCESS":              "",
			"SUID/SGID BINARIES":       "",
			"CAPABILITIES":             "",
			"ENVIRONMENT & TOOLS":      "",
			"WRITABLE PATHS":           "/etc/passwd\n/tmp",
		}

		candidates := p.checkCVECandidates(f, sections)

		foundWritablePasswd := false
		for _, c := range candidates {
			if c.CVE == "WRT-PASSWD" {
				foundWritablePasswd = true
				break
			}
		}
		if !foundWritablePasswd {
			t.Error("expected WRT-PASSWD when /etc/passwd is in writable paths")
		}
	})
}

// ── TestStringToInt ──────────────────────────────────────────────────────────

func TestStringToInt(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   int
		wantOK bool
	}{
		{name: "valid zero", input: "0", want: 0, wantOK: true},
		{name: "valid positive", input: "42", want: 42, wantOK: true},
		{name: "valid large", input: "999999", want: 999999, wantOK: true},
		{name: "empty string", input: "", want: 0, wantOK: false},
		{name: "non-numeric", input: "abc", want: 0, wantOK: false},
		{name: "partial number", input: "12abc", want: 12, wantOK: true},
		{name: "negative", input: "-5", want: -5, wantOK: true},
		{name: "whitespace prefix", input: " 10", want: 10, wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := stringToInt(tc.input)
			if ok != tc.wantOK {
				t.Errorf("stringToInt(%q) ok = %v, want %v", tc.input, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("stringToInt(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// ── TestTruncate ─────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{name: "short string", input: "hello", maxLen: 10, want: "hello"},
		{name: "exact length", input: "hello", maxLen: 5, want: "hello"},
		{name: "truncated", input: "hello world", maxLen: 5, want: "hello"},
		{name: "empty", input: "", maxLen: 5, want: ""},
		{name: "zero max", input: "hello", maxLen: 0, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.input, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
			}
		})
	}
}

// ── TestParsePolkitInfo ──────────────────────────────────────────────────────

func TestParsePolkitInfo(t *testing.T) {
	t.Run("dpkg patched version", func(t *testing.T) {
		output := "polkit-pkg: polkit 0.105-33"
		info := parsePolkitInfo(output)
		if !info.havePackageVersion {
			t.Error("expected havePackageVersion to be true")
		}
		if !info.isPatched {
			t.Error("expected isPatched to be true for 0.105-33")
		}
	})

	t.Run("dpkg unpatched version", func(t *testing.T) {
		output := "polkit-pkg: polkit 0.105-20"
		info := parsePolkitInfo(output)
		if !info.havePackageVersion {
			t.Error("expected havePackageVersion to be true")
		}
		if info.isPatched {
			t.Error("expected isPatched to be false for 0.105-20")
		}
	})

	t.Run("pkexec upstream patched", func(t *testing.T) {
		output := "pkexec version 0.120"
		info := parsePolkitInfo(output)
		if info.havePackageVersion {
			t.Error("expected havePackageVersion to be false for pkexec --version")
		}
		if !info.isPatched {
			t.Error("expected isPatched to be true for pkexec 0.120")
		}
	})

	t.Run("undetected version", func(t *testing.T) {
		output := "some random output"
		info := parsePolkitInfo(output)
		if info.versionStr != "" {
			t.Errorf("expected empty versionStr, got %q", info.versionStr)
		}
	})
}
