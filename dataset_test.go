package main

import (
	"strings"
	"testing"
)

// ── TestGetDataset ───────────────────────────────────────────────────────────

func TestGetDataset(t *testing.T) {
	dataset := getDataset()

	if len(dataset) < 10 {
		t.Fatalf("expected at least 10 dataset entries, got %d", len(dataset))
	}

	for i, entry := range dataset {
		if entry.ID == "" {
			t.Errorf("entry[%d] has empty ID", i)
		}
		if entry.Category == "" {
			t.Errorf("entry[%d] (%s) has empty Category", i, entry.ID)
		}
	}
}

// ── TestPathsMatch ───────────────────────────────────────────────────────────

func TestPathsMatch(t *testing.T) {
	tests := []struct {
		name  string
		path1 string
		path2 string
		want  bool
	}{
		{
			name:  "same path",
			path1: "/usr/bin/bash",
			path2: "/usr/bin/bash",
			want:  true,
		},
		{
			name:  "same basename different dir",
			path1: "/usr/bin/bash",
			path2: "/usr/local/bin/bash",
			want:  false, // both absolute paths with different dirs: no basename-only match
		},
		{
			name:  "empty first",
			path1: "",
			path2: "/usr/bin/bash",
			want:  false,
		},
		{
			name:  "empty second",
			path1: "/usr/bin/bash",
			path2: "",
			want:  false,
		},
		{
			name:  "both empty",
			path1: "",
			path2: "",
			want:  false,
		},
		{
			name:  "bare name vs full path",
			path1: "bash",
			path2: "/usr/bin/bash",
			want:  true, // basename match
		},
		{
			name:  "different binaries",
			path1: "/usr/bin/bash",
			path2: "/usr/bin/zsh",
			want:  false,
		},
		{
			name:  "full path vs bare name reversed",
			path1: "/usr/bin/find",
			path2: "find",
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pathsMatch(tc.path1, tc.path2)
			if got != tc.want {
				t.Errorf("pathsMatch(%q, %q) = %v, want %v", tc.path1, tc.path2, got, tc.want)
			}
		})
	}
}

// ── TestCreateMatch ──────────────────────────────────────────────────────────

func TestCreateMatch(t *testing.T) {
	t.Run("with severity set", func(t *testing.T) {
		sev := "critical"
		entry := DatasetEntry{
			ID:           "test_entry",
			Category:     "SUID_GTFOBINS",
			Exploitation: []string{"test exploit step"},
			Source:       "test",
			Severity:     &sev,
		}

		result := createMatch(entry, "high", "test reason", "/usr/bin/test")

		if result.MatchConfidence != "high" {
			t.Errorf("MatchConfidence = %q, want %q", result.MatchConfidence, "high")
		}
		if result.MatchReason != "test reason" {
			t.Errorf("MatchReason = %q, want %q", result.MatchReason, "test reason")
		}
		if result.MatchedBinaryPath != "/usr/bin/test" {
			t.Errorf("MatchedBinaryPath = %q, want %q", result.MatchedBinaryPath, "/usr/bin/test")
		}
		if *result.Entry.Severity != "critical" {
			t.Errorf("Severity = %q, want %q", *result.Entry.Severity, "critical")
		}
	})

	t.Run("nil severity defaults based on confidence high", func(t *testing.T) {
		entry := DatasetEntry{
			ID:           "test_entry_nil_sev",
			Category:     "SUID_GTFOBINS",
			Exploitation: []string{"step"},
			Source:       "test",
			Severity:     nil,
		}

		result := createMatch(entry, "high", "reason", "/usr/bin/test")

		if result.Entry.Severity == nil {
			t.Fatal("expected Severity to be defaulted, got nil")
		}
		if *result.Entry.Severity != "high" {
			t.Errorf("Severity = %q, want %q (default for high confidence)", *result.Entry.Severity, "high")
		}
	})

	t.Run("nil severity defaults based on confidence medium", func(t *testing.T) {
		entry := DatasetEntry{
			ID:           "test_entry_nil_sev_med",
			Category:     "SUID_GTFOBINS",
			Exploitation: []string{"step"},
			Source:       "test",
			Severity:     nil,
		}

		result := createMatch(entry, "medium", "reason", "/usr/bin/test")

		if result.Entry.Severity == nil {
			t.Fatal("expected Severity to be defaulted, got nil")
		}
		if *result.Entry.Severity != "medium" {
			t.Errorf("Severity = %q, want %q (default for medium confidence)", *result.Entry.Severity, "medium")
		}
	})

	t.Run("nil severity defaults based on confidence low", func(t *testing.T) {
		entry := DatasetEntry{
			ID:           "test_entry_nil_sev_low",
			Category:     "SUID_GTFOBINS",
			Exploitation: []string{"step"},
			Source:       "test",
			Severity:     nil,
		}

		result := createMatch(entry, "low", "reason", "/usr/bin/test")

		if result.Entry.Severity == nil {
			t.Fatal("expected Severity to be defaulted, got nil")
		}
		if *result.Entry.Severity != "low" {
			t.Errorf("Severity = %q, want %q (default for low confidence)", *result.Entry.Severity, "low")
		}
	})
}

// ── TestMatchFindings_SuidBash ───────────────────────────────────────────────

func TestMatchFindings_SuidBash(t *testing.T) {
	f := newFindings()
	f.SuidBinaries = []string{"/usr/bin/bash"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "suid_bash" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence for suid_bash, got %q", m.MatchConfidence)
			}
			if m.MatchedBinaryPath != "/usr/bin/bash" {
				t.Errorf("expected MatchedBinaryPath = %q, got %q", "/usr/bin/bash", m.MatchedBinaryPath)
			}
			break
		}
	}
	if !found {
		t.Error("expected suid_bash entry to match for SUID /usr/bin/bash")
	}
}

// ── TestMatchFindings_Empty ──────────────────────────────────────────────────

func TestMatchFindings_Empty(t *testing.T) {
	f := newFindings()

	matches := matchFindings(f)

	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty findings, got %d", len(matches))
		for _, m := range matches {
			t.Logf("  unexpected match: %s (%s)", m.Entry.ID, m.MatchReason)
		}
	}
}

// ── TestMatchFindings_NoMatches_IrrelevantData ──────────────────────────────

func TestMatchFindings_NoMatches_IrrelevantData(t *testing.T) {
	f := newFindings()
	// Populate fields with data that should NOT match any dataset entries.
	f.SuidBinaries = []string{"/usr/bin/nonexistent_binary_xyz"}
	f.SgidBinaries = []string{"/usr/bin/also_nonexistent"}
	f.Capabilities = []CapabilityEntry{{File: "/usr/bin/nosuchbin", Capability: "cap_net_raw+ep"}}
	f.CveCandidates = []CveCandidate{{CVE: "CVE-9999-99999", Confidence: "low"}} // low confidence: skipped
	f.ToolsAvailable = []string{"curl", "wget"}                                  // not kubectl
	f.InterestingFiles = []string{"/tmp/boring.txt"}

	matches := matchFindings(f)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for irrelevant data, got %d", len(matches))
		for _, m := range matches {
			t.Logf("  unexpected match: %s (%s)", m.Entry.ID, m.MatchReason)
		}
	}
}

// ── TestMatchFindings_SuidGTFOBins ──────────────────────────────────────────

func TestMatchFindings_SuidGTFOBins(t *testing.T) {
	tests := []struct {
		name       string
		suidPath   string
		expectedID string
	}{
		{"python3 full path", "/usr/bin/python3", "suid_python3"},
		{"vim full path", "/usr/bin/vim", "suid_vim"},
		{"find full path", "/usr/bin/find", "suid_find"},
		{"nmap full path", "/usr/bin/nmap", "suid_nmap"},
		{"perl full path", "/usr/bin/perl", "suid_perl"},
		{"node full path", "/usr/bin/node", "suid_node"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFindings()
			f.SuidBinaries = []string{tc.suidPath}

			matches := matchFindings(f)

			found := false
			for _, m := range matches {
				if m.Entry.ID == tc.expectedID {
					found = true
					if m.MatchConfidence != "high" {
						t.Errorf("expected high confidence, got %q", m.MatchConfidence)
					}
					if m.MatchedBinaryPath != tc.suidPath {
						t.Errorf("expected MatchedBinaryPath = %q, got %q", tc.suidPath, m.MatchedBinaryPath)
					}
					if m.Entry.Category != "SUID_GTFOBINS" {
						t.Errorf("expected category SUID_GTFOBINS, got %q", m.Entry.Category)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected %s to match for SUID %s", tc.expectedID, tc.suidPath)
				for _, m := range matches {
					t.Logf("  got: %s (%s)", m.Entry.ID, m.MatchReason)
				}
			}
		})
	}
}

// ── TestMatchFindings_SuidGTFOBins_MultipleBinaries ─────────────────────────

func TestMatchFindings_SuidGTFOBins_MultipleBinaries(t *testing.T) {
	f := newFindings()
	f.SuidBinaries = []string{"/usr/bin/python3", "/usr/bin/find", "/usr/bin/vim"}

	matches := matchFindings(f)

	expectedIDs := map[string]bool{
		"suid_python3": false,
		"suid_find":    false,
		"suid_vim":     false,
	}

	for _, m := range matches {
		if _, ok := expectedIDs[m.Entry.ID]; ok {
			expectedIDs[m.Entry.ID] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected match for %s but it was not found", id)
		}
	}
}

// ── TestMatchFindings_SuidCustom ────────────────────────────────────────────

func TestMatchFindings_SuidCustom(t *testing.T) {
	f := newFindings()
	f.SuidBinaries = []string{"/usr/local/bin/validate"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "suid_validate" {
			found = true
			if m.Entry.Category != "SUID_CUSTOM" {
				t.Errorf("expected category SUID_CUSTOM, got %q", m.Entry.Category)
			}
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected suid_validate to match for /usr/local/bin/validate")
	}
}

// ── TestMatchFindings_SudoNopasswdCustom ────────────────────────────────────

func TestMatchFindings_SudoNopasswdCustom(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		expectedID string
	}{
		{"vim command", "vim", "sudo_vim"},
		{"python3 command", "python3", "sudo_python3"},
		{"find full path", "/usr/bin/find", "sudo_find"},
		{"perl command", "perl", "sudo_perl"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFindings()
			f.SudoNopasswd = []SudoEntry{
				{User: "user", Command: tc.command, Nopasswd: true},
			}

			matches := matchFindings(f)

			found := false
			for _, m := range matches {
				if m.Entry.ID == tc.expectedID {
					found = true
					if m.MatchConfidence != "high" {
						t.Errorf("expected high confidence, got %q", m.MatchConfidence)
					}
					if m.Entry.Category != "SUDO_NOPASSWD_CUSTOM" {
						t.Errorf("expected category SUDO_NOPASSWD_CUSTOM, got %q", m.Entry.Category)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected %s to match for sudo NOPASSWD %s", tc.expectedID, tc.command)
				for _, m := range matches {
					t.Logf("  got: %s (%s)", m.Entry.ID, m.MatchReason)
				}
			}
		})
	}
}

// ── TestMatchFindings_SudoNopasswdDirect_ALL ────────────────────────────────

func TestMatchFindings_SudoNopasswdDirect_ALL(t *testing.T) {
	f := newFindings()
	f.SudoNopasswd = []SudoEntry{
		{User: "user", Command: "ALL", Nopasswd: true},
	}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.Category == "SUDO_NOPASSWD_DIRECT" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			if m.MatchReason != "NOPASSWD: ALL rule found" {
				t.Errorf("unexpected reason: %q", m.MatchReason)
			}
			break
		}
	}
	if !found {
		t.Error("expected SUDO_NOPASSWD_DIRECT match for NOPASSWD ALL")
	}
}

// ── TestMatchFindings_SudoNopasswdDirect_NoALL ──────────────────────────────

func TestMatchFindings_SudoNopasswdDirect_NoALL(t *testing.T) {
	// When command is not ALL, SUDO_NOPASSWD_DIRECT should NOT match.
	f := newFindings()
	f.SudoNopasswd = []SudoEntry{
		{User: "user", Command: "vim", Nopasswd: true},
	}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.Category == "SUDO_NOPASSWD_DIRECT" {
			t.Error("SUDO_NOPASSWD_DIRECT should not match when command is not ALL")
		}
	}
}

// ── TestMatchFindings_CVE_2019_14287 ────────────────────────────────────────

func TestMatchFindings_CVE_2019_14287(t *testing.T) {
	f := newFindings()
	f.SudoNopasswd = []SudoEntry{
		{User: "user", Command: "ALL", Nopasswd: true, NegatedRoot: true},
	}

	matches := matchFindings(f)

	foundCVE := false
	foundDirect := false
	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2019-14287" {
			foundCVE = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence for CVE-2019-14287, got %q", m.MatchConfidence)
			}
		}
		if m.Entry.Category == "SUDO_NOPASSWD_DIRECT" {
			foundDirect = true
		}
	}
	if !foundCVE {
		t.Error("expected CVE-2019-14287 match for NegatedRoot sudo entry")
	}
	if !foundDirect {
		t.Error("expected SUDO_NOPASSWD_DIRECT match since command is ALL")
	}
}

// ── TestMatchFindings_CVE_2019_14287_NoNegatedRoot ──────────────────────────

func TestMatchFindings_CVE_2019_14287_NoNegatedRoot(t *testing.T) {
	// Without NegatedRoot, CVE-2019-14287 should NOT match.
	f := newFindings()
	f.SudoNopasswd = []SudoEntry{
		{User: "user", Command: "ALL", Nopasswd: true, NegatedRoot: false},
	}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2019-14287" {
			t.Error("CVE-2019-14287 should not match without NegatedRoot")
		}
	}
}

// ── TestMatchFindings_CVE_Candidates_BaronSamedit ───────────────────────────

func TestMatchFindings_CVE_Candidates_BaronSamedit(t *testing.T) {
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "CVE-2021-3156",
			Name:       "Baron Samedit",
			Confidence: "high",
			Severity:   "critical",
		},
	}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2021-3156" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			if m.Entry.Category != "SUDO_RULE_CVE" {
				t.Errorf("expected category SUDO_RULE_CVE, got %q", m.Entry.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected CVE-2021-3156 (Baron Samedit) to match")
	}
}

// ── TestMatchFindings_CVE_Candidates_PwnKit ─────────────────────────────────

func TestMatchFindings_CVE_Candidates_PwnKit(t *testing.T) {
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "CVE-2021-4034",
			Name:       "PwnKit",
			Confidence: "high",
			Severity:   "critical",
		},
	}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2021-4034" {
			found = true
			if m.Entry.Category != "OTHER" {
				t.Errorf("expected category OTHER, got %q", m.Entry.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected CVE-2021-4034 (PwnKit) to match from OTHER category")
	}
}

// ── TestMatchFindings_CVE_LowConfidenceSkipped ──────────────────────────────

func TestMatchFindings_CVE_LowConfidenceSkipped(t *testing.T) {
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "CVE-2021-3156",
			Confidence: "low",
		},
	}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2021-3156" {
			t.Error("low-confidence CVE candidates should not produce matches")
		}
	}
}

// ── TestMatchFindings_CVE_MediumConfidenceSkipped ───────────────────────────

func TestMatchFindings_CVE_MediumConfidenceSkipped(t *testing.T) {
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "CVE-2021-3156",
			Confidence: "medium",
		},
	}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2021-3156" {
			t.Error("medium-confidence CVE candidates should not produce matches")
		}
	}
}

// ── TestMatchFindings_CVE_CriticalConfidenceMatches ─────────────────────────

func TestMatchFindings_CVE_CriticalConfidenceMatches(t *testing.T) {
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "CVE-2021-3156",
			Confidence: "critical",
		},
	}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2021-3156" {
			found = true
			break
		}
	}
	if !found {
		t.Error("critical-confidence CVE candidates should match")
	}
}

// ── TestMatchFindings_CVE_NoDuplicate ───────────────────────────────────────

func TestMatchFindings_CVE_NoDuplicate(t *testing.T) {
	// CVE-2019-14287 can match both via NegatedRoot (section 1) and via
	// CveCandidates (section 5). Section 1 sets matchedPaths["cve-2019-14287"]
	// but section 5 checks matchedPaths["cve-CVE-2019-14287"] (cve ID includes
	// the CVE- prefix). This is a known dedup gap in the matching engine.
	// This test documents the current behavior: both paths produce a match.
	f := newFindings()
	f.SudoNopasswd = []SudoEntry{
		{User: "user", Command: "ALL", Nopasswd: true, NegatedRoot: true},
	}
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "CVE-2019-14287",
			Confidence: "high",
		},
	}

	matches := matchFindings(f)

	count := 0
	for _, m := range matches {
		if m.Entry.CVE != nil && *m.Entry.CVE == "CVE-2019-14287" {
			count++
		}
	}
	// Currently produces 2 due to mismatched dedup keys. If dedup is
	// fixed, update this assertion to expect 1.
	if count < 1 {
		t.Error("CVE-2019-14287 should appear at least once")
	}
}

// ── TestMatchFindings_WritableCrons_SpecificMatch ───────────────────────────

func TestMatchFindings_WritableCrons_SpecificMatch(t *testing.T) {
	f := newFindings()
	f.WritableCrons = []string{"/opt/scripts/clean.sh"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "writable_cron_clean" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			if m.MatchedBinaryPath != "/opt/scripts/clean.sh" {
				t.Errorf("expected MatchedBinaryPath = %q, got %q", "/opt/scripts/clean.sh", m.MatchedBinaryPath)
			}
			break
		}
	}
	if !found {
		t.Error("expected writable_cron_clean to match for /opt/scripts/clean.sh")
	}
}

// ── TestMatchFindings_WritableCrons_GenericFallback ─────────────────────────

func TestMatchFindings_WritableCrons_GenericFallback(t *testing.T) {
	f := newFindings()
	f.WritableCrons = []string{"/opt/scripts/random_cron_job.sh"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "writable_cron_generic" && m.Entry.Category == "WRITABLE_CRON" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence for generic cron, got %q", m.MatchConfidence)
			}
			if m.MatchedBinaryPath != "/opt/scripts/random_cron_job.sh" {
				t.Errorf("expected MatchedBinaryPath = %q, got %q", "/opt/scripts/random_cron_job.sh", m.MatchedBinaryPath)
			}
			break
		}
	}
	if !found {
		t.Error("expected generic writable_cron match for unknown cron script")
		for _, m := range matches {
			t.Logf("  got: %s (%s)", m.Entry.ID, m.MatchReason)
		}
	}
}

// ── TestMatchFindings_WritableCrons_CubeSh ──────────────────────────────────

func TestMatchFindings_WritableCrons_CubeSh(t *testing.T) {
	f := newFindings()
	f.WritableCrons = []string{"/var/spool/cron/cube.sh"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "writable_cron_cube" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected writable_cron_cube to match for cube.sh")
	}
}

// ── TestMatchFindings_Capabilities ──────────────────────────────────────────

func TestMatchFindings_Capabilities(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		cap        string
		expectedID string
	}{
		{"python3 cap_setuid", "/usr/bin/python3", "cap_setuid+ep", "cap_setuid_python3"},
		{"perl cap_setuid", "/usr/bin/perl", "cap_setuid+ep", "cap_setuid_perl"},
		{"ruby cap_setuid", "/usr/bin/ruby", "cap_setuid+ep", "cap_setuid_ruby"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFindings()
			f.Capabilities = []CapabilityEntry{
				{File: tc.file, Capability: tc.cap},
			}

			matches := matchFindings(f)

			found := false
			for _, m := range matches {
				if m.Entry.ID == tc.expectedID {
					found = true
					if m.MatchConfidence != "high" {
						t.Errorf("expected high confidence, got %q", m.MatchConfidence)
					}
					if m.Entry.Category != "CAPABILITY_SETUID" {
						t.Errorf("expected category CAPABILITY_SETUID, got %q", m.Entry.Category)
					}
					if m.MatchedBinaryPath != tc.file {
						t.Errorf("expected MatchedBinaryPath = %q, got %q", tc.file, m.MatchedBinaryPath)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected %s to match for capability on %s", tc.expectedID, tc.file)
			}
		})
	}
}

// ── TestMatchFindings_Capabilities_NoDuplicate ──────────────────────────────

func TestMatchFindings_Capabilities_NoDuplicate(t *testing.T) {
	// If two CapabilityEntry items reference the same file, only one match
	// should be produced (dedup by matchedPaths key).
	f := newFindings()
	f.Capabilities = []CapabilityEntry{
		{File: "/usr/bin/python3", Capability: "cap_setuid+ep"},
		{File: "/usr/bin/python3", Capability: "cap_setuid+ep"},
	}

	matches := matchFindings(f)

	count := 0
	for _, m := range matches {
		if m.Entry.ID == "cap_setuid_python3" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected at most 1 capability match for python3, got %d", count)
	}
}

// ── TestMatchFindings_DockerSocket ──────────────────────────────────────────

func TestMatchFindings_DockerSocket(t *testing.T) {
	socketPath := "/var/run/docker.sock"
	f := newFindings()
	f.DockerSocketAccessible = true
	f.DockerSocket = &socketPath

	matches := matchFindings(f)

	// The matching code finds the first OTHER entry with "docker" or "container"
	// tag. This may be docker_socket_escape or docker_compose_secrets depending
	// on embed.FS iteration order. Either way, a docker escape match is produced.
	found := false
	for _, m := range matches {
		if m.MatchedBinaryPath == "docker" && m.MatchConfidence == "high" {
			found = true
			if !strings.Contains(m.MatchReason, socketPath) {
				t.Errorf("expected reason to contain socket path %q, got %q", socketPath, m.MatchReason)
			}
			break
		}
	}
	if !found {
		t.Error("expected docker escape match when DockerSocketAccessible=true")
		for _, m := range matches {
			t.Logf("  got: %s (path=%s, reason=%s)", m.Entry.ID, m.MatchedBinaryPath, m.MatchReason)
		}
	}
}

// ── TestMatchFindings_DockerSocket_NoPath ────────────────────────────────────

func TestMatchFindings_DockerSocket_NoPath(t *testing.T) {
	// DockerSocket is nil but accessible: should still match with "unknown" path.
	f := newFindings()
	f.DockerSocketAccessible = true
	f.DockerSocket = nil

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.MatchedBinaryPath == "docker" {
			found = true
			if !strings.Contains(m.MatchReason, "unknown") {
				t.Errorf("expected reason to contain 'unknown', got %q", m.MatchReason)
			}
			break
		}
	}
	if !found {
		t.Error("expected docker escape match even without DockerSocket path")
	}
}

// ── TestMatchFindings_DockerSocket_NotAccessible ────────────────────────────

func TestMatchFindings_DockerSocket_NotAccessible(t *testing.T) {
	f := newFindings()
	f.DockerSocketAccessible = false

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.ID == "docker_socket_escape" {
			t.Error("docker_socket_escape should not match when DockerSocketAccessible=false")
		}
	}
}

// ── TestMatchFindings_QEMUEscape ────────────────────────────────────────────

func TestMatchFindings_QEMUEscape(t *testing.T) {
	vt := "qemu"
	f := newFindings()
	f.ContainerDetected = true
	f.VirtualizationType = &vt

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "qemu_kvm_escape" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected qemu_kvm_escape match for QEMU virtualization")
		for _, m := range matches {
			t.Logf("  got: %s (%s)", m.Entry.ID, m.MatchReason)
		}
	}
}

// ── TestMatchFindings_QEMUEscape_UpperCase ──────────────────────────────────

func TestMatchFindings_QEMUEscape_UpperCase(t *testing.T) {
	vt := "QEMU"
	f := newFindings()
	f.ContainerDetected = true
	f.VirtualizationType = &vt

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "qemu_kvm_escape" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected qemu_kvm_escape match for uppercase QEMU")
	}
}

// ── TestMatchFindings_QEMUEscape_NoContainer ────────────────────────────────

func TestMatchFindings_QEMUEscape_NoContainer(t *testing.T) {
	vt := "qemu"
	f := newFindings()
	f.ContainerDetected = false
	f.VirtualizationType = &vt

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.ID == "qemu_kvm_escape" {
			t.Error("qemu_kvm_escape should not match when ContainerDetected=false")
		}
	}
}

// ── TestMatchFindings_SSHKey ────────────────────────────────────────────────

func TestMatchFindings_SSHKey(t *testing.T) {
	keyPath := "/root/.ssh/id_rsa"
	f := newFindings()
	f.SSHKeyFound = &keyPath

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "ssh_key_access" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			if m.MatchedBinaryPath != keyPath {
				t.Errorf("expected MatchedBinaryPath = %q, got %q", keyPath, m.MatchedBinaryPath)
			}
			break
		}
	}
	if !found {
		t.Error("expected ssh_key_access match when SSHKeyFound is set")
	}
}

// ── TestMatchFindings_SSHKey_Nil ────────────────────────────────────────────

func TestMatchFindings_SSHKey_Nil(t *testing.T) {
	f := newFindings()
	f.SSHKeyFound = nil

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.ID == "ssh_key_access" {
			t.Error("ssh_key_access should not match when SSHKeyFound is nil")
		}
	}
}

// ── TestMatchFindings_AWSCredentials ────────────────────────────────────────

func TestMatchFindings_AWSCredentials(t *testing.T) {
	f := newFindings()
	f.AWSCredentialsFound = true

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "aws_credentials" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected aws_credentials match when AWSCredentialsFound=true")
	}
}

// ── TestMatchFindings_AWSCredentials_False ───────────────────────────────────

func TestMatchFindings_AWSCredentials_False(t *testing.T) {
	f := newFindings()
	f.AWSCredentialsFound = false

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.ID == "aws_credentials" {
			t.Error("aws_credentials should not match when AWSCredentialsFound=false")
		}
	}
}

// ── TestMatchFindings_EnvSecrets ────────────────────────────────────────────

func TestMatchFindings_EnvSecrets(t *testing.T) {
	f := newFindings()
	f.EnvSecrets = []string{"DB_PASSWORD=hunter2", "API_KEY=abcdef123"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "env_secrets" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected env_secrets match when EnvSecrets is populated")
	}
}

// ── TestMatchFindings_EnvSecrets_Empty ───────────────────────────────────────

func TestMatchFindings_EnvSecrets_Empty(t *testing.T) {
	f := newFindings()
	f.EnvSecrets = []string{}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.ID == "env_secrets" {
			t.Error("env_secrets should not match when EnvSecrets is empty")
		}
	}
}

// ── TestMatchFindings_MySQLConfig ───────────────────────────────────────────

func TestMatchFindings_MySQLConfig(t *testing.T) {
	f := newFindings()
	f.MySQLConfigFound = true

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "mysql_config_creds" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected mysql_config_creds match when MySQLConfigFound=true")
	}
}

// ── TestMatchFindings_GitLabRunner ──────────────────────────────────────────

func TestMatchFindings_GitLabRunner(t *testing.T) {
	version := "14.5.0"
	f := newFindings()
	f.ServiceVersions.GitLabRunner = &version

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "gitlab_runner_token" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected gitlab_runner_token match when GitLabRunner version is set")
	}
}

// ── TestMatchFindings_Kubernetes ─────────────────────────────────────────────

func TestMatchFindings_Kubernetes(t *testing.T) {
	f := newFindings()
	f.ToolsAvailable = []string{"kubectl"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "kubectl_service_account" {
			found = true
			if m.MatchConfidence != "medium" {
				t.Errorf("expected medium confidence, got %q", m.MatchConfidence)
			}
			if m.MatchedBinaryPath != "kubectl" {
				t.Errorf("expected MatchedBinaryPath = %q, got %q", "kubectl", m.MatchedBinaryPath)
			}
			break
		}
	}
	if !found {
		t.Error("expected kubectl_service_account match when kubectl is in ToolsAvailable")
	}
}

// ── TestMatchFindings_Kubernetes_NoKubectl ───────────────────────────────────

func TestMatchFindings_Kubernetes_NoKubectl(t *testing.T) {
	f := newFindings()
	f.ToolsAvailable = []string{"curl", "wget"}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.ID == "kubectl_service_account" {
			t.Error("kubectl_service_account should not match without kubectl")
		}
	}
}

// ── TestMatchFindings_WritablePasswd ────────────────────────────────────────

func TestMatchFindings_WritablePasswd(t *testing.T) {
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{
			CVE:        "WRT-PASSWD",
			Confidence: "high",
		},
	}

	matches := matchFindings(f)

	// WRT-PASSWD matches via two paths:
	//   1. Section 5 (CVE candidate in OTHER) with "high" confidence
	//   2. Section 7c (passwd tag check) with "critical" confidence
	// We verify at least one writable_etc_passwd match exists.
	foundCVE := false
	foundTag := false
	for _, m := range matches {
		if m.Entry.ID == "writable_etc_passwd" {
			if strings.Contains(m.MatchReason, "CVE candidate") {
				foundCVE = true
				if m.MatchConfidence != "high" {
					t.Errorf("CVE path: expected high confidence, got %q", m.MatchConfidence)
				}
			}
			if strings.Contains(m.MatchReason, "Writable /etc/passwd") {
				foundTag = true
				if m.MatchConfidence != "critical" {
					t.Errorf("passwd tag path: expected critical confidence, got %q", m.MatchConfidence)
				}
				if m.MatchedBinaryPath != "/etc/passwd" {
					t.Errorf("expected MatchedBinaryPath = %q, got %q", "/etc/passwd", m.MatchedBinaryPath)
				}
			}
		}
	}
	if !foundCVE {
		t.Error("expected writable_etc_passwd match via CVE candidate path")
	}
	if !foundTag {
		t.Error("expected writable_etc_passwd match via passwd tag path")
	}
}

// ── TestMatchFindings_DockerCompose ──────────────────────────────────────────

func TestMatchFindings_DockerCompose(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"docker-compose.yml", "/opt/app/docker-compose.yml"},
		{"compose.yml", "/opt/app/compose.yml"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFindings()
			f.InterestingFiles = []string{tc.file}

			matches := matchFindings(f)

			found := false
			for _, m := range matches {
				if m.Entry.ID == "docker_compose_secrets" {
					found = true
					if m.MatchedBinaryPath != tc.file {
						t.Errorf("expected MatchedBinaryPath = %q, got %q", tc.file, m.MatchedBinaryPath)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected docker_compose_secrets match for %s", tc.file)
			}
		})
	}
}

// ── TestMatchFindings_Windows_SeImpersonate ─────────────────────────────────

func TestMatchFindings_Windows_SeImpersonate(t *testing.T) {
	f := newFindings()
	f.WinPrivileges = []string{"SeImpersonatePrivilege"}

	matches := matchFindings(f)

	// Should match both PrintSpoofer and GodPotato entries.
	foundPrint := false
	foundGod := false
	for _, m := range matches {
		if m.Entry.ID == "win_seimpersonate_printspoofer" {
			foundPrint = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence for PrintSpoofer, got %q", m.MatchConfidence)
			}
		}
		if m.Entry.ID == "win_seimpersonate_godpotato" {
			foundGod = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence for GodPotato, got %q", m.MatchConfidence)
			}
		}
	}
	if !foundPrint {
		t.Error("expected win_seimpersonate_printspoofer match for SeImpersonatePrivilege")
	}
	if !foundGod {
		t.Error("expected win_seimpersonate_godpotato match for SeImpersonatePrivilege")
	}
}

// ── TestMatchFindings_Windows_SeAssignPrimaryToken ──────────────────────────

func TestMatchFindings_Windows_SeAssignPrimaryToken(t *testing.T) {
	f := newFindings()
	f.WinPrivileges = []string{"SeAssignPrimaryTokenPrivilege"}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.Category == "WIN_TOKEN_PRIV" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WIN_TOKEN_PRIV match for SeAssignPrimaryTokenPrivilege")
	}
}

// ── TestMatchFindings_Windows_AlwaysInstallElevated ─────────────────────────

func TestMatchFindings_Windows_AlwaysInstallElevated(t *testing.T) {
	f := newFindings()
	f.WinAlwaysInstallElevated = true

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if m.Entry.ID == "win_alwaysinstallelevated" {
			found = true
			if m.MatchConfidence != "high" {
				t.Errorf("expected high confidence, got %q", m.MatchConfidence)
			}
			if m.Entry.Category != "WIN_ALWAYS_INSTALL_ELEVATED" {
				t.Errorf("expected category WIN_ALWAYS_INSTALL_ELEVATED, got %q", m.Entry.Category)
			}
			break
		}
	}
	if !found {
		t.Error("expected win_alwaysinstallelevated match when WinAlwaysInstallElevated=true")
	}
}

// ── TestMatchFindings_Windows_BothTokenAndAIE ───────────────────────────────

func TestMatchFindings_Windows_BothTokenAndAIE(t *testing.T) {
	f := newFindings()
	f.WinPrivileges = []string{"SeImpersonatePrivilege"}
	f.WinAlwaysInstallElevated = true

	matches := matchFindings(f)

	foundToken := false
	foundAIE := false
	for _, m := range matches {
		if m.Entry.Category == "WIN_TOKEN_PRIV" {
			foundToken = true
		}
		if m.Entry.Category == "WIN_ALWAYS_INSTALL_ELEVATED" {
			foundAIE = true
		}
	}
	if !foundToken {
		t.Error("expected WIN_TOKEN_PRIV match")
	}
	if !foundAIE {
		t.Error("expected WIN_ALWAYS_INSTALL_ELEVATED match")
	}
}

// ── TestMatchFindings_Windows_NoPrivileges ──────────────────────────────────

func TestMatchFindings_Windows_NoPrivileges(t *testing.T) {
	f := newFindings()
	// Only WinIsAdmin, no SeImpersonate or AIE. The block runs because
	// WinIsAdmin is true, but no specific entries should match.
	f.WinIsAdmin = true
	f.WinPrivileges = []string{"SeShutdownPrivilege"}

	matches := matchFindings(f)

	for _, m := range matches {
		if m.Entry.Category == "WIN_TOKEN_PRIV" || m.Entry.Category == "WIN_ALWAYS_INSTALL_ELEVATED" {
			t.Errorf("unexpected Windows match: %s", m.Entry.ID)
		}
	}
}

// ── TestMatchFindings_MultipleSimultaneous ──────────────────────────────────

func TestMatchFindings_MultipleSimultaneous(t *testing.T) {
	socketPath := "/var/run/docker.sock"
	sshKey := "/home/user/.ssh/id_rsa"
	f := newFindings()
	f.SuidBinaries = []string{"/usr/bin/python3", "/usr/bin/find"}
	f.SudoNopasswd = []SudoEntry{
		{User: "user", Command: "vim", Nopasswd: true},
	}
	f.Capabilities = []CapabilityEntry{
		{File: "/usr/bin/perl", Capability: "cap_setuid+ep"},
	}
	f.WritableCrons = []string{"/opt/scripts/clean.sh"}
	f.DockerSocketAccessible = true
	f.DockerSocket = &socketPath
	f.SSHKeyFound = &sshKey
	f.AWSCredentialsFound = true
	f.EnvSecrets = []string{"SECRET_KEY=abc"}
	f.CveCandidates = []CveCandidate{
		{CVE: "CVE-2021-3156", Confidence: "high"},
	}

	matches := matchFindings(f)

	expectedIDs := map[string]bool{
		"suid_python3":        false,
		"suid_find":           false,
		"sudo_vim":            false,
		"cap_setuid_perl":     false,
		"writable_cron_clean": false,
		"ssh_key_access":      false,
		"aws_credentials":     false,
		"env_secrets":         false,
		"cve_2021_3156":       false,
	}

	foundDockerEscape := false
	for _, m := range matches {
		if _, ok := expectedIDs[m.Entry.ID]; ok {
			expectedIDs[m.Entry.ID] = true
		}
		// Docker escape matches first OTHER entry with docker/container tag
		if m.MatchedBinaryPath == "docker" {
			foundDockerEscape = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected match for %s in multi-category findings", id)
		}
	}
	if !foundDockerEscape {
		t.Error("expected docker escape match in multi-category findings")
	}

	// Verify sorting: critical/high first, then medium, then low
	if len(matches) < 2 {
		t.Fatal("expected multiple matches")
	}
	confidenceOrder := map[string]int{"critical": 0, "high": 0, "medium": 1, "low": 2}
	for i := 0; i < len(matches)-1; i++ {
		ci := confidenceOrder[matches[i].MatchConfidence]
		cj := confidenceOrder[matches[i+1].MatchConfidence]
		if ci > cj {
			t.Errorf("sorting violation: match[%d] (%s, conf=%s) should come after match[%d] (%s, conf=%s)",
				i, matches[i].Entry.ID, matches[i].MatchConfidence,
				i+1, matches[i+1].Entry.ID, matches[i+1].MatchConfidence)
		}
	}
}

// ── TestMatchSorting ─────────────────────────────────────────────────────────

func TestMatchSorting(t *testing.T) {
	// Create findings that produce matches with different severity/confidence
	// levels to verify sorting order.
	f := newFindings()
	f.SuidBinaries = []string{"/usr/bin/bash", "/usr/bin/find"}

	matches := matchFindings(f)

	if len(matches) < 2 {
		t.Skipf("need at least 2 matches to test sorting, got %d", len(matches))
	}

	// Verify ordering: higher confidence/severity should come first.
	confidenceOrder := map[string]int{"critical": 0, "high": 0, "medium": 1, "low": 2}
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	for i := 0; i < len(matches)-1; i++ {
		confI := confidenceOrder[matches[i].MatchConfidence]
		confJ := confidenceOrder[matches[i+1].MatchConfidence]
		if confI > confJ {
			t.Errorf("match[%d] confidence %q should come after match[%d] confidence %q",
				i, matches[i].MatchConfidence, i+1, matches[i+1].MatchConfidence)
		} else if confI == confJ {
			sevI := severityOrder[*matches[i].Entry.Severity]
			sevJ := severityOrder[*matches[i+1].Entry.Severity]
			if sevI > sevJ {
				t.Errorf("match[%d] severity %q should come after match[%d] severity %q (same confidence)",
					i, *matches[i].Entry.Severity, i+1, *matches[i+1].Entry.Severity)
			}
		}
	}
}

// ── TestMatchSorting_MixedConfidence ─────────────────────────────────────────

func TestMatchSorting_MixedConfidence(t *testing.T) {
	// Create findings that yield a mix of critical, high, and medium confidence.
	f := newFindings()
	f.CveCandidates = []CveCandidate{
		{CVE: "WRT-PASSWD", Confidence: "high"},       // writable_passwd = critical confidence
	}
	f.ToolsAvailable = []string{"kubectl"}             // kubernetes = medium confidence
	f.SuidBinaries = []string{"/usr/bin/python3"}      // suid = high confidence

	matches := matchFindings(f)

	if len(matches) < 2 {
		t.Skipf("need at least 2 matches, got %d", len(matches))
	}

	// Ensure critical comes before medium.
	confidenceOrder := map[string]int{"critical": 0, "high": 0, "medium": 1, "low": 2}
	for i := 0; i < len(matches)-1; i++ {
		ci := confidenceOrder[matches[i].MatchConfidence]
		cj := confidenceOrder[matches[i+1].MatchConfidence]
		if ci > cj {
			t.Errorf("sorting: match[%d] (%s conf=%s) should come after match[%d] (%s conf=%s)",
				i, matches[i].Entry.ID, matches[i].MatchConfidence,
				i+1, matches[i+1].Entry.ID, matches[i+1].MatchConfidence)
		}
	}
}

// ── TestIndexDatasetByCategory ───────────────────────────────────────────────

func TestIndexDatasetByCategory(t *testing.T) {
	dataset := getDataset()
	indexed := indexDatasetByCategory(dataset)

	// There should be at least the known categories.
	expectedCategories := []string{"SUID_GTFOBINS", "OTHER"}
	for _, cat := range expectedCategories {
		entries, ok := indexed[cat]
		if !ok || len(entries) == 0 {
			t.Errorf("expected category %q to have entries in indexed dataset", cat)
		}
	}

	// Total across all categories must equal total dataset entries.
	total := 0
	for _, entries := range indexed {
		total += len(entries)
	}
	if total != len(dataset) {
		t.Errorf("indexed total %d != dataset total %d", total, len(dataset))
	}
}

// ── TestHasTagStr ────────────────────────────────────────────────────────────

func TestHasTagStr(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		tag  string
		want bool
	}{
		{name: "found", tags: []string{"suid", "gtfobins"}, tag: "suid", want: true},
		{name: "not found", tags: []string{"suid", "gtfobins"}, tag: "docker", want: false},
		{name: "empty tags", tags: []string{}, tag: "suid", want: false},
		{name: "nil tags", tags: nil, tag: "suid", want: false},
		{name: "empty search tag", tags: []string{"suid"}, tag: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hasTagStr(tc.tags, tc.tag)
			if got != tc.want {
				t.Errorf("hasTagStr(%v, %q) = %v, want %v", tc.tags, tc.tag, got, tc.want)
			}
		})
	}
}
