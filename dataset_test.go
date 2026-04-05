package main

import (
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
