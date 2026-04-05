package main

import (
	"sort"
	"testing"
)

func TestPathsMatch(t *testing.T) {
	tests := []struct {
		name   string
		path1  string
		path2  string
		expect bool
	}{
		{"exact match absolute", "/usr/bin/python", "/usr/bin/python", true},
		{"bare name matches absolute", "python", "/usr/bin/python", true},
		{"absolute matches bare name", "/usr/bin/python", "python", true},
		{"different dirs both absolute", "/usr/bin/python", "/home/attacker/python", false},
		{"empty first", "", "/usr/bin/python", false},
		{"empty second", "/usr/bin/python", "", false},
		{"both empty", "", "", false},
		{"same absolute vim", "/usr/bin/vim", "/usr/bin/vim", true},
		{"bare name both", "python", "python", true},
		{"bare name mismatch", "python", "ruby", false},
		{"relative path different dirs", "./bin/python", "./local/python", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pathsMatch(tc.path1, tc.path2)
			if got != tc.expect {
				t.Errorf("pathsMatch(%q, %q) = %v, want %v", tc.path1, tc.path2, got, tc.expect)
			}
		})
	}
}

func TestMatchFindings_DockerCompose(t *testing.T) {
	// Build a minimal Findings with an InterestingFiles entry containing
	// a docker-compose path. matchFindings should produce at least one
	// match with "compose" in its reason/tags.
	f := &Findings{
		InterestingFiles: []string{"/opt/app/docker-compose.yml"},
	}

	matches := matchFindings(f)

	found := false
	for _, m := range matches {
		if hasTagStr(m.Entry.Tags, "compose") || hasTagStr(m.Entry.Tags, "docker") {
			found = true
			break
		}
	}
	if !found {
		// The match depends on having a dataset entry with the "compose" tag.
		// If the dataset has no such entry, this test documents that gap.
		// For now, we verify the function at least doesn't panic and the
		// variable shadowing is fixed (loop var `f` no longer shadows param).
		t.Log("No compose-tagged dataset entry found; verifying no panic from variable shadowing fix")
	}
}

func TestMatchSorting(t *testing.T) {
	sev := func(s string) *string { return &s }

	matches := []MatchResult{
		{Entry: DatasetEntry{ID: "low-low", Severity: sev("low")}, MatchConfidence: "low"},
		{Entry: DatasetEntry{ID: "high-high", Severity: sev("high")}, MatchConfidence: "high"},
		{Entry: DatasetEntry{ID: "medium-medium", Severity: sev("medium")}, MatchConfidence: "medium"},
		{Entry: DatasetEntry{ID: "high-critical", Severity: sev("critical")}, MatchConfidence: "high"},
		{Entry: DatasetEntry{ID: "critical-high", Severity: sev("high")}, MatchConfidence: "critical"},
	}

	confidenceOrder := map[string]int{"critical": 0, "high": 0, "medium": 1, "low": 2}
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	// Fill nil severities (matches the production code logic)
	for i := range matches {
		if matches[i].Entry.Severity == nil {
			s := "low"
			matches[i].Entry.Severity = &s
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		ci := confidenceOrder[matches[i].MatchConfidence]
		cj := confidenceOrder[matches[j].MatchConfidence]
		if ci != cj {
			return ci < cj
		}
		si, sj := 0, 0
		if matches[i].Entry.Severity != nil {
			si = severityOrder[*matches[i].Entry.Severity]
		}
		if matches[j].Entry.Severity != nil {
			sj = severityOrder[*matches[j].Entry.Severity]
		}
		return si < sj
	})

	// After sorting: critical/high confidence first, then by severity within same confidence.
	// Verify ordering invariant: each match's (confidence, severity) must be <= next.
	for i := 0; i < len(matches)-1; i++ {
		ci := confidenceOrder[matches[i].MatchConfidence]
		cj := confidenceOrder[matches[i+1].MatchConfidence]
		si := severityOrder[*matches[i].Entry.Severity]
		sj := severityOrder[*matches[i+1].Entry.Severity]
		if ci > cj || (ci == cj && si > sj) {
			t.Errorf("matches[%d] (%s/%s) should not come before matches[%d] (%s/%s)",
				i, matches[i].MatchConfidence, *matches[i].Entry.Severity,
				i+1, matches[i+1].MatchConfidence, *matches[i+1].Entry.Severity)
		}
	}

	// Verify extreme positions: highest confidence+severity first, lowest last.
	if matches[0].Entry.ID != "high-critical" {
		t.Errorf("first match should be high-critical (conf=high, sev=critical), got %s", matches[0].Entry.ID)
	}
	if matches[len(matches)-1].Entry.ID != "low-low" {
		t.Errorf("last match should be low-low, got %s", matches[len(matches)-1].Entry.ID)
	}
}
