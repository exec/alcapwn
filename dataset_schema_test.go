package main

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"testing"
)

// TestDatasetEntries_ValidJSON walks all JSON files under data/entries/ and
// validates that each one unmarshals into a valid DatasetEntry with the
// required fields populated and no duplicate IDs across the entire dataset.
func TestDatasetEntries_ValidJSON(t *testing.T) {
	seenIDs := make(map[string]string) // id -> file path

	err := fs.WalkDir(entriesFS, "data/entries", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		data, err := entriesFS.ReadFile(path)
		if err != nil {
			t.Errorf("failed to read %s: %v", path, err)
			return nil
		}

		var entry DatasetEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			t.Errorf("failed to unmarshal %s: %v", path, err)
			return nil
		}

		// ID must be non-empty
		if entry.ID == "" {
			t.Errorf("%s: ID is empty", path)
		}

		// Category must be non-empty
		if entry.Category == "" {
			t.Errorf("%s: Category is empty", path)
		}

		// Exploitation must have at least one step
		if len(entry.Exploitation) == 0 {
			t.Errorf("%s: Exploitation has no steps", path)
		}

		// Check for duplicate IDs
		if prevPath, exists := seenIDs[entry.ID]; exists {
			t.Errorf("duplicate ID %q found in %s (first seen in %s)", entry.ID, path, prevPath)
		} else {
			seenIDs[entry.ID] = path
		}

		return nil
	})

	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	// Sanity check: we should have processed a reasonable number of entries
	if len(seenIDs) < 10 {
		t.Errorf("expected at least 10 entries, found %d", len(seenIDs))
	}
}

// TestDatasetEntries_CategoryMatchesSubdir verifies that the category field
// in each entry is consistent with the subdirectory it resides in.
func TestDatasetEntries_CategoryMatchesSubdir(t *testing.T) {
	// Map subdirectory names to expected category values.
	subdirToCategory := map[string]string{
		"suid_gtfobins":   "SUID_GTFOBINS",
		"suid_custom":     "SUID_CUSTOM",
		"sudo_nopasswd":   "SUDO_NOPASSWD_CUSTOM",
		"sudo_direct":     "SUDO_NOPASSWD_DIRECT",
		"sudo_cve":        "SUDO_RULE_CVE",
		"capability":      "CAPABILITY_SETUID",
		"writable_cron":   "WRITABLE_CRON",
		"other":           "OTHER",
		"windows_privesc": "", // multiple categories possible
	}

	err := fs.WalkDir(entriesFS, "data/entries", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return err
		}

		data, err := entriesFS.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return nil
		}

		var entry DatasetEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil // already covered by ValidJSON test
		}

		// Extract subdirectory name
		dir := filepath.Dir(path)
		subdir := filepath.Base(dir)

		expectedCat, known := subdirToCategory[subdir]
		if !known {
			t.Logf("unknown subdirectory %q in %s", subdir, path)
			return nil
		}

		// Skip if the mapping allows multiple categories (empty string)
		if expectedCat == "" {
			return nil
		}

		if entry.Category != expectedCat {
			t.Errorf("%s: category %q does not match expected %q for subdir %q",
				path, entry.Category, expectedCat, subdir)
		}

		return nil
	})

	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}
}

// TestDatasetEntries_SourceNonEmpty ensures every entry has a non-empty source.
func TestDatasetEntries_SourceNonEmpty(t *testing.T) {
	dataset := getDataset()

	for _, entry := range dataset {
		if entry.Source == "" {
			t.Errorf("entry %q has empty Source field", entry.ID)
		}
	}
}
