package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCredsDump_LargeHistory verifies that a very large history file does not
// cause unbounded memory allocation. Only the last 30 lines should be
// included, read from at most the last 8KB of the file.
func TestCredsDump_LargeHistory(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, ".bash_history")

	// Write a large history file with 100,000 lines.
	f, err := os.Create(histPath)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100000; i++ {
		f.WriteString("ls -la /some/long/path/to/make/lines/bigger\n")
	}
	f.Close()

	fi, err := os.Stat(histPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() < 1_000_000 {
		t.Fatal("test history file too small")
	}

	// Read just the tail using the same logic the fix should implement.
	lines := readHistoryTail(histPath, 30)
	if len(lines) > 30 {
		t.Fatalf("want at most 30 lines, got %d", len(lines))
	}
	if len(lines) == 0 {
		t.Fatal("want some history lines, got 0")
	}
}

// TestCredsDump_SmallHistory verifies that small history files are read
// correctly (the file is smaller than the 8KB read window).
func TestCredsDump_SmallHistory(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, ".bash_history")

	content := "echo hello\necho world\nls\n"
	os.WriteFile(histPath, []byte(content), 0644)

	lines := readHistoryTail(histPath, 30)
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "echo hello" {
		t.Fatalf("want first line 'echo hello', got %q", lines[0])
	}
}

// TestCredsDump_EmptyHistory verifies that an empty history file returns no lines.
func TestCredsDump_EmptyHistory(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, ".bash_history")
	os.WriteFile(histPath, []byte{}, 0644)

	lines := readHistoryTail(histPath, 30)
	if len(lines) != 0 {
		t.Fatalf("want 0 lines for empty file, got %d", len(lines))
	}
}

// TestCredsDump_NonexistentHistory verifies that a missing file returns no lines.
func TestCredsDump_NonexistentHistory(t *testing.T) {
	lines := readHistoryTail("/nonexistent_alcapwn_test_xyz", 30)
	if len(lines) != 0 {
		t.Fatalf("want 0 lines for missing file, got %d", len(lines))
	}
}

// TestCredsDump_ExactlyThirtyLines verifies boundary condition.
func TestCredsDump_ExactlyThirtyLines(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, ".bash_history")

	var sb strings.Builder
	for i := 0; i < 30; i++ {
		sb.WriteString("line\n")
	}
	os.WriteFile(histPath, []byte(sb.String()), 0644)

	lines := readHistoryTail(histPath, 30)
	if len(lines) != 30 {
		t.Fatalf("want 30 lines, got %d", len(lines))
	}
}
