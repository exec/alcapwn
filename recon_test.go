package main

import (
	"strings"
	"testing"
)

// ── TestReconSections_Count ──────────────────────────────────────────────────

func TestReconSections_Count(t *testing.T) {
	// buildReconScript replaces {{HASH_1}} through {{HASH_13}}, i.e. 13 sections.
	// reconSections must list exactly 13 names to match.
	if len(reconSections) != 13 {
		t.Errorf("len(reconSections) = %d, want 13", len(reconSections))
	}
}

// TestReconSections_NoDuplicates ensures no two sections share the same name.
func TestReconSections_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, name := range reconSections {
		if seen[name] {
			t.Errorf("duplicate section name: %q", name)
		}
		seen[name] = true
	}
}

// TestBuildReconScript_AllPlaceholdersReplaced verifies that after building,
// no {{HASH_N}} placeholders remain in the script.
func TestBuildReconScript_AllPlaceholdersReplaced(t *testing.T) {
	nonce := makeReconNonce()
	script := buildReconScript(nonce)

	if strings.Contains(script, "{{HASH_") {
		t.Error("buildReconScript output still contains unreplaced {{HASH_N}} placeholder(s)")
	}
}

// TestBuildReconScript_ContainsSentinel verifies the script ends with the sentinel.
func TestBuildReconScript_ContainsSentinel(t *testing.T) {
	nonce := makeReconNonce()
	script := buildReconScript(nonce)

	if !strings.Contains(script, sentinel) {
		t.Errorf("buildReconScript output does not contain sentinel %q", sentinel)
	}
}

// TestBuildSectionRe_MatchesSections verifies the regex matches all section headers.
func TestBuildSectionRe_MatchesSections(t *testing.T) {
	nonce := makeReconNonce()
	re := buildSectionRe(nonce)
	script := buildReconScript(nonce)

	matched := 0
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		// Skip echo lines — they contain the [SECTION ...] text inside quotes
		if strings.HasPrefix(line, "echo") {
			// Extract the echoed content (strip echo " and trailing ")
			inner := line
			if idx := strings.Index(line, "\""); idx >= 0 {
				inner = line[idx+1:]
				if end := strings.LastIndex(inner, "\""); end >= 0 {
					inner = inner[:end]
				}
			}
			if m := re.FindStringSubmatch(inner); m != nil {
				matched++
			}
		}
	}

	if matched != 13 {
		t.Errorf("expected regex to match 13 section headers in script, matched %d", matched)
	}
}

// TestBuildSectionRe_RejectsFakeHeader verifies that a fake header without the
// correct HMAC hash does not match.
func TestBuildSectionRe_RejectsFakeHeader(t *testing.T) {
	nonce := makeReconNonce()
	re := buildSectionRe(nonce)

	fakeHeader := "[SECTION 1:0000000000000000] IDENTITY"
	if re.MatchString(fakeHeader) {
		t.Error("expected fake header to NOT match section regex")
	}
}

// TestComputeSectionHash_Deterministic verifies same nonce+section gives same hash.
func TestComputeSectionHash_Deterministic(t *testing.T) {
	nonce := makeReconNonce()
	h1 := computeSectionHash(nonce, 1)
	h2 := computeSectionHash(nonce, 1)

	if h1 != h2 {
		t.Errorf("same nonce+section produced different hashes: %q vs %q", h1, h2)
	}
}

// TestComputeSectionHash_DifferentSections verifies different section numbers
// produce different hashes.
func TestComputeSectionHash_DifferentSections(t *testing.T) {
	nonce := makeReconNonce()
	h1 := computeSectionHash(nonce, 1)
	h2 := computeSectionHash(nonce, 2)

	if h1 == h2 {
		t.Error("different section numbers produced the same hash")
	}
}

// TestComputeSectionHash_Length verifies the hash is 16 hex characters.
func TestComputeSectionHash_Length(t *testing.T) {
	nonce := makeReconNonce()
	h := computeSectionHash(nonce, 1)

	if len(h) != 16 {
		t.Errorf("hash length = %d, want 16", len(h))
	}
}

// ── TestStripPS2Lines ────────────────────────────────────────────────────────

func TestStripPS2Lines(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bare PS2 prompt",
			input: "real content\n>\nmore content",
			want:  "real content\nmore content",
		},
		{
			name:  "PS2 with space prefix",
			input: "real content\n> continuation\nmore content",
			want:  "real content\nmore content",
		},
		{
			name:  "no PS2 lines",
			input: "line one\nline two\nline three",
			want:  "line one\nline two\nline three",
		},
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "mixed with carriage returns",
			input: "real content\r\n>\r\nmore content",
			want:  "real content\r\nmore content",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripPS2Lines(tc.input)
			if got != tc.want {
				t.Errorf("stripPS2Lines:\n  input: %q\n  got:   %q\n  want:  %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── TestHideFromHistory ──────────────────────────────────────────────────────

func TestHideFromHistory(t *testing.T) {
	input := "echo hello\necho world\n"
	output := hideFromHistory(input)

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			t.Errorf("expected line to start with space, got %q", line)
		}
	}
}

// TestHideFromHistory_AlreadySpaced verifies lines already starting with space
// are not double-spaced.
func TestHideFromHistory_AlreadySpaced(t *testing.T) {
	input := " already spaced\nnot spaced"
	output := hideFromHistory(input)

	lines := strings.Split(output, "\n")
	if lines[0] != " already spaced" {
		t.Errorf("already-spaced line modified: got %q", lines[0])
	}
	if lines[1] != " not spaced" {
		t.Errorf("unspaced line not prefixed: got %q", lines[1])
	}
}

// ── TestReconDetail ──────────────────────────────────────────────────────────

func TestReconDetail(t *testing.T) {
	tests := []struct {
		name    string
		current int
		total   int
		label   string
	}{
		{name: "start", current: 0, total: 13, label: "starting"},
		{name: "middle", current: 6, total: 13, label: "CRON JOBS"},
		{name: "end", current: 13, total: 13, label: "done"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detail := reconDetail(tc.current, tc.total, tc.label)
			if detail == "" {
				t.Error("reconDetail returned empty string")
			}
			// Should contain the label
			if !strings.Contains(detail, tc.label) {
				t.Errorf("reconDetail should contain label %q, got %q", tc.label, detail)
			}
		})
	}
}

// TestReconDetail_LabelTruncation verifies long labels are truncated.
func TestReconDetail_LabelTruncation(t *testing.T) {
	longLabel := "THIS IS A VERY LONG SECTION LABEL THAT EXCEEDS TWENTY TWO CHARS"
	detail := reconDetail(5, 13, longLabel)

	// Label should be truncated to 22 chars
	if strings.Contains(detail, longLabel) {
		t.Error("expected long label to be truncated")
	}
}

// ── TestExtractAllSections ───────────────────────────────────────────────────

func TestExtractAllSections(t *testing.T) {
	nonce := makeReconNonce()
	re := buildSectionRe(nonce)

	// Build mock output with all 13 sections in order.
	var lines []string
	for i, name := range reconSections {
		hash := computeSectionHash(nonce, i+1)
		header := strings.TrimSpace(strings.Replace(
			"[SECTION N:HASH] NAME",
			"N", strings.Replace("N", "N", itoa(i+1), 1), 1,
		))
		// Build proper header
		header = "[SECTION " + itoa(i+1) + ":" + hash + "] " + name
		lines = append(lines, header)
		lines = append(lines, "content for "+name)
		lines = append(lines, "more content for "+name)
	}
	raw := strings.Join(lines, "\n")

	sections := extractAllSections(raw, re)

	if len(sections) != 13 {
		t.Fatalf("expected 13 sections, got %d", len(sections))
	}

	for _, name := range reconSections {
		content, ok := sections[name]
		if !ok {
			t.Errorf("missing section %q", name)
			continue
		}
		if !strings.Contains(content, "content for "+name) {
			t.Errorf("section %q does not contain expected content", name)
		}
	}
}

// TestExtractAllSections_RejectsFakeHeader verifies that injected headers with
// wrong hashes are ignored.
func TestExtractAllSections_RejectsFakeHeader(t *testing.T) {
	nonce := makeReconNonce()
	re := buildSectionRe(nonce)

	// Build section 1 with correct hash, then inject a fake section 2
	hash1 := computeSectionHash(nonce, 1)
	raw := "[SECTION 1:" + hash1 + "] IDENTITY\nreal identity content\n"
	raw += "[SECTION 2:0000000000000000] SUDO ACCESS\nfake sudo content\n"

	sections := extractAllSections(raw, re)

	// Only section 1 should be extracted
	if _, ok := sections["IDENTITY"]; !ok {
		t.Error("expected IDENTITY section to be present")
	}
	if _, ok := sections["SUDO ACCESS"]; ok {
		t.Error("expected fake SUDO ACCESS section to be rejected")
	}
}

// TestExtractAllSections_OutOfOrderRejected verifies that out-of-order section
// headers are skipped. Section 2 appearing before section 1 is ignored, but
// section 1 is still accepted when it arrives (since nextExpected is still 1).
func TestExtractAllSections_OutOfOrderRejected(t *testing.T) {
	nonce := makeReconNonce()
	re := buildSectionRe(nonce)

	// Emit section 2 before section 1
	hash1 := computeSectionHash(nonce, 1)
	hash2 := computeSectionHash(nonce, 2)
	raw := "[SECTION 2:" + hash2 + "] SUDO ACCESS\nsudo content\n"
	raw += "[SECTION 1:" + hash1 + "] IDENTITY\nidentity content\n"

	sections := extractAllSections(raw, re)

	// Section 2 is skipped (out of order), but section 1 is accepted since
	// nextExpected is still 1 when it appears.
	if len(sections) != 1 {
		t.Errorf("expected 1 section for out-of-order input (only section 1 accepted), got %d", len(sections))
	}
	if _, ok := sections["IDENTITY"]; !ok {
		t.Error("expected IDENTITY section to be present")
	}
	if _, ok := sections["SUDO ACCESS"]; ok {
		t.Error("expected SUDO ACCESS to be rejected (out of order)")
	}
}

// itoa is a simple int-to-string helper to avoid importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

// ── TestStripANSI ────────────────────────────────────────────────────────────

func TestStripANSI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no ANSI",
			input: "plain text",
			want:  "plain text",
		},
		{
			name:  "CSI color code",
			input: "\x1b[31mred text\x1b[0m",
			want:  "red text",
		},
		{
			name:  "OSC sequence",
			input: "\x1b]0;window title\x07rest",
			want:  "rest",
		},
		{
			name:  "bracketed paste",
			input: "\x1b[201~pasted\x1b[202~",
			want:  "pasted",
		},
		{
			name:  "DEC special",
			input: "\x1b(0line drawing\x1b(1",
			want:  "line drawing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripANSI(tc.input)
			if got != tc.want {
				t.Errorf("stripANSI(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── TestMakeReconNonce_Unique ─────────────────────────────────────────────────

func TestMakeReconNonce_Unique(t *testing.T) {
	n1 := makeReconNonce()
	n2 := makeReconNonce()

	if n1 == n2 {
		t.Error("two consecutive makeReconNonce calls returned identical nonces")
	}
}
