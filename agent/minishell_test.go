package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ── MiniExec ──────────────────────────────────────────────────────────────────

func TestMiniExec_simpleCommand(t *testing.T) {
	out, err := MiniExec("echo hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Fatalf("want 'hello' in output, got %q", out)
	}
}

func TestMiniExec_commandWithArgs(t *testing.T) {
	out, err := MiniExec("echo -n foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "foo" {
		t.Fatalf("want 'foo', got %q", out)
	}
}

func TestMiniExec_pipe(t *testing.T) {
	out, err := MiniExec("printf 'alpha\nbeta\ngamma\n' | grep beta")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "beta") {
		t.Fatalf("want 'beta' in output, got %q", out)
	}
}

func TestMiniExec_multiStagePipe(t *testing.T) {
	out, err := MiniExec("printf 'one\ntwo\nthree\n' | grep -v two | sort -r")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), out)
	}
	if lines[0] != "three" || lines[1] != "one" {
		t.Fatalf("unexpected order: %v", lines)
	}
}

func TestMiniExec_redirectStdout(t *testing.T) {
	f := tmpFile(t)
	_, err := MiniExec(fmt.Sprintf("echo written > %s", f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), "written") {
		t.Fatalf("want 'written' in file, got %q", data)
	}
}

func TestMiniExec_redirectAppend(t *testing.T) {
	f := tmpFile(t)
	os.WriteFile(f, []byte("first\n"), 0644)
	_, err := MiniExec(fmt.Sprintf("echo second >> %s", f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), "first") || !strings.Contains(string(data), "second") {
		t.Fatalf("want both lines in file, got %q", data)
	}
}

func TestMiniExec_redirectStdin(t *testing.T) {
	f := tmpFile(t)
	os.WriteFile(f, []byte("from file\n"), 0644)
	out, err := MiniExec(fmt.Sprintf("cat < %s", f))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "from file") {
		t.Fatalf("want 'from file' in output, got %q", out)
	}
}

func TestMiniExec_stderrCaptured(t *testing.T) {
	// A command that writes to stderr; MiniExec returns combined output.
	out, _ := MiniExec("ls /nonexistent_alcapwn_test_path_xyz")
	if len(out) == 0 {
		t.Fatal("want stderr captured in output, got empty")
	}
}

func TestMiniExec_exitError(t *testing.T) {
	_, err := MiniExec("false")
	if err == nil {
		t.Fatal("want non-nil error for failing command")
	}
}

func TestMiniExec_nonZeroExitStillReturnsOutput(t *testing.T) {
	// grep exits 1 when there are no matches but still produces output for
	// lines that do match in a multi-line input.
	out, _ := MiniExec("printf 'match\nnope\n' | grep match")
	if !strings.Contains(string(out), "match") {
		t.Fatalf("want 'match' in output even on non-zero exit, got %q", out)
	}
}

func TestMiniExec_singleQuotes(t *testing.T) {
	out, err := MiniExec("echo 'hello world'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "hello world") {
		t.Fatalf("want 'hello world', got %q", out)
	}
}

func TestMiniExec_doubleQuotes(t *testing.T) {
	out, err := MiniExec(`echo "hello world"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "hello world") {
		t.Fatalf("want 'hello world', got %q", out)
	}
}

func TestMiniExec_backslashEscape(t *testing.T) {
	out, err := MiniExec(`echo hello\ world`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "hello world") {
		t.Fatalf("want 'hello world', got %q", out)
	}
}

func TestMiniExec_emptyCommand(t *testing.T) {
	out, err := MiniExec("   ")
	if err != nil {
		t.Fatalf("empty command should not error, got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("empty command should produce no output, got %q", out)
	}
}

func TestMiniExec_unknownCommand(t *testing.T) {
	_, err := MiniExec("nonexistent_binary_alcapwn_xyz")
	if err == nil {
		t.Fatal("want error for unknown binary")
	}
}

// ── parseArgs ─────────────────────────────────────────────────────────────────

func TestParseArgs_basic(t *testing.T) {
	args, err := parseArgs("ls -la /tmp")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ls", "-la", "/tmp"}
	if !sliceEq(args, want) {
		t.Fatalf("want %v, got %v", want, args)
	}
}

func TestParseArgs_singleQuotes(t *testing.T) {
	args, err := parseArgs("echo 'hello world'")
	if err != nil {
		t.Fatal(err)
	}
	if args[1] != "hello world" {
		t.Fatalf("want 'hello world', got %q", args[1])
	}
}

func TestParseArgs_doubleQuotes(t *testing.T) {
	args, err := parseArgs(`echo "hello world"`)
	if err != nil {
		t.Fatal(err)
	}
	if args[1] != "hello world" {
		t.Fatalf("want 'hello world', got %q", args[1])
	}
}

func TestParseArgs_doubleQuoteBackslash(t *testing.T) {
	args, err := parseArgs(`echo "say \"hi\""`)
	if err != nil {
		t.Fatal(err)
	}
	if args[1] != `say "hi"` {
		t.Fatalf("want 'say \"hi\"', got %q", args[1])
	}
}

func TestParseArgs_unclosedSingleQuote(t *testing.T) {
	_, err := parseArgs("echo 'unclosed")
	if err == nil {
		t.Fatal("want error for unclosed single quote")
	}
}

func TestParseArgs_unclosedDoubleQuote(t *testing.T) {
	_, err := parseArgs(`echo "unclosed`)
	if err == nil {
		t.Fatal("want error for unclosed double quote")
	}
}

func TestParseArgs_redirectionTokens(t *testing.T) {
	args, err := parseArgs("cat file >out 2>err")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cat", "file", ">", "out", "2>", "err"}
	if !sliceEq(args, want) {
		t.Fatalf("want %v, got %v", want, args)
	}
}

func TestParseArgs_appendRedirection(t *testing.T) {
	args, err := parseArgs("echo hi >>file")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", "hi", ">>", "file"}
	if !sliceEq(args, want) {
		t.Fatalf("want %v, got %v", want, args)
	}
}

func TestParseArgs_empty(t *testing.T) {
	args, err := parseArgs("   ")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 {
		t.Fatalf("want empty slice, got %v", args)
	}
}

// ── parsePipeline ─────────────────────────────────────────────────────────────

func TestParsePipeline_single(t *testing.T) {
	stages, err := parsePipeline("ls -la")
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 {
		t.Fatalf("want 1 stage, got %d", len(stages))
	}
	if !sliceEq(stages[0].args, []string{"ls", "-la"}) {
		t.Fatalf("unexpected args: %v", stages[0].args)
	}
}

func TestParsePipeline_twostage(t *testing.T) {
	stages, err := parsePipeline("cat file | grep foo")
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 2 {
		t.Fatalf("want 2 stages, got %d", len(stages))
	}
}

func TestParsePipeline_threestage(t *testing.T) {
	stages, err := parsePipeline("cat file | grep foo | wc -l")
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 3 {
		t.Fatalf("want 3 stages, got %d", len(stages))
	}
}

func TestParsePipeline_pipeInsideQuotes(t *testing.T) {
	// A pipe inside quotes must NOT split the pipeline.
	stages, err := parsePipeline(`echo "a | b"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 1 {
		t.Fatalf("pipe inside quotes must not split pipeline, got %d stages", len(stages))
	}
}

func TestParsePipeline_redirections(t *testing.T) {
	stages, err := parsePipeline("cat < in.txt | grep foo > out.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 2 {
		t.Fatalf("want 2 stages, got %d", len(stages))
	}
	if stages[0].stdinFile != "in.txt" {
		t.Fatalf("want stdinFile 'in.txt', got %q", stages[0].stdinFile)
	}
	if stages[1].stdoutFile != "out.txt" {
		t.Fatalf("want stdoutFile 'out.txt', got %q", stages[1].stdoutFile)
	}
}

// ── splitUnquoted ─────────────────────────────────────────────────────────────

func TestSplitUnquoted_basic(t *testing.T) {
	parts := splitUnquoted("a|b|c", '|')
	if len(parts) != 3 {
		t.Fatalf("want 3 parts, got %v", parts)
	}
}

func TestSplitUnquoted_insideQuotes(t *testing.T) {
	parts := splitUnquoted(`"a|b"|c`, '|')
	if len(parts) != 2 {
		t.Fatalf("want 2 parts (pipe inside quotes is literal), got %v", parts)
	}
}

// ── Completion helpers ────────────────────────────────────────────────────────

func TestLastToken_basic(t *testing.T) {
	if got := lastToken("ls /et"); got != "/et" {
		t.Fatalf("want '/et', got %q", got)
	}
}

func TestLastToken_trailingSpace(t *testing.T) {
	if got := lastToken("ls "); got != "" {
		t.Fatalf("want '' for trailing space, got %q", got)
	}
}

func TestLastToken_empty(t *testing.T) {
	if got := lastToken(""); got != "" {
		t.Fatalf("want '', got %q", got)
	}
}

func TestIsFirstToken_true(t *testing.T) {
	if !isFirstToken("ls") {
		t.Fatal("want true for single token")
	}
}

func TestIsFirstToken_false(t *testing.T) {
	if isFirstToken("ls /tmp") {
		t.Fatal("want false when second token present")
	}
}

func TestLongestCommonPrefix(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"foobar", "foobaz", "fooq"}, "foo"},
		{[]string{"abc"}, "abc"},
		{[]string{"abc", "def"}, ""},
		{[]string{}, ""},
	}
	for _, c := range cases {
		if got := longestCommonPrefix(c.in); got != c.want {
			t.Errorf("longestCommonPrefix(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── MiniShell interactive ─────────────────────────────────────────────────────

func TestMiniShell_exitOnCtrlD(t *testing.T) {
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("\x04"), &out)
	if err := s.Run(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMiniShell_exitCommand(t *testing.T) {
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("exit\n"), &out)
	if err := s.Run(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMiniShell_echoCommand(t *testing.T) {
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("echo shelltest\nexit\n"), &out)
	s.Run()
	if !strings.Contains(out.String(), "shelltest") {
		t.Fatalf("want 'shelltest' in output, got %q", out.String())
	}
}

func TestMiniShell_builtinPwd(t *testing.T) {
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("pwd\nexit\n"), &out)
	s.Run()
	cwd, _ := os.Getwd()
	if !strings.Contains(out.String(), cwd) {
		t.Fatalf("want cwd %q in output, got %q", cwd, out.String())
	}
}

func TestMiniShell_builtinCd(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("cd /tmp\npwd\nexit\n"), &out)
	s.Run()
	if !strings.Contains(out.String(), "/tmp") {
		t.Fatalf("want '/tmp' in output after cd, got %q", out.String())
	}
}

func TestMiniShell_builtinExport(t *testing.T) {
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("export ALCAPWN_TEST=yes\nexport ALCAPWN_TEST\nexit\n"), &out)
	s.Run()
	if !strings.Contains(out.String(), "yes") {
		t.Fatalf("want 'yes' in export output, got %q", out.String())
	}
}

func TestMiniShell_historyNavigation(t *testing.T) {
	// Type a command, then up-arrow to recall it, then Enter to run it again.
	// Up = ESC [ A, Enter = \n
	input := "echo first\n\x1b[A\n" + "exit\n"
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader(input), &out)
	s.Run()
	// "first" should appear at least twice.
	count := strings.Count(out.String(), "first")
	if count < 2 {
		t.Fatalf("want 'first' at least twice (run + recall), got %d occurrences in %q", count, out.String())
	}
}

func TestMiniShell_ctrlCClearsLine(t *testing.T) {
	// Type some chars, Ctrl+C, then exit cleanly.
	input := "abc\x03exit\n"
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader(input), &out)
	if err := s.Run(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "^C") {
		t.Fatalf("want '^C' in output, got %q", out.String())
	}
}

func TestMiniShell_completePath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte{}, 0644)
	os.WriteFile(filepath.Join(dir, "alpha_two.txt"), []byte{}, 0644)
	os.WriteFile(filepath.Join(dir, "beta.txt"), []byte{}, 0644)

	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("exit\n"), &out)
	matches := s.completePath(filepath.Join(dir, "alpha"))
	if len(matches) != 2 {
		t.Fatalf("want 2 completions for 'alpha', got %v", matches)
	}
	for _, m := range matches {
		if !strings.Contains(m, "alpha") {
			t.Errorf("unexpected match %q", m)
		}
	}
}

func TestMiniShell_completeCommand(t *testing.T) {
	var out bytes.Buffer
	s := NewMiniShell(strings.NewReader("exit\n"), &out)
	// "ex" should at minimum complete to "exit" (built-in).
	matches := s.completeCommand("ex")
	found := false
	for _, m := range matches {
		if m == "exit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want 'exit' in completions for 'ex', got %v", matches)
	}
}

// ── Redirection file handle tests ────────────────────────────────────────────

func TestMinishell_RedirectionFilesClosed(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.txt")

	// Run a command with stdout redirection — openRedirections should return
	// the opened file and the caller should close it after cmd.Run.
	st := pipelineStage{
		args:       []string{"echo", "leaked?"},
		stdoutFile: outFile,
	}
	cmd := exec.Command(st.args[0], st.args[1:]...)
	opened, err := openRedirections(cmd, st)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) == 0 {
		t.Fatal("openRedirections should return the opened files")
	}

	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	// Close all opened files.
	for _, f := range opened {
		if err := f.Close(); err != nil {
			t.Fatalf("file should still be open and closable: %v", err)
		}
	}

	// Verify the output was written.
	data, _ := os.ReadFile(outFile)
	if !strings.Contains(string(data), "leaked?") {
		t.Fatalf("want 'leaked?' in output file, got %q", data)
	}

	// Closing again should fail — proves the file was properly closed above.
	for _, f := range opened {
		err := f.Close()
		if err == nil {
			t.Fatal("double close should error — file was already closed")
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func tmpFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "minitest-*")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}
