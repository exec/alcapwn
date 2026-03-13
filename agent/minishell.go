// minishell.go — alcapwn built-in shell for agent-side execution.
//
// Two entry points:
//
//	MiniExec(cmdline)       non-interactive; returns combined output.
//	                        Used as the TaskExec fallback when no system
//	                        shell (/bin/sh, /bin/bash, …) is present.
//
//	NewMiniShell(r, w).Run() interactive; reads keystrokes from r,
//	                        writes output to w.  Intended for future
//	                        TaskShell interactive sessions over the
//	                        encrypted agent channel.
//
// Supported features
//   - Pipes:                cmd1 | cmd2 | cmd3
//   - Redirections:         > >> < 2>
//   - Quoting:              single and double quotes, backslash escapes
//   - Tab completion:       binaries from PATH (first token) or file paths
//   - Command history:      ↑ / ↓ navigation, deduplication
//   - Line editing:         ← → home/end, backspace, Ctrl+A/E/U/C/D
//   - Built-ins:            cd  pwd  export  env  which  help  exit
//   - Colour prompt:        user@host:cwd$  (suppressed when w is not a tty)
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
)

// ── Public non-interactive entrypoint ────────────────────────────────────────

// MiniExec runs cmdline without a shell interpreter and returns combined
// stdout+stderr.  Supports pipes and I/O redirections.
// Used as a TaskExec fallback when no system shell is available.
func MiniExec(cmdline string) ([]byte, error) {
	stages, err := parsePipeline(cmdline)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = runPipeline(stages, nil, &out, &out, os.Environ(), "")
	return out.Bytes(), err
}

// ── MiniShell ─────────────────────────────────────────────────────────────────

// MiniShell is a minimal interactive shell that reads from r and writes to w.
// It handles its own line-editing and tab-completion so the caller does not
// need to provide a real TTY — a network connection works fine.
type MiniShell struct {
	r        io.Reader
	w        io.Writer
	cwd      string
	envExtra []string // vars set via the export built-in

	history []string
	histIdx int // -1 = new line; ≥0 = navigating history

	buf []rune // current line being edited
	pos int    // cursor position within buf (0 = before first rune)
}

// NewMiniShell creates a MiniShell that reads from r and writes to w.
func NewMiniShell(r io.Reader, w io.Writer) *MiniShell {
	cwd, _ := os.Getwd()
	return &MiniShell{r: r, w: w, cwd: cwd, histIdx: -1}
}

// Run starts an interactive shell session.  It blocks until the user types
// exit, sends EOF (Ctrl+D on an empty line), or r returns an error.
//
// Callers that proxy this over a network connection should put the remote
// terminal into raw / no-echo mode before forwarding keystrokes here.
func (s *MiniShell) Run() error {
	s.printPrompt()

	one := make([]byte, 1)
	var escBuf []byte
	inEsc := false

	for {
		if _, err := s.r.Read(one); err != nil {
			if err == io.EOF {
				fmt.Fprintf(s.w, "\r\n")
				return nil
			}
			return err
		}
		b := one[0]

		// ── Escape sequence accumulation (arrow keys, etc.) ──────────────
		if inEsc {
			escBuf = append(escBuf, b)
			if len(escBuf) < 2 {
				continue
			}
			if escBuf[0] != '[' {
				inEsc = false
				escBuf = escBuf[:0]
				continue
			}
			switch escBuf[1] {
			case 'A':
				s.historyPrev()
			case 'B':
				s.historyNext()
			case 'C': // right
				if s.pos < len(s.buf) {
					s.pos++
					fmt.Fprintf(s.w, "\x1b[C")
				}
			case 'D': // left
				if s.pos > 0 {
					s.pos--
					fmt.Fprintf(s.w, "\x1b[D")
				}
			default:
				if len(escBuf) < 3 {
					continue // wait for more bytes
				}
				// Unknown sequence — discard.
			}
			inEsc = false
			escBuf = escBuf[:0]
			continue
		}

		// ── Single-byte control characters ────────────────────────────────
		switch b {
		case 0x1b: // ESC — start of escape sequence
			inEsc = true
			escBuf = escBuf[:0]

		case '\r', '\n': // Enter
			fmt.Fprintf(s.w, "\r\n")
			line := string(s.buf)
			s.buf = s.buf[:0]
			s.pos = 0
			s.histIdx = -1
			if strings.TrimSpace(line) != "" {
				if len(s.history) == 0 || s.history[len(s.history)-1] != line {
					s.history = append(s.history, line)
				}
				if s.execute(line) {
					return nil
				}
			}
			s.printPrompt()

		case 0x09: // Tab — completion
			s.handleTab()

		case 0x03: // Ctrl+C — cancel line
			fmt.Fprintf(s.w, "^C\r\n")
			s.buf = s.buf[:0]
			s.pos = 0
			s.histIdx = -1
			s.printPrompt()

		case 0x04: // Ctrl+D — EOF on empty line
			if len(s.buf) == 0 {
				fmt.Fprintf(s.w, "exit\r\n")
				return nil
			}

		case 0x01: // Ctrl+A — beginning of line
			s.pos = 0
			s.renderLine()

		case 0x05: // Ctrl+E — end of line
			s.pos = len(s.buf)
			s.renderLine()

		case 0x15: // Ctrl+U — kill to beginning of line
			s.buf = s.buf[s.pos:]
			s.pos = 0
			s.renderLine()

		case 0x0b: // Ctrl+K — kill to end of line
			s.buf = s.buf[:s.pos]
			s.renderLine()

		case 0x7f, 0x08: // Backspace / DEL
			if s.pos > 0 {
				s.buf = append(s.buf[:s.pos-1], s.buf[s.pos:]...)
				s.pos--
				s.renderLine()
			}

		default:
			if b >= 0x20 { // printable ASCII
				r := rune(b)
				s.buf = append(s.buf[:s.pos], append([]rune{r}, s.buf[s.pos:]...)...)
				s.pos++
				s.renderLine()
			}
		}
	}
}

// ── Line editing ──────────────────────────────────────────────────────────────

// printPrompt writes the coloured user@host:cwd$ prompt.
func (s *MiniShell) printPrompt() {
	host, _ := os.Hostname()
	uname := "?"
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	cwd := s.cwd
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(cwd, home) {
		cwd = "~" + cwd[len(home):]
	}
	fmt.Fprintf(s.w, "\x1b[1;32m%s@%s\x1b[0m:\x1b[1;34m%s\x1b[0m$ ", uname, host, cwd)
}

// renderLine redraws the prompt + current buffer in-place and repositions
// the cursor to s.pos.
func (s *MiniShell) renderLine() {
	fmt.Fprintf(s.w, "\r\x1b[2K") // carriage-return, erase line
	s.printPrompt()
	fmt.Fprintf(s.w, "%s", string(s.buf))
	if back := len(s.buf) - s.pos; back > 0 {
		fmt.Fprintf(s.w, "\x1b[%dD", back)
	}
}

func (s *MiniShell) historyPrev() {
	if len(s.history) == 0 {
		return
	}
	if s.histIdx < 0 {
		s.histIdx = len(s.history) - 1
	} else if s.histIdx > 0 {
		s.histIdx--
	}
	s.buf = []rune(s.history[s.histIdx])
	s.pos = len(s.buf)
	s.renderLine()
}

func (s *MiniShell) historyNext() {
	if s.histIdx < 0 {
		return
	}
	s.histIdx++
	if s.histIdx >= len(s.history) {
		s.histIdx = -1
		s.buf = s.buf[:0]
		s.pos = 0
	} else {
		s.buf = []rune(s.history[s.histIdx])
		s.pos = len(s.buf)
	}
	s.renderLine()
}

// ── Tab completion ────────────────────────────────────────────────────────────

func (s *MiniShell) handleTab() {
	head := string(s.buf[:s.pos]) // portion of line left of cursor
	completions := s.complete(head)

	switch len(completions) {
	case 0:
		fmt.Fprintf(s.w, "\a") // bell

	case 1:
		// Unique match — insert the missing suffix and a trailing separator.
		prefix := lastToken(head)
		suffix := completions[0][len(prefix):]
		for _, r := range suffix {
			s.buf = append(s.buf[:s.pos], append([]rune{r}, s.buf[s.pos:]...)...)
			s.pos++
		}
		sep := rune(' ')
		if isDir(completions[0]) {
			sep = '/'
		}
		s.buf = append(s.buf[:s.pos], append([]rune{sep}, s.buf[s.pos:]...)...)
		s.pos++
		s.renderLine()

	default:
		// Multiple matches — fill the longest common prefix then list options.
		prefix := lastToken(head)
		lcp := longestCommonPrefix(completions)
		if len(lcp) > len(prefix) {
			for _, r := range lcp[len(prefix):] {
				s.buf = append(s.buf[:s.pos], append([]rune{r}, s.buf[s.pos:]...)...)
				s.pos++
			}
		}
		fmt.Fprintf(s.w, "\r\n")
		printColumns(s.w, completions)
		s.renderLine()
	}
}

// complete generates completions for partial.
// The first token is completed against PATH binaries and built-ins;
// subsequent tokens are completed against file paths.
func (s *MiniShell) complete(partial string) []string {
	token := lastToken(partial)
	first := isFirstToken(partial)

	// Path-style token (contains / or starts with . or ~) → file completion.
	if strings.ContainsAny(token, "/") || strings.HasPrefix(token, ".") || strings.HasPrefix(token, "~") {
		return s.completePath(token)
	}
	if first {
		return s.completeCommand(token)
	}
	return s.completePath(token)
}

func (s *MiniShell) completePath(partial string) []string {
	expanded := partial
	if strings.HasPrefix(partial, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			expanded = home + partial[1:]
		}
	}

	dir, base := filepath.Dir(expanded), filepath.Base(expanded)
	if strings.HasSuffix(expanded, "/") {
		dir, base = expanded, ""
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var matches []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), base) {
			continue
		}
		match := filepath.Join(dir, e.Name())
		if strings.HasPrefix(partial, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				match = "~" + strings.TrimPrefix(match, home)
			}
		}
		matches = append(matches, match)
	}
	sort.Strings(matches)
	return matches
}

func (s *MiniShell) completeCommand(partial string) []string {
	seen := map[string]bool{}
	var matches []string

	// Built-ins first so they show up at the top.
	for _, name := range miniBuiltinNames {
		if strings.HasPrefix(name, partial) {
			matches = append(matches, name)
			seen[name] = true
		}
	}

	pathDirs := filepath.SplitList(s.getEnv("PATH"))
	if len(pathDirs) == 0 {
		pathDirs = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	}
	for _, dir := range pathDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, partial) || seen[name] {
				continue
			}
			info, err := e.Info()
			if err != nil || info.Mode()&0o111 == 0 {
				continue
			}
			matches = append(matches, name)
			seen[name] = true
		}
	}
	sort.Strings(matches)
	return matches
}

// ── Built-in commands ─────────────────────────────────────────────────────────

var miniBuiltinNames = []string{"cd", "env", "exit", "export", "help", "pwd", "which"}

type miniBuiltinStatus int

const (
	miniOK       miniBuiltinStatus = iota
	miniExit                       // shell should exit
	miniNotFound                   // not a built-in; fall through to exec
)

func (s *MiniShell) runBuiltin(args []string) miniBuiltinStatus {
	switch args[0] {

	case "exit":
		return miniExit

	case "cd":
		dir := ""
		if len(args) >= 2 {
			dir = args[1]
		} else {
			dir, _ = os.UserHomeDir()
		}
		if strings.HasPrefix(dir, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				dir = home + dir[1:]
			}
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(s.cwd, dir)
		}
		dir = filepath.Clean(dir)
		if err := os.Chdir(dir); err != nil {
			fmt.Fprintf(s.w, "cd: %v\r\n", err)
		} else {
			s.cwd = dir
		}

	case "pwd":
		fmt.Fprintf(s.w, "%s\r\n", s.cwd)

	case "export":
		if len(args) == 1 {
			for _, e := range s.envExtra {
				fmt.Fprintf(s.w, "export %s\r\n", e)
			}
			return miniOK
		}
		for _, kv := range args[1:] {
			if strings.Contains(kv, "=") {
				s.setEnv(kv)
			} else {
				fmt.Fprintf(s.w, "%s=%s\r\n", kv, s.getEnv(kv))
			}
		}

	case "env":
		for _, e := range append(os.Environ(), s.envExtra...) {
			fmt.Fprintf(s.w, "%s\r\n", e)
		}

	case "which":
		for _, name := range args[1:] {
			pathDirs := filepath.SplitList(s.getEnv("PATH"))
			found := false
			for _, dir := range pathDirs {
				p := filepath.Join(dir, name)
				if info, err := os.Stat(p); err == nil && info.Mode()&0o111 != 0 {
					fmt.Fprintf(s.w, "%s\r\n", p)
					found = true
					break
				}
			}
			if !found {
				fmt.Fprintf(s.w, "%s: not found\r\n", name)
			}
		}

	case "help":
		fmt.Fprintf(s.w, "\r\nminishell — alcapwn built-in shell\r\n\r\n")
		fmt.Fprintf(s.w, "  Built-ins:   cd  pwd  export  env  which  help  exit\r\n")
		fmt.Fprintf(s.w, "  Pipelines:   cmd1 | cmd2 | cmd3\r\n")
		fmt.Fprintf(s.w, "  Redirects:   >  >>  <  2>\r\n")
		fmt.Fprintf(s.w, "  Completion:  Tab (binaries from PATH, file paths)\r\n")
		fmt.Fprintf(s.w, "  History:     ↑ / ↓\r\n")
		fmt.Fprintf(s.w, "  Keys:        Ctrl+A/E  home/end\r\n")
		fmt.Fprintf(s.w, "               Ctrl+U/K  kill left/right of cursor\r\n")
		fmt.Fprintf(s.w, "               Ctrl+C    cancel line\r\n")
		fmt.Fprintf(s.w, "               Ctrl+D    exit (on empty line)\r\n\r\n")

	default:
		return miniNotFound
	}
	return miniOK
}

// getEnv returns the value of key, preferring envExtra over os.Environ.
func (s *MiniShell) getEnv(key string) string {
	prefix := key + "="
	for i := len(s.envExtra) - 1; i >= 0; i-- {
		if strings.HasPrefix(s.envExtra[i], prefix) {
			return s.envExtra[i][len(prefix):]
		}
	}
	return os.Getenv(key)
}

// setEnv upserts a KEY=value pair in envExtra.
func (s *MiniShell) setEnv(kv string) {
	key := kv[:strings.Index(kv, "=")]
	prefix := key + "="
	for i, e := range s.envExtra {
		if strings.HasPrefix(e, prefix) {
			s.envExtra[i] = kv
			return
		}
	}
	s.envExtra = append(s.envExtra, kv)
}

// ── Command execution ─────────────────────────────────────────────────────────

// execute parses and runs line; returns true if the shell should exit.
func (s *MiniShell) execute(line string) (exit bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}

	// Parse first to detect the command name for built-in dispatch.
	args, err := parseArgs(line)
	if err != nil {
		fmt.Fprintf(s.w, "minishell: parse error: %v\r\n", err)
		return false
	}
	if len(args) == 0 {
		return false
	}

	// Built-ins run before pipeline parsing (they mutate shell state).
	switch s.runBuiltin(args) {
	case miniExit:
		return true
	case miniOK:
		return false
	}

	stages, err := parsePipeline(line)
	if err != nil {
		fmt.Fprintf(s.w, "minishell: %v\r\n", err)
		return false
	}

	env := append(os.Environ(), s.envExtra...)
	if err := runPipeline(stages, s.r, s.w, s.w, env, s.cwd); err != nil {
		// Exit-code errors are normal (grep with no match, etc.) — don't print.
		if _, ok := err.(*exec.ExitError); !ok {
			fmt.Fprintf(s.w, "minishell: %v\r\n", err)
		}
	}
	return false
}

// ── Pipeline parsing & execution ──────────────────────────────────────────────

// pipelineStage holds the args and redirection targets for one pipeline stage.
type pipelineStage struct {
	args        []string
	stdinFile   string // "<"
	stdoutFile  string // ">"
	stdoutAppend string // ">>"
	stderrFile  string // "2>"
}

// parsePipeline splits cmdline on unquoted '|' and parses each segment.
func parsePipeline(cmdline string) ([]pipelineStage, error) {
	segments := splitUnquoted(cmdline, '|')
	stages := make([]pipelineStage, 0, len(segments))
	for _, seg := range segments {
		st, err := parseStage(strings.TrimSpace(seg))
		if err != nil {
			return nil, err
		}
		stages = append(stages, st)
	}
	return stages, nil
}

// parseStage tokenises one pipeline segment, extracting redirection operators.
func parseStage(seg string) (pipelineStage, error) {
	tokens, err := parseArgs(seg)
	if err != nil {
		return pipelineStage{}, err
	}
	var st pipelineStage
	clean := tokens[:0]
	for i := 0; i < len(tokens); i++ {
		switch tokens[i] {
		case "<":
			if i+1 >= len(tokens) {
				return pipelineStage{}, fmt.Errorf("expected filename after <")
			}
			i++
			st.stdinFile = tokens[i]
		case ">":
			if i+1 >= len(tokens) {
				return pipelineStage{}, fmt.Errorf("expected filename after >")
			}
			i++
			st.stdoutFile = tokens[i]
		case ">>":
			if i+1 >= len(tokens) {
				return pipelineStage{}, fmt.Errorf("expected filename after >>")
			}
			i++
			st.stdoutAppend = tokens[i]
		case "2>":
			if i+1 >= len(tokens) {
				return pipelineStage{}, fmt.Errorf("expected filename after 2>")
			}
			i++
			st.stderrFile = tokens[i]
		default:
			clean = append(clean, tokens[i])
		}
	}
	st.args = clean
	return st, nil
}

// runPipeline wires stages together and executes them concurrently.
func runPipeline(stages []pipelineStage, defaultStdin io.Reader, defaultStdout, defaultStderr io.Writer, env []string, cwd string) error {
	if len(stages) == 0 {
		return nil
	}
	if len(stages) == 1 {
		return runStage(stages[0], defaultStdin, defaultStdout, defaultStderr, env, cwd)
	}

	n := len(stages)
	readers := make([]*os.File, n-1)
	writers := make([]*os.File, n-1)
	for i := range readers {
		r, w, err := os.Pipe()
		if err != nil {
			return err
		}
		readers[i], writers[i] = r, w
	}

	cmds := make([]*exec.Cmd, n)
	for i, st := range stages {
		if len(st.args) == 0 {
			return fmt.Errorf("empty pipeline stage")
		}
		cmd := exec.Command(st.args[0], st.args[1:]...)
		cmd.Env = env
		if cwd != "" {
			cmd.Dir = cwd
		}
		// Wire inter-stage I/O.
		if i == 0 {
			cmd.Stdin = defaultStdin
		} else {
			cmd.Stdin = readers[i-1]
		}
		if i == n-1 {
			cmd.Stdout = defaultStdout
		} else {
			cmd.Stdout = writers[i]
		}
		cmd.Stderr = defaultStderr
		// Apply any file redirections for this stage.
		if err := openRedirections(cmd, st); err != nil {
			return err
		}
		cmds[i] = cmd
	}

	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			return err
		}
	}
	// Close write-ends in the parent after all children have inherited them.
	for _, w := range writers {
		w.Close()
	}
	var lastErr error
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			lastErr = err
		}
	}
	for _, r := range readers {
		r.Close()
	}
	return lastErr
}

// runStage executes a single command, applying its file redirections.
func runStage(st pipelineStage, defaultStdin io.Reader, defaultStdout, defaultStderr io.Writer, env []string, cwd string) error {
	if len(st.args) == 0 {
		return nil
	}
	cmd := exec.Command(st.args[0], st.args[1:]...)
	cmd.Env = env
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.Stdin = defaultStdin
	cmd.Stdout = defaultStdout
	cmd.Stderr = defaultStderr
	if err := openRedirections(cmd, st); err != nil {
		return err
	}
	return cmd.Run()
}

// openRedirections opens the files named in st and wires them into cmd.
// Opened files are closed after cmd.Run returns via runtime finalisation;
// for long pipelines callers should rely on the OS to reclaim them on exit.
func openRedirections(cmd *exec.Cmd, st pipelineStage) error {
	if st.stdinFile != "" {
		f, err := os.Open(st.stdinFile)
		if err != nil {
			return err
		}
		cmd.Stdin = f
	}
	if st.stdoutFile != "" {
		f, err := os.Create(st.stdoutFile)
		if err != nil {
			return err
		}
		cmd.Stdout = f
	}
	if st.stdoutAppend != "" {
		f, err := os.OpenFile(st.stdoutAppend, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		cmd.Stdout = f
	}
	if st.stderrFile != "" {
		f, err := os.Create(st.stderrFile)
		if err != nil {
			return err
		}
		cmd.Stderr = f
	}
	return nil
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

// parseArgs tokenises s respecting single-quotes, double-quotes, and
// backslash escapes.  Redirection operators (<, >, >>, 2>) are returned
// as their own tokens even without surrounding spaces.
func parseArgs(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inSingle, inDouble := false, false

	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			} else if c == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t':
			flush()
		// Emit redirection operators as their own tokens.
		case c == '2' && i+1 < len(s) && s[i+1] == '>':
			flush()
			args = append(args, "2>")
			i++
		case c == '>' && i+1 < len(s) && s[i+1] == '>':
			flush()
			args = append(args, ">>")
			i++
		case c == '>':
			flush()
			args = append(args, ">")
		case c == '<':
			flush()
			args = append(args, "<")
		default:
			cur.WriteByte(c)
		}
	}
	if inSingle {
		return nil, fmt.Errorf("unclosed single quote")
	}
	if inDouble {
		return nil, fmt.Errorf("unclosed double quote")
	}
	flush()
	return args, nil
}

// splitUnquoted splits s on every occurrence of sep that is not inside
// single or double quotes.
func splitUnquoted(s string, sep byte) []string {
	var parts []string
	var cur strings.Builder
	inSingle, inDouble := false, false

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteByte(c)
		case c == sep && !inSingle && !inDouble:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	return parts
}

// ── Completion utilities ──────────────────────────────────────────────────────

// lastToken returns the last whitespace-delimited word in line, or "" if
// line is empty or ends with whitespace (cursor is between tokens).
func lastToken(line string) string {
	if line == "" || line[len(line)-1] == ' ' || line[len(line)-1] == '\t' {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// isFirstToken returns true when line contains only one token (no whitespace
// after the first non-space character), meaning we're completing a command.
func isFirstToken(line string) bool {
	return !strings.ContainsAny(strings.TrimLeft(line, " \t"), " \t")
}

// longestCommonPrefix returns the longest string that is a prefix of every
// element in ss.
func longestCommonPrefix(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	prefix := ss[0]
	for _, s := range ss[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// isDir reports whether path refers to a directory.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// printColumns prints names in a compact column layout suitable for an
// 80-character-wide terminal.
func printColumns(w io.Writer, names []string) {
	const termWidth = 80
	maxLen := 0
	for _, n := range names {
		if len(n) > maxLen {
			maxLen = len(n)
		}
	}
	colW := maxLen + 2
	nCols := termWidth / colW
	if nCols < 1 {
		nCols = 1
	}
	for i, n := range names {
		fmt.Fprintf(w, "%-*s", colW, n)
		if (i+1)%nCols == 0 {
			fmt.Fprintf(w, "\r\n")
		}
	}
	if len(names)%nCols != 0 {
		fmt.Fprintf(w, "\r\n")
	}
}
