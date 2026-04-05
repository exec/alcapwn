package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"
)

// ANSIState is the state machine for parsing ANSI escape sequences.
// pbsh v2.0 attacks try to bypass regex-based stripping by fragmenting
// escape sequences across multiple reads. This state machine handles
// byte-by-byte parsing to catch all escape sequences.
//
// WARNING: Some ANSI sequences cannot be safely stripped without affecting
// legitimate terminal output. APC sequences (\x1b_) are a prime example - they
// are used for advanced terminal control but can also be used for TTY hijacking.
// These sequences trigger warnings to the operator.
type ANSIState struct {
	buf      []byte
	apcWarn  bool // Track if we've warned about APC in this session
}

// NewANSIState creates a new stateful ANSI parser.
func NewANSIState() *ANSIState {
	return &ANSIState{buf: make([]byte, 0, 256)}
}

// Reset clears the parser state.
func (s *ANSIState) Reset() {
	s.buf = s.buf[:0]
	s.apcWarn = false
}

// HasAPCWarning returns true if an APC sequence warning was triggered.
func (s *ANSIState) HasAPCWarning() bool {
	return s.apcWarn
}

// Parse processes a byte buffer and returns cleaned output with all
// ANSI sequences stripped. It handles byte-level fragmentation where
// escape sequences are split across multiple reads.
//
// APC sequences (\x1b_) are detected but NOT stripped - they trigger a warning
// because they may contain user-facing content that should not be silently
// removed. The operator should be aware of this potential TTY hijacking vector.
func (s *ANSIState) Parse(data []byte) []byte {
	// Append to buffer first
	s.buf = append(s.buf, data...)

	// Strip C1 control codes (0x80-0x9F) — 8-bit equivalents of dangerous ESC sequences.
	// These have no legitimate use in UTF-8 terminal output. UTF-8 lead bytes (0xC0+)
	// and their continuation bytes (0x80-0xBF) are preserved.
	// Sequence-bearing C1 codes consume their body (matching their 2-byte ESC equivalents).
	{
		n := 0
		for i := 0; i < len(s.buf); i++ {
			b := s.buf[i]
			if b >= 0xc0 {
				// UTF-8 lead byte — copy it and all continuation bytes.
				seqLen := 1
				switch {
				case b < 0xe0:
					seqLen = 2
				case b < 0xf0:
					seqLen = 3
				default:
					seqLen = 4
				}
				end := i + seqLen
				if end > len(s.buf) {
					end = len(s.buf)
				}
				copy(s.buf[n:], s.buf[i:end])
				n += end - i
				i = end - 1 // -1 because the for loop increments
				continue
			}
			if b >= 0x80 && b <= 0x9f {
				switch b {
				case 0x9b: // C1 CSI — skip params + final byte
					i++
					for i < len(s.buf) {
						fb := s.buf[i]
						if (fb >= 'A' && fb <= 'Z') || (fb >= 'a' && fb <= 'z') || (fb >= 0x40 && fb <= 0x7e) {
							break // final byte consumed
						}
						i++
					}
				case 0x9d: // C1 OSC — skip to BEL or ST
					i++
					for i < len(s.buf) {
						if s.buf[i] == 0x07 {
							break
						}
						if s.buf[i] == 0x1b && i+1 < len(s.buf) && s.buf[i+1] == '\\' {
							i++ // skip the '\' too (loop will advance past it)
							break
						}
						i++
					}
				case 0x90, 0x9e, 0x9f: // C1 DCS, PM, APC — skip to ST
					i++
					for i < len(s.buf)-1 {
						if s.buf[i] == 0x1b && s.buf[i+1] == '\\' {
							i++ // skip the '\' too
							break
						}
						i++
					}
				}
				// Other C1 codes (0x80-0x8F, 0x91-0x9A, 0x9C): just strip the byte.
				continue
			}
			s.buf[n] = b
			n++
		}
		s.buf = s.buf[:n]
	}

	// Use regex-based stripping for OSC sequences (handles variable-length content)
	// This avoids the slice bounds issue with the stateful approach
	// We strip OSC after accumulating, which is safe since we're processing in order
	for {
		// Find \x1b]...(\x07|\x1b\\)
		found := false
		for i := 0; i < len(s.buf)-1; i++ {
			if s.buf[i] == 0x1b && s.buf[i+1] == ']' {
				// Found OSC start, find terminator
				for j := i + 2; j < len(s.buf); j++ {
					if s.buf[j] == 0x07 || (s.buf[j] == 0x1b && j+1 < len(s.buf) && s.buf[j+1] == '\\') {
						// Strip this OSC sequence
						end := j + 1
						if s.buf[j] == 0x1b {
							end = j + 2 // Include \x1b\
						}
						// Remove the OSC sequence
						s.buf = append(s.buf[:i], s.buf[end:]...)
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
		if !found {
			break
		}
	}

	// Strip CSI sequences (simple ones that don't span fragments)
	// \x1b[...[a-zA-Z] or \x1b[?...[a-zA-Z]
	for {
		found := false
		for i := 0; i < len(s.buf)-1; i++ {
			if s.buf[i] == 0x1b && i+1 < len(s.buf) && s.buf[i+1] == '[' {
				// Find the final letter
				for j := i + 2; j < len(s.buf); j++ {
					b := s.buf[j]
					// CSI ends with [A-Za-z] or specific ranges
					if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= 0x40 && b <= 0x7e) {
						// Strip this CSI sequence
						s.buf = append(s.buf[:i], s.buf[j+1:]...)
						found = true
						break
					}
				}
				if found {
					break
				}
			}
		}
		if !found {
			break
		}
	}

	// Strip DCS (\x1bP), APC (\x1b_), PM (\x1b^), and SOS (\x1bX) sequences.
	// All use ST (\x1b\) as the terminator. Strip the full body.
	for {
		found := false
		for i := 0; i < len(s.buf)-1; i++ {
			if s.buf[i] == 0x1b && (s.buf[i+1] == 'P' || s.buf[i+1] == '_' || s.buf[i+1] == '^' || s.buf[i+1] == 'X') {
				if s.buf[i+1] == '_' {
					s.apcWarn = true
				}
				// Find ST terminator (\x1b\)
				end := -1
				for j := i + 2; j < len(s.buf)-1; j++ {
					if s.buf[j] == 0x1b && s.buf[j+1] == '\\' {
						end = j + 2
						break
					}
				}
				if end == -1 {
					// No ST found — strip from introducer to end of buffer
					s.buf = s.buf[:i]
				} else {
					s.buf = append(s.buf[:i], s.buf[end:]...)
				}
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	// Return a copy of the buffer. Returning s.buf directly would alias the
	// backing array, so the next Parse call would silently overwrite the
	// caller's data.
	result := make([]byte, len(s.buf))
	copy(result, s.buf)
	s.buf = s.buf[:0]
	return result
}

// PTYUpgrader handles upgrading a basic reverse shell to a fully functional PTY.
type PTYUpgrader struct {
	conn      net.Conn
	addr      net.Addr
	verbosity int
	reader    *bufio.Reader
	disp      *statusDisplay
	ptyTask   int
	setupTask int
	// Stateful ANSI parser for fragmenting pbsh v2.0 attacks
	ansiState *ANSIState
	// TLS reconnect support — populated only when tlsMode is true.
	tlsMode    bool
	usedPython bool   // true if python3 or python drove the PTY upgrade
	pythonBin  string // "python3" or "python"
}

// NewPTYUpgrader creates a new PTYUpgrader and registers its status tasks on disp.
// tlsMode gates the post-upgrade Python detection needed for TLS reconnect;
// when false it is a strict no-op so --tls=false behaviour is byte-for-byte identical.
func NewPTYUpgrader(conn net.Conn, verbosity int, disp *statusDisplay, tlsMode bool) *PTYUpgrader {
	p := &PTYUpgrader{
		conn:      conn,
		addr:      conn.RemoteAddr(),
		verbosity: verbosity,
		reader:    bufio.NewReaderSize(conn, 4096),
		disp:      disp,
		ansiState: NewANSIState(),
		tlsMode:   tlsMode,
	}
	p.ptyTask = disp.addTask("PTY Upgrade")
	p.setupTask = disp.addTask("Terminal Setup")
	return p
}

// switchConn replaces the underlying connection after a TLS reconnect.
func (p *PTYUpgrader) switchConn(c net.Conn) {
	p.conn = c
	p.reader = bufio.NewReaderSize(c, 4096)
}

// write sends data to the connection.
func (p *PTYUpgrader) write(data string) error {
	_, err := p.conn.Write([]byte(data))
	return err
}

// clearDeadline removes any read/write deadline on the connection, resets the
// bufio.Reader, and drains any residual data from the OS TCP receive buffer.
// Must be called before starting any new command operation (recon, exec, etc.).
//
// Why Reset + drain:
//   - bufio.Reader caches read errors (b.err); Reset clears that error so the
//     next ReadByte doesn't return a stale timeout immediately.
//   - readUntilSentinelProgress may find the sentinel in the command echo
//     (since the command itself contains the sentinel string) and return early,
//     leaving the actual output and bash prompt unread in the OS TCP receive
//     buffer.  readUntilPrompt has a 1 s timeout; if it times out before
//     draining the residual bytes, those bytes remain in the TCP buffer and
//     corrupt the next operation's read stream.
//   - The drain reads with a short 150 ms deadline until no more data arrives.
//     This is safe between commands because the remote shell is idle.
func (p *PTYUpgrader) clearDeadline() {
	p.conn.SetDeadline(time.Time{}) //nolint:errcheck
	p.reader.Reset(p.conn)

	// Drain any bytes left in the OS TCP receive buffer.
	drain := make([]byte, 4096)
	for {
		p.conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)) //nolint:errcheck
		n, err := p.conn.Read(drain)
		if n == 0 || err != nil {
			break
		}
	}
	p.conn.SetDeadline(time.Time{}) //nolint:errcheck
}

// PythonBin returns the detected Python binary ("python3" or "python").
// Only valid after PTY upgrade completes and only if tlsMode was true.
func (p *PTYUpgrader) PythonBin() string {
	return p.pythonBin
}

// UsedPython returns true if Python was used for the PTY upgrade.
func (p *PTYUpgrader) UsedPython() bool {
	return p.usedPython
}

// readUntilPrompt reads until a prompt pattern ($ or #) is detected or timeout.
// Uses Read instead of ReadBytes('\n') so it returns as soon as any data lands
// in the buffer — shell prompts have no trailing newline, so ReadBytes always
// blocks for the full timeout duration on the final chunk.
//
// Uses stateful ANSI parser to catch fragmented escape sequences from pbsh v2.0.
func (p *PTYUpgrader) readUntilPrompt(timeout time.Duration) (string, error) {
	p.conn.SetReadDeadline(time.Now().Add(timeout))
	defer p.conn.SetReadDeadline(time.Time{})

	var data strings.Builder
	buf := make([]byte, 4096)
	p.ansiState.Reset()

	for {
		// Only check the tail of the accumulated buffer for the prompt
		// pattern. data.String() copies the entire builder contents; by
		// checking just the last 50 bytes we avoid O(n^2) allocations on
		// large outputs.
		s := data.String()
		tail := s
		if len(tail) > 50 {
			tail = tail[len(tail)-50:]
		}
		if rePromptPattern.MatchString(tail) {
			break
		}

		n, err := p.reader.Read(buf)
		if n > 0 {
			// Strip ANSI sequences before appending to data
			clean := p.ansiState.Parse(buf[:n])
			data.Write(clean)
		}
		if err != nil {
			break
		}
	}

	// Check for APC warnings during this read operation
	if p.ansiState.HasAPCWarning() {
		fmt.Printf("\n[!] WARNING: Suspicious APC sequence detected during prompt read.\r\n")
		fmt.Printf("[!] Potential TTY hijacking attempt from %s\r\n", p.addr)
		fmt.Printf("[!] Do not enter any credentials or sensitive information.\r\n")
	}

	return data.String(), nil
}

// readUntilSentinel reads until a specific sentinel string is found.
func (p *PTYUpgrader) readUntilSentinel(sentinel string, timeout time.Duration) (string, error) {
	return p.readUntilSentinelProgress(sentinel, timeout, nil)
}

// readUntilSentinelProgress reads until sentinel, calling onLine for each line as it arrives.
// timeout is a per-read idle timeout: it resets after each successful read so that a slow
// but still-producing script doesn't get cut off by a single fixed deadline.
func (p *PTYUpgrader) readUntilSentinelProgress(sentinel string, timeout time.Duration, onLine func(string)) (string, error) {
	defer p.conn.SetReadDeadline(time.Time{})

	var sb strings.Builder

	for !strings.Contains(sb.String(), sentinel) {
		// Reset the deadline before every read so idle time is measured per-line,
		// not as a single wall-clock budget for the entire operation.
		p.conn.SetReadDeadline(time.Now().Add(timeout))
		chunk, err := p.reader.ReadBytes('\n')
		if len(chunk) > 0 {
			line := string(chunk)
			sb.WriteString(line)
			if onLine != nil {
				onLine(line)
			}
		}
		if err != nil {
			if p.verbosity >= 2 {
				fmt.Printf("[DEBUG readUntilSentinel] err=%v, sb=%q\n", err, sb.String())
			}
			return sb.String(), err
		}
	}

	data := sb.String()
	if idx := strings.Index(data, sentinel); idx >= 0 {
		data = data[:idx]
	}
	if p.verbosity >= 2 {
		fmt.Printf("[DEBUG readUntilSentinel] returning %q\n", data)
	}
	return data, nil
}

// Upgrade attempts to upgrade the shell to a PTY using multiple fallback strategies.
func (p *PTYUpgrader) Upgrade() error {
	upgradeChain := []string{
		"python3 -c 'import pty,os; os.setsid(); pty.spawn(\"/bin/bash\")'",
		"python -c 'import pty,os; os.setsid(); pty.spawn(\"/bin/bash\")'",
		"script -qc /bin/bash /dev/null",
	}
	upgradeCmd := strings.Join(upgradeChain, " || ")

	p.disp.set(p.ptyTask, taskRunning, "")

	maxRetries := 2
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			p.disp.set(p.ptyTask, taskRetrying, "")
		}

		if err := p.write("\n"); err != nil {
			p.disp.set(p.ptyTask, taskFailed, "")
			return err
		}
		time.Sleep(100 * time.Millisecond)

		if err := p.write(upgradeCmd + "\n"); err != nil {
			p.disp.set(p.ptyTask, taskFailed, "")
			return err
		}

		output, err := p.readUntilPrompt(5 * time.Second)
		if p.verbosity > 1 {
			fmt.Printf("\n[DEBUG] readUntilPrompt: err=%v, len=%d, tail=%q\n",
				err, len(output), last50(output))
		}

		if err == nil && p.hasRealPrompt(output) {
			return p.finalizeUpgrade()
		}

		if attempt < maxRetries-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	p.disp.set(p.ptyTask, taskFailed, "")
	return fmt.Errorf("PTY upgrade failed after %d attempts", maxRetries)
}

func last50(s string) string {
	if len(s) > 50 {
		return s[len(s)-50:]
	}
	return s
}

// finalizeUpgrade sets up the terminal environment and verifies the connection.
func (p *PTYUpgrader) finalizeUpgrade() error {
	p.disp.set(p.ptyTask, taskDone, "")
	p.disp.set(p.setupTask, taskRunning, "")

	cols, rows, sizeErr := term.GetSize(int(os.Stdin.Fd()))
	if sizeErr != nil || cols <= 0 || rows <= 0 {
		cols, rows = 220, 50
	}

	// One write, one sentinel read — replaces the old per-command round trips.
	// The sentinel guarantees the shell processed everything before we proceed.
	cmd := fmt.Sprintf(
		"export TERM=xterm-256color SHELL=/bin/bash; stty columns %d rows %d; echo ALCAPWN_SETUP_DONE\n",
		cols, rows,
	)
	if err := p.write(cmd); err != nil {
		p.disp.set(p.setupTask, taskFailed, "")
		return err
	}
	if _, err := p.readUntilSentinel("ALCAPWN_SETUP_DONE", 10*time.Second); err != nil {
		p.disp.set(p.setupTask, taskFailed, "")
		return err
	}

	// Drain the prompt that follows the sentinel so the bufio buffer is clean.
	// With Read-based readUntilPrompt this returns as soon as the prompt lands.
	p.readUntilPrompt(1 * time.Second)

	p.disp.set(p.setupTask, taskDone, "")

	// Only when TLS mode is active do we need to know which Python binary is available.
	// This detection is a strict no-op when tlsMode is false.
	if p.tlsMode {
		p.detectPythonBin()
	}

	return nil
}

// detectPythonBin queries the upgraded shell to determine which Python binary the
// upgrade chain used (python3 first, then python). Sets usedPython and pythonBin.
// Called when tlsMode is true (during PTY upgrade) or when manually upgrading
// a session to TLS via cmdTLSUpgrade.
func (p *PTYUpgrader) detectPythonBin() {
	const sentinel = "ALCAPWN_PYEND"
	cmd := "if command -v python3 >/dev/null 2>&1; then echo ALCAPWN_PY3; elif command -v python >/dev/null 2>&1; then echo ALCAPWN_PY; else echo ALCAPWN_NOPY; fi; echo " + sentinel + "\n"
	if err := p.write(cmd); err != nil {
		if p.verbosity >= 2 {
			fmt.Fprintf(os.Stderr, "[DEBUG detectPythonBin] write failed: %v\n", err)
		}
		return
	}
	output, err := p.readUntilSentinel(sentinel, 5*time.Second)
	p.readUntilPrompt(1 * time.Second)

	if p.verbosity >= 2 {
		fmt.Fprintf(os.Stderr, "[DEBUG detectPythonBin] err=%v output=%q\n", err, output)
	}

	if strings.Contains(output, "ALCAPWN_PY3") {
		p.usedPython = true
		p.pythonBin = "python3"
	} else if strings.Contains(output, "ALCAPWN_PY") {
		p.usedPython = true
		p.pythonBin = "python"
	}
}

// reStripOSC strips OSC sequences (\x1b]...\x07 or \x1b]...\x1b\).
// These are used for terminal title setting and other out-of-band data
// and commonly appear inside shell prompts.
//
// FIXED FOR pbsh DEFENSE:
// - Changed .* to [^\x07\x1b]* to prevent catastrophic backtracking
// - Added bracketed paste sequence filtering (\e[201~, \e[202~)
var reStripOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

// reStripBracketedPaste filters bracketed paste sequences.
// pbsh can use \e[201~ (start paste) and \e[202~ (end paste) to inject commands.
var reStripBracketedPaste = regexp.MustCompile(`\x1b\[(201~|202~)`)

// reStripDecSpecial filters DEC Special Character/Line Drawing mode entries.
// pbsh can send \x1b(0 to switch to G0 graphics set, rendering letters as boxes/lines.
// We only strip the "entry" sequences (0, 1, A), NOT the reset sequence (B).
// The reset sequence \x1b(B should be allowed to pass through.
var reStripDecSpecial = regexp.MustCompile(`\x1b\([01A]`)

// reStripCSI strips CSI sequences including DEC private mode codes (\x1b[?...).
// Used by both StripPrompts and stripANSI (recon.go) for consistent stripping.
var reStripCSI = regexp.MustCompile(`\x1b\[[?0-9;]*[a-zA-Z]`)

// rePromptBare matches a line that is nothing but a prompt character ($ or #) with
// optional surrounding whitespace — used by StripPrompts to drop bare prompt lines.
var rePromptBare = regexp.MustCompile(`^[$#]\s*$`)

// rePromptTrail matches a line ending in a prompt character followed by exactly one
// whitespace — catches "$ " and "# " style prompts at the end of cleaned lines.
var rePromptTrail = regexp.MustCompile(`[$#]\s$`)

// StripPrompts removes shell prompt lines from output.
func (p *PTYUpgrader) StripPrompts(output string) string {
	lines := []string{}

	for _, line := range strings.Split(output, "\n") {
		clean := reStripOSC.ReplaceAllString(line, "")
		clean = reStripCSI.ReplaceAllString(clean, "")
		clean = strings.TrimSpace(clean)

		if strings.Contains(clean, "@") && (strings.Contains(clean, "$") || strings.Contains(clean, "#")) {
			continue
		}
		if rePromptBare.MatchString(clean) {
			continue
		}
		if rePromptTrail.MatchString(clean) {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// hasRealPrompt checks if output contains a real shell prompt.
func (p *PTYUpgrader) hasRealPrompt(output string) bool {
	if !rePromptPattern.MatchString(output) {
		return false
	}

	promptMatch := rePromptPattern.FindStringIndex(output)
	if promptMatch == nil {
		return false
	}

	beforePrompt := output[:promptMatch[0]]
	lines := strings.Split(strings.TrimSpace(beforePrompt), "\n")

	nonEmpty := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			nonEmpty++
		}
	}
	return nonEmpty >= 1
}

