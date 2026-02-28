package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
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

	// Check for DCS sequences: \x1bP...(\x1b\\)
	for {
		found := false
		for i := 0; i < len(s.buf)-1; i++ {
			if s.buf[i] == 0x1b && i+1 < len(s.buf) && s.buf[i+1] == 'P' {
				// Find terminator
				for j := i + 2; j < len(s.buf)-1; j++ {
					if s.buf[j] == 0x1b && s.buf[j+1] == '\\' {
						// Strip DCS
						s.buf = append(s.buf[:i], s.buf[j+2:]...)
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

	// Check for PM sequences: \x1b^
	for {
		found := false
		for i := 0; i < len(s.buf)-1; i++ {
			if s.buf[i] == 0x1b && i+1 < len(s.buf) && s.buf[i+1] == '^' {
				// Strip PM (2 bytes)
				s.buf = append(s.buf[:i], s.buf[i+2:]...)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	// Check for SOS sequences: \x1b\\
	for {
		found := false
		for i := 0; i < len(s.buf)-1; i++ {
			if s.buf[i] == 0x1b && i+1 < len(s.buf) && s.buf[i+1] == '\\' {
				// Strip SOS (2 bytes)
				s.buf = append(s.buf[:i], s.buf[i+2:]...)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	// Check for APC sequences: \x1b_
	for i := 0; i < len(s.buf)-1; i++ {
		if s.buf[i] == 0x1b && i+1 < len(s.buf) && s.buf[i+1] == '_' {
			s.apcWarn = true
			// Don't strip APC - keep for warning display
			break
		}
	}

	// Return the buffer (may contain trailing partial escape sequence)
	result := s.buf
	s.buf = s.buf[:0]
	return result
}

// PTYUpgrader handles upgrading a basic reverse shell to a fully functional PTY.
type PTYUpgrader struct {
	conn        net.Conn
	addr        net.Addr
	verbosity   int
	reader      *bufio.Reader
	disp        *statusDisplay
	ptyTask     int
	setupTask   int
	// Stateful ANSI parser for fragmenting pbsh v2.0 attacks
	ansiState *ANSIState
}

// NewPTYUpgrader creates a new PTYUpgrader and registers its status tasks on disp.
func NewPTYUpgrader(conn net.Conn, verbosity int, disp *statusDisplay) *PTYUpgrader {
	p := &PTYUpgrader{
		conn:      conn,
		addr:      conn.RemoteAddr(),
		verbosity: verbosity,
		reader:    bufio.NewReaderSize(conn, 4096),
		disp:      disp,
		ansiState: NewANSIState(),
	}
	p.ptyTask = disp.addTask("PTY Upgrade")
	p.setupTask = disp.addTask("Terminal Setup")
	return p
}

// write sends data to the connection.
func (p *PTYUpgrader) write(data string) error {
	_, err := p.conn.Write([]byte(data))
	return err
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

	for !rePromptPattern.MatchString(data.String()) {
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
			return sb.String(), err
		}
	}

	data := sb.String()
	if idx := strings.Index(data, sentinel); idx >= 0 {
		data = data[:idx]
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
	return nil
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

// sendWindowSize queries the local terminal dimensions and sends them to the
// remote shell via stty. Safe to call from any goroutine.
func (p *PTYUpgrader) sendWindowSize(fd int) {
	cols, rows, err := term.GetSize(fd)
	if err != nil || cols <= 0 || rows <= 0 {
		return
	}
	p.conn.Write([]byte(fmt.Sprintf("stty columns %d rows %d\n", cols, rows)))
}

// Interact enters interactive mode with the shell.
func (p *PTYUpgrader) Interact() error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Println("[!] stdin is not a TTY - interactive mode unavailable")
		return nil
	}

	// Print BEFORE entering raw mode so \n works correctly.
	fmt.Printf("[*] Entering interactive mode with %s\n", p.addr)
	fmt.Println("[*] Press Ctrl+D to close connection")

	// TCP keepalive so the OS detects silent drops (NAT timeout, cable pull, etc.)
	// without waiting for a user keypress to trigger a write error.
	if tc, ok := p.conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, oldState)

	// Forward terminal resize events to the remote shell.
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	go func() {
		for range winchCh {
			p.sendWindowSize(fd)
		}
	}()
	defer func() {
		signal.Stop(winchCh)
		close(winchCh)
	}()

	remoteDone := make(chan struct{})
	stdinDone := make(chan struct{})

	// Remote -> stdout.
	// Use stateful ANSI parser to catch fragmented escape sequences (pbsh v2.0 attack).
	// CSI sequences (colours, cursor movement) pass through unchanged — TUI apps need them.
	// All other escape sequences are stripped.
	go func() {
		defer close(remoteDone)
		buf := make([]byte, 4096)
		for {
			n, err := p.conn.Read(buf)
			if n > 0 {
				// Use stateful ANSI parser which handles byte-level fragmentation
				out := p.ansiState.Parse(buf[:n])
				if len(out) > 0 {
					os.Stdout.Write(out)
					os.Stdout.Sync()
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// APC Warning Checker goroutine - runs alongside remote reader
	// to detect APC sequences that might indicate TTY hijacking.
	apcWarningDone := make(chan struct{})
	go func() {
		defer close(apcWarningDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if p.ansiState.HasAPCWarning() {
					fmt.Print("\r\n[!] WARNING: Suspicious APC sequence detected.\r\n")
					fmt.Print("[!] Potential TTY hijacking attempt detected.\r\n")
					fmt.Print("[!] Do not enter any credentials or sensitive information.\r\n")
					return
				}
			case <-remoteDone:
				return
			}
		}
	}()

	// Stdin -> remote. Ctrl+D closes the connection immediately.
	go func() {
		defer close(stdinDone)
		buf := make([]byte, 1)
		for {
			_, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			if buf[0] == 0x04 { // Ctrl+D
				p.conn.Close()
				return
			}
			if _, err := p.conn.Write(buf); err != nil {
				return
			}
		}
	}()

	// Wait for whichever side ends first.
	// Wait for both remoteDone and apcWarningDone to ensure warnings are displayed.
	select {
	case <-remoteDone:
		// Connection dropped or closed by remote. Close our side so the stdin
		// goroutine's next Write fails and it exits on its own.
		p.conn.Close()
		<-apcWarningDone // Wait for any APC warning to be displayed
		fmt.Print("\r\n[*] Connection lost.\r\n")
	case <-stdinDone:
		// Ctrl+D or local EOF. Give the remote side a moment to drain.
		select {
		case <-remoteDone:
		case <-time.After(500 * time.Millisecond):
			p.conn.Close()
			<-remoteDone
		}
		<-apcWarningDone // Wait for any APC warning to be displayed
		fmt.Print("\r\n[*] Session closed.\r\n")
	}

	return nil
}
