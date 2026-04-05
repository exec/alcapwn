package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"alcapwn/proto"
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
	fmt.Println(colorizePrefixed(fmt.Sprintf(format, args...)))
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

// makeInputRaw is defined in makeInputRaw_linux.go / makeInputRaw_darwin.go.

// ── lineEditor ────────────────────────────────────────────────────────────────

// lineEditor provides arrow-key navigation and command history at the operator
// prompt by putting the terminal in raw mode during input so escape sequences
// are delivered as byte sequences instead of being processed by the OS line
// discipline.
type lineEditor struct {
	mu        sync.Mutex
	buf       []rune   // current input line
	pos       int      // cursor position within buf
	history   []string // submitted command history
	histIdx   int      // index into history (len == "none selected")
	active    bool     // true while readLine is blocking for input
	prompt    string   // prompt string, for redraws triggered by Notify
	fd        int      // terminal fd for raw-mode operations
	restoreFn func()   // terminal restore callback; set while in raw mode
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

// restoreTerminal calls the stored terminal restore function if one is set.
// Safe to call from any goroutine (e.g. signal handler).
func (e *lineEditor) restoreTerminal() {
	e.mu.Lock()
	fn := e.restoreFn
	e.mu.Unlock()
	if fn != nil {
		fn()
	}
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
	e.restoreFn = restore
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.active = false
		e.restoreFn = nil
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
	registry      *Registry
	listeners     *listenerRegistry
	httpListeners *httpListenerRegistry
	opts          sessionOpts
	printer       *consolePrinter
	state         consoleState
	editor        *lineEditor

	// pendingTLSUpgrade maps source IP → channel for in-flight manual TLS
	// upgrades.  acceptLoop checks this before allocating a new session so the
	// reconnecting connection is handed directly to cmdTLSUpgrade's goroutine
	// instead of creating an unwanted new session.
	pendingTLSMu      sync.Mutex
	pendingTLSUpgrade map[string]chan net.Conn

	// persistence and config
	persistMu sync.Mutex
	persist   *PersistenceStore
	config    *Config
	configMu  sync.Mutex

	// firewall
	firewallMu sync.Mutex
	firewalls  *FirewallStore
}

// NewConsole creates a Console bound to the given registry and base opts.
func NewConsole(registry *Registry, opts sessionOpts) *Console {
	c := &Console{
		registry:          registry,
		listeners:         newListenerRegistry(),
		httpListeners:     newHTTPListenerRegistry(),
		opts:              opts,
		pendingTLSUpgrade: make(map[string]chan net.Conn),
		editor:            newLineEditor(int(os.Stdin.Fd())),
		persist:           NewPersistenceStore(),
		config:            &Config{AutoOpenListeners: true},
		firewalls:         NewFirewallStore(),
	}
	c.printer = &consolePrinter{console: c}

	// Load config and persistence if they exist
	c.LoadConfig()
	c.LoadPersistence()
	c.LoadFirewalls()

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

		// Enable TCP keepalives so the OS detects dead connections and closes
		// them without needing an explicit heartbeat command.  The drain
		// goroutine then receives the error and removes the session cleanly.
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		srcIP := hostFromAddr(conn.RemoteAddr())

		// Check firewall if listener has one assigned
		if !c.checkFirewall(srcIP, entry.addr) {
			c.printer.Notify("[!] Connection denied by firewall: %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// If a manual 'tls <id>' upgrade is in flight for this source IP, hand
		// the raw connection directly to its goroutine instead of creating a new
		// session.  The goroutine does its own TLS peek + handshake.
		c.pendingTLSMu.Lock()
		upgradeCh := c.pendingTLSUpgrade[srcIP]
		c.pendingTLSMu.Unlock()
		if upgradeCh != nil {
			select {
			case upgradeCh <- conn:
				// Session will be created by cmdTLSUpgrade, auto-whitelist IP
				c.autoWhitelistIP(srcIP)
				continue // owned by cmdTLSUpgrade goroutine; skip normal path
			default:
				// Upgrade timed out; fall through to normal session handling.
			}
		}

		var finalConn net.Conn = conn
		isTLS := false
		isAgent := false

		// Peek the first 4 bytes to identify the connection protocol:
		//   'A','L','C','A' → alcapwn agent binary (proto.Magic)
		//   0x16            → TLS ClientHello (when --tls is active)
		//   anything else   → raw PTY / reverse shell
		// The peeked bytes are re-injected via prefixConn so downstream
		// readers (proto.ReadMsg, PTYUpgrader) see the full original stream.
		{
			peek := make([]byte, 4)
			n, _ := io.ReadFull(conn, peek)
			peek = peek[:n]

			switch {
			case proto.IsAgentHandshake(peek):
				isAgent = true
				if c.opts.verbosity >= 1 {
					c.printer.Notify("[*] Incoming connection identified as agent (magic: %q)", string(peek))
				}
				finalConn = &prefixConn{Conn: conn, prefix: peek}

			case n > 0 && peek[0] == 0x16 && c.opts.tlsEnabled && c.opts.tlsCfg != nil:
				tlsConn := tls.Server(&prefixConn{Conn: conn, prefix: peek}, c.opts.tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					c.printer.Notify("[!] TLS handshake failed from %s: %v", conn.RemoteAddr(), err)
					continue
				}
				finalConn = tlsConn
				isTLS = true

			default:
				if n > 0 {
					finalConn = &prefixConn{Conn: conn, prefix: peek}
				}
			}
		}

		sess := c.registry.Allocate(finalConn, isTLS)
		if sess == nil {
			finalConn.Close()
			continue
		}
		sess.ListenerAddr = entry.addr

		atomic.AddInt32(&entry.sessionCount, 1)

		// Check if this looks like a reconnect from a named persistent session.
		// If so, auto-label the new session with the stored name.
		persistLabel := c.lookupPersistentName(srcIP, entry.addr)
		if persistLabel != "" {
			sess.Label = sanitizeLabel(persistLabel) // sanitize even though value came from us
			c.printer.Notify("[+] Session [%d] opened — %s  (persistent: %s)", sess.ID, finalConn.RemoteAddr(), persistLabel)
		} else {
			c.printer.Notify("[+] Session [%d] opened — %s", sess.ID, finalConn.RemoteAddr())
		}

		sessOpts := c.opts
		sessOpts.printer = c.printer
		sessOpts.registry = c.registry
		sessOpts.listenIP = listenIP
		sessOpts.listenPort = listenPort
		sessOpts.registerTLSWaiter = c.registerTLSWaiter
		sessOpts.persist = c.persist
		sessOpts.persistMu = &c.persistMu

		if isAgent {
			if sessOpts.autoRecon {
				sessOpts.agentReadyCb = func(s *Session) { c.cmdReconAgent(s) }
			}
			go func(s *Session, o sessionOpts, e *listenerEntry) {
				handleAgentSession(s, o)
				atomic.AddInt32(&e.sessionCount, -1)
			}(sess, sessOpts, entry)
		} else {
			go func(s *Session, o sessionOpts, e *listenerEntry) {
				handleSession(s, o)
				atomic.AddInt32(&e.sessionCount, -1)
			}(sess, sessOpts, entry)
		}
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
			c.cmdSessions(args)
		case "use":
			c.cmdUse(args)
		case "kill":
			c.cmdKill(args)
		case "info":
			c.cmdInfo(args)
		case "exec":
			c.cmdExec(args)
		case "ps":
			c.cmdPs(args)
		case "shell":
			c.cmdShell(args)
		case "pivot":
			c.cmdPivot(args)
		case "scan":
			c.cmdScan(args)
		case "killproc":
			c.cmdKillproc(args)
		case "export":
			c.cmdExport(args)
		case "firewall":
			c.cmdFirewall(args)
		case "download":
			c.cmdDownload(args)
		case "upload":
			c.cmdUpload(args)
		case "persist":
			c.cmdPersist(args)
		case "config":
			c.cmdConfig(args)
		case "labels":
			c.cmdLabels(args)
		case "notes":
			c.cmdNotes(args)
		case "recon":
			c.cmdRecon(args)
		case "creds":
			c.cmdCreds(args)
		case "exploit":
			c.cmdExploit(args)
		case "generate", "gen":
			c.cmdGenerate(args)
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
			c.editor.restoreTerminal()
			c.cleanShutdown()
			os.Exit(0)
		}
	}
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
	state    ifState
	oscBuf   []byte // buffers \e] + up to 3 content bytes to detect OSC 52
	apcSeen  bool   // true after the first APC — prevents repeat warnings
	utf8Rem  int    // remaining expected UTF-8 continuation bytes (0 = not in multibyte seq)
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
// The filter is byte-by-byte and f.state persists across calls, so sequences
// split across TCP chunk boundaries are handled correctly.
func (f *interactiveFilter) process(p []byte) (out []byte, apcDetected bool) {
	for _, b := range p {
		switch f.state {

		case ifNormal:
			// Strip C1 control codes (0x80-0x9F) — 8-bit equivalents of dangerous ESC sequences.
			// These have no legitimate use in UTF-8 terminal output.
			if b >= 0x80 && b <= 0x9f {
				continue
			}
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
			fdSet(&rfds, fd)
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

// shellInteract is the raw I/O loop for 'shell <id>' agent sessions.
// conn is the relay TCP connection to the agent's shell subprocess.
// Ctrl+D closes the shell.  Ctrl+C is forwarded.
// Blocks until the shell exits or the relay closes.
func (c *Console) shellInteract(sessID int, conn net.Conn) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Println("[!] stdin is not a TTY — interactive mode unavailable")
		return
	}

	fmt.Printf("[*] Shell session %d — Ctrl+D to close\n", sessID)

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Printf("[!] raw mode: %v\n", err)
		return
	}

	remoteDone := make(chan struct{})
	stdinDone := make(chan struct{})
	cancelCh := make(chan struct{})
	var cancelOnce sync.Once
	cancelStdin := func() { cancelOnce.Do(func() { close(cancelCh) }) }

	// remote → stdout with ANSI safety filter.
	go func() {
		defer close(remoteDone)
		flt := &interactiveFilter{}
		buf := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				safe, apcDetected := flt.process(buf[:n])
				if apcDetected {
					os.Stdout.Write([]byte("\r\n[!] APC sequence stripped\r\n")) //nolint:errcheck
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

	// stdin → remote; Ctrl+D closes the relay.
	go func() {
		defer close(stdinDone)
		buf := make([]byte, 1)
		for {
			var rfds unix.FdSet
			fdSet(&rfds, fd)
			tv := unix.Timeval{Sec: 0, Usec: 50_000}
			n, selErr := unix.Select(fd+1, &rfds, nil, nil, &tv)
			if selErr != nil {
				if selErr == syscall.EINTR {
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
			if buf[0] == 0x04 { // Ctrl+D → close shell
				conn.Close()
				return
			}
			if _, writeErr := conn.Write(buf); writeErr != nil {
				return
			}
		}
	}()

	select {
	case <-remoteDone:
		cancelStdin()
		select {
		case <-stdinDone:
		case <-time.After(150 * time.Millisecond):
		}
	case <-stdinDone:
		conn.Close()
		select {
		case <-remoteDone:
		case <-time.After(500 * time.Millisecond):
		}
	}

	term.Restore(fd, oldState) //nolint:errcheck
	fmt.Printf("\r\n[*] Shell session %d closed.\n", sessID)
}

