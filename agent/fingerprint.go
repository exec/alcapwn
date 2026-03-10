package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"strings"
)

// machineID returns a stable 16-character hex identifier for this host derived
// from /etc/machine-id (Linux) and the first non-loopback hardware MAC address.
// Falls back to hostname when neither source is available (macOS, minimal containers).
func machineID() string {
	var parts []string

	// Primary source: /etc/machine-id (systemd, present on nearly all Linux)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			parts = append(parts, s)
		}
	}

	// Secondary source: first non-loopback, non-virtual hardware MAC
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if mac := iface.HardwareAddr.String(); mac != "" {
				parts = append(parts, mac)
				break
			}
		}
	}

	// Fallback: hostname (universally available)
	if len(parts) == 0 {
		hostname, _ := os.Hostname()
		parts = append(parts, hostname)
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return fmt.Sprintf("%x", sum[:8]) // 16 hex chars
}
