//go:build !windows

package main

import "fmt"

// runWindowsRecon is a stub for non-Windows platforms.
// The real implementation is in recon_windows.go.
func runWindowsRecon() ([]byte, error) {
	return nil, fmt.Errorf("windows recon not supported on this platform")
}
