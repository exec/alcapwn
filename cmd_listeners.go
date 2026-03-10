package main

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

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
