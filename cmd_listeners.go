package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
)

func (c *Console) cmdListen(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: listen <host:port>  |  listen http <host:port>")
		return
	}

	// listen http <addr>
	if strings.ToLower(args[0]) == "http" {
		if len(args) < 2 {
			fmt.Println("[!] Usage: listen http <host:port>")
			return
		}
		addr := args[1]
		if _, _, err := net.SplitHostPort(addr); err != nil {
			fmt.Printf("[!] Invalid address %q: %v\n", addr, err)
			return
		}
		if err := c.StartHTTPListener(addr); err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}
		fmt.Printf("[*] HTTP listener started on %s\n", addr)
		return
	}

	// listen <addr>  (TCP)
	addr := args[0]
	if _, _, err := net.SplitHostPort(addr); err != nil {
		fmt.Printf("[!] Invalid address %q: %v\n", addr, err)
		return
	}
	c.StartListener(addr)
}

func (c *Console) cmdListeners() {
	tcpEntries := c.listeners.all()
	httpAddrs := c.httpListeners.all()
	sort.Strings(httpAddrs)

	if len(tcpEntries) == 0 && len(httpAddrs) == 0 {
		fmt.Println("[*] No active listeners.")
		return
	}

	fmt.Printf("  %-6s  %-22s  %s\n", "Proto", "Address", "Sessions")
	fmt.Printf("  %-6s  %-22s  %s\n",
		strings.Repeat("─", 6),
		strings.Repeat("─", 22),
		strings.Repeat("─", 8))

	for _, e := range tcpEntries {
		n := int(atomic.LoadInt32(&e.sessionCount))
		noun := "sessions"
		if n == 1 {
			noun = "session"
		}
		fmt.Printf("  %-6s  %-22s  %d %s\n", "TCP", e.addr, n, noun)
	}
	for _, addr := range httpAddrs {
		fmt.Printf("  %-6s  %-22s  —\n", "HTTP", addr)
	}
}

func (c *Console) cmdUnlisten(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: unlisten <port|host:port>  |  unlisten http <host:port>")
		return
	}

	// unlisten http <addr>
	if strings.ToLower(args[0]) == "http" {
		if len(args) < 2 {
			fmt.Println("[!] Usage: unlisten http <host:port>")
			return
		}
		addr := args[1]
		if err := c.StopHTTPListener(addr); err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}
		fmt.Printf("[*] HTTP listener on %s closed.\n", addr)
		return
	}

	// unlisten <port|addr>  (TCP)
	query := args[0]
	entry := c.listeners.findByPort(query)
	if entry == nil {
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
