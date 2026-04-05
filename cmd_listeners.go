package main

import (
	"crypto/tls"
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

	// listen http <addr> [--register <path>] [--beacon <path>]
	if strings.ToLower(args[0]) == "http" {
		if len(args) < 2 {
			fmt.Println("[!] Usage: listen http <host:port> [--register <path>] [--beacon <path>] [--tls]")
			return
		}
		addr := args[1]
		if _, _, err := net.SplitHostPort(addr); err != nil {
			fmt.Printf("[!] Invalid address %q: %v\n", addr, err)
			return
		}
		var registerPath, beaconPath, downloadDir string
		var useTLSFlag bool
		rest := args[2:]
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--register":
				if i+1 < len(rest) { i++; registerPath = rest[i] }
			case "--beacon":
				if i+1 < len(rest) { i++; beaconPath = rest[i] }
			case "--download-dir":
				if i+1 < len(rest) { i++; downloadDir = rest[i] }
			case "--tls":
				useTLSFlag = true
			default:
				fmt.Printf("[!] Unknown flag: %s\n", rest[i])
				return
			}
		}

		var httpTLSCfg *tls.Config
		if useTLSFlag {
			httpTLSCfg = c.opts.tlsCfg
			if httpTLSCfg == nil {
				// Should not happen after Task 1 (cert is always generated at startup),
				// but guard against misconfiguration.
				fmt.Println("[!] TLS config unavailable — was the server started normally?")
				return
			}
		}
		if err := c.StartHTTPListener(addr, registerPath, beaconPath, downloadDir, httpTLSCfg); err != nil {
			fmt.Printf("[!] %v\n", err)
			return
		}
		// Defaults for success print (mirror what StartHTTPListener uses internally).
		rp := registerPath
		if rp == "" { rp = "/register" }
		bp := beaconPath
		if bp == "" { bp = "/beacon/" }
		scheme := "http"
		if useTLSFlag { scheme = "https" }
		fmt.Printf("[*] %s listener started on %s (register=%s beacon=%s)\n",
			strings.ToUpper(scheme), addr, rp, bp)
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

	fmt.Printf("  %-3s  %-6s  %-22s  %s\n", "Idx", "Proto", "Address", "Info")
	fmt.Printf("  %-3s  %-6s  %-22s  %s\n",
		strings.Repeat("─", 3),
		strings.Repeat("─", 6),
		strings.Repeat("─", 22),
		strings.Repeat("─", 20))

	idx := 1
	// TCP listeners first
	for _, e := range tcpEntries {
		n := int(atomic.LoadInt32(&e.sessionCount))
		noun := "sessions"
		if n == 1 {
			noun = "session"
		}
		fmt.Printf("  %-3d  %-6s  %-22s  %d %s\n", idx, "TCP", e.addr, n, noun)
		idx++
	}
	// Then HTTP listeners
	for _, addr := range httpAddrs {
		c.httpListeners.mu.Lock()
		e := c.httpListeners.listeners[addr]
		c.httpListeners.mu.Unlock()

		proto := "HTTP"
		displayAddr := "http://" + addr
		if e != nil && e.useTLS {
			proto = "HTTPS"
			displayAddr = "https://" + addr
		}
		info := "—"
		if e != nil && e.useTLS {
			info = "[TLS]"
		}
		if e != nil && e.downloadDir != "" {
			if info == "[TLS]" {
				info += " download=" + e.downloadToken
			} else {
				info = "download=" + e.downloadToken
			}
		}
		fmt.Printf("  %-3d  %-6s  %-22s  %s\n", idx, proto, displayAddr, info)
		idx++
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
