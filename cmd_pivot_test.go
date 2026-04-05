package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// ── TestSocks5Handshake ─────────────────────────────────────────────────────

// socks5GreetingNoAuth builds a SOCKS5 greeting requesting NO AUTH (0x00).
func socks5GreetingNoAuth() []byte {
	return []byte{0x05, 0x01, 0x00} // VER=5, NMETHODS=1, METHOD=NO_AUTH
}

// socks5ConnectIPv4 builds a SOCKS5 CONNECT request to an IPv4 address.
func socks5ConnectIPv4(ip net.IP, port uint16) []byte {
	buf := []byte{0x05, 0x01, 0x00, 0x01} // VER=5 CMD=CONNECT RSV=0 ATYP=IPv4
	buf = append(buf, ip.To4()...)
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// socks5ConnectDomain builds a SOCKS5 CONNECT request to a domain.
func socks5ConnectDomain(domain string, port uint16) []byte {
	buf := []byte{0x05, 0x01, 0x00, 0x03}    // VER=5 CMD=CONNECT RSV=0 ATYP=DOMAIN
	buf = append(buf, byte(len(domain)))       // domain length
	buf = append(buf, []byte(domain)...)       // domain
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// socks5ConnectIPv6 builds a SOCKS5 CONNECT request to an IPv6 address.
func socks5ConnectIPv6(ip net.IP, port uint16) []byte {
	buf := []byte{0x05, 0x01, 0x00, 0x04} // VER=5 CMD=CONNECT RSV=0 ATYP=IPv6
	buf = append(buf, ip.To16()...)
	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

func TestSocks5Handshake_IPv4(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	targetCh := make(chan string, 1)

	go func() {
		target, err := socks5Handshake(server)
		errCh <- err
		targetCh <- target
	}()

	// Send greeting
	if _, err := client.Write(socks5GreetingNoAuth()); err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	// Read method selection reply
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("expected NO AUTH reply, got %x", reply)
	}

	// Send CONNECT to 10.0.0.1:8080
	ip := net.ParseIP("10.0.0.1")
	if _, err := client.Write(socks5ConnectIPv4(ip, 8080)); err != nil {
		t.Fatalf("write connect: %v", err)
	}

	// Read connect reply
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(client, connectReply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if connectReply[1] != 0x00 {
		t.Fatalf("expected success reply, got status %x", connectReply[1])
	}

	err := <-errCh
	target := <-targetCh

	if err != nil {
		t.Fatalf("socks5Handshake error: %v", err)
	}
	if target != "10.0.0.1:8080" {
		t.Errorf("target = %q, want %q", target, "10.0.0.1:8080")
	}
}

func TestSocks5Handshake_Domain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	targetCh := make(chan string, 1)

	go func() {
		target, err := socks5Handshake(server)
		errCh <- err
		targetCh <- target
	}()

	// Greeting
	client.Write(socks5GreetingNoAuth())
	reply := make([]byte, 2)
	io.ReadFull(client, reply)

	// CONNECT to example.com:443
	client.Write(socks5ConnectDomain("example.com", 443))

	connectReply := make([]byte, 10)
	io.ReadFull(client, connectReply)

	err := <-errCh
	target := <-targetCh

	if err != nil {
		t.Fatalf("socks5Handshake error: %v", err)
	}
	if target != "example.com:443" {
		t.Errorf("target = %q, want %q", target, "example.com:443")
	}
}

func TestSocks5Handshake_IPv6(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	targetCh := make(chan string, 1)

	go func() {
		target, err := socks5Handshake(server)
		errCh <- err
		targetCh <- target
	}()

	// Greeting
	client.Write(socks5GreetingNoAuth())
	reply := make([]byte, 2)
	io.ReadFull(client, reply)

	// CONNECT to [::1]:22
	ip := net.ParseIP("::1")
	client.Write(socks5ConnectIPv6(ip, 22))

	connectReply := make([]byte, 10)
	io.ReadFull(client, connectReply)

	err := <-errCh
	target := <-targetCh

	if err != nil {
		t.Fatalf("socks5Handshake error: %v", err)
	}
	if target != "::1:22" {
		t.Errorf("target = %q, want %q", target, "::1:22")
	}
}

func TestSocks5Handshake_InvalidVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)

	go func() {
		_, err := socks5Handshake(server)
		errCh <- err
	}()

	// Send SOCKS4 greeting (wrong version)
	client.Write([]byte{0x04, 0x01, 0x00})

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for invalid SOCKS version, got nil")
	}
}

func TestSocks5Handshake_UnsupportedAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)

	go func() {
		_, err := socks5Handshake(server)
		errCh <- err
	}()

	// Send greeting with only GSSAPI (0x01) — no NO_AUTH (0x00)
	client.Write([]byte{0x05, 0x01, 0x01})

	// Server should reply with 0xFF (no acceptable method)
	reply := make([]byte, 2)
	io.ReadFull(client, reply)

	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Errorf("expected rejection reply [05 FF], got %x", reply)
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for unsupported auth, got nil")
	}
}

func TestSocks5Handshake_TruncatedGreeting(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	errCh := make(chan error, 1)

	go func() {
		_, err := socks5Handshake(server)
		errCh <- err
	}()

	// Send only 1 byte then close
	client.Write([]byte{0x05})
	client.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for truncated greeting, got nil")
	}
}

func TestSocks5Handshake_TruncatedConnect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)

	go func() {
		_, err := socks5Handshake(server)
		errCh <- err
	}()

	// Greeting
	client.Write(socks5GreetingNoAuth())
	reply := make([]byte, 2)
	io.ReadFull(client, reply)

	// Send truncated CONNECT request (only 4 bytes, needs at least 10 for IPv4)
	client.Write([]byte{0x05, 0x01, 0x00, 0x01})
	client.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for truncated connect, got nil")
	}
}

func TestSocks5Handshake_UnsupportedCommand(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)

	go func() {
		_, err := socks5Handshake(server)
		errCh <- err
	}()

	// Greeting
	client.Write(socks5GreetingNoAuth())
	reply := make([]byte, 2)
	io.ReadFull(client, reply)

	// Send BIND command (0x02) instead of CONNECT (0x01)
	buf := []byte{0x05, 0x02, 0x00, 0x01} // VER CMD=BIND RSV ATYP=IPv4
	buf = append(buf, 10, 0, 0, 1)         // 10.0.0.1
	buf = append(buf, 0x1F, 0x90)           // port 8080
	client.Write(buf)

	// Read the rejection
	reject := make([]byte, 10)
	io.ReadFull(client, reject)

	if reject[1] != 0x07 {
		t.Errorf("expected command-not-supported reply (0x07), got %x", reject[1])
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for unsupported command, got nil")
	}
}

func TestSocks5Handshake_LargeDomain(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	targetCh := make(chan string, 1)

	go func() {
		target, err := socks5Handshake(server)
		errCh <- err
		targetCh <- target
	}()

	// Greeting
	client.Write(socks5GreetingNoAuth())
	reply := make([]byte, 2)
	io.ReadFull(client, reply)

	// 255-byte domain (maximum for a single length byte)
	domain := ""
	for i := 0; i < 255; i++ {
		domain += "a"
	}
	client.Write(socks5ConnectDomain(domain, 80))

	connectReply := make([]byte, 10)
	io.ReadFull(client, connectReply)

	err := <-errCh
	target := <-targetCh

	if err != nil {
		t.Fatalf("socks5Handshake error: %v", err)
	}
	want := domain + ":80"
	if target != want {
		t.Errorf("target length = %d, want %d", len(target), len(want))
	}
}

// ── TestSocks5Handshake_Timeout ────────────────────────────────────────────

func TestSocks5Handshake_Timeout(t *testing.T) {
	// If the client never sends data, the 10s deadline should eventually fire.
	// We use a short-lived pipe and close the client side to simulate no data.
	client, server := net.Pipe()

	errCh := make(chan error, 1)
	go func() {
		_, err := socks5Handshake(server)
		errCh <- err
		server.Close()
	}()

	// Close client immediately without sending anything.
	client.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("socks5Handshake did not return within timeout")
	}
}

// ── TestPivotLocalPort ──────────────────────────────────────────────────────

func TestPivotLocalPort(t *testing.T) {
	tests := []struct {
		name       string
		remotePort int
		want       int
	}{
		{
			name:       "standard SSH",
			remotePort: 22,
			want:       10022,
		},
		{
			name:       "HTTP",
			remotePort: 80,
			want:       10080,
		},
		{
			name:       "HTTPS",
			remotePort: 443,
			want:       10443,
		},
		{
			name:       "high port wraps back",
			remotePort: 60000,
			want:       60000, // 70000 > 65535, so returns remotePort
		},
		{
			name:       "boundary: port 55535",
			remotePort: 55535,
			want:       65535,
		},
		{
			name:       "boundary: port 55536",
			remotePort: 55536,
			want:       55536, // 65536 > 65535, so returns remotePort
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pivotLocalPort(tc.remotePort)
			if got != tc.want {
				t.Errorf("pivotLocalPort(%d) = %d, want %d", tc.remotePort, got, tc.want)
			}
		})
	}
}

// ── TestC2RelayIP ──────────────────────────────────────────────────────────

func TestC2RelayIP(t *testing.T) {
	tests := []struct {
		name         string
		listenerAddr string
		remoteAddr   string
		want         string // empty means "any non-empty result"
	}{
		{
			name:         "specific listener IP returned",
			listenerAddr: "10.0.0.1:4444",
			remoteAddr:   "10.0.0.5:12345",
			want:         "10.0.0.1",
		},
		{
			name:         "specific listener IPv6",
			listenerAddr: "[::1]:4444",
			remoteAddr:   "[::1]:12345",
			want:         "::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := &Session{
				ListenerAddr: tc.listenerAddr,
				RemoteAddr:   tc.remoteAddr,
			}
			got := c2RelayIP(sess)
			if tc.want != "" && got != tc.want {
				t.Errorf("c2RelayIP() = %q, want %q", got, tc.want)
			}
			if got == "" {
				t.Error("c2RelayIP() returned empty string")
			}
		})
	}
}

// TestC2RelayIP_WildcardFallback tests that when the listener is on 0.0.0.0,
// c2RelayIP falls back to finding the local IP that routes to the agent.
func TestC2RelayIP_WildcardFallback(t *testing.T) {
	sess := &Session{
		ListenerAddr: "0.0.0.0:4444",
		RemoteAddr:   "127.0.0.1:12345",
	}
	got := c2RelayIP(sess)
	// On any machine, this should return a non-empty routable IP.
	if got == "" {
		t.Error("c2RelayIP() returned empty for wildcard listener")
	}
}

// Ensure binary helpers compile — unused import guard.
var _ = binary.BigEndian
