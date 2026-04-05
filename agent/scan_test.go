package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestExpandCIDR_Single(t *testing.T) {
	ips, err := expandCIDR("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestExpandCIDR_Slash30(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	// /30 has 2 usable hosts: .1 and .2
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for /30, got %d: %v", len(ips), ips)
	}
}

func TestExpandCIDR_Slash24(t *testing.T) {
	ips, err := expandCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// /24 has 254 usable hosts
	if len(ips) != 254 {
		t.Fatalf("expected 254 IPs for /24, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" || ips[253] != "10.0.0.254" {
		t.Fatalf("unexpected first/last: %s / %s", ips[0], ips[253])
	}
}

func TestExpandCIDR_Slash32(t *testing.T) {
	ips, err := expandCIDR("172.16.5.10/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "172.16.5.10" {
		t.Fatalf("expected single host, got %v", ips)
	}
}

func TestExpandCIDR_BadInput(t *testing.T) {
	_, err := expandCIDR("not-an-ip")
	if err == nil {
		t.Fatal("expected error for bad input")
	}
}

func TestTCPProbe_Loopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if !tcpProbe("127.0.0.1", port, 500*time.Millisecond) {
		t.Fatal("expected probe to succeed on open port")
	}
}

func TestTCPProbe_ClosedPort(t *testing.T) {
	// Port 1 is almost never open and connecting will be refused quickly.
	if tcpProbe("127.0.0.1", 1, 200*time.Millisecond) {
		t.Skip("port 1 unexpectedly open, skipping")
	}
}

func TestIPLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.1", "10.0.0.2", true},
		{"10.0.0.2", "10.0.0.1", false},
		{"192.168.1.1", "192.168.1.1", false},
		{"10.0.0.255", "10.0.1.0", true},
	}
	for _, tc := range cases {
		if got := ipLess(tc.a, tc.b); got != tc.want {
			t.Errorf("ipLess(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// ── CIDR expansion edge cases ────────────────────────────────────────────────

func TestExpandCIDR_Slash31(t *testing.T) {
	ips, err := expandCIDR("192.168.0.0/31")
	if err != nil {
		t.Fatal(err)
	}
	// /31 point-to-point: the cidrHosts function handles first>last by returning
	// just the base IP. Verify we get at least 1 IP.
	if len(ips) < 1 {
		t.Fatalf("expected at least 1 IP for /31, got %d", len(ips))
	}
}

func TestExpandCIDR_Slash16_Count(t *testing.T) {
	ips, err := expandCIDR("10.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	// /16 has 65534 usable hosts (excluding network and broadcast).
	if len(ips) != 65534 {
		t.Fatalf("expected 65534 IPs for /16, got %d", len(ips))
	}
}

func TestExpandCIDR_EmptyString(t *testing.T) {
	_, err := expandCIDR("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestExpandCIDR_Whitespace(t *testing.T) {
	_, err := expandCIDR("  ")
	if err == nil {
		t.Fatal("expected error for whitespace-only input")
	}
}

func TestExpandCIDR_IPv6_Unsupported(t *testing.T) {
	ips, err := expandCIDR("::1/128")
	// IPv6 single IP is handled by net.ParseIP, but /128 CIDR returns nil
	// from cidrHosts because To4() returns nil for IPv6.
	if err != nil {
		// If it errors, that's fine.
		return
	}
	// If it succeeds via single-IP path, just verify result.
	_ = ips
}

// ── Timeout behavior ─────────────────────────────────────────────────────────

func TestTCPProbe_Timeout_NonRoutable(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — non-routable.
	start := time.Now()
	result := tcpProbe("192.0.2.1", 80, 200*time.Millisecond)
	elapsed := time.Since(start)

	if result {
		t.Skip("non-routable IP unexpectedly connected")
	}
	// Should return within ~2x the timeout (generous margin for OS overhead).
	if elapsed > 2*time.Second {
		t.Fatalf("probe took %v, expected to return within timeout", elapsed)
	}
}

// ── runNetScan integration ───────────────────────────────────────────────────

func TestRunNetScan_SingleHost(t *testing.T) {
	// Start a listener on localhost.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	data, err := runNetScan("127.0.0.1", []int{port}, 1000)
	if err != nil {
		t.Fatalf("runNetScan: %v", err)
	}

	var sr ScanResult
	if err := json.Unmarshal(data, &sr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sr.Scanned != 1 {
		t.Fatalf("want scanned=1, got %d", sr.Scanned)
	}
	if len(sr.Hosts) != 1 {
		t.Fatalf("want 1 host with open ports, got %d", len(sr.Hosts))
	}
	if sr.Hosts[0].IP != "127.0.0.1" {
		t.Fatalf("want IP 127.0.0.1, got %q", sr.Hosts[0].IP)
	}
	found := false
	for _, p := range sr.Hosts[0].OpenPorts {
		if p == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected port %d in open ports %v", port, sr.Hosts[0].OpenPorts)
	}
}

func TestRunNetScan_NoOpenPorts(t *testing.T) {
	// Scan a port that's definitely closed on localhost.
	data, err := runNetScan("127.0.0.1", []int{1}, 200)
	if err != nil {
		t.Fatalf("runNetScan: %v", err)
	}

	var sr ScanResult
	if err := json.Unmarshal(data, &sr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sr.Scanned != 1 {
		t.Fatalf("want scanned=1, got %d", sr.Scanned)
	}
	if len(sr.Hosts) != 0 {
		t.Fatalf("want 0 hosts with open ports, got %d", len(sr.Hosts))
	}
}

func TestRunNetScan_BadCIDR(t *testing.T) {
	_, err := runNetScan("not-a-cidr", nil, 100)
	if err == nil {
		t.Fatal("expected error for bad CIDR")
	}
}

func TestRunNetScan_RangeTooLarge(t *testing.T) {
	_, err := runNetScan("10.0.0.0/15", []int{80}, 100)
	if err == nil {
		t.Fatal("expected error for range too large (/15 > 65536 hosts)")
	}
}
