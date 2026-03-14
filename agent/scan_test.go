package main

import (
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
