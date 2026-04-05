package main

import (
	"net"
	"testing"
)

// mockAddr implements net.Addr for testing hostFromAddr.
type mockAddr struct {
	network string
	str     string
}

func (m mockAddr) Network() string { return m.network }
func (m mockAddr) String() string  { return m.str }

func TestHostFromAddr(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{
			name: "IPv4 with port",
			addr: mockAddr{network: "tcp", str: "10.0.0.1:4444"},
			want: "10.0.0.1",
		},
		{
			name: "IPv6 loopback with port",
			addr: mockAddr{network: "tcp", str: "[::1]:4444"},
			want: "::1",
		},
		{
			name: "IPv6 full with port",
			addr: mockAddr{network: "tcp", str: "[2001:db8::1]:8080"},
			want: "2001:db8::1",
		},
		{
			name: "no port fallback",
			addr: mockAddr{network: "tcp", str: "10.0.0.1"},
			want: "10.0.0.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hostFromAddr(tc.addr)
			if got != tc.want {
				t.Errorf("hostFromAddr(%q) = %q, want %q", tc.addr.String(), got, tc.want)
			}
		})
	}
}
