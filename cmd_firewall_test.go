package main

import (
	"testing"
)

// ── TestIpInRange ───────────────────────────────────────────────────────────

func TestIpInRange(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		// Exact CIDR match
		{
			name: "IP in /24 range",
			ip:   "10.0.0.5",
			cidr: "10.0.0.0/24",
			want: true,
		},
		{
			name: "IP at start of /24 range",
			ip:   "10.0.0.0",
			cidr: "10.0.0.0/24",
			want: true,
		},
		{
			name: "IP at end of /24 range",
			ip:   "10.0.0.255",
			cidr: "10.0.0.0/24",
			want: true,
		},

		// CIDR miss
		{
			name: "IP outside /24 range",
			ip:   "10.0.1.5",
			cidr: "10.0.0.0/24",
			want: false,
		},
		{
			name: "completely different subnet",
			ip:   "192.168.1.1",
			cidr: "10.0.0.0/8",
			want: false,
		},

		// /32 single host CIDR
		{
			name: "/32 exact match",
			ip:   "10.0.0.5",
			cidr: "10.0.0.5/32",
			want: true,
		},
		{
			name: "/32 no match",
			ip:   "10.0.0.6",
			cidr: "10.0.0.5/32",
			want: false,
		},

		// /16 range
		{
			name: "IP in /16 range",
			ip:   "172.16.50.100",
			cidr: "172.16.0.0/16",
			want: true,
		},
		{
			name: "IP outside /16 range",
			ip:   "172.17.0.1",
			cidr: "172.16.0.0/16",
			want: false,
		},

		// /8 range
		{
			name: "IP in /8 range",
			ip:   "10.255.255.255",
			cidr: "10.0.0.0/8",
			want: true,
		},

		// Invalid inputs
		{
			name: "invalid CIDR string",
			ip:   "10.0.0.5",
			cidr: "not-a-cidr",
			want: false,
		},
		{
			name: "invalid IP string",
			ip:   "not-an-ip",
			cidr: "10.0.0.0/24",
			want: false,
		},
		{
			name: "empty IP",
			ip:   "",
			cidr: "10.0.0.0/24",
			want: false,
		},
		{
			name: "empty CIDR",
			ip:   "10.0.0.5",
			cidr: "",
			want: false,
		},

		// IPv6
		{
			name: "IPv6 in range",
			ip:   "2001:db8::1",
			cidr: "2001:db8::/32",
			want: true,
		},
		{
			name: "IPv6 outside range",
			ip:   "2001:db9::1",
			cidr: "2001:db8::/32",
			want: false,
		},
		{
			name: "IPv6 loopback in /128",
			ip:   "::1",
			cidr: "::1/128",
			want: true,
		},

		// Edge cases
		{
			name: "CIDR with host bits set (net.ParseCIDR normalizes)",
			ip:   "10.0.0.5",
			cidr: "10.0.0.1/24",
			want: true,
		},
		{
			name: "/0 matches everything IPv4",
			ip:   "192.168.1.1",
			cidr: "0.0.0.0/0",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ipInRange(tc.ip, tc.cidr)
			if got != tc.want {
				t.Errorf("ipInRange(%q, %q) = %v, want %v", tc.ip, tc.cidr, got, tc.want)
			}
		})
	}
}

// ── TestCheckFirewall ───────────────────────────────────────────────────────

func TestCheckFirewall(t *testing.T) {
	tests := []struct {
		name         string
		firewalls    map[string]Firewall
		srcIP        string
		listenerAddr string
		want         bool
	}{
		{
			name:         "no firewalls allows all",
			firewalls:    map[string]Firewall{},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         true,
		},
		{
			name: "firewall not assigned to listener allows all",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:5555"},
					Rules: []FirewallRule{
						{IP: "10.0.0.5", Action: "deny"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         true,
		},
		{
			name: "exact IP allow rule",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:4444"},
					Rules: []FirewallRule{
						{IP: "10.0.0.5", Action: "allow"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         true,
		},
		{
			name: "exact IP deny rule",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:4444"},
					Rules: []FirewallRule{
						{IP: "10.0.0.5", Action: "deny"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         false,
		},
		{
			name: "CIDR allow rule",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:4444"},
					Rules: []FirewallRule{
						{IP: "10.0.0.0/24", Action: "allow"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         true,
		},
		{
			name: "CIDR deny rule",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:4444"},
					Rules: []FirewallRule{
						{IP: "10.0.0.0/24", Action: "deny"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         false,
		},
		{
			name: "default deny when assigned but no matching rule",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:4444"},
					Rules: []FirewallRule{
						{IP: "192.168.1.0/24", Action: "allow"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         false,
		},
		{
			name: "first matching rule wins (allow before deny)",
			firewalls: map[string]Firewall{
				"fw1": {
					Name:              "fw1",
					AssignedListeners: []string{"0.0.0.0:4444"},
					Rules: []FirewallRule{
						{IP: "10.0.0.5", Action: "allow"},
						{IP: "10.0.0.0/24", Action: "deny"},
					},
				},
			},
			srcIP:        "10.0.0.5",
			listenerAddr: "0.0.0.0:4444",
			want:         true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Console{
				firewalls: &FirewallStore{
					Firewalls: tc.firewalls,
				},
			}
			got := c.checkFirewall(tc.srcIP, tc.listenerAddr)
			if got != tc.want {
				t.Errorf("checkFirewall(%q, %q) = %v, want %v", tc.srcIP, tc.listenerAddr, got, tc.want)
			}
		})
	}
}
