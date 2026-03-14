package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// defaultScanPorts is the port list used when the operator doesn't specify one.
var defaultScanPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
	445, 993, 995, 1433, 1521, 3306, 3389, 5432,
	5900, 6379, 8080, 8443, 8888, 9200, 27017,
}

// ScanHost holds the open ports discovered on one IP.
type ScanHost struct {
	IP        string `json:"ip"`
	OpenPorts []int  `json:"open_ports"`
}

// ScanResult is the JSON payload returned from a TaskScan.
type ScanResult struct {
	Hosts    []ScanHost `json:"hosts"`
	Scanned  int        `json:"scanned"`  // total IPs probed
	Duration string     `json:"duration"`
}

// runNetScan scans all IPs in cidr for open ports and returns JSON.
// cidr may be a bare IP ("10.0.0.1"), an IP range ("10.0.0.1-10.0.0.20"),
// or CIDR notation ("10.0.0.0/24"). Max range: 65536 hosts (/16).
func runNetScan(cidr string, ports []int, timeoutMs int) ([]byte, error) {
	if len(ports) == 0 {
		ports = defaultScanPorts
	}
	timeout := 500 * time.Millisecond
	if timeoutMs > 0 {
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}

	ips, err := expandCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(ips) > 65536 {
		return nil, fmt.Errorf("scan: range too large (%d hosts, max 65536)", len(ips))
	}

	start := time.Now()

	// Semaphore: limit total concurrent dials to avoid overwhelming the target.
	const maxConcurrent = 200
	sem := make(chan struct{}, maxConcurrent)

	type result struct {
		ip    string
		ports []int
	}
	resultCh := make(chan result, len(ips))

	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			var open []int
			var mu sync.Mutex
			var pw sync.WaitGroup
			for _, port := range ports {
				pw.Add(1)
				sem <- struct{}{}
				go func(port int) {
					defer pw.Done()
					defer func() { <-sem }()
					if tcpProbe(ip, port, timeout) {
						mu.Lock()
						open = append(open, port)
						mu.Unlock()
					}
				}(port)
			}
			pw.Wait()
			resultCh <- result{ip: ip, ports: open}
		}(ip)
	}

	wg.Wait()
	close(resultCh)

	var hosts []ScanHost
	for r := range resultCh {
		if len(r.ports) > 0 {
			sort.Ints(r.ports)
			hosts = append(hosts, ScanHost{IP: r.ip, OpenPorts: r.ports})
		}
	}
	// Sort hosts by IP for deterministic output.
	sort.Slice(hosts, func(i, j int) bool {
		return ipLess(hosts[i].IP, hosts[j].IP)
	})

	sr := ScanResult{
		Hosts:    hosts,
		Scanned:  len(ips),
		Duration: time.Since(start).Round(time.Millisecond).String(),
	}
	return json.Marshal(sr)
}

// tcpProbe returns true if host:port accepts a TCP connection within timeout.
func tcpProbe(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// expandCIDR returns all host IPs in the given CIDR, single IP, or dash-range.
func expandCIDR(s string) ([]string, error) {
	// Single IP
	if ip := net.ParseIP(s); ip != nil {
		return []string{ip.String()}, nil
	}

	// CIDR notation
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return cidrHosts(ipnet), nil
	}

	return nil, fmt.Errorf("unrecognised address format: %q (use IP, CIDR, or IP/prefix)", s)
}

// cidrHosts returns all usable host addresses in the network (excludes network/broadcast).
func cidrHosts(ipnet *net.IPNet) []string {
	var ips []string
	// Convert to 4-byte representation.
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil // IPv6 not supported for scanning
	}
	base := binary.BigEndian.Uint32(ip4)
	mask := binary.BigEndian.Uint32([]byte(ipnet.Mask))
	first := base&mask + 1   // skip network address
	last := base | ^mask - 1 // skip broadcast

	if first > last {
		// /32 or /31
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base)
		return []string{ip.String()}
	}
	for n := first; n <= last; n++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, n)
		ips = append(ips, ip.String())
	}
	return ips
}

// ipLess compares two IPv4 strings numerically.
func ipLess(a, b string) bool {
	ia := net.ParseIP(a).To4()
	ib := net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ia) < binary.BigEndian.Uint32(ib)
}
