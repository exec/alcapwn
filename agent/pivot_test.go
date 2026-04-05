package main

import (
	"net"
	"testing"
	"time"
)

// TestPivotRelay_NonTCPConn verifies that runRelay's CloseWrite calls do not
// panic when the connections are not *net.TCPConn. We can't easily test
// runRelay directly (it dials real addresses), so we test the extracted
// helper closeWrite which must use a checked type assertion.
func TestPivotRelay_NonTCPConn(t *testing.T) {
	// net.Pipe returns net.Conn values that are NOT *net.TCPConn.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// closeWrite must not panic on non-TCP connections.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("closeWrite panicked on non-TCP conn: %v", r)
		}
	}()
	closeWrite(c1)
	closeWrite(c2)
}

// TestPivotRelay_TCPConn verifies closeWrite works on real TCP connections.
func TestPivotRelay_TCPConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-accepted
	defer server.Close()

	// closeWrite should succeed silently on a real TCP conn.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("closeWrite panicked on TCP conn: %v", r)
		}
	}()
	closeWrite(client)
	closeWrite(server)
}
