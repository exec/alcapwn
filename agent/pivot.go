package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// runRelay dials target and relayAddr, then proxies data bidirectionally.
// Used by TaskForward: the server opens a relay listener, sends us both
// addresses, and we stitch them together so the server can proxy traffic
// from the operator tool through us to the target.
func runRelay(target, relayAddr string) error {
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial target %s: %w", target, err)
	}
	defer targetConn.Close()

	relayConn, err := net.DialTimeout("tcp", relayAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial relay %s: %w", relayAddr, err)
	}
	defer relayConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(targetConn, relayConn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(relayConn, targetConn)
		relayConn.(*net.TCPConn).CloseWrite()
	}()
	wg.Wait()
	return nil
}
