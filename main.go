package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	listen := flag.String("l", "0.0.0.0:4444", "Listen address HOST:PORT")
	verbose := flag.Int("v", 0, "Verbosity (use -v=1 or -v=2)")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to listen on %s: %v\n", *listen, err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Printf("[*] Listening for reverse shells on %s\n", *listen)
	fmt.Println("[*] Press Ctrl+C to stop")

	// Graceful shutdown on Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Shutting down...")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		handleSession(conn, *verbose) // sequential — next conn queues in OS backlog
		fmt.Printf("\n[*] Waiting for next connection on %s\n", *listen)
	}
}
