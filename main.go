package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strings"
)

func printLogo() {
	fmt.Println()
	fmt.Println("                                 ▄███▄                             ")
	fmt.Println("                                 ▀▀▀▀▀")
	fmt.Println("   ▄▄▄  ▄▄     ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▀█▀▀▀█▀ ▄▄  ▄▄")
	fmt.Println("  ██▀██ ██    ██▀▀▀ ██▀██ ██▄█▀ ██ ▄ ██ ███▄██")
	fmt.Println("  ██▀██ ██▄▄▄ ▀████ ██▀██ ██     ▀█▀█▀  ██ ▀██")
	fmt.Println()
}

func main() {
	listen := flag.String("l", "", "Listen address HOST:PORT (optional; use 'listen' command otherwise)")
	verbose := flag.Int("v", 0, "Verbosity (use -v=1 or -v=2)")

	var noRecon bool
	flag.BoolVar(&noRecon, "n", false, "Skip recon — drop straight to interactive shell")
	flag.BoolVar(&noRecon, "no-recon", false, "Skip recon — drop straight to interactive shell")

	var findingsDir string
	flag.StringVar(&findingsDir, "o", "", "Save findings JSON to DIR (off by default)")
	flag.StringVar(&findingsDir, "output", "", "Save findings JSON to DIR (off by default)")

	var rawDir string
	flag.StringVar(&rawDir, "r", "", "Save raw terminal capture to DIR (off by default)")
	flag.StringVar(&rawDir, "raw", "", "Save raw terminal capture to DIR (off by default)")

	var timeout int
	flag.IntVar(&timeout, "t", 15, "Per-section idle timeout in seconds (5–300)")
	flag.IntVar(&timeout, "timeout", 15, "Per-section idle timeout in seconds (5–300)")

	var useTLS bool
	flag.BoolVar(&useTLS, "T", false, "Enable automatic session encryption via ephemeral TLS")
	flag.BoolVar(&useTLS, "tls", false, "Enable automatic session encryption via ephemeral TLS")

	flag.Parse()

	if timeout < 5 || timeout > 300 {
		fmt.Fprintf(os.Stderr, "[!] --timeout must be between 5 and 300 seconds (got %d)\n", timeout)
		os.Exit(1)
	}

	var tlsCfg *tls.Config
	var fingerprint, fingerprintHex string

	if useTLS {
		var err error
		tlsCfg, fingerprint, err = generateEphemeralTLSConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to generate TLS certificate: %v\n", err)
			os.Exit(1)
		}
		fingerprintHex = strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))

		fmt.Println("[*] TLS enabled — ephemeral cert fingerprint:")
		fmt.Printf("    %s\n", fingerprint)
	}

	opts := sessionOpts{
		verbosity:      *verbose,
		noRecon:        noRecon,
		findingsDir:    findingsDir,
		rawDir:         rawDir,
		timeout:        timeout,
		tlsEnabled:     useTLS,
		tlsCfg:         tlsCfg,
		fingerprint:    fingerprint,
		fingerprintHex: fingerprintHex,
	}

	printLogo()

	registry := NewRegistry()
	console := NewConsole(registry, opts)

	if *listen != "" {
		console.StartListener(*listen)
	}

	console.Run()
}
