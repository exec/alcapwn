package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"alcapwn/proto"
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

	var autoRecon bool
	flag.BoolVar(&autoRecon, "r", false, "Run automated recon on every new session")
	flag.BoolVar(&autoRecon, "recon", false, "Run automated recon on every new session")

	var findingsDir string
	flag.StringVar(&findingsDir, "o", "", "Save findings JSON to DIR (off by default)")
	flag.StringVar(&findingsDir, "output", "", "Save findings JSON to DIR (off by default)")

	var rawDir string
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

	// Always generate the ephemeral TLS cert (replaces lines 54–68, before the
	// first err := on line 74, so := is safe — no prior err in scope here).
	// fingerprintHex is used by HTTP TLS agents regardless of whether --tls is set.
	// opts.tlsEnabled (set from useTLS below) controls TCP PTY session TLS reconnect.
	tlsCfg, fingerprint, err := generateEphemeralTLSConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to generate TLS certificate: %v\n", err)
		os.Exit(1)
	}
	fingerprintHex := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	fmt.Printf("[*] Ephemeral TLS cert fingerprint: %s\n    (embed with --tls when using HTTP listeners)\n", fingerprint)

	// Load (or generate) the server's long-term X25519 key used to encrypt
	// agent connections.  The fingerprint is displayed so operators can embed
	// it into agents at build time via -ldflags "-X main.serverFingerprint=...".
	keyPath := filepath.Join(GetAlcapwnDir(), "server_key.bin")
	serverKey, serverFP, err := proto.LoadOrCreateServerKey(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to load agent key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[*] Agent key fingerprint: %s\n", serverFP)

	opts := sessionOpts{
		verbosity:         *verbose,
		autoRecon:         autoRecon,
		findingsDir:       findingsDir,
		rawDir:            rawDir,
		timeout:           timeout,
		tlsEnabled:        useTLS,
		tlsCfg:            tlsCfg,
		fingerprint:       fingerprint,
		fingerprintHex:    fingerprintHex,
		serverKey:         serverKey,
		serverFingerprint: serverFP,
	}

	printLogo()

	registry := NewRegistry()
	console := NewConsole(registry, opts)

	// Load persistence store and auto-start persistent listeners
	if console.config.AutoOpenListeners {
		console.persistMu.Lock()
		for addr, cfg := range console.persist.Listeners {
			if cfg.Persistent && cfg.AutoOpen {
				fmt.Printf("[*] Auto-starting persistent listener on %s\n", addr)
				console.StartListener(addr)
			}
		}
		console.persistMu.Unlock()
	}

	if *listen != "" {
		console.StartListener(*listen)
	}

	console.Run()
}
