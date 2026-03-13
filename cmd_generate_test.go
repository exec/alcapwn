package main

import (
	"strings"
	"testing"
)

// ── TestLookupTarget ──────────────────────────────────────────────────────────

func TestLookupTarget_linuxAmd64(t *testing.T) {
	got := lookupTarget("linux", "amd64")
	if got == nil {
		t.Fatal("expected non-nil for linux/amd64")
	}
	if got.Name != "linux-amd64" {
		t.Fatalf("expected Name=%q, got %q", "linux-amd64", got.Name)
	}
}

func TestLookupTarget_linuxArm64(t *testing.T) {
	got := lookupTarget("linux", "arm64")
	if got == nil {
		t.Fatal("expected non-nil for linux/arm64")
	}
	if got.Name != "linux-arm64" {
		t.Fatalf("expected Name=%q, got %q", "linux-arm64", got.Name)
	}
}

func TestLookupTarget_linuxArmAlias(t *testing.T) {
	got := lookupTarget("linux", "arm")
	if got == nil {
		t.Fatal("expected non-nil for linux/arm (armv7 alias)")
	}
	if got.GOARM != "7" {
		t.Fatalf("expected GOARM=%q, got %q", "7", got.GOARM)
	}
}

func TestLookupTarget_linuxArmv7Alias(t *testing.T) {
	got := lookupTarget("linux", "armv7")
	if got == nil {
		t.Fatal("expected non-nil for linux/armv7")
	}
	if got.GOARM != "7" {
		t.Fatalf("expected GOARM=%q, got %q", "7", got.GOARM)
	}
}

func TestLookupTarget_windowsAmd64HasExt(t *testing.T) {
	got := lookupTarget("windows", "amd64")
	if got == nil {
		t.Fatal("expected non-nil for windows/amd64")
	}
	if got.Ext != ".exe" {
		t.Fatalf("expected Ext=%q, got %q", ".exe", got.Ext)
	}
}

func TestLookupTarget_darwinArm64(t *testing.T) {
	got := lookupTarget("darwin", "arm64")
	if got == nil {
		t.Fatal("expected non-nil for darwin/arm64")
	}
	if got.Name != "macos-aarch64" {
		t.Fatalf("expected Name=%q, got %q", "macos-aarch64", got.Name)
	}
}

func TestLookupTarget_unknownMips(t *testing.T) {
	got := lookupTarget("linux", "mips")
	if got != nil {
		t.Fatalf("expected nil for linux/mips, got %+v", got)
	}
}

func TestLookupTarget_caseInsensitive(t *testing.T) {
	got := lookupTarget("Linux", "AMD64")
	if got == nil {
		t.Fatal("expected non-nil for Linux/AMD64 (case-insensitive)")
	}
	if got.Name != "linux-amd64" {
		t.Fatalf("expected Name=%q, got %q", "linux-amd64", got.Name)
	}
}

func TestLookupTarget_emptyArgs(t *testing.T) {
	got := lookupTarget("", "")
	if got != nil {
		t.Fatalf("expected nil for empty/empty, got %+v", got)
	}
}

// ── TestGenerateOpts_defaultOut ───────────────────────────────────────────────

func TestGenerateOpts_defaultOut(t *testing.T) {
	tests := []struct {
		goos      string
		goarch    string
		transport string
		want      string
	}{
		{"linux", "amd64", "tcp", "agent-linux-amd64"},
		{"linux", "amd64", "http", "agent-linux-amd64-http"},
		{"windows", "amd64", "tcp", "agent-windows-amd64.exe"},
		{"windows", "amd64", "http", "agent-windows-amd64-http.exe"},
	}
	for _, tc := range tests {
		target := lookupTarget(tc.goos, tc.goarch)
		if target == nil {
			t.Fatalf("lookupTarget(%q,%q) returned nil", tc.goos, tc.goarch)
		}
		opts := generateOpts{target: target, transport: tc.transport}
		got := opts.defaultOut()
		if got != tc.want {
			t.Errorf("defaultOut(%s/%s, %s) = %q, want %q", tc.goos, tc.goarch, tc.transport, got, tc.want)
		}
	}
}

// ── TestBuildGenerateLDFlags ──────────────────────────────────────────────────

func TestBuildGenerateLDFlags_allFieldsNoPin(t *testing.T) {
	c := &Console{opts: sessionOpts{serverFingerprint: "abcdef1234"}}
	target := lookupTarget("linux", "amd64")
	opts := generateOpts{
		target:    target,
		lhost:     "10.0.0.1",
		lport:     "4444",
		transport: "tcp",
		interval:  "60",
		jitter:    "20",
		noPin:     false,
	}
	flags := buildGenerateLDFlags(opts, c)

	mustContain := []string{
		"-X main.lhost=10.0.0.1",
		"-X main.lport=4444",
		"-X main.transport=tcp",
		"-X main.interval=60",
		"-X main.jitter=20",
		"-X main.serverFingerprint=abcdef1234",
	}
	for _, want := range mustContain {
		if !strings.Contains(flags, want) {
			t.Errorf("expected flags to contain %q, flags=%q", want, flags)
		}
	}
}

func TestBuildGenerateLDFlags_noPinSkipsFingerprint(t *testing.T) {
	c := &Console{opts: sessionOpts{serverFingerprint: "abcdef1234"}}
	target := lookupTarget("linux", "amd64")
	opts := generateOpts{
		target:    target,
		lhost:     "10.0.0.1",
		lport:     "4444",
		transport: "tcp",
		interval:  "60",
		jitter:    "20",
		noPin:     true,
	}
	flags := buildGenerateLDFlags(opts, c)

	if strings.Contains(flags, "serverFingerprint") {
		t.Errorf("expected no serverFingerprint when noPin=true, flags=%q", flags)
	}
	// Five base flags must still be present.
	for _, want := range []string{"-X main.lhost", "-X main.lport", "-X main.transport", "-X main.interval", "-X main.jitter"} {
		if !strings.Contains(flags, want) {
			t.Errorf("expected flags to contain %q, flags=%q", want, flags)
		}
	}
}

func TestBuildGenerateLDFlags_emptyFpSkipsFingerprint(t *testing.T) {
	c := &Console{opts: sessionOpts{serverFingerprint: ""}}
	target := lookupTarget("linux", "amd64")
	opts := generateOpts{
		target:    target,
		lhost:     "10.0.0.1",
		lport:     "4444",
		transport: "tcp",
		interval:  "60",
		jitter:    "20",
		noPin:     false,
	}
	flags := buildGenerateLDFlags(opts, c)

	if strings.Contains(flags, "serverFingerprint") {
		t.Errorf("expected no serverFingerprint when fp is empty, flags=%q", flags)
	}
}

func TestBuildGenerateLDFlags_httpTransport(t *testing.T) {
	c := &Console{}
	target := lookupTarget("linux", "amd64")
	opts := generateOpts{
		target:    target,
		lhost:     "192.168.1.5",
		lport:     "8080",
		transport: "http",
		interval:  "30",
		jitter:    "10",
		noPin:     true,
	}
	flags := buildGenerateLDFlags(opts, c)

	if !strings.Contains(flags, "-X main.lhost=192.168.1.5") {
		t.Errorf("expected lhost in flags, flags=%q", flags)
	}
	if !strings.Contains(flags, "-X main.lport=8080") {
		t.Errorf("expected lport=8080 in flags, flags=%q", flags)
	}
	if !strings.Contains(flags, "-X main.transport=http") {
		t.Errorf("expected transport=http in flags, flags=%q", flags)
	}
}

func TestBuildGenerateLDFlags_fiveFlagsAlwaysPresent(t *testing.T) {
	tests := []struct {
		noPin bool
		fp    string
	}{
		{noPin: false, fp: "abc"},
		{noPin: true, fp: "abc"},
		{noPin: false, fp: ""},
		{noPin: true, fp: ""},
	}
	base := []string{"-X main.lhost", "-X main.lport", "-X main.transport", "-X main.interval", "-X main.jitter"}
	for _, tc := range tests {
		c := &Console{opts: sessionOpts{serverFingerprint: tc.fp}}
		target := lookupTarget("linux", "amd64")
		opts := generateOpts{
			target: target, lhost: "1.2.3.4", lport: "4444",
			transport: "tcp", interval: "60", jitter: "20",
			noPin: tc.noPin,
		}
		flags := buildGenerateLDFlags(opts, c)
		for _, want := range base {
			if !strings.Contains(flags, want) {
				t.Errorf("noPin=%v fp=%q: missing %q in flags=%q", tc.noPin, tc.fp, want, flags)
			}
		}
	}
}

// ── TestParseGenerateArgs ─────────────────────────────────────────────────────

func TestParseGenerateArgs_basicLhost(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.lhost != "10.0.0.1" {
		t.Errorf("lhost=%q, want %q", opts.lhost, "10.0.0.1")
	}
	if opts.transport != "tcp" {
		t.Errorf("transport=%q, want tcp", opts.transport)
	}
	if opts.lport != "443" {
		t.Errorf("lport=%q, want 443", opts.lport)
	}
}

func TestParseGenerateArgs_httpDefaultPort(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--transport", "http"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.lport != "443" {
		t.Errorf("expected http default lport=443, got %q", opts.lport)
	}
}

func TestParseGenerateArgs_explicitLportOverridesDefault(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--lport", "9000", "--transport", "http"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.lport != "9000" {
		t.Errorf("expected explicit lport=9000, got %q", opts.lport)
	}
}

func TestParseGenerateArgs_missingLhost(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{"linux", "amd64"}, c)
	if ok {
		t.Fatal("expected ok=false when --lhost is missing")
	}
}

func TestParseGenerateArgs_unknownTarget(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{"linux", "mips", "--lhost", "10.0.0.1"}, c)
	if ok {
		t.Fatal("expected ok=false for unknown target linux/mips")
	}
}

func TestParseGenerateArgs_noPin(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--no-pin"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !opts.noPin {
		t.Error("expected noPin=true")
	}
}

func TestParseGenerateArgs_outFlag(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--out", "myagent"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.out != "myagent" {
		t.Errorf("out=%q, want %q", opts.out, "myagent")
	}
}

func TestParseGenerateArgs_missingLhostValue(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost"}, c)
	if ok {
		t.Fatal("expected ok=false when --lhost has no value")
	}
}

func TestParseGenerateArgs_badTransport(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--transport", "ftp"}, c)
	if ok {
		t.Fatal("expected ok=false for invalid transport 'ftp'")
	}
}

func TestParseGenerateArgs_intervalAndJitter(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--interval", "30", "--jitter", "10"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.interval != "30" {
		t.Errorf("interval=%q, want %q", opts.interval, "30")
	}
	if opts.jitter != "10" {
		t.Errorf("jitter=%q, want %q", opts.jitter, "10")
	}
}

func TestParseGenerateArgs_emptyArgs(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{}, c)
	if ok {
		t.Fatal("expected ok=false for empty args")
	}
}

func TestParseGenerateArgs_onlyOS(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{"linux"}, c)
	if ok {
		t.Fatal("expected ok=false when only OS is provided (no arch)")
	}
}

func TestParseGenerateArgs_unknownFlag(t *testing.T) {
	c := &Console{}
	_, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--bogus"}, c)
	if ok {
		t.Fatal("expected ok=false for unknown flag --bogus")
	}
}

// ── TestGenerateTargets_count ─────────────────────────────────────────────────

func TestGenerateTargets_count(t *testing.T) {
	if len(generateTargets) != 11 {
		t.Errorf("expected 11 targets, got %d", len(generateTargets))
	}
}

func TestGenerateTargets_fieldsNonEmpty(t *testing.T) {
	for i, tgt := range generateTargets {
		if tgt.GOOS == "" {
			t.Errorf("target[%d].GOOS is empty", i)
		}
		if tgt.GOARCH == "" {
			t.Errorf("target[%d].GOARCH is empty", i)
		}
		if tgt.Name == "" {
			t.Errorf("target[%d].Name is empty", i)
		}
	}
}

// ── TestGenerateTargets_windowsHasExt ────────────────────────────────────────

func TestGenerateTargets_windowsHasExt(t *testing.T) {
	for _, tgt := range generateTargets {
		if tgt.GOOS == "windows" {
			if tgt.Ext != ".exe" {
				t.Errorf("windows target %q has Ext=%q, want .exe", tgt.Name, tgt.Ext)
			}
		} else {
			if tgt.Ext != "" {
				t.Errorf("non-windows target %q has Ext=%q, want empty", tgt.Name, tgt.Ext)
			}
		}
	}
}

// ── TestBuildGenerateLDFlags obfuscate ────────────────────────────────────────

func TestBuildGenerateLDFlags_obfuscate(t *testing.T) {
	c := &Console{opts: sessionOpts{serverFingerprint: "deadbeef1234"}}
	target := lookupTarget("linux", "amd64")
	opts := generateOpts{
		target:    target,
		lhost:     "10.0.0.1",
		lport:     "443",
		transport: "tcp",
		interval:  "60",
		jitter:    "20",
		obfuscate: true,
	}
	flags := buildGenerateLDFlags(opts, c)

	// Obfuscated build must include xorKey and encoded variants.
	for _, want := range []string{
		"-X main.xorKey=",
		"-X main.lhostEnc=",
		"-X main.lportEnc=",
		"-X main.transportEnc=",
		"-X main.intervalEnc=",
		"-X main.jitterEnc=",
	} {
		if !strings.Contains(flags, want) {
			t.Errorf("expected flags to contain %q\nflags=%q", want, flags)
		}
	}

	// Plain vars must be cleared (set to empty string).
	for _, cleared := range []string{
		"-X main.lhost=",
		"-X main.lport=",
		"-X main.transport=",
		"-X main.interval=",
		"-X main.jitter=",
	} {
		if !strings.Contains(flags, cleared) {
			t.Errorf("expected plain var clear %q in flags\nflags=%q", cleared, flags)
		}
	}

	// Plain lhost value must NOT appear as a standalone assignment.
	if strings.Contains(flags, "-X main.lhost=10.0.0.1") {
		t.Errorf("plain lhost value should not appear in obfuscated flags\nflags=%q", flags)
	}
}

func TestBuildGenerateLDFlags_obfuscateNoFingerprint(t *testing.T) {
	// When obfuscate=true and no fingerprint is set, serverFingerprintEnc must not appear.
	c := &Console{opts: sessionOpts{serverFingerprint: ""}}
	target := lookupTarget("linux", "amd64")
	opts := generateOpts{
		target:    target,
		lhost:     "10.0.0.1",
		lport:     "443",
		transport: "tcp",
		interval:  "60",
		jitter:    "20",
		obfuscate: true,
	}
	flags := buildGenerateLDFlags(opts, c)

	if strings.Contains(flags, "serverFingerprintEnc") {
		t.Errorf("serverFingerprintEnc should not appear when no fingerprint is set\nflags=%q", flags)
	}
}

// ── TestXorEncodeStr_roundTrip ────────────────────────────────────────────────

func TestXorEncodeStr_roundTrip(t *testing.T) {
	plain := "192.168.1.100"
	key := []byte{0x12, 0x34, 0x56, 0x78}
	hexEnc := xorEncodeStr(plain, key)

	// Manually decode: hex-decode then XOR.
	encBytes := make([]byte, len(hexEnc)/2)
	nibble := func(c byte) byte {
		if c >= '0' && c <= '9' {
			return c - '0'
		}
		return c - 'a' + 10
	}
	for i := range encBytes {
		encBytes[i] = (nibble(hexEnc[i*2])<<4 | nibble(hexEnc[i*2+1])) ^ key[i%len(key)]
	}
	got := string(encBytes)
	if got != plain {
		t.Fatalf("roundTrip: want %q got %q", plain, got)
	}
}

// ── TestXorGenKey ─────────────────────────────────────────────────────────────

func TestXorGenKey_length(t *testing.T) {
	k16 := xorGenKey(16)
	if len(k16) != 16 {
		t.Errorf("xorGenKey(16): want len=16, got %d", len(k16))
	}
	k32 := xorGenKey(32)
	if len(k32) != 32 {
		t.Errorf("xorGenKey(32): want len=32, got %d", len(k32))
	}
}

func TestXorGenKey_random(t *testing.T) {
	k1 := xorGenKey(16)
	k2 := xorGenKey(16)
	same := true
	for i := range k1 {
		if k1[i] != k2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two xorGenKey(16) calls returned identical keys — crypto/rand may be broken")
	}
}

// ── TestParseGenerateArgs new flags ──────────────────────────────────────────

func TestParseGenerateArgs_obfuscate(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--obfuscate"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !opts.obfuscate {
		t.Error("expected obfuscate=true")
	}
}

func TestParseGenerateArgs_httpUA(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{"linux", "amd64", "--lhost", "10.0.0.1", "--http-ua", "Custom/1.0"}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.httpUA != "Custom/1.0" {
		t.Errorf("httpUA=%q, want %q", opts.httpUA, "Custom/1.0")
	}
}

func TestParseGenerateArgs_httpPaths(t *testing.T) {
	c := &Console{}
	opts, ok := parseGenerateArgs([]string{
		"linux", "amd64",
		"--lhost", "10.0.0.1",
		"--http-register-path", "/api/v1/health",
		"--http-beacon-path", "/cdn/",
	}, c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if opts.httpRegisterPath != "/api/v1/health" {
		t.Errorf("httpRegisterPath=%q, want %q", opts.httpRegisterPath, "/api/v1/health")
	}
	if opts.httpBeaconPath != "/cdn/" {
		t.Errorf("httpBeaconPath=%q, want %q", opts.httpBeaconPath, "/cdn/")
	}
}
