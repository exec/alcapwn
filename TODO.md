# alcapwn — C2 Evolution TODO

Current state: full C2 framework with encrypted agent, multi-protocol beaconing,
cross-platform payload generation, obfuscation, and built-in shell fallback.
Goal: pivoting, Windows support, interactive agent shell, post-exploitation modules.

---

## Completed

### Phase 1 — Agent/Server Split ✓ (commit d3bac6c)
- [x] `agent/` package: standalone Go binary (no CGo)
- [x] Agent protocol: handshake → register session → receive task → send result
- [x] Server session registry wired to agent connections
- [x] Agent auto-reconnect with configurable sleep interval + jitter
- [x] Task/result message envelopes (exec, download, upload)
- [x] Hardware fingerprint (machine-id + MAC) for reconnect auto-labeling

### Phase 2 — Multi-Protocol Listeners ✓ (partial)
- [x] HTTP listener (POST /register + GET|POST /beacon/{token})
- [x] Per-session X25519+AES-256-GCM over HTTP bodies (same proto as TCP)

### Phase 3 — Payload Generation ✓
- [x] `generate` command: cross-compile agent for target arch/OS
- [x] `-ldflags` injection for C2 config (lhost, lport, transport, fingerprint)
- [x] Shell one-liner output (`generate oneliner`)
- [x] `-buildvcs=false` so builds work outside the git worktree

### Phase 4 — Encryption Hardening ✓
- [x] ECDH (X25519) key agreement → per-session AES-256-GCM keys
- [x] Certificate pinning on agent side (serverFingerprint ldflags var)
- [x] XOR/AES stub wrapper for generated agent strings

### Phase 5 — Obfuscation & OPSEC ✓
- [x] XOR per-build string encryption (`--obfuscate` flag on generate)
- [x] HTTP traffic blending: browser UA, custom URI paths, browser-like headers
- [x] Proxy-aware agent: http.ProxyFromEnvironment
- [x] Random 0-63 byte padding per encrypted message
- [x] Configurable beacon jitter (jitteredSleep)
- [x] HTTP listener serves agent binaries at `/download/{token}/{filename}`
- [x] `generate --listener <idx>` wires C2 + download URL in one step

### Phase 6b — Built-in Shell Fallback ✓
- [x] `agent/minishell.go` — pure Go shell, zero dependencies, all arches
  - `MiniExec(cmdline)` — pipes, redirections, quoting, backslash escapes
  - `NewMiniShell(r,w).Run()` — interactive: tab completion (PATH + files),
    LCP fill, columnar display, ↑↓ history, full line editing, colour prompt
  - Built-ins: cd  pwd  export  env  which  help  exit
- [x] `detectShell()` probes target for /bin/bash, /bin/sh, /bin/dash, busybox
- [x] `runShell()` uses system shell if found, MiniExec otherwise (transparent)
- [x] `Hello.Shell` field reports discovered shell to server; `info <id>` shows it
- [x] dhsh (exec/dhsh) updated: non-tty/pipe-friendly mode, -c CMD flag,
      convenience-mode defaults (no seccomp, no whitelist, no char blocking),
      `make static` target — committed directly to exec/dhsh main

### Test & Quality ✓
- [x] All Go unit tests pass with `-race` (alcapwn, alcapwn/agent, alcapwn/proto)
- [x] All 40+ harness tests pass: core, commands, multi, persist, TLS, firewall,
      HTTP listener, generate command
- [x] 7 bugs fixed in audit: transport default, data race, log ordering,
      download lookup, dead code, harness `-v` flag, `-buildvcs=false`

---

## Phase 6 — Pivoting & Lateral Movement  ← NEXT / HIGH VALUE

Most impactful for NCL — multi-hop network segments are common.

- [ ] SOCKS5 proxy through agent session (`pivot <id> --socks5 :1080`)
      Agent dials targets on operator's behalf; operator points tools at local port.
- [ ] TCP port forward (`pivot <id> --fwd 8080:192.168.1.10:80`)
      Simple single-target forward; useful for hitting internal web UIs.
- [ ] Reverse port forward (agent opens inbound listener, proxies to C2 side)
- [ ] Chain pivots: route traffic through an existing pivot session
- [ ] Basic network scan from target (ping sweep + common-port SYN scan in Go;
      no nmap dependency)

---

## Phase 7 — Windows Support  ← HIGH VALUE

NCL has Windows boxes. Agent already cross-compiles with GOOS=windows;
gap is recon, dataset entries, and persistence.

- [ ] Windows recon (`recon_windows.go` or OS-gated block in recon.go):
  - `whoami /priv` token privileges
  - `net localgroup administrators`
  - Unquoted service paths
  - AlwaysInstallElevated registry check
  - Weak service ACLs (`sc qc` + `icacls`)
  - Scheduled task enumeration
  - Credential store detection (SAM, Credential Manager, DPAPI blobs)
  - Running processes with `tasklist /svc`
- [ ] Windows dataset entries for exploit matcher
      (PrintSpoofer, SeImpersonatePrivilege, AlwaysInstallElevated, etc.)
- [ ] Windows-specific persistence: registry Run keys, scheduled tasks, service install

---

## Phase 6c — Interactive Agent Shell  ← MEDIUM VALUE

MiniShell.Run() exists; needs the transport plumbing to connect it.

- [ ] New task type `TaskShell` — agent spawns MiniShell (or system shell) and
      streams bidirectional I/O through the encrypted channel
- [ ] Operator-side `shell <id>` command — puts console into raw passthrough mode,
      forwards keystrokes to agent, displays output; similar to interactWithSession
      but over the agent protocol instead of PTY

---

## Phase 2 — Additional Listeners (deferred, low CTF value)

- [ ] WebSocket listener (bypasses basic DPI, works through most HTTP proxies)
- [ ] DNS beacon listener (TXT record polling; ultra-low-and-slow)
- [ ] ICMP listener (fallback when all TCP/UDP is filtered)

---

## Phase 3 — Stagers (deferred)

- [ ] Stage0 dropper: tiny payload (<5KB) that fetches and executes stage1 in memory
- [ ] Stage1 loader: in-memory execution without touching disk

---

## Phase 8 — Post-Exploitation Modules (deferred)

- [ ] **Native credential harvesting from agent** (currently PTY-side only):
      `/etc/shadow`, SSH keys, `.env`, bash history, git credentials, AWS/GCP configs;
      auto-trigger post `exploit auto` success
- [ ] Keylogger, screenshot, process injection — out of scope for NCL

---

## Phase 9 — Async File Transfer (deferred)

Current download/upload is blocking and fine for CTF file sizes.

- [ ] Chunked transfer with resume + SHA-256 integrity check
- [ ] Progress bar in operator console
- [ ] Optional gzip compression

---

## Phase 10 — Multi-Operator / Teamserver (nice to have)

- [ ] mTLS management port, operator auth, shared session/event log

---

## Known Limitations

- [ ] Interactive filter in `console.go` — stateful ANSI parser may miss sequences
      fragmented across chunk boundaries (complex, deferred)
- [ ] macOS recon — OS detected but no macOS-specific priv-esc checks
- [ ] Recon parser regexes — brittle against non-standard version strings
- [ ] MiniShell `;` in `-c` mode doesn't chain commands (tokenizer limitation;
      use newline-separated piped input for multiple commands)
- [ ] Session rekeying — MsgRekey type defined but not auto-triggered

---

## Out of Scope

- Kernel rootkit / firmware persistence
- Hardware implants
- Browser extension implants
- Cloud provider metadata API abuse (AWS IMDSv2, GCP, Azure)
- Active Directory attacks (Kerberoasting, AS-REP roasting) — too infra-specific
