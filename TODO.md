# alcapwn — C2 Evolution TODO

Current state: polished reverse-shell operator console for Linux CTF.
Goal: full C2 framework with cross-platform agent, multi-protocol beaconing,
advanced post-exploitation, and OPSEC-aware infrastructure.

---

## Completed

### Phase 1 — Agent/Server Split ✓ (commit d3bac6c)
All items complete. See DEVELOPMENT_v3.md for design notes.

### Phase 3 — Payload Generation ✓
Core generate command complete. Shell one-liner output added. Stage0/Stage1 stager deferred.

### Phase 4 — Encryption Hardening ✓ (complete)
ECDH key agreement, certificate pinning, XOR obfuscation all complete. Rekeying deferred.

### Phase 5 — Obfuscation & OPSEC ✓
XOR string obfuscation, HTTP traffic blending, proxy support, random padding, agent download complete.

---

## Phase 1 — Agent / Server Split  (BLOCKING everything else)

~~The entire codebase is currently server-side only. There is no agent binary.
Everything below depends on this.~~

- [x] Create `agent/` package: standalone Go binary (no CGo, static-linked)
- [x] Agent protocol: handshake → register session → receive task → send result
- [x] Wire existing server session registry to agent connections (not just PTY shells)
- [x] Agent auto-reconnect with configurable sleep interval + jitter
- [x] Replace raw TCP PTY assumptions with a proper task/result message envelope
- [x] Agent identifier: hardware fingerprint (machine-id + MAC) for reconnect auto-labeling

---

## Phase 2 — Multi-Protocol Listeners ✓ (partial)
Server-side HTTP listener + agent HTTP transport complete.
WebSocket, DNS, ICMP listeners deferred to later.

- [x] HTTP listener (POST /register + GET|POST /beacon/{token})
- [x] Per-session X25519+AES-256-GCM over HTTP bodies (same proto as TCP)
- [ ] WebSocket listener (bypasses basic DPI, works through most HTTP proxies)
- [ ] DNS beacon listener (TXT record polling; ultra-low-and-slow)
- [ ] ICMP listener (fallback when all TCP/UDP is filtered)
- [ ] Listener multiplexer: route to correct session handler by protocol
- [ ] Per-listener protocol config (beacon interval, jitter, max chunk size)

---

## Phase 3 — Payload Generation ✓ (generate + oneliner done)

- [x] `generate` command: produce agent binary for target arch/OS — ✓
- [x] Cross-compilation via `GOOS`/`GOARCH` with `-ldflags` injection — ✓
- [x] Shell one-liner output (`generate oneliner`) — ✓
- [ ] Stage0 dropper: tiny payload (<5KB) that fetches and executes stage1 in memory
- [ ] Stage1 loader: in-memory execution of stage2 without touching disk

---

## Phase 4 — Encryption Hardening ✓ (partial)

Current: optional TLS with ephemeral cert. No per-session symmetric keys.

- [x] ECDH (X25519) key agreement on first contact → per-session AES-256-GCM keys — ✓
- [x] Certificate pinning on agent side (embed server FP at generate time) — ✓ (serverFingerprint ldflags var)
- [ ] Session rekeying at configurable intervals — deferred (MsgRekey type defined but not auto-triggered)
- [ ] Encrypted command queue persisted to disk (survive server restart) — deferred
- [x] Payload encryption: XOR/AES stub wrapper for generated agents — ✓ (Phase 5 includes this)

---

## Phase 5 — Obfuscation & OPSEC ✓

- [x] Payload string encryption (XOR per-build key, --obfuscate flag on generate) ✓
- [x] Traffic blending: browser UA, custom URI paths, browser-like HTTP headers ✓
- [x] Proxy-aware agent: http.ProxyFromEnvironment (HTTP_PROXY/HTTPS_PROXY/NO_PROXY) ✓
- [x] Chunked/randomized packet sizes — random 0-63 byte padding per encrypted message ✓
- [x] Configurable beacon jitter (already implemented in jitteredSleep) ✓
- [ ] Import table obfuscation (requires garble or //go:linkname tricks; deferred)
- [ ] Malleable profiles (profile create browser --user-agent ... --beacon 60s)

### Agent Download via HTTP Listener (NEW)

- [x] HTTP listener serves files at `/download/{token}/{filename}` — DONE
- [x] Random 6-char token per listener for URL obscurity — DONE
- [x] File whitelist (only generated agents can be downloaded) — DONE
- [x] `generate --listener <idx>` uses listener for C2 + download — DONE
- [x] `--download-dir` flag on `listen http` command — DONE

---

## Phase 6 — Pivoting & Lateral Movement

- [ ] SOCKS5 proxy through session (`pivot <id> --socks5 :1080`)
- [ ] TCP port forward through session (`pivot <id> --fwd 8080:192.168.1.10:80`)
- [ ] Reverse port forward (agent opens inbound, server side gets remote service)
- [ ] Chain pivots: route pivot traffic through another session
- [ ] Basic network scan from target: ping sweep + SYN scan on common ports
  (avoid nmap dep; implement in agent using raw sockets or Go net)

---

## Phase 7 — Windows Support

- [ ] Windows agent: compile with `GOOS=windows`
- [ ] Windows recon section in `recon.go` (or separate `recon_windows.go`):
  - `whoami /priv` token privileges
  - `net localgroup administrators`
  - Unquoted service paths
  - AlwaysInstallElevated registry check
  - Weak service ACLs (`sc qc` + `icacls`)
  - Scheduled task enumeration
  - Credential store detection (SAM, Credential Manager, DPAPI blobs)
  - Running processes with `tasklist /svc`
- [ ] Windows dataset entries for exploit matcher (PrintSpoofer, SeImpersonate, etc.)
- [ ] Windows-specific persistence: registry Run keys, scheduled tasks, service install
- [ ] Upload/download without Python dependency (agent handles it natively)

---

## Phase 8 — Post-Exploitation Modules

These run inside the agent on the target, results returned to operator.

- [ ] **Credential harvesting**:
  - Linux: `/etc/shadow`, SSH keys, `.env`, bash history, git credentials, AWS/GCP configs
  - Windows: DPAPI blob extraction, browser stores (Chrome/Firefox), WinCred, SAM dump
  - Auto-trigger on privilege gain (post `exploit auto` success)
- [ ] **Keylogger** (`module keylog start <id>`):
  - Linux: X11 (`XQueryKeymap`), Wayland (`libinput` evdev `/dev/input`)
  - Windows: `SetWindowsHookEx(WH_KEYBOARD_LL)`
  - Buffer flush to operator on demand or interval
- [ ] **Screenshot** (`module screenshot <id>`):
  - Linux: X11 `XGetImage`, Wayland fallback (`grim` if available)
  - Windows: `BitBlt` GDI capture
  - Encode PNG, stream to operator
- [ ] **Process injection** (`module inject <id> --pid <pid> --payload <file>`):
  - Linux: `ptrace` + shellcode write, or `LD_PRELOAD` `.so` injection
  - Windows: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
- [ ] **LSASS dump** (Windows; privilege required):
  - `MiniDumpWriteDump` via own process or via comsvcs.dll
  - Transfer dump to operator for offline parsing (pass the hash / cracking)

---

## Phase 9 — Async File Transfer

Current: blocking `download`/`upload` commands — connection holds until done.

- [ ] Background file transfer with progress bar in operator console
- [ ] Chunked transfer with resume (file offset tracking)
- [ ] Transfer queue per session (multiple files queued)
- [ ] Integrity check on completion (SHA-256)
- [ ] Optional compression (gzip before base64/encrypt)
- [ ] Bandwidth throttle option (`--bw 512k`)

---

## Phase 10 — Multi-Operator / Teamserver

Nice to have; probably not needed for NCL but architecturally correct.

- [ ] Teamserver mode: bind a management port, accept operator connections (mTLS)
- [ ] Operator authentication (shared secret or per-operator certs)
- [ ] Session ownership: sessions assigned to operator, or shared
- [ ] Shared event log: all operators see session connections, command results
- [ ] Operator chat (simple broadcast)
- [ ] Command audit log (sqlite): every command issued, by whom, timestamp, result

---

## Phase 6b — Shell Payload (dhsh integration)

**Problem**: agent on a box with no `/bin/sh` or `/bin/bash` can still run tasks but has
no shell interpreter — `exec` tasks fail, interactive shell is impossible.

**Plan**: modify dhsh upstream (exec/dhsh) with two small PRs, then integrate into alcapwn.

### dhsh changes needed (PRs to exec/dhsh)
- [ ] `isatty(STDIN_FILENO)` check in `dhsh_loop` → skip raw termios, ANSI colors, and
      colored prompt when stdin is not a terminal (pipe-friendly mode)
- [ ] `-c CMD` flag support → one-shot non-interactive execution (`dhsh -c "id"`)
- [ ] Static build target in Makefile (`make static` using musl or `-static`) for
      portability to minimal containers without glibc

### alcapwn agent changes
- [ ] `shell upload <id>` command — uploads pre-built dhsh binary to `/tmp/.d` on target,
      marks executable; records that session now has a shell interpreter
- [ ] Agent `exec` task falls back to `/tmp/.d -c CMD` if `sh`/`bash` not found
- [ ] New task type `TaskShell` — agent spawns dhsh (or fallback sh/dash/busybox sh) and
      does bidirectional stdin/stdout streaming through the encrypted channel
- [ ] Operator-side: `shell <id>` command drops into interactive shell mode via TaskShell,
      similar to the PTY interact flow but over the agent protocol

**No fork needed** — dhsh stays a general-purpose shell. alcapwn treats it as a payload.
A fork (`shellcapwn`) would only make sense if dhsh needed its own TCP connect-back, but
the alcapwn agent already handles encrypted transport.

---

## Existing Bugs / Known Limitations

- [x] `exec <id>` — has 5s (PTY) / 30s (agent) timeout
- [x] `ps <id>` — runs `ps -eo pid,user,%cpu,%mem,comm` with columns
- [x] `broadcast` — already sends commands to sessions (not notes)
- [x] `creds <id>` — auto-harvests shadow, SSH keys, .env, bash history
- [ ] Interactive filter in `console.go` — stateful ANSI parser may miss fragmented sequences (complex, deferred)
- [x] Drain goroutine coordination — `stopDrain` race on rapid re-use (fixed with state check)
- [ ] macOS recon — OS type detected but no macOS-specific priv-esc checks
- [ ] Recon parser regexes — brittle against non-standard version string formats

---

## Out of Scope (for now)

- Kernel rootkit / firmware persistence
- Hardware implants
- Browser extension implants
- Cloud provider metadata API abuse (AWS IMDSv2, GCP, Azure)
- Active Directory attacks (Kerberoasting, AS-REP roasting) — too infra-specific
