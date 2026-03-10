# alcapwn — C2 Evolution TODO

Current state: polished reverse-shell operator console for Linux CTF.
Goal: full C2 framework with cross-platform agent, multi-protocol beaconing,
advanced post-exploitation, and OPSEC-aware infrastructure.

---

## Completed

### Phase 1 — Agent/Server Split ✓ (commit d3bac6c)
All items complete. See DEVELOPMENT_v3.md for design notes.

### Phase 4 — Encryption Hardening ✓ (partial)
ECDH key agreement and certificate pinning complete. Rekeying and encrypted queue deferred.
See DEVELOPMENT_v3.md for design notes.

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

## Phase 2 — Multi-Protocol Listeners

- [ ] HTTP/S listener (blend with web traffic; GET=poll, POST=result)
- [ ] WebSocket listener (bypasses basic DPI, works through most HTTP proxies)
- [ ] DNS beacon listener (TXT record polling; ultra-low-and-slow)
- [ ] ICMP listener (fallback when all TCP/UDP is filtered)
- [ ] Listener multiplexer: route to correct session handler by protocol
- [ ] Per-listener protocol config (beacon interval, jitter, max chunk size)

---

## Phase 3 — Payload Generation

- [ ] `generate` command: produce agent binary for target arch/OS
  - `generate linux amd64 --lhost X --lport Y --format elf`
  - `generate windows amd64 --lhost X --lport Y --format exe`
  - `generate linux arm64 ...`
  - `generate macos amd64 ...`
- [ ] Shell one-liner output (`generate oneliner bash/ps1/python`)
- [ ] Cross-compilation via `GOOS`/`GOARCH` in embedded build step
- [ ] Templated stager: configurable LHOST/LPORT/interval injected at generate time
- [ ] Stage0 dropper: tiny payload (<5KB) that fetches and executes stage1 in memory
- [ ] Stage1 loader: in-memory execution of stage2 without touching disk

---

## Phase 4 — Encryption Hardening

Current: optional TLS with ephemeral cert. No per-session symmetric keys.

- [x] ECDH (X25519) key agreement on first contact → per-session AES-256-GCM keys — DONE
- [x] Certificate pinning on agent side (embed server FP at generate time) — DONE (serverFingerprint ldflags var)
- [ ] Session rekeying at configurable intervals — NOT YET (MsgRekey type defined but not auto-triggered; defer)
- [ ] Encrypted command queue persisted to disk (survive server restart) — NOT YET (deferred; different concern)
- [ ] Payload encryption: XOR/AES stub wrapper for generated agents — NOT YET (this is Phase 5)

---

## Phase 5 — Obfuscation & OPSEC

- [ ] Payload string encryption (RC4/XOR keys embedded, decrypt at runtime)
- [ ] Import table obfuscation (Go: use `//go:linkname` tricks or syscall wrappers)
- [ ] Configurable beacon jitter (e.g. ±20% of interval)
- [ ] Traffic blending: normalize HTTP headers/URIs to mimic a known service
- [ ] Malleable profiles (`profile create browser --user-agent "..." --beacon 60s`)
- [ ] Chunked/randomized packet sizes to defeat size-based fingerprinting
- [ ] Proxy-aware agent: read system proxy (HTTP_PROXY / WinHTTP) and use it

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

## Existing Bugs / Known Limitations

- [ ] `exec <id>` — no timeout handling; hangs on commands with no output terminator
- [ ] `ps <id>` — output is raw; no structured parsing (PID/name/user columns)
- [ ] `broadcast` — sends a message to sessions' notes, not an actual command; wire to `exec`
- [ ] `creds <id>` — manual entry only; hook into auto-harvest post-exploit
- [ ] Interactive filter in `console.go` — stateful ANSI parser may miss fragmented sequences
- [ ] Drain goroutine coordination — `stopDrain` has a small race on rapid re-use
- [ ] macOS recon — OS type detected but no macOS-specific priv-esc checks
- [ ] Recon parser regexes — brittle against non-standard version string formats

---

## Out of Scope (for now)

- Kernel rootkit / firmware persistence
- Hardware implants
- Browser extension implants
- Cloud provider metadata API abuse (AWS IMDSv2, GCP, Azure)
- Active Directory attacks (Kerberoasting, AS-REP roasting) — too infra-specific
