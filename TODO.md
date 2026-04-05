# alcapwn — TODO

> **Warning: Wire format break in v2.0.0-rc1:** AES-256-GCM now binds the 4-byte
> length prefix as AAD. Agents built before this version cannot communicate
> with servers built after it. All agents must be rebuilt.

---

## Audit findings (2026-03-17, publish-readiness review)

### Fixed in this pass

- [x] **[ROBUST] `readUntilPrompt` unbounded buffer** — added `maxPromptBuf`
      (1 MiB) hard cap; breaks the read loop before OOM from a hostile target
      that streams data indefinitely without sending a prompt. (`pty_upgrader.go`)

- [x] **[ROBUST] `readUntilSentinelProgress` unbounded buffer + O(n²) scan** —
      added `maxSentinelBuf` (8 MiB) hard cap and a rolling `tail` buffer
      so the sentinel check only scans the last `2*len(sentinel)` bytes per
      line instead of the full accumulated output. (`pty_upgrader.go`)

- [x] **[SEC] `cleanShutdown` leaks pivot listeners** — added `ps.Close()` and
      `c.stopDrain(s)` for every session during shutdown so pivot ports and
      drain goroutines are cleaned up on exit. (`console.go`)

- [x] **[SEC] `X-Forwarded-For` trusted in HTTP register** — removed; the TCP
      peer address is always used as `RemoteAddr`. Attacker-controlled headers
      must not influence addressing or display. (`listener_http.go`)

- [x] **[SEC] `stripDangerousAnsi` missing DCS (`\eP`)** — added `|| s[i+1] == 'P'`
      to the APC/PM/SOS branch; DCS sequences are now fully stripped from exec /
      creds / broadcast output, matching the interactive-path filter. (`cmd_sessions.go`)

- [x] **[SEC] `autoWhitelistIP` applied to all firewalls** — fixed to only update
      firewalls assigned to the listener that received the TLS reconnect, not
      every firewall in the store. Call site updated to pass `entry.addr`.
      (`cmd_firewall.go`, `console.go`)

### Remaining (cannot fix without broader changes)

- [ ] **[SEC] Static recon sentinel (`ALCAPWN_RECON_COMPLETE_7f3x9q`)** —
      the sentinel is a compile-time constant embedded in both the binary and
      the bash script template. A target that reads `/proc/self/mem` or
      intercepts the unencrypted recon script delivery can inject it early to
      truncate recon output (silent missing-data attack, not false findings).
      Fix: derive the sentinel from the per-session HMAC nonce already used for
      section headers (requires coordinated change to `recon.go` + `reconScript`
      const + all existing compiled agents). Defer until next major refactor.

- [ ] **[SEC] APC warning in `readUntilPrompt` uses `fmt.Printf` directly** —
      prints to stdout without `consolePrinter.Notify`'s mutex, so the message
      can interleave with concurrent session output. Fix: thread the
      `consolePrinter` into `PTYUpgrader` (requires API change). Low priority
      since `readUntilPrompt` is not called during the live interactive phase.

---

## Audit findings (2026-03-14)

Issues ordered by severity. Tags: **[SEC]** security, **[PERF]** performance,
**[ROBUST]** robustness/correctness, **[REUSE]** reusability/maintainability.

---

### Critical

- [x] **[SEC] HTTP download path traversal** — added `filepath.Base(filename)`
      before whitelist check in `handleHTTPDownload`; eliminates all directory
      traversal regardless of router normalisation. (`listener_http.go`)

- [x] **[SEC] No authentication on relay-back connections** — added
      `RelayToken` field to `proto.Task`; `openRelayListener` generates a
      random 16-hex-char token, included in `TaskShell` / `TaskForward`
      dispatches; agent sends token before proxying; server reads and verifies
      via new `acceptRelayConn` helper. (`proto/proto.go`, `cmd_pivot.go`,
      `cmd_sessions.go`, `agent/shell.go`, `agent/pivot.go`, `agent/main.go`)

- [x] **[SEC] `stripDangerousAnsi` incomplete** — APC / PM / SOS branch now
      scans forward to the ST terminator (`\x1b\\` or `\x07`) and discards
      the full sequence body, matching the OSC handler. (`cmd_sessions.go`)

- [x] **[SEC] Nonce counter overflow / reuse** — *not* a false positive:
      two independent keys prevent cross-direction reuse, but a single
      direction's nonce wraps at 2^96 (silent, catastrophic for GCM).
      Fixed: `incrementNonce` now returns error at 2^32 invocations per
      NIST SP 800-38D. Also replaced hand-rolled HKDF with
      `golang.org/x/crypto/hkdf`, added length prefix as AAD to GCM
      Seal/Open, and added error handling to `LoadOrCreateServerKey`
      (was silently regenerating on corrupt file). (`proto/crypto.go`)

- **[SEC] Relay listener binds 0.0.0.0** — relay must be reachable by the
      remote agent, so 0.0.0.0 is intentional. The relay token auth (above)
      is the actual mitigation. No code change needed.

---

### High

- [x] **[SEC] `agentTaskID` is predictable** — replaced
      `time.UnixNano()+len(content)` with `crypto/rand` (16 random hex chars).
      (`agent_session.go`)

- [x] **[ROBUST] Unbounded `ANSIState.Parse` buffer** — added `maxANSIBuf`
      (64 KiB) cap; excess input is discarded and the buffer reset to prevent
      OOM from a never-terminated escape sequence. (`pty_upgrader.go`)

- [x] **[ROBUST] No rate limiting on `acceptLoop`** — added `connSem chan
      struct{}` (capacity 64) to `Console`; each spawned handler goroutine
      acquires a slot and releases it on exit. (`console.go`)

- ~~**[SEC] HTTP beacon token is session-ID-derived**~~ — *false positive*:
      `newHTTPToken()` already uses `crypto/rand` for a 32-hex-char token
      independent of session ID. No change needed.

- [ ] **[ROBUST] `readUntilPrompt` / `readUntilSentinel` have fixed timeouts**
      — long-running commands on slow targets silently truncate output at the
      5 s / 30 s deadline. Surface the timeout to the operator rather than
      returning partial data silently.

- [x] **[SEC] HTTP listener has no TLS** — `listen http --tls` now wraps the
      listener with `tls.NewListener` using the process-level ephemeral cert.
      Ephemeral cert fingerprint printed unconditionally at startup. Agent-side
      TLS cert pinning (`transport_http.go`, `cmd_generate.go` ldflag wiring)
      not implemented.

---

### Medium

- [x] **[ROBUST] Duplicated session-ID allocation** — extracted `nextFreeID()`
      helper used by both `Allocate` and `AllocateHTTP`. (`registry.go`)

- [x] **[ROBUST] `hostFromAddr` breaks on IPv6** — replaced manual `:` split
      with `net.SplitHostPort`. (`session.go`)

- [x] **[PERF] Bubble sort in `matchFindings`** — replaced O(n²) hand-rolled
      bubble sort with `sort.Slice`. (`dataset.go`)

- [x] **[PERF] `sortSessions` acquires `persistMu` inside `sort.Slice`** —
      *not* a false positive: the `"match_count"` sort case in `cmdSessions`
      acquired the lock inside every comparator call — O(N·M·logN) lock
      acquisitions. Fixed: pre-compute match counts into a map before sorting.
      (`cmd_sessions.go`)

- [ ] **[ROBUST] `displayGroupedSessions` duplicates display logic** —
      ~60 lines of row-formatting code duplicated between `displaySessions`
      and `displayGroupedSessions`. Extract a shared `formatSessionRow`.

- ~~**[ROBUST] Recon script HMAC key is static per session**~~ — *false
      positive*: `makeReconNonce()` uses `crypto/rand` for a fresh 16-byte
      nonce per recon invocation. No change needed.

- [ ] **[REUSE] `console.go` is 1400+ lines** — split into `line_editor.go`,
      `printer.go`, `interact.go`, etc.

- [ ] **[REUSE] Magic numbers throughout** — define named constants for
      timeouts (5s, 30s, 60s), buffer sizes, port offsets (10000), etc.

- [ ] **[ROBUST] Firewall first-match semantics undocumented** — document in
      `help firewall` output that rules are evaluated top-to-bottom and the
      first match wins.

- [ ] **[ROBUST] `MaxBodySize` (4 MiB) may be too small for large uploads** —
      chunk uploads or raise the cap with a comment on memory impact.

---

### Low

- [x] **[REUSE] Stale dependencies** — updated `golang.org/x/sys` v0.18→v0.30,
      `golang.org/x/term` v0.18→v0.29, added `golang.org/x/crypto` v0.33
      (replaces hand-rolled HKDF). Fixed `// indirect` markers via `go mod tidy`.

- [ ] **[ROBUST] Session limit is hardcoded 1024** — fine for CTF; add a
      `--max-sessions` flag or at least a clearer error if hit in production.

- [ ] **[REUSE] `cmd_persist.go` is 939 lines** — split per persistence type.

- [ ] **[PERF] `buildSectionRe` recompiles regex per recon call** — pre-
      compile and cache (keyed by nonce) if recon is called frequently.

- [x] **[ROBUST] `containsAnsiSequences` has off-by-one** — changed loop
      guard from `i < len(s)-2` to `i+2 < len(s)`. (`cmd_sessions.go`)

- [x] **[REUSE] No `go vet` / `staticcheck` in CI** — `go vet` was already
      present in the lint job. Added `go test -race ./...` as a dedicated test
      job. `staticcheck` still not wired. (`.github/workflows/ci.yml`)

---

## Done

- Agent/server split, encrypted TCP + HTTP transports, auto-reconnect, hardware fingerprint
- ECDH X25519 + AES-256-GCM per-session encryption, certificate pinning, XOR obfuscation
- HTTP traffic blending (browser UA, custom paths, padding, jitter)
- Cross-platform payload generation (`generate`), one-liner output, `--listener` wiring
- PTY upgrade, TLS upgrade, interactive session (`use`), drain loop
- Recon pipeline (bash script → parser → structured Findings), auto-recon flag
- 74-entry exploit dataset (SUID, sudo, caps, crons, CVEs, docker, env secrets, AWS, etc.)
- `exploit list / exploit <id> / exploit auto` — ranked matches, template fill, root check
  - **Now works on agent sessions** (dispatches via TaskExec, checks uid/admin post-exploit)
- **Recon auto-prints top 5 matches** on completion — no extra `exploit list` call needed
- Persistence: `cron`, `bashrc`, `sshkey`, `systemd`, `setuid` (Linux PTY)
  - `reg`, `schtask` (Windows agent) — HKCU Run key + scheduled task, no elevation needed
- Pivot: server-side SOCKS5 (`pivot <id> --socks5 <port>`) + TCP forward (`--fwd lp:h:p`)
  via agent relay-back mechanism; works with proxychains4 / curl --socks5
- Network scan from agent (`scan <id> <cidr>`) — pure-Go TCP-connect, concurrent, no nmap
- Windows recon (agent): whoami /all, services, registry checks (AlwaysInstallElevated, UAC)
- Windows dataset entries: SeImpersonate→GodPotato/PrintSpoofer, AlwaysInstallElevated,
  WeakServiceACL, UnquotedServicePath — matched + executed via `exploit auto`
- Agent credential harvest (`creds <id>` on agent sessions): shadow, SSH keys, env secrets,
  shell history, .env files, AWS creds, git creds (Linux); PS history, env, SSH, .env (Win)
- Built-in minishell (MiniExec + MiniShell.Run()) — zero-dep, all arches, tab completion
- Security: all remote strings through `stripDangerousAnsi()` before terminal output
- Full test suite: unit tests with `-race`, 40+ integration harness tests
- **v2.0.0-rc1 code review** (2026-04-04): 40+ fixes across crypto, agent,
  commands, CI/CD. Nonce overflow hardening, stdlib HKDF, GCM AAD binding,
  IPv6 fixes, agent robustness (size limits, deadlines, fd leak fixes),
  command handler cleanup. 12 new test files (~1500 lines), test count ~40→337.
  CI now runs `go test -race`; releases include SHA-256 checksums.
  `fdset_linux.go` made portable across 32/64-bit GOARCH.

---

## Open

### Flow improvements still worth doing

- [x] **`shell <id>` interactive agent shell** — `TaskShell` dispatched via agent
      task channel; agent execs system shell with stdio piped to ephemeral relay
      TCP conn; C2 accepts relay-back and enters raw terminal I/O loop (same ANSI
      safety filter as PTY sessions).  Ctrl+D closes the shell.
- [x] **Auto-recon on agent connect** — `--recon` / `-r` flag now triggers
      `cmdReconAgent` automatically when an agent session becomes ready, mirroring
      the existing PTY auto-recon behaviour.

- [x] **Linux agent recon → structured Findings** — `recon <id>` on a bash-capable
      Linux agent now runs the full HMAC-tagged recon script via TaskExec, feeds raw
      output through `extractAllSections` → `ReconParser.Parse` → `matchFindings`,
      and stores results in sess.Findings/sess.Matches. `exploit auto` works end-to-end
      on Linux agents. Falls back to simple TaskRecon output if bash not available.

- [x] **`scan` → pivot suggestions** — after a scan, auto-prints ready-to-run
      `pivot <id> --fwd localPort:host:port` for every open port found (local port
      = remote + 10000 to avoid conflicts).

### Windows server support

The operator console needs two platform abstractions to compile on Windows.
Both are isolated — PTY sessions would be stub-only on Windows, agent sessions
work fine without them.

- [ ] **`unix.Select` stdin polling** — the main blocker. Used in two places:
      `interactWithSession` and `shellInteract`. Both poll stdin with a 50 ms
      timeout so cancellation doesn't consume a character from the next prompt.
      Windows approach: blocking goroutine read on `os.Stdin` + a small cancel
      pipe (write a dummy byte to unblock the goroutine) wrapped behind a
      `stdinPoller` interface with `_windows` / `_unix` implementations.

- [ ] **`unix.SIGWINCH` / `unix.SIGTERM`** — wrap in build-tagged signal files.
      SIGWINCH (terminal resize) silently no-ops on Windows; SIGTERM doesn't
      exist but `os.Interrupt` covers Ctrl+C. One small `signals_windows.go`
      stub handles both.

- [ ] **PTY upgrader stub** — `pty_upgrader.go` is Linux-only. Add a
      `pty_upgrader_windows.go` stub that returns an error from `NewUpgrader`
      so PTY sessions are cleanly rejected rather than failing to compile.

  **Effort:** ~half a day. Agent sessions, recon, exploit, creds, pivot, scan,
  shell all work on Windows already. Only PTY sessions are unsupported.

---

### Module system

Right now post-exploitation capabilities are hardcoded commands. A module
system would let new capabilities be added (or swapped out) without touching
core console code — useful for custom CTF scenarios and keeping the agent lean
by only shipping what's needed.

#### Design

**Server-side modules** — loaded from `~/.alcapwn/modules/*.go` (or a compiled
plugin `.so`) at startup. Each module registers itself against a name and
implements a small interface:

```go
type Module interface {
    Name()        string   // command name, e.g. "keylog"
    Description() string   // shown in `help` and `modules list`
    // For agent modules: the TaskKind the server sends and the agent handles.
    // For PTY modules: runs against the Upgrader directly.
    Run(c *Console, sess *Session, args []string) error
}
```

Modules appear automatically in the command dispatch and `help` output.
`modules list` shows all loaded modules and their source.

**Agent-side modules** — compiled into the agent at generate-time via
`--modules keylog,screenshot` flag. Each agent module registers a new
`TaskKind` handler. The server-side module sends that task; if the agent
wasn't built with the module, it returns `"unknown task kind"`.

#### What should move to modules first

These are the best candidates — self-contained, well-defined I/O, no deep
coupling to core session state:

| Feature | Why it's a good module |
|---------|------------------------|
| `creds` | Completely independent harvest logic; Linux/Windows variants already split |
| `scan` | Zero coupling to session state; pure input→JSON output |
| `pivot` / SOCKS5 | Manages its own listener state; already isolated in `cmd_pivot.go` |
| `shell` | Single relay open/accept/interact pattern; no core dependencies |
| `keylog` *(new)* | New capability; agent captures keystrokes, server `keylog <id> start/dump/stop` |
| `screenshot` *(new)* | Agent encodes screen to PNG, server downloads + opens; Windows/Linux/macOS |
| `clipboard` *(new)* | Agent reads/writes clipboard; server `clip <id> [text]` |

#### What stays core

`exec`, `use`/interactive, `recon`+`exploit`, `persist`, `download`/`upload`,
`sessions`/`kill`/`info` — these are tightly coupled to session lifecycle,
the Findings pipeline, or the encrypted task channel and shouldn't move.

#### Effort breakdown

- Module interface + registry + dispatch hook: small (1–2 hours)
- Moving `creds`, `scan`, `pivot`, `shell` to modules: medium (half day each,
  mostly mechanical extraction + wiring the new TaskKind per module)
- Agent-side module flag in `generate`: small (add `--modules` ldflags list,
  build-tag each agent module file)
- New modules (keylog, screenshot, clipboard): varies by platform complexity

---

### Known limitations (not worth fixing for NCL)

- MiniShell `;` in `-c` mode doesn't chain commands — use newlines or pipes instead
- Recon parser regexes are brittle against non-standard version strings
- Interactive ANSI filter: byte-by-byte state machine preserves state across chunks — fragmentation is handled correctly
- Session rekeying (MsgRekey) is defined but never auto-triggered
- macOS recon: OS detected but no macOS-specific priv-esc checks
