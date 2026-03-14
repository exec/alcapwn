# alcapwn — TODO

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

### Known limitations (not worth fixing for NCL)

- MiniShell `;` in `-c` mode doesn't chain commands — use newlines or pipes instead
- Recon parser regexes are brittle against non-standard version strings
- Interactive ANSI filter: byte-by-byte state machine preserves state across chunks — fragmentation is handled correctly
- Session rekeying (MsgRekey) is defined but never auto-triggered
- macOS recon: OS detected but no macOS-specific priv-esc checks
