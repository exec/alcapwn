# alcapwn v2 TODO

## High Priority (Must-Have for NCL)

### 1. File Transfer (Upload/Download)
**Why:** Essential for NCL - uploading tools, downloading credentials
- `download <id> <remote_path> [local_path]`
  - If no local_path, save to current directory with hostname_timestamp prefix
  - Support resuming large files
- `upload <id> <local_path> [remote_path]`
  - Detect if target is a directory
  - Preserve file permissions where possible

### 2. Persistence Installation
**Why:** Shells die during NCL (reboots, network issues, manual cleanup). Need persistent access.
- `persist <id> <method>` - Install persistence
  - `cron` - Add to /etc/cron.d or user crontab (reboot)
  - `bashrc` - Add to ~/.bashrc or ~/.bash_profile (new shells)
  - `sshkey` - Add SSH public key to authorized_keys
  - `systemd` - Create systemd service (reboot, if systemctl available)
  - `setuid` - Set SUID bit on uploaded binary
- `persist list <id>` - List existing persistence entries
- `persist remove <id> <entry_id>` - Remove persistence entry

### 3. Quick Command Execution
**Why:** Even at 5 seconds, full recon is overkill for quick checks like `whoami` or `id`
- `exec <id> <command>` - Run single command without triggering full recon
  - Returns raw output with minimal processing
  - No prompt stripping, no state changes
  - Example: `exec 1 whoami`, `exec 1 id`, `exec 1 cat /etc/passwd`
- `exec -t <timeout> <id> <cmd>` - Timeout flag for long-running commands

### 4. Process Management
**Why:** Need to see what's running, kill specific processes without killing shell
- `ps <id>` - List processes (PID, user, %CPU, %MEM, command)
- `killproc <id> <pid>` - Kill specific process (SIGTERM, then SIGKILL if needed)
- `bgproc <id> <cmd>` - Run command in background with job tracking
- `jobs <id>` - List background jobs
- `bgoutput <id> <jobid>` - Get output from background job

---

## Medium Priority (Very Useful)

### 5. Session Filtering & Grouping
**Why:** NCL boxes often have 20+ similar machines; need to manage them
- `sessions --filter <keyword>` - Filter by:
  - OS: `--filter ubuntu`, `--filter debian`, `--filter kali`
  - Hostname: `--filter web`, `--filter db`
  - IP: `--filter 192.168`
  - CVE matches: `--filter cve`, `--filter high`, `--filter critical`
- `sessions --group <field>` - Group by:
  - `os` - Group by distro
  - `container` - Docker vs bare metal
  - `match_count` - High match count first
  - `status` - Interactive vs backgrounded
- `sessions --sort <field>` - Sort by:
  - `uptime` - Most/least recent
  - `match_count` - Most privesc options first
  - `id` - Default, by session ID

### 6. Credential Harvesting Helper
**Why:** You detect credentials but need to extract them
- `creds <id>` - Quick credential check
  - SSH keys in home dirs (id_rsa, id_ed25519, id_ecdsa)
  - AWS credentials (~/.aws/credentials, /root/.aws/credentials)
  - MySQL configs (~/.my.cnf, /root/.my.cnf, /etc/mysql/debian.cnf)
  - Docker configs (config.json)
  - Pip/Gem rc files
- `dump shadow <id>` - Dump /etc/shadow (requires root)
- `dump crontab <id>` - Dump all crontabs

### 7. Filesystem Navigation Enhancements
**Why:** Need to browse and examine files on target
- `ls <id> <path>` - List directory contents
- `cat <id> <path>` - View file contents (pager support)
- `find <id> <path> <pattern>` - Find files by pattern
- `md5 <id> <path>` - Get file MD5 hash
- `stat <id> <path>` - Get file stat info
- `head <id> <path> [lines]` - View first N lines
- `tail <id> <path> [lines]` - View last N lines

### 8. Export Improvements
**Why:** Share findings with team, create reports
- `export <id> --txt [path]` - Human-readable report
- `export <id> --html [path]` - HTML summary for sharing
- `export all --json [dir]` - Export all sessions' findings

---

## Lower Priority (Nice to Have)

### 9. Shell Switching
**Why:** Bash may be restricted, other shells may be available
- `shell <id> <shell>` - Switch between available shells
  - `shell 1 zsh` - Try switching to zsh
  - `shell 1 sh` - Fallback to dash/sh
  - Detect if shell exists first

### 10. Port Forwarding
**Why:** Pivot through compromised host to internal networks
- `portforward <id> <local_port>:<remote_host>:<remote_port>`
  - Create TCP forward through session
  - Example: `portforward 1 8080:localhost:3306`
- `portforwards <id>` - List active forwards
- `portforward kill <id> <forward_id>` - Kill specific forward

### 11. Auto-Exploitation Helper
**Why:** Speed up exploitation of identified vectors
- `suggest <id>` - Show top match + exact command from dataset
- `exploit <id> <match_index>` - Run exploitation command directly
- `exploit list <id>` - List all exploitable findings

### 12. Session Notes/Tags
**Why:** Track findings and next steps per session
- `notes <id> <note>` - Attach freeform notes to session
- `tags <id> <tag1> [tag2...]` - Tag sessions for grouping
- `search <keyword>` - Find sessions by tag or note

### 13. Network Discovery
**Why:** Map internal network from compromised host
- `scan <id> <target> <ports>` - Port scan from target (tcp connect)
- `arp <id>` - Get ARP table
- `routes <id>` - Get routing table
- `hosts <id>` - Check /etc/hosts

### 14. Heartbeat/Monitoring
**Why:** Check if backgrounded sessions are still alive
- `heartbeat <id>` - Send simple command, check response
- `heartbeat all` - Check all backgrounded sessions
- `watch <id>` - Start periodic heartbeat with notifications

### 15. Browser Interaction
**Why:** NCL often has web app attacks
- `history <id>` - Get browser history (if present)
- `cookies <id>` - Dump browser cookies
- `screenshot <id>` - Take screenshot (if x11 forwarding available)

### 16. Lateral Movement Aids
**Why:** Spread after gaining initial access
- `spray <cmd>` - Run command across all sessions (shared credentials)
- `forward <id> <target:port>` - Forward connections through session

---

## Firewall Feature (High Priority - Elegant Design)

### `firewall` Command
**Why:** Control incoming connections, prevent self-DoS when shells reconnect
- `firewall create <name>` - Create a named firewall
- `firewall list` - List all firewalls
- `firewall delete <name>` - Delete a firewall
- `firewall rule <name> <allow|deny> <ip|cidr>` - Add rule
- `firewall rules <name>` - List rules
- `firewall clear <name>` - Clear all rules (deny all)
- `firewall assign <name> <listener_addr>` - Assign firewall to listener

**Design principles:**
- Deny by default; only whitelisted IPs connect
- Active session IPs are auto-whitelisted (prevents self-block)
- Firewall applies at `accept()` time, before session creation
- Listeners can operate without firewall (default: allow all)

**Auto-behavior:**
- When session opens: source IP auto-added to firewall's allow list
- When session closes: source IP auto-removed (cleanup)
- TLS reconnects: IP already whitelisted from original session

---

## Architecture Improvements (Internal)

### 17. Drain Goroutine Race Condition
**File:** `console.go` - `startDrain()`
**Issue:** The drain goroutine reads from `conn` while `interactWithSession` may also read. Need better coordination.
**Risk:** Data loss or missed output when switching between background/interactive modes.

### 18. Config Command
**Why:** NCL shells reconnect for ~15 minutes every 10 seconds by default; need configurable reconnect handling
- `config set reconnect_timeout <seconds>` - How long to wait for reconnect
- `config set max_reconnects <count>` - Max reconnection attempts
- `config show` - Show current config
- `config reset` - Reset to defaults

### 19. Listener Multiplexing
**Issue:** One listener per port; can't have both TLS and plain on same port with different behavior.
**Current:** Auto-detection works via byte peeking, which is fine.
**Consider:** Explicit `--plain` vs `--tls` listener modes if needed.

---

## Out of Scope

### Windows Support
**Why:** NCL is Linux-focused; keep tool simple.

### encrypted payload execution
**Why:** AV evasion is beyond NCL scope; use base64 encoding if needed.

### C2 infrastructure (beaconing, command queue, etc.)
**Why:** This is a CTF tool, not a production C2. Keep it simple.
