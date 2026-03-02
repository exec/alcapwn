# alcapwn v2 TODO

## Priority 1 (Next Implementation)

### File Transfer (Upload/Download)
**Why:** Essential for NCL - uploading tools, downloading credentials
- `download <id> <remote_path> [local_path]`
  - If no local_path, save to current directory with hostname_timestamp prefix
  - Support resuming large files
- `upload <id> <local_path> [remote_path]`
  - Detect if target is a directory
  - Preserve file permissions where possible

## Priority 2 (After File Transfer)

### Quick Command Execution
**Why:** Recon takes 10-30 seconds; sometimes you just need a quick check
- `exec <id> <command>` - Run single command without full recon
  - Returns raw output (minimal processing)
  - No prompt stripping, no state changes
  - Example use: `exec 1 whoami`, `exec 1 id`
- Consider adding timeout flag: `exec -t 5 <id> <cmd>`

### Session Filtering & Grouping
**Why:** NCL boxes often have many similar machines
- `sessions --filter <keyword>` - Filter by:
  - OS: `--filter ubuntu`, `--filter debian`, `--filter kali`
  - Hostname: `--filter web`, `--filter db`
  - IP: `--filter 192.168`
  - CVE matches: `--filter cve`
- `sessions --group <field>` - Group by:
  - `os` - Group by distro
  - `container` - Docker vs bare metal
  - `status` - Interactive vs backgrounded
  - `match_count` - High match count first
- `sessions --sort <field>` - Sort by:
  - `uptime` - Most/least recent
  - `match_count` - Most privesc options first
  - `id` - Default, by session ID

## Priority 3 (Later)

### Export Improvements
- `export <id> --json [path]` - JSON format (current)
- `export <id> --txt [path]` - Human-readable report
- `export <id> --html [path]` - HTML summary for sharing

### Shell Switching
- `shell <id> <shell>` - Switch between available shells
  - `shell 1 zsh` - Try switching to zsh
  - `shell 1 sh` - Fallback to dash/sh
  - Useful when bash is restricted

### Credential Harvesting Helper
- `creds <id>` - Quick credential check
  - SSH keys in home dirs
  - AWS credentials
  - MySQL configs
  - Docker configs
  - Pip/Gem rc files

### Port Forwarding
- `portforward <id> <local_port>:<remote_host>:<remote_port>`
  - Create TCP forward through session
  - Example: `portforward 1 8080:localhost:3306`

### Task Scheduling
- `schedule <id> <interval> <command>`
  - Run commands periodically
  - Useful for monitoring or waiting for conditions

### Session Notes/Tags
- `notes <id> <note>` - Attach freeform notes
- `tags <id> <tag1> [tag2...]` - Tag for grouping
- `search <keyword>` - Find sessions by tag/note

### Auto-Exploitation Helper
- `suggest <id>` - Show top match + exact command
- `exploit <id> <match_index>` - Run exploitation command directly

---

## Architecture Notes

### Mini-C2 Approach
The multi-session C2 architecture is a natural evolution:
- Session state already exists in `Session` struct
- Interactive loop already handles backgrounding (Ctrl+D)
- Recon already stores findings in memory
- Minimal overhead - just keeps sessions alive and adds commands

### Backward Compatibility
Still works identically:
- `./alcapwn -l :4444` → catches, upgrades, recon, shows ready
- Just now you get an interactive prompt (can be ignored)
- No breaking changes to existing workflow
