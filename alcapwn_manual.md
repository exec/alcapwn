# alcapwn v2 - Operator Manual

## What alcapwn Is

alcapwn is a reverse shell catching and privilege escalation reconnaissance tool. It provides:

- Automatic PTY upgrade for stable interactive shells
- Comprehensive system reconnaissance (13 information sections)
- CVE candidate detection (sudo exploits, PwnKit, etc.)
- Findings export as JSON for further analysis

## What alcapwn Is NOT

alcapwn is **not** an invincible security tool. It is a defensive tool with specific, known limitations:

### The pbsh Threat Model

A "pwnback shell" (pbsh) is an adversarial reverse shell designed to turn the tables on defenders. The pbsh v2.0 threat model targets alcapwn's technical limitations:

| Attack | Can alcapwn prevent it? | alcapwn's response |
|--------|------------------------|-------------------|
| **ANSI Fragmentation** | Yes - stateful parser catches byte-level fragments | Full prevention via state machine |
| **Nonce Reflection** | Yes - HMAC obfuscation | Nonce is unpredictable |
| **DCS/PM Sequences** | Yes - stateful parser filters them | Full prevention |
| **APC Sequences** | No - cannot strip safely | **WARNING ALERT** |
| **Process Breakaways (setsid/nohup)** | No - remote process has its own PID | **WARNING ALERT** |
| **Human Social Engineering** | No - can't stop you from typing Y | **WARNING ALERT** |

### Logical Limits

**alcapwn cannot prevent these pbsh v3.0 attacks:**

1. **APC Sequences (`\x1b_`)** - These are "Application Program Command" sequences used for advanced terminal control. They cannot be safely stripped because they may contain visible content. When detected, alcapwn displays a warning.

2. **Process Breakaways** - pbsh can use `setsid`, `nohup`, or double-forking to create processes that survive alcapwn's session cleanup. This is a fundamental limitation - once the shell has spawned a background process, alcapwn cannot control it remotely.

3. **Human Operator Attacks** - The most powerful attack vector. pbsh might try to:
   - Inject fake prompts asking for credentials
   - Send malicious links that look legitimate
   - Exploit trust in the "clean" terminal experience

## Safety Guidelines for Operators

### Always Remember

1. **Never trust unexpected prompts** - A prompt appearing in the middle of recon output is suspicious.
2. **Verify command sources** - If pbsh injects `whoami` or `ls -la` output, it might be fake.
3. **No credentials in prompts** - Legitimate systems will never ask for passwords in an alcapwn session.
4. **Beware of "too clean" output** - pbsh might hide its activity by only showing "clean" output.

### What to Look For

When reviewing recon findings, watch for:

- Inconsistent timestamps in process listings
- Unusual file paths that don't match the expected OS
- SSH keys pointing to non-existent locations
- Process trees that don't make sense for the reported kernel version

### Recommended Configuration

Create a `config.json` in your `~/.alcapwn/` directory:

```json
{
  "auto_open_listeners": true,
  "findings_dir": "/path/to/safe/storage",
  "max_reconnect_attempts": 5,
  "reconnect_timeout": 30
}
```

## Known Vulnerabilities & Workarounds

### Terminal Emulator Bugs

Some terminal emulators (especially older versions) have bugs in their ANSI sequence handling. pbsh may exploit these.

**Mitigation**: Keep your terminal emulator updated and use state-of-the-art emulators like:
- iTerm2 (macOS)
- Alacritty (cross-platform)
- Kitty (Linux/macOS)

### Process Cleanup Limitations

alcapwn's `pkill -9 -g $$` command may not catch all persistence mechanisms.

**Workaround**: After session closure, manually verify:
```bash
ps aux | grep -E "(nohup|setsid|nohup)" | grep -v grep
```

## Technical Details

### Stateful ANSI Parser

alcapwn uses a state machine to parse ANSI escape sequences byte-by-byte. This catches:
- Split sequences across network packets
- Non-standard terminators
- Nested escape sequences

### Nonce Obfuscation

Section headers use HMAC-SHA256 with a session-specific nonce. This prevents:
- Nonce guessing attacks
- Recon script injection
- Fake section header injection

### Kill Remote Process Group

Before session termination, alcapwn sends:
```bash
pkill -9 -g $$
```

This kills all processes in the current session's process group.

## Support & Reporting

If you suspect pbsh has bypassed alcapwn's defenses:

1. Capture the full session output (including ANSI sequences)
2. Note the exact timing of suspicious behavior
3. Report to the maintainers with the full context

## License

[Your license here]
