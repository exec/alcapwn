# pbsh - Pwnback Shell Threat Profile

## Overview

**pbsh** (pwnback shell) is a *defensive* reverse shell designed to identify, frustrate, and counter-exploit unauthorized reverse shell sessions. It acts as a "honey-pipe," sitting between the operating system and the remote connection.

### Philosophy: Deceptive Resilience

pbsh is designed to look like a vulnerable, slightly buggy shell to the attacker while functioning as a high-fidelity trap for the defender.

## Core Objectives

1. **Identification**: Distinguish between a local TTY and a remote reverse shell
2. **Active Defense**: Deploy non-destructive (or destructive) payloads against the attacker's terminal
3. **Data Poisoning**: Feed fake, high-value "recon" data to automated tools
4. **Session Capture**: Log every keystroke, environment change, and attempted exploit

## Attack Vectors Against alcapwn

### v1.0: Basic Attack (Easily Defended)

| Attack | Status | Why It Failed |
|--------|--------|---------------|
| **Brute Force Nonce** | Defeated | 16-byte random nonce, HMAC obfuscation |
| **Regex Buffer Overflow** | Defeated | Stateful parser with bounded buffers |
| **Simple OSC Injection** | Defeated | OSC stripping + bracketed paste filter |

### v2.0: Adaptive Attack (Mostly Defended)

| Attack | Status | How It's Defended |
|--------|--------|-------------------|
| **ANSI Fragmentation** | Defeated | Stateful byte-by-byte parser |
| **DCS/PM Sequence Injection** | Defeated | Stateful parser filters them |
| **Nonce Reflection** | Defeated | HMAC obfuscation, nonce never in script |

### v3.0: Logical Attack (NOT Defended - By Design)

These attacks exploit the *inherent limitations* of any remote shell catching tool:

| Attack | Status | Explanation |
|--------|--------|-------------|
| **APC Sequences** | **WARNING** | Cannot safely strip - may contain visible content |
| **Process Breakaways** | **WARNING** | Remote process has independent PID |
| **Human Social Engineering** | **WARNING** | Cannot stop operator from typing |

## Technical Specifications

### Discrimination Engine

pbsh runs environmental fingerprinting tests to set its Threat_Level:

- **Socket Verification**: Check if stdin/stdout are AF_INET socket
- **PTY Presence**: Absence of /dev/tty indicates remote shell
- **Environment Scrubbing**: Missing /usr/local/bin, TERM=dumb

### Pwnback Modules

#### 1. Ghost in the Machine (ANSI/CSI Injection)

- Injects DSR (Device Status Report) to query attacker's terminal
- Attempts terminal color redefinition to hide malicious output

#### 2. Sticky Fingers (OSC 52 Hijack)

- Sends Base64 payloads to attacker's clipboard via `\e]52;c;...`

#### 3. The Mirage (Recon Defeat)

- Detects common recon commands (whoami, ls -la /home, cat /etc/passwd)
- Generates synthetic output: fake directories, falsified shadow files

### Defense Against Hardened Catchers

To counter tools like alcapwn's recent hardening fixes, pbsh implements:

- **CSI Fragmentation**: Break up escape sequences across multiple packets
- **Zero-Width Injection**: Place invisible characters in headers to break nonce matching
- **APC Sequence Injection**: `echo -e "\x1b_MALICIOUS_CONTENT\x1b\\"`

## Vulnerability Research Methodology

### Test Your Catcher Against pbsh

1. **Fragmentation Test**: Send escape sequences byte-by-byte with delays
   ```
   echo -e "\x1b\x5b\x31\x4d\x1b\x5b\x30\x6d"
   ```

2. **APC Sequence Test**: Inject APC sequences
   ```
   echo -e "\x1b_APP_VERSION=1.0.0\x1b\\"
   ```

3. **Process Breakaway Test**: Spawn background process
   ```bash
   (echo "persistence" > /tmp/pbsh_persist &) > /dev/null 2>&1
   ```

### The "ReadMe" Strategy

The key insight: Instead of trying to make the tool invincible, make it **transparent about its limitations**.

```go
// alcapwn's warning when APC detected:
fmt.Print("[!] WARNING: Suspicious APC sequence detected.\r\n")
fmt.Print("[!] Potential TTY hijacking attempt detected.\r\n")
fmt.Print("[!] Do not enter any credentials or sensitive information.\r\n")
```

## PoC Availability

A working PoC of pbsh will be available at `github.com/exec/pbsh` in the near future.

This repository will contain:
- Basic pbsh implementation with all attack vectors
- Fragmentation tester script
- APC sequence injection examples
- Test cases for various catchers

## Defenders: How to Test Your Catcher

### Run the Fragmentation Tester

```bash
./pbsh-test-fragmentation --target localhost:4444
```

This sends:
- Byte-by-byte escape sequences
- Split CSI sequences
- APC sequences with embedded content
- Process breakaways

### Check for These Symptoms

Your catcher is vulnerable if:

1. **Output is corrupted** - Escape sequences weren't stripped
2. **Unexpected prompts appear** - APC sequences with prompts passed through
3. **Processes survive termination** - Breakaways not cleaned up
4. **Warning doesn't appear** - APC detection not implemented

## The Arms Race Framework

| Layer | alcapwn Defense | pbsh Attack | Outcome |
|-------|----------------|-------------|---------|
| Network | Socket close | `nohup &` | pbsh wins |
| Process | `pkill -9 -g $$` | `setsid` | pbsh wins |
| ANSI | Stateful parser | Fragmentation | alcapwn wins |
| Sequence | Filter DCS/PM | APC injection | WARNING only |

## Key Takeaway

**The human operator is the last line of defense.**

No matter how sophisticated your ANSI parser, no matter how thorough your process cleanup, if the operator types `Y` to a fake prompt, the attacker wins.

This is why the "ReadMe" strategy is essential:
- Warn the operator about bypass attempts
- Document the tool's limitations
- Guide the operator toward safe behavior
