package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Compiled regexes at package level
var (
	rePromptPattern   = regexp.MustCompile(`[$#]\s*$`)
	reSudoUser        = regexp.MustCompile(`User\s+(\w+)\s+may run`)
	reSudoUserLine    = regexp.MustCompile(`^(\w+)\s+ALL`)
	reSudoCmd         = regexp.MustCompile(`NOPASSWD:\s*(.+)$`)
	reCapability      = regexp.MustCompile(`^(/[\w/._-]+)\s+(cap_\w+)(?:=(\w+))?`)
	reWritableCron    = regexp.MustCompile(`Writable:\s*(/[\w/._-]+)`)
	rePath            = regexp.MustCompile(`^/[\w/._-]+$`)
	reHostname        = regexp.MustCompile(`Hostname:\s*(\S+)`)
	reUser            = regexp.MustCompile(`Current user:\s*(\S+)`)
	reUID             = regexp.MustCompile(`uid=(\d+)`)
	reOSInfo          = regexp.MustCompile(`(?m)OS Info:\s*([^$\n].+)$`)
	reKernelVersion   = regexp.MustCompile(`(?m)Kernel Version:\s*(.+)$`)
	reSudoVersion     = regexp.MustCompile(`Sudo version\s+(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?`)
	reApache          = regexp.MustCompile(`Apache/(\d+\.\d+\.\d+)`)
	reNginx           = regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)
	rePHP             = regexp.MustCompile(`PHP (\d+\.\d+\.\d+)`)
	rePython          = regexp.MustCompile(`Python (\d+\.\d+\.\d+)`)
	reNode            = regexp.MustCompile(`(?m)^v(\d+\.\d+\.\d+)\s*$`)
	reDocker          = regexp.MustCompile(`Docker version (\d+\.\d+\.\d+)`)
	reMySQL           = regexp.MustCompile(`mysql\s+Ver (\d+\.\d+)`)
	rePsql            = regexp.MustCompile(`psql \(PostgreSQL\) (\d+\.\d+)`)
	reGitLabToken     = regexp.MustCompile(`token\s*=\s*"([^"]+)"`)
	reDaemonPort      = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+):(\d+)`)
	reSuidPath        = regexp.MustCompile(`/[\w/._-]+`)
	reSuidLine        = regexp.MustCompile(`^/[\w/._-]+$`)
	reOSDistro        = regexp.MustCompile(`(Ubuntu|Debian|CentOS|Red Hat|Fedora|Kali|Parrot|Raspbian)\s*(?:GNU/Linux)?[\s]*(\d+)?`)
	rePolkitExec      = regexp.MustCompile(`pkexec version (\d+)\.(\d+)(?:\.(\d+))?`)
	rePolkitDeb       = regexp.MustCompile(`polkit-pkg: polkit (\d+)\.(\d+)(?:\.(\d+))?-(\d+)`)
	rePolkitRpm       = regexp.MustCompile(`(?m)^polkit-(\d+)\.(\d+)(?:\.(\d+))?-(\d+)`)
)

type ReconParser struct{}

func newFindings() *Findings {
	return &Findings{
		SudoNopasswd:     []SudoEntry{},
		SuidBinaries:     []string{},
		SgidBinaries:     []string{},
		Capabilities:     []CapabilityEntry{},
		WritableCrons:    []string{},
		ToolsAvailable:   []string{},
		CveCandidates:    []CveCandidate{},
		InterestingFiles: []string{},
		ServiceVersions: ServiceVersions{
			Apache:       nil,
			Nginx:        nil,
			PHP:          nil,
			Python:       nil,
			Node:         nil,
			Docker:       nil,
			MySQL:        nil,
			Postgres:     nil,
			GitLabRunner: nil,
		},
		EnvSecrets:         []string{},
	}
}

func (p *ReconParser) Parse(sections map[string]string) *Findings {
	f := newFindings()

	// Parse each section
	sudoOutput := sections["SUDO ACCESS"]
	f.SudoRequiresPassword = strings.Contains(sudoOutput, "SUDO_REQUIRES_PASSWORD")
	f.SudoNopasswd = p.parseSudoNopasswd(sudoOutput)

	suidOutput := sections["SUID/SGID BINARIES"]
	suidResults := p.parseSuidSgid(suidOutput)
	f.SuidBinaries = suidResults.suid
	f.SgidBinaries = suidResults.sgid

	capOutput := sections["CAPABILITIES"]
	f.Capabilities = p.parseCapabilities(capOutput)
	if pv := parsePolkitInfo(capOutput); pv.versionStr != "" {
		f.PolkitVersion = stringPtr(pv.versionStr)
	}

	cronOutput := sections["CRON JOBS"]
	f.WritableCrons = p.parseWritableCrons(cronOutput)

	envOutput := sections["ENVIRONMENT & TOOLS"]
	f.ToolsAvailable = p.parseToolsAvailable(envOutput)

	filesOutput := sections["INTERESTING FILES"]
	f.InterestingFiles = p.parseInterestingFiles(filesOutput)
	f.AWSCredentialsFound = p.parseAWSCredentials(filesOutput)
	f.MySQLConfigFound = p.parseMySQLConfig(filesOutput)

	// Set SSHKeyFound from InterestingFiles
	for _, file := range f.InterestingFiles {
		if strings.Contains(file, "id_rsa") || strings.Contains(file, "id_ed25519") {
			f.SSHKeyFound = &file
			break
		}
	}

	versionsOutput := sections["SERVICE VERSION DETECTION"]
	f.ServiceVersions = p.parseServiceVersions(versionsOutput)

	dockerOutput := sections["DOCKER SOCKET DETECTION"]
	dockerInfo := p.parseDockerSocketDetection(dockerOutput)
	f.DockerSocket = dockerInfo.socketPath
	f.DockerSocketAccessible = dockerInfo.socketAccessible

	containerOutput := sections["CONTAINER/VM DETECTION"]
	containerInfo := p.parseContainerDetection(containerOutput)
	f.ContainerDetected = containerInfo.detected
	f.VirtualizationType = containerInfo.containerType

	identityOutput := sections["IDENTITY"]
	identityInfo := p.parseIdentity(identityOutput)
	f.Hostname = identityInfo.hostname
	f.User = identityInfo.user
	f.UID = identityInfo.uid
	f.OS = identityInfo.os
	f.KernelVersion = identityInfo.kernelVersion

	// Check CVE candidates
	f.CveCandidates = p.checkCVECandidates(f, sections)

	return f
}

func (p *ReconParser) parseSudoNopasswd(output string) []SudoEntry {
	results := []SudoEntry{}
	seen := make(map[string]bool)

	// Look for lines like:
	// (ALL) NOPASSWD: ALL
	// username ALL=(ALL) NOPASSWD: ALL
	// username ALL=(ALL, !root) NOPASSWD: /bin/bash
	// username ALL=(root) NOPASSWD: /home/anansi/bin/anansi_util
	lines := strings.Split(output, "\n")

	// First, try to extract the username from "User <username> may run..." line
	defaultUser := "unknown"
	userMatch := reSudoUser.FindStringSubmatch(output)
	if userMatch != nil {
		defaultUser = userMatch[1]
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Match patterns with NOPASSWD
		if strings.Contains(strings.ToUpper(line), "NOPASSWD") {
			// Check for (ALL, !root) pattern - CVE-2019-14287 fingerprint
			negatedRoot := strings.Contains(line, ", !root") || strings.Contains(line, ",!root")

			// Extract username if present at the beginning
			user := defaultUser
			userMatch := reSudoUserLine.FindStringSubmatch(line)
			if userMatch != nil {
				user = userMatch[1]
			}

			// Extract the command after NOPASSWD:
			cmd := "ALL"
			cmdMatch := reSudoCmd.FindStringSubmatch(line)
			if cmdMatch != nil {
				cmd = strings.TrimSpace(cmdMatch[1])
			}

			// Create a unique key to avoid duplicates
			entryKey := user + ":" + cmd
			if !seen[entryKey] {
				seen[entryKey] = true
				results = append(results, SudoEntry{
					User:        user,
					Command:     cmd,
					Nopasswd:    true,
					NegatedRoot: negatedRoot,
				})
			}
		}
	}

	return results
}

type suidSgidResults struct {
	suid []string
	sgid []string
}

func (p *ReconParser) parseSuidSgid(output string) suidSgidResults {
	suid := []string{}
	sgid := []string{}

	lines := strings.Split(output, "\n")
	inSGID := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Switch to SGID subsection
		if line == "SGID binaries:" {
			inSGID = true
			continue
		}
		if line == "SUID binaries:" {
			inSGID = false
			continue
		}

		// First, try to match ls -l style output with SUID bit (-rws)
		if strings.Contains(line, "-rws") {
			match := reSuidPath.FindString(line)
			if match != "" {
				if inSGID {
					sgid = append(sgid, match)
				} else {
					suid = append(suid, match)
				}
				continue
			}
		}

		// Check for SGID in ls -l style (s in group execute position)
		if strings.Contains(line, "r-x") || strings.Contains(line, "rwx") {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				perms := parts[0]
				if len(perms) >= 6 && perms[5] == 's' { // Group execute position
					match := reSuidPath.FindString(line)
					if match != "" {
						sgid = append(sgid, match)
						continue
					}
				}
			}
		}

		// If not ls -l style, treat any clean absolute path as find(1) output.
		// find already guarantees these are SUID/SGID files; don't filter by location
		// or we miss custom binaries in /opt, /home, /app, etc.
		if strings.HasPrefix(line, "/") && reSuidLine.MatchString(line) {
			if inSGID {
				sgid = append(sgid, line)
			} else {
				suid = append(suid, line)
			}
		}
	}

	return suidSgidResults{suid: suid, sgid: sgid}
}

func (p *ReconParser) parseCapabilities(output string) []CapabilityEntry {
	capabilities := []CapabilityEntry{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Pattern: /path/to/file cap_name=value
		match := reCapability.FindStringSubmatch(line)
		if match != nil {
			value := "set"
			if len(match) > 3 && match[3] != "" {
				value = match[3]
			}
			capabilities = append(capabilities, CapabilityEntry{
				File:       match[1],
				Capability: match[2],
				Value:      value,
			})
		}
	}

	return capabilities
}

func (p *ReconParser) parseWritableCrons(output string) []string {
	writable := []string{}

	// Only match lines that are preceded by the literal string "Writable:"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Writable:") {
			// Extract the path after "Writable:"
			match := reWritableCron.FindStringSubmatch(line)
			if match != nil {
				writable = append(writable, match[1])
			}
		}
	}

	return writable
}

func (p *ReconParser) parseToolsAvailable(output string) []string {
	tools := []string{}
	toolNames := map[string]bool{
		"python":  true,
		"python3": true,
		"perl":    true,
		"ruby":    true,
		"php":     true,
		"nc":      true,
		"ncat":    true,
		"netcat":  true,
		"socat":   true,
		"wget":    true,
		"curl":    true,
		"bash":    true,
		"zsh":     true,
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "/") {
			continue
		}
		// Extract just the binary name from the path
		binary := line
		lastSlash := strings.LastIndex(line, "/")
		if lastSlash >= 0 {
			binary = line[lastSlash+1:]
		}
		binary = strings.TrimSpace(binary)
		if toolNames[binary] {
			// Avoid duplicates
			found := false
			for _, t := range tools {
				if t == binary {
					found = true
					break
				}
			}
			if !found {
				tools = append(tools, binary)
			}
		}
	}

	return tools
}

func (p *ReconParser) parseInterestingFiles(output string) []string {
	interesting := []string{}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "/") && (strings.Contains(line, "id_rsa") || strings.Contains(line, ".ssh") || strings.Contains(strings.ToLower(line), "password")) {
			interesting = append(interesting, line)
		}
	}

	return interesting
}

func (p *ReconParser) parseAWSCredentials(output string) bool {
	return strings.Contains(output, "AWS credentials found:")
}

func (p *ReconParser) parseMySQLConfig(output string) bool {
	return strings.Contains(output, "MySQL config found:")
}

type containerDetectionResult struct {
	detected      bool
	containerType *string
}

func (p *ReconParser) parseContainerDetection(output string) containerDetectionResult {
	result := containerDetectionResult{detected: false, containerType: nil}

	// Check for Docker indicators
	if strings.Contains(output, ".dockerenv") || strings.Contains(output, "/.dockerenv") {
		result.detected = true
		result.containerType = stringPtr("docker")
	}

	// Check for LXC
	if strings.Contains(strings.ToLower(output), "lxc") {
		if strings.Contains(output, "/proc/1/cgroup") {
			if strings.Contains(strings.ToLower(output), "container=lxc") || strings.Contains(strings.ToLower(output), "lxc/container") {
				result.detected = true
				result.containerType = stringPtr("lxc")
			}
		}
	}

	// Check for QEMU/KVM
	if strings.Contains(strings.ToLower(output), "qemu") {
		if strings.Contains(strings.ToLower(output), "hypervisor") || strings.Contains(strings.ToLower(output), "processor") {
			result.detected = true
			result.containerType = stringPtr("qemu")
		}
	}

	// Docker environment detection
	if strings.Contains(output, "Docker environment detected") {
		result.detected = true
		result.containerType = stringPtr("docker")
	}

	return result
}

type dockerSocketDetectionResult struct {
	socketPath       *string
	socketAccessible bool
}

func (p *ReconParser) parseDockerSocketDetection(output string) dockerSocketDetectionResult {
	result := dockerSocketDetectionResult{socketPath: nil, socketAccessible: false}

	// Check for Docker socket paths - only if file exists (not "not found")
	if strings.Contains(output, "/var/run/docker.sock") && !strings.Contains(output, "/var/run/docker.sock not found") {
		result.socketPath = stringPtr("/var/run/docker.sock")
	}

	if strings.Contains(output, "/run/docker.sock") && !strings.Contains(output, "/run/docker.sock not found") {
		result.socketPath = stringPtr("/run/docker.sock")
	}

	// Check if socket is accessible
	if strings.Contains(output, "Docker socket exists and is accessible") {
		result.socketAccessible = true
	}

	return result
}

func (p *ReconParser) parseServiceVersions(output string) ServiceVersions {
	result := ServiceVersions{
		Apache:       nil,
		Nginx:        nil,
		PHP:          nil,
		Python:       nil,
		Node:         nil,
		Docker:       nil,
		MySQL:        nil,
		Postgres:     nil,
		GitLabRunner: nil,
	}

	// Parse Apache version
	if match := reApache.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.Apache = &v
	}

	// Parse Nginx version
	if match := reNginx.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.Nginx = &v
	}

	// Parse PHP version
	if match := rePHP.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.PHP = &v
	}

	// Parse Python version
	if match := rePython.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.Python = &v
	}

	// Parse Node.js version
	if match := reNode.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.Node = &v
	}

	// Parse Docker version
	if match := reDocker.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.Docker = &v
	}

	// Parse MySQL version
	if match := reMySQL.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.MySQL = &v
	}

	// Parse PostgreSQL version
	if match := rePsql.FindStringSubmatch(output); match != nil {
		v := match[1]
		result.Postgres = &v
	}

	// Parse GitLab Runner token
	if strings.Contains(output, "GitLab runner token") {
		if match := reGitLabToken.FindStringSubmatch(output); match != nil {
			v := match[1]
			result.GitLabRunner = &v
		}
	}

	return result
}

type identityInfo struct {
	hostname      *string
	user          *string
	uid           *string
	os            *string
	kernelVersion *string
}

func (p *ReconParser) parseIdentity(output string) identityInfo {
	result := identityInfo{
		hostname:      nil,
		user:          nil,
		uid:           nil,
		os:            nil,
		kernelVersion: nil,
	}

	// Extract hostname
	if match := reHostname.FindStringSubmatch(output); match != nil {
		result.hostname = stringPtr(match[1])
	}

	// Extract user
	if match := reUser.FindStringSubmatch(output); match != nil {
		result.user = stringPtr(match[1])
	}

	// Extract uid (from id command output like "uid=1000(user) gid=...")
	if match := reUID.FindStringSubmatch(output); match != nil {
		result.uid = stringPtr(match[1])
	}

	// Extract OS info from "OS Info:" line
	// The [^$] guard prevents capturing PS2 echo-back of unexpanded shell variables
	if match := reOSInfo.FindStringSubmatch(output); match != nil {
		result.os = stringPtr(strings.TrimSpace(match[1]))
	} else {
		// Fallback: try to extract from other patterns
		osMatch := reOSDistro.FindStringSubmatch(output)
		if osMatch != nil {
			result.os = stringPtr(strings.TrimSpace(osMatch[0]))
		} else {
			// Check for macOS
			if strings.Contains(output, "macOS") {
				result.os = stringPtr("macOS")
			}
		}
	}

	// Extract kernel version from "Kernel Version:" line
	if match := reKernelVersion.FindStringSubmatch(output); match != nil {
		result.kernelVersion = stringPtr(strings.TrimSpace(match[1]))
	}

	return result
}

func (p *ReconParser) checkCVECandidates(f *Findings, sections map[string]string) []CveCandidate {
	candidates := []CveCandidate{}

	sudoOutput := sections["SUDO ACCESS"]
	suidOutput := sections["SUID/SGID BINARIES"]
	capOutput := sections["CAPABILITIES"]
	envOutput := sections["ENVIRONMENT & TOOLS"]

	// Extract sudo version if present.
	// Regex captures: major, minor, patch (optional), pnum (optional).
	// e.g. "1.9.5p2" → major=1, minor=9, patch=5, pnum=2
	var sudoVersion *struct{ major, minor, patch, pnum int }
	versionMatch := reSudoVersion.FindStringSubmatch(sudoOutput)
	if versionMatch != nil {
		major, _ := stringToInt(versionMatch[1])
		minor, _ := stringToInt(versionMatch[2])
		patch := 0
		pnum := 0
		if len(versionMatch) > 3 && versionMatch[3] != "" {
			patch, _ = stringToInt(versionMatch[3])
		}
		if len(versionMatch) > 4 && versionMatch[4] != "" {
			pnum, _ = stringToInt(versionMatch[4])
		}
		sudoVersion = &struct{ major, minor, patch, pnum int }{major, minor, patch, pnum}
	}

	// CVE-2021-4034 (PwnKit) — version-aware: only flag when pkexec is SUID and
	// polkit is not confirmed patched. Presence of pkexec in SUID alone is not
	// enough — pkexec is always SUID when polkit is installed.
	if strings.Contains(suidOutput, "pkexec") {
		pv := parsePolkitInfo(capOutput)
		if !pv.isPatched {
			confidence := "low"
			evidence := "pkexec in SUID binaries (polkit version not detected)"
			if pv.havePackageVersion {
				confidence = "high"
				evidence = fmt.Sprintf("pkexec in SUID, polkit %s (confirmed not patched)", pv.versionStr)
			} else if pv.versionStr != "" {
				evidence = fmt.Sprintf("pkexec in SUID, pkexec %s (package version not detected)", pv.versionStr)
			}
			candidates = append(candidates, CveCandidate{
				CVE:         "CVE-2021-4034",
				Name:        "PwnKit",
				Description: "Local privilege escalation in pkexec",
				Severity:    "critical",
				Evidence:    evidence,
				Confidence:  confidence,
			})
		}
	}

	// CVE-2021-3156 (Baron Samedit) - Sudo heap buffer overflow
	// Vulnerable: sudo < 1.9.5p2
	// Skip entirely when sudo requires a password — we can't enumerate version or
	// run sudo commands, so the finding has no actionable value for this session.
	if strings.Contains(sudoOutput, "sudo") && !f.SudoRequiresPassword {
		if sudoVersion != nil {
			v := sudoVersion
			if versionBefore(v.major, v.minor, v.patch, v.pnum, 1, 9, 5, 2) {
				candidates = append(candidates, CveCandidate{
					CVE:         "CVE-2021-3156",
					Name:        "Baron Samedit",
					Description: "Sudo heap-based buffer overflow",
					Severity:    "high",
					Evidence:    fmt.Sprintf("sudo %d.%d.%d p%d", v.major, v.minor, v.patch, v.pnum),
					Confidence:  "high",
				})
			}
		} else {
			candidates = append(candidates, CveCandidate{
				CVE:         "CVE-2021-3156",
				Name:        "Baron Samedit",
				Description: "Sudo heap-based buffer overflow (potential)",
				Severity:    "high",
				Evidence:    "sudo command available (version unknown)",
				Confidence:  "low",
			})
		}
	}

	// CVE-2019-14287 - Sudo NOPASSWD bypass via integer overflow
	hasNegatedRoot := false
	for _, entry := range f.SudoNopasswd {
		if entry.NegatedRoot {
			hasNegatedRoot = true
			break
		}
	}

	if hasNegatedRoot {
		if sudoVersion != nil {
			v := sudoVersion
			// Vulnerable: < 1.8.28 (no p-number requirement)
			if versionBefore(v.major, v.minor, v.patch, v.pnum, 1, 8, 28, 0) {
				candidates = append(candidates, CveCandidate{
					CVE:         "CVE-2019-14287",
					Name:        "Sudo Integer Overflow (Bypass !root)",
					Description: "Sudo version < 1.8.28 with (ALL, !root) NOPASSWD rule",
					Severity:    "critical",
					Evidence:    fmt.Sprintf("sudo %d.%d.%d p%d with (ALL, !root) rule found", v.major, v.minor, v.patch, v.pnum),
					Confidence:  "high",
				})
			} else {
				candidates = append(candidates, CveCandidate{
					CVE:         "CVE-2019-14287",
					Name:        "Sudo Integer Overflow (Patched)",
					Description: "(ALL, !root) NOPASSWD rule exists but sudo >= 1.8.28",
					Severity:    "medium",
					Evidence:    fmt.Sprintf("sudo %d.%d.%d p%d with (ALL, !root) rule found (patched)", v.major, v.minor, v.patch, v.pnum),
					Confidence:  "medium",
				})
			}
		} else {
			candidates = append(candidates, CveCandidate{
				CVE:         "CVE-2019-14287",
				Name:        "Sudo Integer Overflow (Potential)",
				Description: "(ALL, !root) NOPASSWD rule found - version check needed",
				Severity:    "critical",
				Evidence:    "(ALL, !root) NOPASSWD rule found (sudo version unknown)",
				Confidence:  "low",
			})
		}
	} else if len(f.SudoNopasswd) > 0 {
		// Generic NOPASSWD found (not the CVE-2019-14287 pattern)
		cve := "CVE-2019-14287"
		name := "Sudo NOPASSWD Configuration"
		candidates = append(candidates, CveCandidate{
			CVE:         cve,
			Name:        name,
			Description: "Sudo NOPASSWD rule found (not the CVE-2019-14287 pattern)",
			Severity:    "high",
			Evidence:    fmt.Sprintf("NOPASSWD entries found: %d", len(f.SudoNopasswd)),
			Confidence:  "high",
		})
	}

	// GitLab Runner token detection
	if f.ServiceVersions.GitLabRunner != nil {
		cve := "GITLAB-CONFIG"
		name := "GitLab Runner Token"
		candidates = append(candidates, CveCandidate{
			CVE:         cve,
			Name:        name,
			Description: "GitLab Runner configuration accessible",
			Severity:    "high",
			Evidence:    "GitLab Runner service detected",
			Confidence:  "high",
		})
	}

	// Kubernetes kubectl token detection
	for _, tool := range f.ToolsAvailable {
		if tool == "kubectl" {
			cve := "KUBERNETES-TOKEN"
			name := "Kubernetes Service Account Token"
			candidates = append(candidates, CveCandidate{
				CVE:         cve,
				Name:        name,
				Description: "Kubectl available - service account token may be accessible",
				Severity:    "high",
				Evidence:    "kubectl command available",
				Confidence:  "medium",
				Tags:        []string{"kubernetes"},
			})
			break
		}
	}

	// Capabilities detection for CAP_SETUID escalation
	hasCapSetuid := false
	for _, cap := range f.Capabilities {
		if strings.Contains(strings.ToLower(cap.Capability), "setuid") {
			hasCapSetuid = true
			break
		}
	}
	if hasCapSetuid {
		cve := "CAP_SETUID"
		name := "CAP_SETUID Capability"
		candidates = append(candidates, CveCandidate{
			CVE:         cve,
			Name:        name,
			Description: "CAP_SETUID capability allows privilege escalation",
			Severity:    "high",
			Evidence:    "CAP_SETUID capability found",
			Confidence:  "high",
		})
	}

	// Writable /etc/passwd detection — only trigger if /etc/passwd literally appears
	// in the writable files output, not from "Passwords in files" grep results.
	writableOutput := sections["WRITABLE PATHS"]
	if strings.Contains(writableOutput, "/etc/passwd") {
		cve := "WRT-PASSWD"
		name := "Writable /etc/passwd"
		candidates = append(candidates, CveCandidate{
			CVE:         cve,
			Name:        name,
			Description: "Writable /etc/passwd allows user creation with root privileges",
			Severity:    "critical",
			Evidence:    "/etc/passwd writable by current user",
			Confidence:  "high",
		})
	}

	// Environment variable secrets detection — populate both EnvSecrets and CveCandidates.
	envOutputLines := strings.Split(envOutput, "\n")
	secretPatterns := []string{"password", "secret", "token", "api_key", "apikey", "access_key", "passwd"}
	for _, pattern := range secretPatterns {
		for _, line := range envOutputLines {
			if strings.Contains(strings.ToLower(line), pattern) && strings.Contains(line, "=") {
				f.EnvSecrets = append(f.EnvSecrets, strings.TrimSpace(line))
				candidates = append(candidates, CveCandidate{
					CVE:         "ENV-SECRET",
					Name:        "Environment Variable Secret",
					Description: "Sensitive credential in environment variables",
					Severity:    "high",
					Evidence:    fmt.Sprintf("Secret found: %s", truncate(line, 50)),
					Confidence:  "high",
				})
				break
			}
		}
	}

	return candidates
}

// polkitInfo holds the result of polkit version detection from the CAPABILITIES section.
type polkitInfo struct {
	havePackageVersion bool   // true when dpkg or rpm package version was detected
	isPatched          bool   // true when version is confirmed patched for CVE-2021-4034
	versionStr         string // human-readable version string; empty if undetected
}

// parsePolkitInfo extracts polkit version details from the CAPABILITIES section output.
// Priority: dpkg (most precise, includes Debian revision) → rpm → pkexec --version.
//
// Patch thresholds for CVE-2021-4034:
//   - Debian/Ubuntu: polkit >= 0.105-33 is patched
//   - Fedora:        polkit >= 0.117-2   is patched
//   - Upstream:      polkit >= 0.120     is patched (upstream fix)
func parsePolkitInfo(output string) polkitInfo {
	buildVS := func(major, minor, patch int, hasPatch bool, rev int, hasRev bool) string {
		vs := fmt.Sprintf("%d.%d", major, minor)
		if hasPatch {
			vs = fmt.Sprintf("%d.%d.%d", major, minor, patch)
		}
		if hasRev {
			vs += fmt.Sprintf("-%d", rev)
		}
		return vs
	}

	// 1. dpkg: "polkit-pkg: polkit 0.105-33"
	if m := rePolkitDeb.FindStringSubmatch(output); m != nil {
		major, _ := stringToInt(m[1])
		minor, _ := stringToInt(m[2])
		patch, hasPatch := 0, m[3] != ""
		if hasPatch {
			patch, _ = stringToInt(m[3])
		}
		rev, _ := stringToInt(m[4])
		patched := !versionBefore(major, minor, patch, 0, 0, 120, 0, 0) ||
			(major == 0 && minor == 105 && !hasPatch && rev >= 33)
		return polkitInfo{
			havePackageVersion: true,
			isPatched:          patched,
			versionStr:         buildVS(major, minor, patch, hasPatch, rev, true),
		}
	}

	// 2. rpm: "polkit-0.117-2.fc33.x86_64"
	if m := rePolkitRpm.FindStringSubmatch(output); m != nil {
		major, _ := stringToInt(m[1])
		minor, _ := stringToInt(m[2])
		patch, hasPatch := 0, m[3] != ""
		if hasPatch {
			patch, _ = stringToInt(m[3])
		}
		rev, _ := stringToInt(m[4])
		patched := !versionBefore(major, minor, patch, 0, 0, 120, 0, 0) ||
			(major == 0 && minor == 117 && !hasPatch && rev >= 2)
		return polkitInfo{
			havePackageVersion: true,
			isPatched:          patched,
			versionStr:         buildVS(major, minor, patch, hasPatch, rev, true),
		}
	}

	// 3. pkexec --version: "pkexec version 0.105" — no revision, can only check upstream
	if m := rePolkitExec.FindStringSubmatch(output); m != nil {
		major, _ := stringToInt(m[1])
		minor, _ := stringToInt(m[2])
		patch, hasPatch := 0, m[3] != ""
		if hasPatch {
			patch, _ = stringToInt(m[3])
		}
		// Upstream >= 0.120 is definitively patched; earlier versions may have
		// distro backports we can't detect without the package revision.
		patched := !versionBefore(major, minor, patch, 0, 0, 120, 0, 0)
		return polkitInfo{
			havePackageVersion: false,
			isPatched:          patched,
			versionStr:         buildVS(major, minor, patch, hasPatch, 0, false),
		}
	}

	return polkitInfo{} // version undetected
}

// versionBefore reports whether version (maj, min, pat, pnum) is strictly
// less than the target version (tMaj, tMin, tPat, tPnum).
// Used for sudo, polkit, and any other 4-component version comparisons.
func versionBefore(maj, min, pat, pnum, tMaj, tMin, tPat, tPnum int) bool {
	switch {
	case maj != tMaj:
		return maj < tMaj
	case min != tMin:
		return min < tMin
	case pat != tPat:
		return pat < tPat
	default:
		return pnum < tPnum
	}
}

func stringPtr(s string) *string {
	return &s
}

func stringToInt(s string) (int, bool) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err == nil
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}

