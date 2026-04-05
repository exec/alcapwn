package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Each file under data/entries/**/*.json is a single DatasetEntry object.
// Subdirectory names are cosmetic (suid_gtfobins/, sudo_nopasswd/, etc.) and
// do not affect parsing — category comes from the entry's "category" field.
//
//go:embed data/entries
var entriesFS embed.FS

var (
	datasetOnce    sync.Once
	datasetEntries []DatasetEntry
)

func getDataset() []DatasetEntry {
	datasetOnce.Do(func() {
		var entries []DatasetEntry
		err := fs.WalkDir(entriesFS, "data/entries", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
				return err
			}
			data, err := entriesFS.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			var entry DatasetEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			entries = append(entries, entry)
			return nil
		})
		if err != nil {
			panic("failed to load dataset entries: " + err.Error())
		}
		datasetEntries = entries
	})
	return datasetEntries
}

func indexDatasetByCategory(dataset []DatasetEntry) map[string][]DatasetEntry {
	indexed := make(map[string][]DatasetEntry)
	for _, entry := range dataset {
		indexed[entry.Category] = append(indexed[entry.Category], entry)
	}
	return indexed
}

func pathsMatch(path1, path2 string) bool {
	if path1 == "" || path2 == "" {
		return false
	}
	if path1 == path2 {
		return true
	}
	// Basename match only if at least one is a bare name (no directory component)
	b1, b2 := filepath.Base(path1), filepath.Base(path2)
	if b1 == path1 || b2 == path2 {
		return b1 == b2
	}
	return false
}

func createMatch(entry DatasetEntry, confidence, reason, binaryPath string) MatchResult {
	result := MatchResult{
		Entry:             entry,
		MatchConfidence:   confidence,
		MatchReason:       reason,
		MatchedBinaryPath: binaryPath,
	}
	if entry.Severity == nil {
		sev := confidence
		if sev != "medium" && sev != "low" {
			sev = "high"
		}
		result.Entry.Severity = &sev
	}
	return result
}

func matchFindings(f *Findings) []MatchResult {
	indexed := indexDatasetByCategory(getDataset())
	matches := make([]MatchResult, 0)

	// Track matched paths to avoid duplicates
	matchedPaths := make(map[string]bool)

	// Pre-load category entries
	sudoRuleCVE := indexed["SUDO_RULE_CVE"]
	sudoNOPASSWDCustom := indexed["SUDO_NOPASSWD_CUSTOM"]
	sudoNOPASSWDDirect := indexed["SUDO_NOPASSWD_DIRECT"]
	suidGTFOBINS := indexed["SUID_GTFOBINS"]
	suidCustom := indexed["SUID_CUSTOM"]
	writableCron := indexed["WRITABLE_CRON"]
	capabilitySetuid := indexed["CAPABILITY_SETUID"]
	other := indexed["OTHER"]

	// 1. Check for CVE-2019-14287 (sudo -u#-1 bypass)
	if len(f.SudoNopasswd) > 0 {
		hasNegatedRoot := false
		for _, entry := range f.SudoNopasswd {
			if entry.NegatedRoot {
				hasNegatedRoot = true
				break
			}
		}
		if hasNegatedRoot {
			for _, entry := range sudoRuleCVE {
				if entry.CVE != nil && *entry.CVE == "CVE-2019-14287" {
					matches = append(matches, createMatch(entry, "high", "Found (ALL, !root) sudo rule with sudo -u#-1 bypass", "sudo"))
					matchedPaths["cve-2019-14287"] = true
					break
				}
			}
		}
	}

	// 2. Match constrained sudo commands to SUDO_NOPASSWD_CUSTOM
	if len(f.SudoNopasswd) > 0 {
		for _, entry := range sudoNOPASSWDCustom {
			entryBinary := entry.Binary
			if entryBinary == nil {
				continue
			}
			for _, sudoEntry := range f.SudoNopasswd {
				cmd := sudoEntry.Command
				if pathsMatch(cmd, *entryBinary) {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Constrained NOPASSWD: %s matches SUDO_NOPASSWD_CUSTOM", cmd), cmd))
					matchedPaths[fmt.Sprintf("custom-%s", cmd)] = true
					break
				}
			}
		}
	}

	// 3. Match generic ALL NOPASSWD to SUDO_NOPASSWD_DIRECT
	if len(f.SudoNopasswd) > 0 {
		hasAll := false
		for _, entry := range f.SudoNopasswd {
			if entry.Command == "ALL" {
				hasAll = true
				break
			}
		}
		if hasAll {
			for _, entry := range sudoNOPASSWDDirect {
				matches = append(matches, createMatch(entry, "high", "NOPASSWD: ALL rule found", ""))
				matchedPaths["nopasswd-all"] = true
				break
			}
		}
	}

	// 4. Match SUID binaries to SUID_GTFOBINS
	if len(f.SuidBinaries) > 0 {
		for _, entry := range suidGTFOBINS {
			entryBinary := entry.Binary
			if entryBinary == nil {
				continue
			}
			for _, suidBinary := range f.SuidBinaries {
				if pathsMatch(suidBinary, *entryBinary) {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("SUID binary %s matches GTFOBins entry", suidBinary), suidBinary))
					matchedPaths[fmt.Sprintf("suid-%s", *entryBinary)] = true
					break
				}
			}
		}
	}

	// 4b. Match SUID binaries to SUID_CUSTOM
	if len(f.SuidBinaries) > 0 {
		for _, entry := range suidCustom {
			entryBinary := entry.Binary
			if entryBinary == nil {
				continue
			}
			for _, suidBinary := range f.SuidBinaries {
				if pathsMatch(suidBinary, *entryBinary) {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("SUID binary %s matches custom SUID entry", suidBinary), suidBinary))
					matchedPaths[fmt.Sprintf("suid-custom-%s", *entryBinary)] = true
					break
				}
			}
		}
	}

	// 5. Match CVE candidates to SUDO_RULE_CVE and OTHER
	if len(f.CveCandidates) > 0 {
		// Only high/critical confidence CVEs
		for _, cve := range f.CveCandidates {
			if cve.Confidence != "high" && cve.Confidence != "critical" {
				continue
			}
			cveID := cve.CVE
			// Skip if already matched
			if matchedPaths[fmt.Sprintf("cve-%s", cveID)] {
				continue
			}
			for _, entry := range sudoRuleCVE {
				if entry.CVE != nil && *entry.CVE == cveID {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("High confidence CVE candidate: %s", cveID), ""))
					matchedPaths[fmt.Sprintf("cve-%s", cveID)] = true
					break
				}
			}
		}

		// Check other CVE candidates not in SUDO_RULE_CVE
		for _, cve := range f.CveCandidates {
			if cve.Confidence != "high" && cve.Confidence != "critical" {
				continue
			}
			cveID := cve.CVE
			if matchedPaths[fmt.Sprintf("cve-%s", cveID)] {
				continue
			}
			for _, entry := range other {
				if entry.CVE != nil && *entry.CVE == cveID {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("High confidence CVE candidate: %s", cveID), ""))
					matchedPaths[fmt.Sprintf("cve-%s", cveID)] = true
					break
				}
			}
		}
	}

	// 5b. Match writable cron scripts
	if len(f.WritableCrons) > 0 {
		for _, scriptPath := range f.WritableCrons {
			matched := false
			for _, entry := range writableCron {
				entryBinary := entry.Binary
				if entryBinary != nil && *entryBinary != "" && filepath.Base(scriptPath) == *entryBinary {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Writable cron script %s matches %s", scriptPath, *entryBinary), scriptPath))
					matchedPaths[fmt.Sprintf("writable-cron-%s", *entryBinary)] = true
					matched = true
					break
				}
			}
			if !matched {
				// No specific dataset entry for this cron file — any writable cron
				// is exploitable regardless of its name, so emit a generic match.
				base := filepath.Base(scriptPath)
				sev := "high"
				matches = append(matches, MatchResult{
					Entry: DatasetEntry{
						ID:           "writable_cron_generic",
						Category:     "WRITABLE_CRON",
						Binary:       &base,
						Exploitation: []string{"Append a reverse shell or command to the writable cron file"},
						Source:       "generic",
						Tags:         []string{"cron", "writable"},
						Severity:     &sev,
					},
					MatchConfidence: "high",
					MatchReason:        fmt.Sprintf("Writable cron file (no specific dataset entry): %s", scriptPath),
				MatchedBinaryPath: scriptPath,
				})
				matchedPaths[fmt.Sprintf("writable-cron-generic-%s", scriptPath)] = true
			}
		}
	}

	// 6. Match capabilities to CAPABILITY_SETUID — match by binary file name if possible.
	if len(f.Capabilities) > 0 {
		for _, cap := range f.Capabilities {
			for _, entry := range capabilitySetuid {
				if entry.Binary != nil && pathsMatch(cap.File, *entry.Binary) {
					key := fmt.Sprintf("cap-%s", cap.File)
					if !matchedPaths[key] {
						matches = append(matches, createMatch(entry, "high", fmt.Sprintf("cap_setuid on %s", cap.File), cap.File))
						matchedPaths[key] = true
					}
				}
			}
		}
	}

	// 7a. Docker socket escape — requires only DockerSocketAccessible.
	// ContainerDetected is NOT required: a host machine with an exposed docker
	// socket is just as exploitable as one inside a container.
	if f.DockerSocketAccessible {
		for _, entry := range other {
			if hasTagStr(entry.Tags, "docker") || hasTagStr(entry.Tags, "container") {
				socketPath := "unknown"
				if f.DockerSocket != nil {
					socketPath = *f.DockerSocket
				}
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Docker escape via accessible socket: %s", socketPath), "docker"))
				matchedPaths["docker-escape"] = true
				break
			}
		}
	}

	// 7b. QEMU/KVM escape — requires ContainerDetected with QEMU virtualization type.
	if f.ContainerDetected && f.VirtualizationType != nil {
		vt := *f.VirtualizationType
		if vt == "qemu" || vt == "QEMU" {
			for _, entry := range other {
				if hasTagStr(entry.Tags, "qemu") || hasTagStr(entry.Tags, "kvm") {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("QEMU/KVM escape: %s", vt), ""))
					matchedPaths["qemu-escape"] = true
					break
				}
			}
		}
	}

	// 7c. Match OTHER entries for GitLab Runner, kubectl, writable passwd, SSH keys, etc.
	matchedTags := make(map[string]bool)
	for _, entry := range other {
		tags := entry.Tags

		// GitLab Runner match
		if !matchedTags["gitlab"] && (hasTagStr(tags, "gitlab") || hasTagStr(tags, "ci-cd")) {
			if f.ServiceVersions.GitLabRunner != nil {
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("GitLab Runner token accessible: %s", *f.ServiceVersions.GitLabRunner), ""))
				matchedPaths["gitlab-runner"] = true
				matchedTags["gitlab"] = true
			}
		}

		// Kubernetes kubectl match
		if !matchedTags["kubernetes"] && hasTagStr(tags, "kubernetes") {
			for _, tool := range f.ToolsAvailable {
				if tool == "kubectl" {
					matches = append(matches, createMatch(entry, "medium", "Kubernetes kubectl available - service account token may be accessible", "kubectl"))
					matchedPaths["kubernetes-token"] = true
					matchedTags["kubernetes"] = true
					break
				}
			}
		}

		// Writable passwd match
		if !matchedTags["passwd"] && hasTagStr(tags, "passwd") {
			for _, cve := range f.CveCandidates {
				if cve.CVE == "WRT-PASSWD" {
					matches = append(matches, createMatch(entry, "critical", "Writable /etc/passwd detected - potential for user creation with root privileges", "/etc/passwd"))
					matchedPaths["writable-passwd"] = true
					matchedTags["passwd"] = true
					break
				}
			}
		}

		// SSH key leak match
		if !matchedTags["ssh"] && hasTagStr(tags, "ssh") {
			if f.SSHKeyFound != nil {
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("SSH private key found: %s", *f.SSHKeyFound), *f.SSHKeyFound))
				matchedPaths["ssh-key"] = true
				matchedTags["ssh"] = true
			}
		}

		// Environment secrets match
		if !matchedTags["env"] && hasTagStr(tags, "env") {
			if len(f.EnvSecrets) > 0 {
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Environment variable secrets found: %d entries", len(f.EnvSecrets)), ""))
				matchedPaths["env-secrets"] = true
				matchedTags["env"] = true
			}
		}

		// AWS credentials match
		if !matchedTags["aws"] && hasTagStr(tags, "aws") {
			if f.AWSCredentialsFound {
				matches = append(matches, createMatch(entry, "high", "AWS credentials file accessible", ""))
				matchedPaths["aws-creds"] = true
				matchedTags["aws"] = true
			}
		}

		// MySQL config match
		if !matchedTags["mysql"] && hasTagStr(tags, "mysql") {
			if f.MySQLConfigFound {
				matches = append(matches, createMatch(entry, "high", "MySQL credentials found in config", ""))
				matchedPaths["mysql-creds"] = true
				matchedTags["mysql"] = true
			}
		}

		// Docker Compose match
		if !matchedTags["compose"] && hasTagStr(tags, "compose") {
			for _, file := range f.InterestingFiles {
				if filepath.Base(file) == "docker-compose.yml" || filepath.Base(file) == "compose.yml" {
					matches = append(matches, createMatch(entry, "high", "Docker Compose file with secrets found", file))
					matchedPaths["docker-compose"] = true
					matchedTags["compose"] = true
					break
				}
			}
		}
	}

	// 8. Windows privilege escalation matches (agent sessions with Win recon).
	if len(f.WinPrivileges) > 0 || f.WinAlwaysInstallElevated || f.WinIsAdmin {
		winTokenPriv := indexed["WIN_TOKEN_PRIV"]
		winAIE := indexed["WIN_ALWAYS_INSTALL_ELEVATED"]

		// SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege → potato exploits.
		hasSeImpersonate := false
		for _, priv := range f.WinPrivileges {
			lower := strings.ToLower(priv)
			if strings.Contains(lower, "impersonate") || strings.Contains(lower, "assignprimarytoken") {
				hasSeImpersonate = true
				break
			}
		}
		if hasSeImpersonate && !matchedPaths["win-token-priv"] {
			for _, entry := range winTokenPriv {
				matches = append(matches, createMatch(entry, "high", "SeImpersonatePrivilege (or SeAssignPrimaryTokenPrivilege) found — potato attacks applicable", ""))
			}
			matchedPaths["win-token-priv"] = true
		}

		// AlwaysInstallElevated registry keys.
		if f.WinAlwaysInstallElevated && !matchedPaths["win-aie"] {
			for _, entry := range winAIE {
				matches = append(matches, createMatch(entry, "high", "AlwaysInstallElevated registry keys set — MSI privesc applicable", ""))
			}
			matchedPaths["win-aie"] = true
		}
	}

	// Sort by confidence (critical, high > medium > low), then by severity
	confidenceOrder := map[string]int{"critical": 0, "high": 0, "medium": 1, "low": 2}
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

	for i := range matches {
		if matches[i].Entry.Severity == nil {
			sev := "low"
			matches[i].Entry.Severity = &sev
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		ci := confidenceOrder[matches[i].MatchConfidence]
		cj := confidenceOrder[matches[j].MatchConfidence]
		if ci != cj {
			return ci < cj
		}
		si, sj := 0, 0
		if matches[i].Entry.Severity != nil {
			si = severityOrder[*matches[i].Entry.Severity]
		}
		if matches[j].Entry.Severity != nil {
			sj = severityOrder[*matches[j].Entry.Severity]
		}
		return si < sj
	})

	return matches
}

func hasTagStr(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
