package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"

	_ "embed"
)

//go:embed data/privesc_dataset.json
var datasetJSON []byte

var (
	datasetOnce    sync.Once
	datasetEntries []DatasetEntry
)

func getDataset() []DatasetEntry {
	datasetOnce.Do(func() {
		var ds Dataset
		if err := json.Unmarshal(datasetJSON, &ds); err != nil {
			panic("failed to parse embedded dataset: " + err.Error())
		}
		datasetEntries = ds.Entries
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
	if filepath.Base(path1) == filepath.Base(path2) {
		return true
	}
	return path1 == path2
}

func createMatch(entry DatasetEntry, confidence, reason string) MatchResult {
	result := MatchResult{
		Entry:           entry,
		MatchConfidence: confidence,
		MatchReason:     reason,
	}
	if entry.Severity == nil {
		sev := "high"
		if confidence == "medium" {
			sev = "medium"
		}
		if confidence == "low" {
			sev = "low"
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
					matches = append(matches, createMatch(entry, "high", "Found (ALL, !root) sudo rule with sudo -u#-1 bypass"))
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
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Constrained NOPASSWD: %s matches SUDO_NOPASSWD_CUSTOM", cmd)))
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
				matches = append(matches, createMatch(entry, "high", "NOPASSWD: ALL rule found"))
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
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("SUID binary %s matches GTFOBins entry", suidBinary)))
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
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("SUID binary %s matches custom SUID entry", suidBinary)))
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
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("High confidence CVE candidate: %s", cveID)))
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
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("High confidence CVE candidate: %s", cveID)))
					matchedPaths[fmt.Sprintf("cve-%s", cveID)] = true
					break
				}
			}
		}
	}

	// 5b. Match writable cron scripts
	if len(f.WritableCrons) > 0 && len(writableCron) > 0 {
		for _, scriptPath := range f.WritableCrons {
			for _, entry := range writableCron {
				entryBinary := entry.Binary
				if entryBinary != nil && *entryBinary != "" && filepath.Base(scriptPath) == *entryBinary {
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Writable cron script %s matches %s", scriptPath, *entryBinary)))
					matchedPaths[fmt.Sprintf("writable-cron-%s", *entryBinary)] = true
					break
				}
			}
		}
	}

	// 6. Match capabilities to CAPABILITY_SETUID
	if len(f.Capabilities) > 0 && len(capabilitySetuid) > 0 {
		for _, entry := range capabilitySetuid {
			matches = append(matches, createMatch(entry, "medium", fmt.Sprintf("File capabilities found: %d entries", len(f.Capabilities))))
			matchedPaths["capabilities"] = true
			break
		}
	}

	// 7. Container escape - check for docker/QEMU
	if f.ContainerDetected {
		for _, entry := range other {
			if hasTagStr(entry.Tags, "docker") || hasTagStr(entry.Tags, "container") {
				if f.DockerSocketAccessible {
					socketPath := "unknown"
					if f.DockerSocket != nil {
						socketPath = *f.DockerSocket
					}
					matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Docker escape via accessible socket: %s", socketPath)))
					matchedPaths["docker-escape"] = true
					break
				}
			}
			if hasTagStr(entry.Tags, "qemu") || hasTagStr(entry.Tags, "kvm") {
				if f.VirtualizationType != nil {
					vt := *f.VirtualizationType
					if vt == "qemu" || vt == "QEMU" {
						matches = append(matches, createMatch(entry, "high", fmt.Sprintf("QEMU/KVM escape: %s", vt)))
						matchedPaths["qemu-escape"] = true
						break
					}
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
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("GitLab Runner token accessible: %s", *f.ServiceVersions.GitLabRunner)))
				matchedPaths["gitlab-runner"] = true
				matchedTags["gitlab"] = true
			}
		}

		// Kubernetes kubectl match
		if !matchedTags["kubernetes"] && hasTagStr(tags, "kubernetes") {
			for _, tool := range f.ToolsAvailable {
				if tool == "kubectl" {
					matches = append(matches, createMatch(entry, "medium", "Kubernetes kubectl available - service account token may be accessible"))
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
					matches = append(matches, createMatch(entry, "critical", "Writable /etc/passwd detected - potential for user creation with root privileges"))
					matchedPaths["writable-passwd"] = true
					matchedTags["passwd"] = true
					break
				}
			}
		}

		// SSH key leak match
		if !matchedTags["ssh"] && hasTagStr(tags, "ssh") {
			if f.SSHKeyFound != nil {
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("SSH private key found: %s", *f.SSHKeyFound)))
				matchedPaths["ssh-key"] = true
				matchedTags["ssh"] = true
			}
		}

		// Environment secrets match
		if !matchedTags["env"] && hasTagStr(tags, "env") {
			if len(f.EnvSecrets) > 0 {
				matches = append(matches, createMatch(entry, "high", fmt.Sprintf("Environment variable secrets found: %d entries", len(f.EnvSecrets))))
				matchedPaths["env-secrets"] = true
				matchedTags["env"] = true
			}
		}

		// AWS credentials match
		if !matchedTags["aws"] && hasTagStr(tags, "aws") {
			if f.AWSCredentialsFound {
				matches = append(matches, createMatch(entry, "high", "AWS credentials file accessible"))
				matchedPaths["aws-creds"] = true
				matchedTags["aws"] = true
			}
		}

		// MySQL config match
		if !matchedTags["mysql"] && hasTagStr(tags, "mysql") {
			if f.MySQLConfigFound {
				matches = append(matches, createMatch(entry, "high", "MySQL credentials found in config"))
				matchedPaths["mysql-creds"] = true
				matchedTags["mysql"] = true
			}
		}

		// Docker Compose match
		if !matchedTags["compose"] && hasTagStr(tags, "compose") {
			for _, f := range f.InterestingFiles {
				if filepath.Base(f) == "docker-compose.yml" || filepath.Base(f) == "compose.yml" {
					matches = append(matches, createMatch(entry, "high", "Docker Compose file with secrets found"))
					matchedPaths["docker-compose"] = true
					matchedTags["compose"] = true
					break
				}
			}
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

	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			swap := false
			confI := confidenceOrder[matches[i].MatchConfidence]
			confJ := confidenceOrder[matches[j].MatchConfidence]
			if confI > confJ {
				swap = true
			} else if confI == confJ {
				secI := severityOrder[*matches[i].Entry.Severity]
				secJ := severityOrder[*matches[j].Entry.Severity]
				if secI > secJ {
					swap = true
				}
			}
			if swap {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

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
