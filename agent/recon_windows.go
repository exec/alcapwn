//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// windowsReconResult holds structured recon data for Windows targets.
type windowsReconResult struct {
	Hostname       string   `json:"hostname"`
	User           string   `json:"user"`
	Domain         string   `json:"domain"`
	IsAdmin        bool     `json:"is_admin"`
	OSVersion      string   `json:"os_version"`
	Arch           string   `json:"arch"`
	Privileges     []string `json:"privileges"`
	Admins         []string `json:"admins"`
	Services       []string `json:"services"`
	RunningProcs   []string `json:"running_procs"`
	NetworkPorts   []string `json:"network_ports"`
	Interesting    []string `json:"interesting_paths"`
	Registry       []string `json:"registry_checks"`
	DockerSocket   bool     `json:"docker_socket"`
	Elevated       bool     `json:"elevated"`
}

// runWindowsRecon executes PowerShell commands for Windows enumeration.
func runWindowsRecon() ([]byte, error) {
	var res windowsReconResult

	// Basic info
	if out, err := exec.Command("hostname").CombinedOutput(); err == nil {
		res.Hostname = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("whoami", "/all").CombinedOutput(); err == nil {
		res.User = parseWhoamiUser(string(out))
		res.IsAdmin = bytes.Contains(out, []byte("S-1-5-32-544")) // Administrators group
		res.Privileges = parseWhoamiPrivs(string(out))
	}

	// OS Version
	if out, err := exec.Command("cmd", "/c", "ver").CombinedOutput(); err == nil {
		res.OSVersion = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("cmd", "/c", "echo %PROCESSOR_ARCHITECTURE%").CombinedOutput(); err == nil {
		res.Arch = strings.TrimSpace(string(out))
	}

	// Domain
	if out, err := exec.Command("cmd", "/c", "echo %USERDOMAIN%").CombinedOutput(); err == nil {
		res.Domain = strings.TrimSpace(string(out))
	}

	// Local admins
	if out, err := exec.Command("net", "localgroup", "Administrators").CombinedOutput(); err == nil {
		res.Admins = parseNetLocalgroup(string(out))
	}

	// Services
	if out, err := exec.Command("sc", "query", "state=all").CombinedOutput(); err == nil {
		res.Services = parseSCQuery(string(out))
	}

	// Running processes
	if out, err := exec.Command("tasklist", "/v").CombinedOutput(); err == nil {
		res.RunningProcs = parseTasklist(string(out))
	}

	// Network ports
	if out, err := exec.Command("netstat", "-ano").CombinedOutput(); err == nil {
		res.NetworkPorts = parseNetstat(string(out))
	}

	// Interesting paths
	res.Interesting = checkInterestingPaths()

	// Registry checks
	res.Registry = checkRegistry()

	// Docker socket
	res.DockerSocket = checkDockerSocket()

	// Elevated check
	res.Elevated = res.IsAdmin

	// Marshal to JSON
	data, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return data, nil
}

func parseWhoamiUser(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "USER INFORMATION") {
			continue
		}
		if strings.Contains(line, "User Name") || strings.HasPrefix(strings.TrimSpace(line), "NT AUTHORITY") {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[len(parts)-1])
			}
		}
	}
	// Fallback: try whoami /groups
	if out, err := exec.Command("whoami").CombinedOutput(); err == nil {
		return strings.TrimSpace(string(out))
	}
	return ""
}

func parseWhoamiPrivs(output string) []string {
	var privs []string
	lines := strings.Split(output, "\n")
	inPrivs := false
	for _, line := range lines {
		if strings.Contains(line, "PRIVILEGES") {
			inPrivs = true
			continue
		}
		if inPrivs && strings.Contains(line, "SE_") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				priv := strings.TrimSuffix(parts[len(parts)-1], "*")
				if priv != "" {
					privs = append(privs, priv)
				}
			}
		}
		if inPrivs && strings.Contains(line, "GROUP INFORMATION") {
			break
		}
	}
	return privs
}

func parseNetLocalgroup(output string) []string {
	var users []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "Members") || strings.HasPrefix(line, "The command") {
			continue
		}
		if strings.Contains(line, "command completed") {
			break
		}
		users = append(users, line)
	}
	return users
}

func parseSCQuery(output string) []string {
	var services []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "SERVICE_NAME") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				services = append(services, strings.TrimSpace(parts[1]))
			}
		}
	}
	return services
}

func parseTasklist(output string) []string {
	var procs []string
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Image Name") {
			continue
		}
		if strings.HasPrefix(line, "==") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			procs = append(procs, fields[0])
			count++
			if count >= 30 {
				break
			}
		}
	}
	return procs
}

func parseNetstat(output string) []string {
	var ports []string
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}
		if strings.Contains(line, "LISTENING") || strings.Contains(line, "ESTABLISHED") {
			ports = append(ports, strings.TrimSpace(line))
			count++
			if count >= 20 {
				break
			}
		}
	}
	return ports
}

func checkInterestingPaths() []string {
	var paths []string
	interesting := []string{
		`C:\Windows\System32\config\sam`,
		`C:\Windows\System32\config\system`,
		`C:\Windows\System32\config\security`,
		`C:\Program Files\`,
		`C:\Program Files (x86)\`,
		`C:\Users\Public\`,
		`C:\Windows\Temp\`,
		`%APPDATA%`,
		`%LOCALAPPDATA%`,
	}
	for _, p := range interesting {
		out, _ := exec.Command("cmd", "/c", "if exist \""+p+"\" echo "+p).CombinedOutput()
		if strings.Contains(string(out), p) {
			paths = append(paths, p)
		}
	}
	return paths
}

func checkRegistry() []string {
	var results []string
	// AlwaysInstallElevated
	out, _ := exec.Command("reg", "query", `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`, "/v", "AlwaysInstallElevated").CombinedOutput()
	if strings.Contains(string(out), "AlwaysInstallElevated") {
		results = append(results, "AlwaysInstallElevated: "+extractRegValue(string(out)))
	}
	// UAC
	out, _ = exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA").CombinedOutput()
	if strings.Contains(string(out), "EnableLUA") {
		results = append(results, "UAC: "+extractRegValue(string(out)))
	}
	return results
}

func extractRegValue(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "REG_") {
			parts := strings.Split(line, "REG_")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func checkDockerSocket() bool {
	out, _ := exec.Command("cmd", "/c", "if exist \"C:\\Program Files\\Docker\\Docker\\resources\\docker.sock\" echo 1").CombinedOutput()
	return strings.Contains(string(out), "1")
}