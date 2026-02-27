package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

func printSummary(f *Findings, matches []MatchResult) {
	// Check if stdout is a TTY before emitting color codes

	// Extract identity info
	hostname := "unknown"
	if f.Hostname != nil {
		hostname = *f.Hostname
	}
	user := "unknown"
	if f.User != nil {
		user = *f.User
	}
	uid := "unknown"
	if f.UID != nil {
		uid = *f.UID
	}
	osInfo := "unknown"
	if f.OS != nil {
		osInfo = *f.OS
	}
	kernel := "unknown"
	if f.KernelVersion != nil {
		kernel = *f.KernelVersion
	}

	// Print header
	fmt.Println(" " + strings.Repeat("━", 58))
	fmt.Println(" ALCAPWN RECON SUMMARY")
	fmt.Printf(" Host: %s | User: %s (uid=%s)\n", hostname, user, uid)
	fmt.Printf(" OS: %s | Kernel: %s\n", osInfo, kernel)
	fmt.Println(" " + strings.Repeat("━", 58))

	// Print privesc matches by priority
	if len(matches) > 0 {
		fmt.Println("\n[PRIVESC MATCHES]")
		for _, match := range matches {
			confidence := strings.ToUpper(match.MatchConfidence)
			cve := ""
			if match.Entry.CVE != nil {
				cve = *match.Entry.CVE
			}
			binary := ""
			if match.Entry.Binary != nil {
				binary = *match.Entry.Binary
			}
			category := match.Entry.Category

			if cve != "" {
				name := match.Entry.ID
				fmt.Printf(" [%s] %s — %s\n", confidence, cve, name)
			} else if binary != "" {
				fmt.Printf(" [%s] %s: %s\n", confidence, category, binary)
			} else {
				// Get the action/exploitation info
				exploitCmd := "unknown"
				if len(match.Entry.Exploitation) > 0 {
					exploitCmd = match.Entry.Exploitation[0]
				}
				// Truncate to 50 runes
				if utf8.RuneCountInString(exploitCmd) > 50 {
					exploitCmd = string([]rune(exploitCmd)[:50]) + "..."
				}
				fmt.Printf(" [%s] %s: %s\n", confidence, category, exploitCmd)
			}
		}

		// Show suggested path
		if len(matches) > 0 {
			topMatch := matches[0]
			exploitation := topMatch.Entry.Exploitation
			if len(exploitation) > 0 {
				firstCmd := exploitation[0]
				fmt.Printf("\n Suggested path: %s\n", firstCmd)
			}
		}
	} else {
		fmt.Println("\n[NO MATCHES]")
		fmt.Println(" No known privesc vectors matched in dataset")
	}

	// Print other findings
	fmt.Println("\n[OTHER FINDINGS]")

	// Sudo nopasswd
	if f.SudoRequiresPassword {
		fmt.Println("\n [INFO] sudo requires password — skipped")
	} else if len(f.SudoNopasswd) > 0 {
		fmt.Printf("\n SUDO NOPASSWD: %d entries\n", len(f.SudoNopasswd))
		for i, entry := range f.SudoNopasswd {
			if i >= 5 {
				fmt.Printf("   ... and %d more\n", len(f.SudoNopasswd)-5)
				break
			}
			neg := ""
			if entry.NegatedRoot {
				neg = " (!root)"
			}
			fmt.Printf("   %s: %s%s\n", entry.User, entry.Command, neg)
		}
	}

	// SUID binaries
	if len(f.SuidBinaries) > 0 {
		fmt.Printf("\n SUID BINARIES: %d found\n", len(f.SuidBinaries))
		for i, binary := range f.SuidBinaries {
			if i >= 10 {
				fmt.Printf("   ... and %d more\n", len(f.SuidBinaries)-10)
				break
			}
			fmt.Printf("   %s\n", binary)
		}
	}

	// SGID binaries
	if len(f.SgidBinaries) > 0 {
		fmt.Printf("\n SGID BINARIES: %d found\n", len(f.SgidBinaries))
		for i, binary := range f.SgidBinaries {
			if i >= 5 {
				fmt.Printf("   ... and %d more\n", len(f.SgidBinaries)-5)
				break
			}
			fmt.Printf("   %s\n", binary)
		}
	}

	// Writable cron scripts
	if len(f.WritableCrons) > 0 {
		fmt.Printf("\n WRITABLE CRON SCRIPTS: %d\n", len(f.WritableCrons))
		for _, path := range f.WritableCrons {
			fmt.Printf("   %s\n", path)
		}
	}

	// Capabilities
	if len(f.Capabilities) > 0 {
		fmt.Printf("\n FILE CAPABILITIES: %d\n", len(f.Capabilities))
		for i, cap := range f.Capabilities {
			if i >= 5 {
				break
			}
			fmt.Printf("   %s: %s\n", cap.File, cap.Capability)
		}
	}

	// CVE candidates
	if len(f.CveCandidates) > 0 {
		fmt.Printf("\n CVE CANDIDATES: %d\n", len(f.CveCandidates))
		for i, cve := range f.CveCandidates {
			if i >= 5 {
				break
			}
			fmt.Printf("   %s: %s (%s)\n", cve.CVE, cve.Name, cve.Confidence)
		}
	}

	// Tools available
	if len(f.ToolsAvailable) > 0 {
		tools := f.ToolsAvailable
		if len(tools) > 10 {
			tools = tools[:10]
		}
		fmt.Printf("\n AVAILABLE TOOLS: %s\n", strings.Join(tools, ", "))
	}

	// Interesting files (non-SSH)
	nonSSH := []string{}
	for _, file := range f.InterestingFiles {
		if !strings.Contains(file, "id_rsa") && !strings.Contains(file, "id_ed25519") {
			nonSSH = append(nonSSH, file)
		}
	}
	if len(nonSSH) > 0 {
		fmt.Printf("\n INTERESTING FILES: %d\n", len(nonSSH))
		for i, file := range nonSSH {
			if i >= 5 {
				fmt.Printf("   ... and %d more\n", len(nonSSH)-5)
				break
			}
			fmt.Printf("   %s\n", file)
		}
	}

	// AWS credentials
	if f.AWSCredentialsFound {
		fmt.Println("\n AWS CREDENTIALS: FOUND")
	}

	// MySQL config
	if f.MySQLConfigFound {
		fmt.Println("\n MYSQL CONFIG: FOUND")
	}

	// Container detection
	if f.ContainerDetected {
		vt := "unknown"
		if f.VirtualizationType != nil {
			vt = *f.VirtualizationType
		}
		fmt.Printf("\n CONTAINER DETECTED: %s\n", vt)
	}

	// Docker socket detection
	if f.DockerSocket != nil {
		status := "FOUND"
		if f.DockerSocketAccessible {
			status = "ACCESSIBLE"
		}
		fmt.Printf("\n DOCKER SOCKET: %s - %s\n", status, *f.DockerSocket)
	}

	// Service versions
	if f.ServiceVersions.Apache != nil || f.ServiceVersions.Nginx != nil ||
		f.ServiceVersions.PHP != nil || f.ServiceVersions.Python != nil ||
		f.ServiceVersions.Node != nil || f.ServiceVersions.Docker != nil ||
		f.ServiceVersions.MySQL != nil || f.ServiceVersions.Postgres != nil ||
		f.ServiceVersions.GitLabRunner != nil {
		services := []string{}
		if f.ServiceVersions.Apache != nil {
			services = append(services, fmt.Sprintf("apache=%s", *f.ServiceVersions.Apache))
		}
		if f.ServiceVersions.Nginx != nil {
			services = append(services, fmt.Sprintf("nginx=%s", *f.ServiceVersions.Nginx))
		}
		if f.ServiceVersions.PHP != nil {
			services = append(services, fmt.Sprintf("php=%s", *f.ServiceVersions.PHP))
		}
		if f.ServiceVersions.Python != nil {
			services = append(services, fmt.Sprintf("python=%s", *f.ServiceVersions.Python))
		}
		if f.ServiceVersions.Node != nil {
			services = append(services, fmt.Sprintf("node=%s", *f.ServiceVersions.Node))
		}
		if f.ServiceVersions.Docker != nil {
			services = append(services, fmt.Sprintf("docker=%s", *f.ServiceVersions.Docker))
		}
		if f.ServiceVersions.MySQL != nil {
			services = append(services, fmt.Sprintf("mysql=%s", *f.ServiceVersions.MySQL))
		}
		if f.ServiceVersions.Postgres != nil {
			services = append(services, fmt.Sprintf("postgres=%s", *f.ServiceVersions.Postgres))
		}
		if f.ServiceVersions.GitLabRunner != nil {
			services = append(services, fmt.Sprintf("gitlab_runner=%s", *f.ServiceVersions.GitLabRunner))
		}
		fmt.Printf("\n SERVICE VERSIONS: %s\n", strings.Join(services, ", "))
	}

	fmt.Println("\n" + strings.Repeat("━", 60))
}
