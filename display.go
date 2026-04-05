package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func printSummary(f *Findings, matches []MatchResult) {
	// All values that originate on the remote machine must be passed through
	// clean() before being written to the terminal.  This prevents a hostile
	// target from injecting ANSI escape sequences (OSC 52 clipboard hijack,
	// screen-clear, terminal title change, etc.) via crafted recon output.
	clean := stripDangerousAnsi

	// Extract identity info.
	hostname := "unknown"
	if f.Hostname != nil {
		hostname = clean(*f.Hostname)
	}
	user := "unknown"
	if f.User != nil {
		user = clean(*f.User)
	}
	uid := "unknown"
	if f.UID != nil {
		uid = clean(*f.UID)
	}
	osInfo := "unknown"
	if f.OS != nil {
		osInfo = clean(*f.OS)
	}
	kernel := "unknown"
	if f.KernelVersion != nil {
		kernel = clean(*f.KernelVersion)
	}

	bar := ansiBold + " " + strings.Repeat("━", 58) + ansiReset
	fmt.Println(bar)
	fmt.Println(ansiBoldCyan + " ALCAPWN RECON SUMMARY" + ansiReset)
	fmt.Printf(" Host: %s | User: %s (uid=%s)\n", hostname, user, uid)
	fmt.Printf(" OS: %s | Kernel: %s\n", osInfo, kernel)
	fmt.Println(bar)

	// confidenceColor returns the ANSI color for a match confidence level.
	confidenceColor := func(c string) string {
		switch strings.ToUpper(c) {
		case "CRITICAL":
			return ansiBoldRed
		case "HIGH":
			return ansiRed
		case "MEDIUM":
			return ansiYellow
		default:
			return ansiDim
		}
	}

	if len(matches) > 0 {
		fmt.Println("\n" + ansiBoldYellow + "[PRIVESC MATCHES]" + ansiReset)
		for _, match := range matches {
			confidence := strings.ToUpper(match.MatchConfidence)
			cc := confidenceColor(confidence)
			cve := ""
			if match.Entry.CVE != nil {
				cve = *match.Entry.CVE
			}
			binary := ""
			if match.Entry.Binary != nil {
				binary = *match.Entry.Binary
			}
			category := match.Entry.Category

			bracket := cc + "[" + confidence + "]" + ansiReset

			if cve != "" {
				fmt.Printf(" %s %s — %s\n", bracket, clean(cve), match.Entry.ID)
			} else if binary != "" {
				fmt.Printf(" %s %s: %s%s%s\n", bracket, category, ansiCyan, clean(binary), ansiReset)
			} else {
				exploitCmd := "unknown"
				if len(match.Entry.Exploitation) > 0 {
					exploitCmd = match.Entry.Exploitation[0]
				}
				if utf8.RuneCountInString(exploitCmd) > 50 {
					exploitCmd = string([]rune(exploitCmd)[:50]) + "..."
				}
				fmt.Printf(" %s %s: %s\n", bracket, category, exploitCmd)
			}
		}

		topMatch := matches[0]
		if len(topMatch.Entry.Exploitation) > 0 {
			binaryPath := topMatch.MatchedBinaryPath
			if binaryPath == "" && topMatch.Entry.Binary != nil {
				binaryPath = *topMatch.Entry.Binary
			}
			firstCmd := fillTemplates(topMatch.Entry.Exploitation, binaryPath, "/bin/sh", "", "")[0]
			fmt.Printf("\n %sSuggested path:%s %s%s%s\n", ansiBold, ansiReset, ansiCyan, firstCmd, ansiReset)
		}
	} else {
		fmt.Println("\n" + ansiDim + "[NO MATCHES]" + ansiReset)
		fmt.Println(ansiDim + " No known privesc vectors matched in dataset" + ansiReset)
	}

	fmt.Println("\n" + ansiBold + "[OTHER FINDINGS]" + ansiReset)

	// Sudo nopasswd
	if f.SudoRequiresPassword {
		fmt.Println(ansiDim + "\n [INFO] sudo requires password — skipped" + ansiReset)
	} else if len(f.SudoNopasswd) > 0 {
		fmt.Printf("\n %sSUDO NOPASSWD:%s %d entries\n", ansiBoldYellow, ansiReset, len(f.SudoNopasswd))
		for i, entry := range f.SudoNopasswd {
			if i >= 5 {
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(f.SudoNopasswd)-5)
				break
			}
			neg := ""
			if entry.NegatedRoot {
				neg = ansiRed + " (!root)" + ansiReset
			}
			fmt.Printf("   %s: %s%s\n", clean(entry.User), clean(entry.Command), neg)
		}
	}

	// SUID binaries
	if len(f.SuidBinaries) > 0 {
		fmt.Printf("\n %sSUID BINARIES:%s %d found\n", ansiYellow, ansiReset, len(f.SuidBinaries))
		for i, binary := range f.SuidBinaries {
			if i >= 5 {
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(f.SuidBinaries)-5)
				break
			}
			fmt.Printf("   %s\n", clean(binary))
		}
	}

	// SGID binaries
	if len(f.SgidBinaries) > 0 {
		fmt.Printf("\n %sSGID BINARIES:%s %d found\n", ansiYellow, ansiReset, len(f.SgidBinaries))
		for i, binary := range f.SgidBinaries {
			if i >= 5 {
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(f.SgidBinaries)-5)
				break
			}
			fmt.Printf("   %s\n", clean(binary))
		}
	}

	// Writable cron scripts
	if len(f.WritableCrons) > 0 {
		fmt.Printf("\n %sWRITABLE CRON SCRIPTS:%s %d\n", ansiYellow, ansiReset, len(f.WritableCrons))
		for i, path := range f.WritableCrons {
			if i >= 5 {
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(f.WritableCrons)-5)
				break
			}
			fmt.Printf("   %s\n", clean(path))
		}
	}

	// Capabilities
	if len(f.Capabilities) > 0 {
		fmt.Printf("\n %sFILE CAPABILITIES:%s %d\n", ansiYellow, ansiReset, len(f.Capabilities))
		for i, cap := range f.Capabilities {
			if i >= 5 {
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(f.Capabilities)-5)
				break
			}
			fmt.Printf("   %s: %s\n", clean(cap.File), clean(cap.Capability))
		}
	}

	// CVE candidates
	if len(f.CveCandidates) > 0 {
		fmt.Printf("\n %sCVE CANDIDATES:%s %d\n", ansiRed, ansiReset, len(f.CveCandidates))
		for i, cve := range f.CveCandidates {
			if i >= 5 {
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(f.CveCandidates)-5)
				break
			}
			fmt.Printf("   %s%s%s: %s (%s)\n", ansiRed, clean(cve.CVE), ansiReset, clean(cve.Name), cve.Confidence)
		}
	}

	// Tools available
	if len(f.ToolsAvailable) > 0 {
		tools := f.ToolsAvailable
		extra := 0
		if len(tools) > 10 {
			extra = len(tools) - 10
			tools = tools[:10]
		}
		cleaned := make([]string, len(tools))
		for i, t := range tools {
			cleaned[i] = clean(t)
		}
		fmt.Printf("\n AVAILABLE TOOLS: %s%s%s\n", ansiDim, strings.Join(cleaned, ", "), ansiReset)
		if extra > 0 {
			fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, extra)
		}
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
				fmt.Printf(ansiDim+"   ... and %d more\n"+ansiReset, len(nonSSH)-5)
				break
			}
			fmt.Printf("   %s\n", clean(file))
		}
	}

	// AWS credentials
	if f.AWSCredentialsFound {
		fmt.Println(ansiYellow + "\n AWS CREDENTIALS: FOUND" + ansiReset)
	}

	// MySQL config
	if f.MySQLConfigFound {
		fmt.Println(ansiYellow + "\n MYSQL CONFIG: FOUND" + ansiReset)
	}

	// Container detection
	if f.ContainerDetected {
		vt := "unknown"
		if f.VirtualizationType != nil {
			vt = clean(*f.VirtualizationType)
		}
		fmt.Printf("\n CONTAINER DETECTED: %s\n", vt)
	}

	// Docker socket
	if f.DockerSocket != nil {
		status := "FOUND"
		color := ansiYellow
		if f.DockerSocketAccessible {
			status = "ACCESSIBLE"
			color = ansiRed
		}
		fmt.Printf("\n %sDOCKER SOCKET: %s%s — %s\n", color, status, ansiReset, clean(*f.DockerSocket))
	}

	// Service versions
	if f.ServiceVersions.Apache != nil || f.ServiceVersions.Nginx != nil ||
		f.ServiceVersions.PHP != nil || f.ServiceVersions.Python != nil ||
		f.ServiceVersions.Node != nil || f.ServiceVersions.Docker != nil ||
		f.ServiceVersions.MySQL != nil || f.ServiceVersions.Postgres != nil ||
		f.ServiceVersions.GitLabRunner != nil {
		services := []string{}
		if f.ServiceVersions.Apache != nil {
			services = append(services, fmt.Sprintf("apache=%s", clean(*f.ServiceVersions.Apache)))
		}
		if f.ServiceVersions.Nginx != nil {
			services = append(services, fmt.Sprintf("nginx=%s", clean(*f.ServiceVersions.Nginx)))
		}
		if f.ServiceVersions.PHP != nil {
			services = append(services, fmt.Sprintf("php=%s", clean(*f.ServiceVersions.PHP)))
		}
		if f.ServiceVersions.Python != nil {
			services = append(services, fmt.Sprintf("python=%s", clean(*f.ServiceVersions.Python)))
		}
		if f.ServiceVersions.Node != nil {
			services = append(services, fmt.Sprintf("node=%s", clean(*f.ServiceVersions.Node)))
		}
		if f.ServiceVersions.Docker != nil {
			services = append(services, fmt.Sprintf("docker=%s", clean(*f.ServiceVersions.Docker)))
		}
		if f.ServiceVersions.MySQL != nil {
			services = append(services, fmt.Sprintf("mysql=%s", clean(*f.ServiceVersions.MySQL)))
		}
		if f.ServiceVersions.Postgres != nil {
			services = append(services, fmt.Sprintf("postgres=%s", clean(*f.ServiceVersions.Postgres)))
		}
		if f.ServiceVersions.GitLabRunner != nil {
			services = append(services, fmt.Sprintf("gitlab_runner=%s", clean(*f.ServiceVersions.GitLabRunner)))
		}
		fmt.Printf("\n SERVICE VERSIONS: %s\n", strings.Join(services, ", "))
	}

	fmt.Println("\n" + ansiBold + strings.Repeat("━", 60) + ansiReset)
}
