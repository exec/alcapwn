package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// lookupPersistentName checks the persistence store for a named persistent session
// whose stored IP and listener match the incoming connection.  Returns the stored
// Name if found, or "" if no match or no name was set.  This is called from
// acceptLoop to auto-label reconnecting persistent backdoors.
func (c *Console) lookupPersistentName(srcIP, listenerAddr string) string {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	if c.persist == nil {
		return ""
	}
	// Walk stored sessions looking for a persistent entry that matches.
	// If multiple match, prefer the most recently seen one.
	best := ""
	bestTime := ""
	for _, meta := range c.persist.Sessions {
		if !meta.Persistent || meta.Name == "" {
			continue
		}
		if meta.IP != srcIP {
			continue
		}
		// Listener match: exact, or the stored listener is on the same port.
		if meta.Listener != listenerAddr {
			_, storedPort, err1 := net.SplitHostPort(meta.Listener)
			_, incomingPort, err2 := net.SplitHostPort(listenerAddr)
			if err1 != nil || err2 != nil || storedPort != incomingPort {
				continue
			}
		}
		if meta.LastSeen > bestTime {
			bestTime = meta.LastSeen
			best = meta.Name
		}
	}
	return best
}

// checkFirewall checks if a source IP is allowed through the firewall for a listener
func (c *Console) checkFirewall(srcIP, listenerAddr string) bool {
	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	// Find firewalls assigned to this listener
	for _, fw := range c.firewalls.Firewalls {
		assigned := false
		for _, addr := range fw.AssignedListeners {
			if addr == listenerAddr {
				assigned = true
				break
			}
		}
		if !assigned {
			continue
		}

		// Check each rule
		for _, rule := range fw.Rules {
			if rule.IP == srcIP {
				return rule.Action == "allow"
			}
			// Check CIDR match
			if strings.Contains(rule.IP, "/") {
				if ipInRange(srcIP, rule.IP) {
					return rule.Action == "allow"
				}
			}
		}

		// Default deny if firewall assigned but no rule matches
		return false
	}

	// No firewall assigned to this listener - allow all
	return true
}

// ipInRange checks if an IP is within a CIDR range
func ipInRange(ipStr, cidrStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}

	return cidr.Contains(ip)
}

// autoWhitelistIP adds a source IP to all active firewalls (for auto-whitelisting)
func (c *Console) autoWhitelistIP(srcIP string) {
	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	for name, fw := range c.firewalls.Firewalls {
		// Check if IP already exists
		exists := false
		for _, rule := range fw.Rules {
			if rule.IP == srcIP {
				exists = true
				break
			}
		}
		if !exists {
			fw.Rules = append(fw.Rules, FirewallRule{
				IP:      srcIP,
				Action:  "allow",
				Created: time.Now().Format(time.RFC3339),
			})
			c.firewalls.Firewalls[name] = fw
		}
	}
}

// cmdFirewall manages firewall configurations
// Usage:
//
//	firewall create <name>                    - Create a named firewall
//	firewall list                               - List all firewalls
//	firewall delete <name>                      - Delete a firewall
//	firewall rule <name> <allow|deny> <ip>     - Add a rule
//	firewall rules <name>                       - List rules for a firewall
//	firewall clear <name>                       - Clear all rules
//	firewall assign <name> <listener_addr>     - Assign firewall to listener
//	firewall unassign <name> <listener_addr>   - Remove listener assignment
func (c *Console) cmdFirewall(args []string) {
	if len(args) == 0 {
		fmt.Println("[!] Usage:")
		fmt.Println("  firewall create <name>                  - Create a named firewall")
		fmt.Println("  firewall list                           - List all firewalls")
		fmt.Println("  firewall delete <name>                  - Delete a firewall")
		fmt.Println("  firewall rule <name> <allow|deny> <ip>  - Add a rule")
		fmt.Println("  firewall rules <name>                   - List rules for a firewall")
		fmt.Println("  firewall clear <name>                   - Clear all rules")
		fmt.Println("  firewall assign <name> <addr>           - Assign firewall to listener")
		fmt.Println("  firewall unassign <name> <addr>         - Remove listener assignment")
		return
	}

	subCmd := args[0]

	switch subCmd {
	case "create":
		c.cmdFirewallCreate(args[1:])
	case "list":
		c.cmdFirewallList(args[1:])
	case "delete":
		c.cmdFirewallDelete(args[1:])
	case "rule":
		c.cmdFirewallRule(args[1:])
	case "rules":
		c.cmdFirewallRules(args[1:])
	case "clear":
		c.cmdFirewallClear(args[1:])
	case "assign":
		c.cmdFirewallAssign(args[1:])
	case "unassign":
		c.cmdFirewallUnassign(args[1:])
	default:
		fmt.Printf("[!] Unknown firewall subcommand: %s\n", subCmd)
		fmt.Println("Use 'firewall' without arguments for help")
	}
}

// cmdFirewallCreate creates a new firewall
func (c *Console) cmdFirewallCreate(args []string) {
	if len(args) < 1 {
		fmt.Println("[!] Usage: firewall create <name>")
		return
	}

	name := args[0]

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	// Check if firewall already exists
	if _, exists := c.firewalls.Firewalls[name]; exists {
		fmt.Printf("[!] Firewall '%s' already exists\n", name)
		return
	}

	fw := Firewall{
		Name:              name,
		Rules:             []FirewallRule{},
		AssignedListeners: []string{},
		Created:           time.Now().Format(time.RFC3339),
	}
	c.firewalls.Firewalls[name] = fw

	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Failed to save firewall: %v\n", err)
		return
	}

	fmt.Printf("[*] Firewall '%s' created\n", name)
}

// cmdFirewallList lists all firewalls
func (c *Console) cmdFirewallList(args []string) {
	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	if len(c.firewalls.Firewalls) == 0 {
		fmt.Println("[*] No firewalls defined")
		return
	}

	fmt.Println("[*] Firewalls:")
	fmt.Printf("  %-20s  %5s  %s\n", "Name", "Rules", "Listeners")
	fmt.Printf("  %-20s  %5s  %s\n", strings.Repeat("-", 20), strings.Repeat("-", 5), strings.Repeat("-", 20))
	for name, fw := range c.firewalls.Firewalls {
		ruleCount := len(fw.Rules)
		listenerCount := len(fw.AssignedListeners)
		fmt.Printf("  %-20s  %5d  %d listener(s)\n", name, ruleCount, listenerCount)
	}
}

// cmdFirewallDelete deletes a firewall
func (c *Console) cmdFirewallDelete(args []string) {
	if len(args) < 1 {
		fmt.Println("[!] Usage: firewall delete <name>")
		return
	}

	name := args[0]

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	if _, exists := c.firewalls.Firewalls[name]; !exists {
		fmt.Printf("[!] Firewall '%s' not found\n", name)
		return
	}

	delete(c.firewalls.Firewalls, name)

	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Failed to save firewall: %v\n", err)
		return
	}

	fmt.Printf("[*] Firewall '%s' deleted\n", name)
}

// cmdFirewallRule adds a rule to a firewall
func (c *Console) cmdFirewallRule(args []string) {
	if len(args) < 3 {
		fmt.Println("[!] Usage: firewall rule <name> <allow|deny> <ip|cidr>")
		return
	}

	name := args[0]
	action := strings.ToLower(args[1])
	ip := args[2]

	if action != "allow" && action != "deny" {
		fmt.Println("[!] Action must be 'allow' or 'deny'")
		return
	}

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	fw, exists := c.firewalls.Firewalls[name]
	if !exists {
		fmt.Printf("[!] Firewall '%s' not found\n", name)
		return
	}

	// Check if rule already exists
	for _, rule := range fw.Rules {
		if rule.IP == ip {
			fmt.Printf("[!] Rule for '%s' already exists\n", ip)
			return
		}
	}

	fw.Rules = append(fw.Rules, FirewallRule{
		IP:      ip,
		Action:  action,
		Created: time.Now().Format(time.RFC3339),
	})
	c.firewalls.Firewalls[name] = fw

	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Failed to save firewall: %v\n", err)
		return
	}

	fmt.Printf("[*] Rule added: %s %s -> %s\n", name, action, ip)
}

// cmdFirewallRules lists rules for a firewall
func (c *Console) cmdFirewallRules(args []string) {
	if len(args) < 1 {
		fmt.Println("[!] Usage: firewall rules <name>")
		return
	}

	name := args[0]

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	fw, exists := c.firewalls.Firewalls[name]
	if !exists {
		fmt.Printf("[!] Firewall '%s' not found\n", name)
		return
	}

	if len(fw.Rules) == 0 {
		fmt.Printf("[*] No rules for firewall '%s'\n", name)
		return
	}

	fmt.Printf("[*] Rules for firewall '%s':\n", name)
	fmt.Printf("  %-8s  %s\n", "Action", "IP/CIDR")
	fmt.Printf("  %-8s  %s\n", strings.Repeat("-", 8), strings.Repeat("-", 20))
	for _, rule := range fw.Rules {
		fmt.Printf("  %-8s  %s\n", rule.Action, rule.IP)
	}
}

// cmdFirewallClear clears all rules from a firewall
func (c *Console) cmdFirewallClear(args []string) {
	if len(args) < 1 {
		fmt.Println("[!] Usage: firewall clear <name>")
		return
	}

	name := args[0]

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	fw, exists := c.firewalls.Firewalls[name]
	if !exists {
		fmt.Printf("[!] Firewall '%s' not found\n", name)
		return
	}

	fw.Rules = []FirewallRule{}
	c.firewalls.Firewalls[name] = fw

	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Failed to save firewall: %v\n", err)
		return
	}

	fmt.Printf("[*] All rules cleared from firewall '%s'\n", name)
}

// cmdFirewallAssign assigns a firewall to a listener
func (c *Console) cmdFirewallAssign(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: firewall assign <name> <listener_addr>")
		return
	}

	name := args[0]
	listenerAddr := args[1]

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	fw, exists := c.firewalls.Firewalls[name]
	if !exists {
		fmt.Printf("[!] Firewall '%s' not found\n", name)
		return
	}

	// Check if already assigned
	for _, addr := range fw.AssignedListeners {
		if addr == listenerAddr {
			fmt.Printf("[!] Listener '%s' already assigned to firewall '%s'\n", listenerAddr, name)
			return
		}
	}

	fw.AssignedListeners = append(fw.AssignedListeners, listenerAddr)
	c.firewalls.Firewalls[name] = fw

	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Failed to save firewall: %v\n", err)
		return
	}

	fmt.Printf("[*] Firewall '%s' assigned to listener '%s'\n", name, listenerAddr)
}

// cmdFirewallUnassign removes a listener from a firewall
func (c *Console) cmdFirewallUnassign(args []string) {
	if len(args) < 2 {
		fmt.Println("[!] Usage: firewall unassign <name> <listener_addr>")
		return
	}

	name := args[0]
	listenerAddr := args[1]

	c.firewallMu.Lock()
	defer c.firewallMu.Unlock()

	fw, exists := c.firewalls.Firewalls[name]
	if !exists {
		fmt.Printf("[!] Firewall '%s' not found\n", name)
		return
	}

	// Find and remove the listener
	newListeners := make([]string, 0)
	found := false
	for _, addr := range fw.AssignedListeners {
		if addr == listenerAddr {
			found = true
		} else {
			newListeners = append(newListeners, addr)
		}
	}

	if !found {
		fmt.Printf("[!] Listener '%s' not assigned to firewall '%s'\n", listenerAddr, name)
		return
	}

	fw.AssignedListeners = newListeners
	c.firewalls.Firewalls[name] = fw

	if err := c.firewalls.Save(); err != nil {
		fmt.Printf("[!] Failed to save firewall: %v\n", err)
		return
	}

	fmt.Printf("[*] Listener '%s' removed from firewall '%s'\n", listenerAddr, name)
}
