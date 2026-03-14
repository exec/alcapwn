package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type SudoEntry struct {
	User        string `json:"user"`
	Command     string `json:"command"`
	Nopasswd    bool   `json:"nopasswd"`
	NegatedRoot bool   `json:"negated_root"`
}

type CapabilityEntry struct {
	File       string `json:"file"`
	Capability string `json:"capability"`
	Value      string `json:"value"`
}

type CveCandidate struct {
	CVE         string   `json:"cve"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Evidence    string   `json:"evidence"`
	Confidence  string   `json:"confidence"`
	Tags        []string `json:"tags,omitempty"`
}

type ServiceVersions struct {
	Apache       *string `json:"apache"`
	Nginx        *string `json:"nginx"`
	PHP          *string `json:"php"`
	Python       *string `json:"python"`
	Node         *string `json:"node"`
	Docker       *string `json:"docker"`
	MySQL        *string `json:"mysql"`
	Postgres     *string `json:"postgres"`
	GitLabRunner *string `json:"gitlab_runner"`
}

type Findings struct {
	SudoNopasswd          []SudoEntry      `json:"sudo_nopasswd"`
	SuidBinaries          []string         `json:"suid_binaries"`
	SgidBinaries          []string         `json:"sgid_binaries"`
	Capabilities          []CapabilityEntry `json:"capabilities"`
	WritableCrons         []string         `json:"writable_crons"`
	KernelVersion         *string          `json:"kernel_version"`
	ToolsAvailable        []string         `json:"tools_available"`
	CveCandidates         []CveCandidate   `json:"cve_candidates"`
	PolkitVersion         *string          `json:"polkit_version,omitempty"`
	InterestingFiles      []string         `json:"interesting_files"`
	ContainerDetected     bool             `json:"container_detected"`
	VirtualizationType    *string          `json:"virtualization_type"`
	DockerSocket          *string          `json:"docker_socket"`
	DockerSocketAccessible bool            `json:"docker_socket_accessible"`
	ServiceVersions       ServiceVersions  `json:"service_versions"`
	EnvSecrets            []string         `json:"env_secrets"`
	SudoRequiresPassword  bool             `json:"sudo_requires_password"`
	SSHKeyFound           *string          `json:"ssh_key_found"`
	AWSCredentialsFound   bool             `json:"aws_credentials_found"`
	MySQLConfigFound      bool             `json:"mysql_config_found"`
	Hostname              *string          `json:"hostname"`
	User                  *string          `json:"user"`
	UID                   *string          `json:"uid"`
	OS                    *string          `json:"os"`
	// Windows agent session fields (populated by cmdReconAgent for GOOS=windows).
	WinPrivileges            []string `json:"win_privileges,omitempty"`
	WinIsAdmin               bool     `json:"win_is_admin,omitempty"`
	WinAlwaysInstallElevated bool     `json:"win_always_install_elevated,omitempty"`
	WinDomain                string   `json:"win_domain,omitempty"`
}

// Dataset types
//
// Template variables used in Exploitation and PostExploit:
//
//	{{binary}}        full path of the matched binary on the target (from recon)
//	{{shell}}         shell to spawn, default /bin/sh
//	{{listener_ip}}   attacker listener IP (for reverse-shell payloads)
//	{{listener_port}} attacker listener port
type DatasetEntry struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Binary      *string  `json:"binary"`
	CVE         *string  `json:"cve"`
	Exploitation []string `json:"exploitation"`  // parameterized exploit steps
	PostExploit  []string `json:"post_exploit,omitempty"` // run after exploit to stabilise shell
	Notes        string   `json:"notes,omitempty"`        // version/compat caveats
	Source       string   `json:"source"`
	Tags         []string `json:"tags"`
	Severity     *string  `json:"severity"`
}


type MatchResult struct {
	Entry              DatasetEntry
	MatchConfidence    string
	MatchReason        string
	MatchedBinaryPath  string // full path from recon (e.g. /usr/bin/find); used for {{binary}} substitution
}

// PersistenceEntry represents a persistence method installed on a session
type PersistenceEntry struct {
	ID        string `json:"id"`
	Method    string `json:"method"`
	CreatedAt string `json:"created_at"`
	Details   string `json:"details"` // For storing config like cron schedule or path
}

// SessionMetadata stores persistent state for a session
type SessionMetadata struct {
	ID          int      `json:"id"`
	Listener    string   `json:"listener"`
	Name        string   `json:"name,omitempty"` // session rename label (from 'rename' command); used to auto-label reconnects
	Labels      []string `json:"labels"`          // user tags
	Notes       string   `json:"notes"`           // freeform notes
	Persistent  bool     `json:"persistent"`      // auto-reconnect?
	LastSeen    string   `json:"last_seen"`       // RFC3339 timestamp
	OS          string   `json:"os"`              // cached from recon
	Hostname    string   `json:"hostname"`        // cached from recon
	IP          string   `json:"ip"`              // source IP
}

// PersistenceProfile represents a persistent access method
type PersistenceProfile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`        // human-readable name
	Method      string `json:"method"`      // cron, bashrc, sshkey, etc.
	Sessions    []int  `json:"sessions"`    // which sessions use this
	Listener    string `json:"listener"`    // which listener it's tied to
	Enabled     bool   `json:"enabled"`     // is it active?
	CreatedAt   string `json:"created_at"`  // RFC3339 timestamp
	Details     string `json:"details"`
}

// ListenerConfig stores listener info for persistence
type ListenerConfig struct {
	Address       string   `json:"address"`
	Persistent    bool     `json:"persistent"`
	AutoOpen      bool     `json:"auto_open"`
	Labels        []string `json:"labels"`        // tags like "web", "db", "internal"
	Description   string   `json:"description"`   // human-readable description
	LastSessionID int      `json:"last_session"`  // most recent session on this listener
	Sessions      []int    `json:"sessions"`      // all session IDs that connected
}

// Config holds application-wide settings
type Config struct {
	AutoOpenListeners       bool   `json:"auto_open_listeners"`
	FindingsDir             string `json:"findings_dir"`
	MaxReconnectAttempts    int    `json:"max_reconnect_attempts"`
	ReconnectTimeout        int    `json:"reconnect_timeout"`
}

// PersistenceStore manages persisted sessions, profiles, and listeners
type PersistenceStore struct {
	Profiles      map[string]PersistenceProfile `json:"profiles"`      // profile_id -> profile
	Listeners     map[string]ListenerConfig     `json:"listeners"`     // address -> config
	Sessions      map[int]SessionMetadata       `json:"sessions"`      // session_id -> metadata
	Persistence   map[string][]PersistenceEntry `json:"persistence"`   // session_id -> entries (legacy)
	NextProfileID int                           `json:"next_profile_id"`
}

// FirewallRule represents a firewall rule for IP/CIDR
type FirewallRule struct {
	IP      string `json:"ip"`      // IP address or CIDR
	Action  string `json:"action"`  // "allow" or "deny"
	Created string `json:"created"` // RFC3339 timestamp
}

// Firewall represents a named firewall configuration
type Firewall struct {
	Name              string         `json:"name"`
	Rules             []FirewallRule `json:"rules"`
	AssignedListeners []string       `json:"assigned_listeners"` // listener addresses
	Created           string         `json:"created"`          // RFC3339 timestamp
}

// FirewallStore manages persistent firewalls
type FirewallStore struct {
	Firewalls     map[string]Firewall `json:"firewalls"` // name -> firewall
	NextFirewallID int                `json:"next_firewall_id"`
}

// NewFirewallStore creates a new firewall store
func NewFirewallStore() *FirewallStore {
	return &FirewallStore{
		Firewalls:      make(map[string]Firewall),
		NextFirewallID: 1,
	}
}

// Save saves the firewall store to ~/.alcapwn/firewalls.json
func (f *FirewallStore) Save() error {
	return saveConfigFile(f, "firewalls.json")
}

// Load loads the firewall store from ~/.alcapwn/firewalls.json
func (f *FirewallStore) Load() error {
	return loadConfigFile(f, "firewalls.json")
}

// NewPersistenceStore creates a new persistence store
func NewPersistenceStore() *PersistenceStore {
	return &PersistenceStore{
		Profiles:      make(map[string]PersistenceProfile),
		Listeners:     make(map[string]ListenerConfig),
		Sessions:      make(map[int]SessionMetadata),
		Persistence:   make(map[string][]PersistenceEntry),
		NextProfileID: 1,
	}
}

// Save saves the persistence store to ~/.alcapwn/persistence.json
func (p *PersistenceStore) Save() error {
	return saveConfigFile(p, "persistence.json")
}

// Load loads the persistence store from ~/.alcapwn/persistence.json
func (p *PersistenceStore) Load() error {
	return loadConfigFile(p, "persistence.json")
}

// SaveConfig saves the config to ~/.alcapwn/config.json
func (c *Config) Save() error {
	return saveConfigFile(c, "config.json")
}

// LoadConfig loads the config from ~/.alcapwn/config.json
func (c *Config) Load() error {
	return loadConfigFile(c, "config.json")
}

// GetConfigPath returns the full path to a config file in ~/.alcapwn
func GetConfigPath(filename string) string {
	return filepath.Join(GetAlcapwnDir(), filename)
}

// GetAlcapwnDir returns the ~/.alcapwn directory
func GetAlcapwnDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".alcapwn"
	}
	return filepath.Join(home, ".alcapwn")
}

// saveConfigFile saves a struct as JSON to a file in ~/.alcapwn
func saveConfigFile(v interface{}, filename string) error {
	dir := GetAlcapwnDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	path := filepath.Join(dir, filename)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// loadConfigFile loads JSON from a file in ~/.alcapwn into a struct
func loadConfigFile(v interface{}, filename string) error {
	path := filepath.Join(GetAlcapwnDir(), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, that's fine
		}
		return err
	}

	return json.Unmarshal(data, v)
}
