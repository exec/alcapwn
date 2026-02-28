package main

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
}

// Dataset types
type DatasetEntry struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	Binary       *string  `json:"binary"`
	CVE          *string  `json:"cve"`
	Exploitation []string `json:"exploitation"`
	Source       string   `json:"source"`
	Tags         []string `json:"tags"`
	Severity     *string  `json:"severity"`
}

type Dataset struct {
	Version string         `json:"version"`
	Entries []DatasetEntry `json:"entries"`
}

type MatchResult struct {
	Entry           DatasetEntry
	MatchConfidence string
	MatchReason     string
}
