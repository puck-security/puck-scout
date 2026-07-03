package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	MCPListen         string `yaml:"mcp_listen"`
	AgentListen       string `yaml:"agent_listen"`
	InvestigationDir  string `yaml:"investigation_dir"`
	GlobalAuditLog    string `yaml:"global_audit_log"`
	SkillsDir         string `yaml:"skills_dir"`
	MaxTurns          int    `yaml:"max_turns"`
	MaxCommands       int    `yaml:"max_commands_per_investigation"`
	AgentStaleTimeout int    `yaml:"agent_stale_timeout"`
	// MCPToken is the Bearer token MCP clients must present to /sse and /message.
	// Empty string disables authentication (not recommended for production).
	MCPToken string `yaml:"mcp_token"`
	// MaxActiveInvestigations caps the number of concurrent in-progress investigations.
	// 0 means no limit (not recommended for production). Default: 100.
	MaxActiveInvestigations int `yaml:"max_active_investigations"`
	// MaxSSEConns caps the number of concurrent SSE connections on the MCP server.
	// 0 means no limit. Default: 100.
	MaxSSEConns int `yaml:"max_sse_conns"`
	// MaxFanoutConcurrency caps the number of in-flight per-host operations
	// during a fleet-wide tool call (puck_query_fleet, puck_run_batch).
	// 0 means no limit (unsafe past ~30 hosts: spawns one outbound mTLS
	// connection per host simultaneously).  Default: 50.
	MaxFanoutConcurrency int `yaml:"max_fanout_concurrency"`
	// PolicyOverridesPath is an optional path to a TOML overrides file that
	// supplements or replaces entries in the embedded policy.toml.
	// Relative paths are resolved from the config file's directory.
	PolicyOverridesPath string `yaml:"policy_overrides_path"`

	// Transport / auth (Cluster B)
	CACertPath        string   `yaml:"ca_cert_path"`
	CAKeyPath         string   `yaml:"ca_key_path"`
	ServerCertPath    string   `yaml:"server_cert_path"`
	ServerKeyPath     string   `yaml:"server_key_path"`
	ServerCertSans    []string `yaml:"server_cert_sans"`
	BootstrapTokenDir string   `yaml:"bootstrap_token_dir"`

	// AllowTokenMinting gates whether the puck_enroll_instructions MCP tool
	// may mint bootstrap tokens itself (returning a live single-use
	// enrollment credential through the MCP client). Default false: the
	// tool returns the generate-bootstrap-token command for an operator to
	// run instead. This is a code-level gate, not an LLM-supplied flag, so
	// a hostile or prompt-injected client cannot mint tokens on its own —
	// see architectural invariant #8 (untrusted driving LLM).
	AllowTokenMinting bool `yaml:"allow_token_minting"`
}

// ValidateTransportAuth fails fast on missing/bad transport-auth config.
func (c *Config) ValidateTransportAuth() error {
	if c.MCPToken == "" {
		return fmt.Errorf("mcp_token must be set and non-empty (generate with `openssl rand -hex 32`)")
	}
	if c.CACertPath == "" {
		c.CACertPath = "/etc/puck-mcp/ca.pem"
	}
	if c.CAKeyPath == "" {
		c.CAKeyPath = "/etc/puck-mcp/ca-key.pem"
	}
	if c.ServerCertPath == "" {
		c.ServerCertPath = "/etc/puck-mcp/server.pem"
	}
	if c.ServerKeyPath == "" {
		c.ServerKeyPath = "/etc/puck-mcp/server-key.pem"
	}
	if len(c.ServerCertSans) == 0 {
		c.ServerCertSans = []string{"puck-mcp.local", "127.0.0.1", "::1"}
	}
	if c.BootstrapTokenDir == "" {
		c.BootstrapTokenDir = "/var/lib/puck-mcp"
	}
	return nil
}

type WhitelistConfig struct {
	Unrestricted       []string            `yaml:"unrestricted"`
	AllowedSubcommands map[string]any      `yaml:"allowed_subcommands"`
	BlockedArgs        map[string][]string `yaml:"blocked_args"`
	GlobalBlocked      []string            `yaml:"global_blocked_patterns"`
}

func Load(path string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	configDir := filepath.Dir(absPath)

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Defaults
	if cfg.MCPListen == "" {
		cfg.MCPListen = "127.0.0.1:50280"
	}
	if cfg.AgentListen == "" {
		cfg.AgentListen = "0.0.0.0:50281"
	}
	if cfg.InvestigationDir == "" {
		cfg.InvestigationDir = "./investigations"
	}
	if cfg.GlobalAuditLog == "" {
		cfg.GlobalAuditLog = "./audit.jsonl"
	}
	if cfg.SkillsDir == "" {
		cfg.SkillsDir = "./skills"
	}
	if cfg.MaxTurns == 0 {
		cfg.MaxTurns = 5
	}
	if cfg.MaxCommands == 0 {
		// 50 was tuned for v1.0 skills with ~8 phases. credential-exposure
		// v1.2.0 has 17 phases plus a permissions-audit pass after each
		// file read; ~150–200 commands is realistic for a populated dev
		// host before the budget bites and forces the AI to drop late
		// phases (Downloads sweep, Section-K generalized sweep).
		cfg.MaxCommands = 200
	}
	if cfg.AgentStaleTimeout == 0 {
		cfg.AgentStaleTimeout = 300
	}
	if cfg.MaxActiveInvestigations == 0 {
		cfg.MaxActiveInvestigations = 100
	}
	if cfg.MaxSSEConns == 0 {
		cfg.MaxSSEConns = 100
	}
	if cfg.MaxFanoutConcurrency == 0 {
		cfg.MaxFanoutConcurrency = 50
	}

	// Resolve relative paths from the config file's directory, not CWD.
	cfg.InvestigationDir = resolvePath(configDir, cfg.InvestigationDir)
	cfg.GlobalAuditLog = resolvePath(configDir, cfg.GlobalAuditLog)
	cfg.SkillsDir = resolvePath(configDir, cfg.SkillsDir)
	if cfg.PolicyOverridesPath != "" {
		cfg.PolicyOverridesPath = resolvePath(configDir, cfg.PolicyOverridesPath)
	}

	if err := cfg.ValidateTransportAuth(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// resolvePath makes a relative path absolute by resolving it from baseDir.
// Absolute paths are returned unchanged.
func resolvePath(baseDir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}
