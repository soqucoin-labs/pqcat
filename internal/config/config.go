// Package config provides YAML-based configuration loading with precedence chain.
// Precedence: CLI flags > env vars > ./pqcat.yaml > ~/.pqcat/config.yaml > /etc/pqcat/pqcat.yaml
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config represents the full PQCAT configuration.
type Config struct {
	// Organization identity
	Organization string `yaml:"organization,omitempty"`
	Environment  string `yaml:"environment,omitempty"` // "production", "staging", "test"

	// Default scan settings
	Framework   string `yaml:"framework,omitempty"`   // nsm10, cnsa2, sp800131a, fisma, fedramp
	Criticality string `yaml:"criticality,omitempty"` // STANDARD, HVA, NSS
	Workers     int    `yaml:"workers,omitempty"`

	// Output defaults
	OutputDir    string `yaml:"output_dir,omitempty"`
	BaselineDir  string `yaml:"baseline_dir,omitempty"`
	ReportFormat string `yaml:"report_format,omitempty"` // json, pdf, html

	// SIEM integration
	SIEM SIEMConfig `yaml:"siem,omitempty"`

	// Intel configuration
	Intel IntelConfig `yaml:"intel,omitempty"`

	// Scan policy
	ScanPolicy ScanPolicyConfig `yaml:"scan_policy,omitempty"`

	// Database
	Database DatabaseConfig `yaml:"database,omitempty"`

	// Server (Pro edition only)
	Server ServerConfig `yaml:"server,omitempty"`
}

// SIEMConfig configures SIEM integration defaults.
type SIEMConfig struct {
	Format   string `yaml:"format,omitempty"`   // splunk, elk, cef
	Endpoint string `yaml:"endpoint,omitempty"` // URL or syslog address
	Token    string `yaml:"token,omitempty"`    // API token (Splunk HEC)
}

// IntelConfig configures threat intelligence sources.
type IntelConfig struct {
	Sidecar    string `yaml:"sidecar,omitempty"`     // Path to sidecar JSON file
	FeedURL    string `yaml:"feed_url,omitempty"`    // Live feed URL (Pro only)
	AutoUpdate bool   `yaml:"auto_update,omitempty"` // Auto-fetch on scan (Pro only)
}

// ScanPolicyConfig defines org-wide scan policies.
type ScanPolicyConfig struct {
	TLSPorts       []int    `yaml:"tls_ports,omitempty"`
	SSHPorts       []int    `yaml:"ssh_ports,omitempty"`
	ExcludeSubnets []string `yaml:"exclude_subnets,omitempty"`
	ExcludeHosts   []string `yaml:"exclude_hosts,omitempty"`
	MaxScanTime    string   `yaml:"max_scan_time,omitempty"` // e.g., "30m", "2h"
}

// DatabaseConfig configures scan history storage.
type DatabaseConfig struct {
	Path string `yaml:"path,omitempty"` // SQLite database file path
}

// ServerConfig configures the REST API server (Pro edition only).
type ServerConfig struct {
	Listen   string `yaml:"listen,omitempty"` // e.g., "localhost:8443"
	TLS      bool   `yaml:"tls,omitempty"`
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Framework:    "cnsa2",
		Criticality:  "STANDARD",
		Workers:      20,
		OutputDir:    ".",
		BaselineDir:  ".",
		ReportFormat: "json",
		ScanPolicy: ScanPolicyConfig{
			TLSPorts: []int{443},
			SSHPorts: []int{22},
		},
		Database: DatabaseConfig{
			Path: "pqcat.db",
		},
		Server: ServerConfig{
			Listen: "localhost:8443",
		},
	}
}

// Load reads configuration from the precedence chain and returns a merged Config.
// Precedence: CLI flags > env vars > ./pqcat.yaml > ~/.pqcat/config.yaml > /etc/pqcat/pqcat.yaml
func Load(explicitPath string) (*Config, string) {
	cfg := DefaultConfig()
	source := "defaults"

	// Load from config file chain (lowest to highest priority)
	configPaths := getConfigPaths()
	if explicitPath != "" {
		configPaths = append(configPaths, explicitPath) // explicit path wins
	}

	for _, path := range configPaths {
		if fileConfig, err := loadFile(path); err == nil {
			mergeConfig(cfg, fileConfig)
			source = path
		}
	}

	// Environment variable overrides
	applyEnvOverrides(cfg)

	return cfg, source
}

// getConfigPaths returns config file paths in ascending priority order.
func getConfigPaths() []string {
	var paths []string

	// Lowest priority: system-wide
	paths = append(paths, "/etc/pqcat/pqcat.yaml")
	paths = append(paths, "/etc/pqcat/config.yaml")

	// Medium priority: user home
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".pqcat", "config.yaml"),
			filepath.Join(home, ".pqcat", "pqcat.yaml"),
		)
	}

	// Highest priority: current directory
	paths = append(paths, "pqcat.yaml", "config.yaml")

	return paths
}

// loadFile reads and parses a YAML config file.
func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config in %s: %w", path, err)
	}

	return &cfg, nil
}

// mergeConfig applies non-zero values from src onto dst.
func mergeConfig(dst, src *Config) {
	if src.Organization != "" {
		dst.Organization = src.Organization
	}
	if src.Environment != "" {
		dst.Environment = src.Environment
	}
	if src.Framework != "" {
		dst.Framework = src.Framework
	}
	if src.Criticality != "" {
		dst.Criticality = src.Criticality
	}
	if src.Workers > 0 {
		dst.Workers = src.Workers
	}
	if src.OutputDir != "" {
		dst.OutputDir = src.OutputDir
	}
	if src.BaselineDir != "" {
		dst.BaselineDir = src.BaselineDir
	}
	if src.ReportFormat != "" {
		dst.ReportFormat = src.ReportFormat
	}
	// SIEM
	if src.SIEM.Format != "" {
		dst.SIEM.Format = src.SIEM.Format
	}
	if src.SIEM.Endpoint != "" {
		dst.SIEM.Endpoint = src.SIEM.Endpoint
	}
	if src.SIEM.Token != "" {
		dst.SIEM.Token = src.SIEM.Token
	}
	// Intel
	if src.Intel.Sidecar != "" {
		dst.Intel.Sidecar = src.Intel.Sidecar
	}
	if src.Intel.FeedURL != "" {
		dst.Intel.FeedURL = src.Intel.FeedURL
	}
	if src.Intel.AutoUpdate {
		dst.Intel.AutoUpdate = true
	}
	// Scan policy
	if len(src.ScanPolicy.TLSPorts) > 0 {
		dst.ScanPolicy.TLSPorts = src.ScanPolicy.TLSPorts
	}
	if len(src.ScanPolicy.SSHPorts) > 0 {
		dst.ScanPolicy.SSHPorts = src.ScanPolicy.SSHPorts
	}
	if len(src.ScanPolicy.ExcludeSubnets) > 0 {
		dst.ScanPolicy.ExcludeSubnets = src.ScanPolicy.ExcludeSubnets
	}
	if len(src.ScanPolicy.ExcludeHosts) > 0 {
		dst.ScanPolicy.ExcludeHosts = src.ScanPolicy.ExcludeHosts
	}
	if src.ScanPolicy.MaxScanTime != "" {
		dst.ScanPolicy.MaxScanTime = src.ScanPolicy.MaxScanTime
	}
	// Database
	if src.Database.Path != "" {
		dst.Database.Path = src.Database.Path
	}
	// Server
	if src.Server.Listen != "" {
		dst.Server.Listen = src.Server.Listen
	}
	if src.Server.TLS {
		dst.Server.TLS = true
	}
	if src.Server.CertFile != "" {
		dst.Server.CertFile = src.Server.CertFile
	}
	if src.Server.KeyFile != "" {
		dst.Server.KeyFile = src.Server.KeyFile
	}
}

// applyEnvOverrides reads PQCAT_* environment variables.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PQCAT_FRAMEWORK"); v != "" {
		cfg.Framework = v
	}
	if v := os.Getenv("PQCAT_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Workers = n
		}
	}
	if v := os.Getenv("PQCAT_OUTPUT_DIR"); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv("PQCAT_DB_PATH"); v != "" {
		cfg.Database.Path = v
	}
	if v := os.Getenv("PQCAT_SIEM_ENDPOINT"); v != "" {
		cfg.SIEM.Endpoint = v
	}
	if v := os.Getenv("PQCAT_SIEM_FORMAT"); v != "" {
		cfg.SIEM.Format = v
	}
	if v := os.Getenv("PQCAT_INTEL_SIDECAR"); v != "" {
		cfg.Intel.Sidecar = v
	}
	if v := os.Getenv("PQCAT_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
}

// GenerateTemplate writes a well-documented example config file.
func GenerateTemplate(path string) error {
	template := `# PQCAT Configuration
# Soqucoin Labs Inc. — Post-Quantum Compliance Assessment Tool
#
# Precedence: CLI flags > env vars > ./pqcat.yaml > ~/.pqcat/config.yaml > /etc/pqcat/pqcat.yaml
# Environment variables: PQCAT_FRAMEWORK, PQCAT_WORKERS, PQCAT_OUTPUT_DIR, PQCAT_DB_PATH, etc.

# Organization identity (appears in reports)
organization: "Your Agency Name"
environment: "production"  # production, staging, test

# Default scan settings
framework: cnsa2           # nsm10, cnsa2, sp800131a, fisma, fedramp
criticality: STANDARD      # STANDARD, HVA, NSS
workers: 20                # Concurrent scan workers

# Output defaults
output_dir: "/var/lib/pqcat/reports"
baseline_dir: "/var/lib/pqcat/baselines"
report_format: json        # json, pdf, html

# SIEM integration
siem:
  format: cef              # splunk, elk, cef
  endpoint: "syslog://siem.agency.mil:514"
  # token: "your-splunk-hec-token"  # Uncomment for Splunk HEC

# Threat intelligence
intel:
  sidecar: "/etc/pqcat/pqcat-intel.json"
  # feed_url: "https://intel.pqcat.io/v1/latest"  # Pro edition only
  # auto_update: false

# Scan policy
scan_policy:
  tls_ports: [443, 8443, 4443]
  ssh_ports: [22, 2222]
  exclude_subnets: []
  exclude_hosts: []
  max_scan_time: "30m"

# Scan history database
database:
  path: "/var/lib/pqcat/pqcat.db"

# REST API server (Pro edition only)
# server:
#   listen: "localhost:8443"
#   tls: true
#   cert_file: "/etc/pqcat/tls/cert.pem"
#   key_file: "/etc/pqcat/tls/key.pem"
`
	return os.WriteFile(path, []byte(template), 0644)
}
