// Package config provides YAML-based configuration loading with precedence chain.
// Precedence: CLI flags > env vars > ./pqcat.yaml > ~/.pqcat/config.yaml > /etc/pqcat/pqcat.yaml
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config represents the full PQCAT configuration.
type Config struct {
	// Organization identity
	Organization string `yaml:"organization,omitempty"`
	Environment  string `yaml:"environment,omitempty"` // "production", "staging", "test"

	// Default scan settings
	Framework     string `yaml:"framework,omitempty"`   // nsm10, cnsa2, sp800131a, fisma, fedramp
	Criticality   string `yaml:"criticality,omitempty"` // STANDARD, HVA, NSS
	Workers       int    `yaml:"workers,omitempty"`
	DataRetention int    `yaml:"data_retention,omitempty"` // HNDL: data retention period in years
	Confidential  bool   `yaml:"confidential,omitempty"`   // CCE: default to confidential mode on scans

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

	// Alert channels (webhook, slack, cdm, email)
	Alerts AlertsConfig `yaml:"alerts,omitempty"`

	// Report branding (logo, accent colors, org tagline)
	Branding BrandingConfig `yaml:"branding,omitempty"`

	// Server (Pro edition only)
	Server ServerConfig `yaml:"server,omitempty"`
}

// BrandingConfig customizes PDF report appearance for enterprise deployments.
// Logo must be JPEG format (the only image format that PDF 1.4 supports natively
// without compression libraries). PNG/SVG are not supported in zero-dependency mode.
type BrandingConfig struct {
	// LogoPath points to a JPEG logo file. Displayed on cover page and report headers.
	// Best results: horizontal wordmark, min 400px wide, light or transparent background.
	LogoPath string `yaml:"logo_path,omitempty" json:"logo_path,omitempty"`

	// AccentColor overrides the navy blue used for section headers and title bar.
	// Format: hex (#1a3366) or CSS name. Default: PQCAT navy (#1a3361).
	AccentColor string `yaml:"accent_color,omitempty" json:"accent_color,omitempty"`

	// OrgName overrides the organization name on the cover page.
	// Falls back to config.Organization if empty.
	OrgName string `yaml:"org_name,omitempty" json:"org_name,omitempty"`

	// Tagline appears below the org name on the cover page.
	// Example: "Enterprise Post-Quantum Compliance Division"
	Tagline string `yaml:"tagline,omitempty" json:"tagline,omitempty"`

	// CoverPage enables a full branded cover page before the report content.
	// Default: true when branding is configured.
	CoverPage *bool `yaml:"cover_page,omitempty" json:"cover_page,omitempty"`

	// FooterText overrides the default "Soqucoin Labs Inc." footer line.
	FooterText string `yaml:"footer_text,omitempty" json:"footer_text,omitempty"`

	// Classification level (TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED, CONFIDENTIAL, etc.)
	Classification string `yaml:"classification,omitempty" json:"classification,omitempty"`
}

// AlertsConfig defines alert channel configuration.
// These are independent of watch mode — they configure where alerts go.
type AlertsConfig struct {
	Webhooks     []WebhookDef `yaml:"webhooks,omitempty" json:"webhooks,omitempty"`
	Slack        *SlackDef    `yaml:"slack,omitempty" json:"slack,omitempty"`
	CDM          *CDMDef      `yaml:"cdm,omitempty" json:"cdm,omitempty"`
	Email        *EmailDef    `yaml:"email,omitempty" json:"email,omitempty"`
	AlertOnScan  bool         `yaml:"alert_on_scan,omitempty" json:"alert_on_scan,omitempty"`
	AlertOnDrift bool         `yaml:"alert_on_drift,omitempty" json:"alert_on_drift,omitempty"`
	AlertOnRed   bool         `yaml:"alert_on_red,omitempty" json:"alert_on_red,omitempty"`
	ScoreDropMin float64      `yaml:"score_drop_min,omitempty" json:"score_drop_min,omitempty"`
}

// WebhookDef defines webhook config in pqcat.yaml.
type WebhookDef struct {
	URL           string            `yaml:"url" json:"url"`
	Headers       map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Secret        string            `yaml:"secret,omitempty" json:"secret,omitempty"`
	TLSSkipVerify bool              `yaml:"tls_skip_verify,omitempty" json:"tls_skip_verify,omitempty"`
	RetryCount    int               `yaml:"retry_count,omitempty" json:"retry_count,omitempty"`
}

// SlackDef defines Slack config in pqcat.yaml.
type SlackDef struct {
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
	Channel    string `yaml:"channel,omitempty" json:"channel,omitempty"`
}

// CDMDef defines CDM/syslog config in pqcat.yaml.
type CDMDef struct {
	SyslogHost string `yaml:"syslog_host" json:"syslog_host"`
	Protocol   string `yaml:"protocol" json:"protocol"`
	Facility   int    `yaml:"facility,omitempty" json:"facility,omitempty"`
	Format     string `yaml:"format,omitempty" json:"format,omitempty"`
	AppName    string `yaml:"app_name,omitempty" json:"app_name,omitempty"`
	AgencyID   string `yaml:"agency_id,omitempty" json:"agency_id,omitempty"`
}

// EmailDef defines email alert config in pqcat.yaml.
type EmailDef struct {
	SMTPHost   string   `yaml:"smtp_host" json:"smtp_host"`
	SMTPPort   int      `yaml:"smtp_port" json:"smtp_port"`
	Username   string   `yaml:"username,omitempty" json:"username,omitempty"`
	Password   string   `yaml:"password,omitempty" json:"password,omitempty"`
	From       string   `yaml:"from" json:"from"`
	To         []string `yaml:"to" json:"to"`
	SubjectPfx string   `yaml:"subject_prefix,omitempty" json:"subject_prefix,omitempty"`
	UseTLS     bool     `yaml:"use_tls,omitempty" json:"use_tls,omitempty"`
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
	Listen     string `yaml:"listen,omitempty"` // e.g., "localhost:8443"
	TLS        bool   `yaml:"tls,omitempty"`
	CertFile   string `yaml:"cert_file,omitempty"`
	KeyFile    string `yaml:"key_file,omitempty"`
	APIKey     string `yaml:"api_key,omitempty"`     // Required for API access when set
	RateLimit  int    `yaml:"rate_limit,omitempty"`  // Requests per minute per IP (0=unlimited)
	CORSOrigin string `yaml:"cors_origin,omitempty"` // Allowed CORS origin ("*" for any)

	// TargetPolicy controls which networks a scan request may target:
	// "estate" (default: allow private and public, deny link-local),
	// "public-only" (also deny loopback/private/CGNAT/ULA),
	// "unrestricted" (no network check; logged at startup).
	//
	// Link-local is denied under both non-opt-out policies because it holds the
	// cloud instance metadata service and never holds cryptographic assets.
	// Private ranges are allowed by default because scanning your own estate is
	// what the product is for. See internal/server/target_policy.go.
	TargetPolicy string `yaml:"target_policy,omitempty"`
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
			Path: defaultDatabasePath(),
		},
		Server: ServerConfig{
			Listen: "localhost:8443",
		},
	}
}

// defaultDatabasePath returns ~/.pqcat/pqcat.db. A relative default breaks
// Finder/double-click launches (cwd is /) and litters pqcat.db into whatever
// directory the CLI happens to run from. Falls back to ./pqcat.db only if
// the home directory cannot be determined.
func defaultDatabasePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "pqcat.db"
	}
	return filepath.Join(home, ".pqcat", "pqcat.db")
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

	// Environment variable overrides. The reported source names the last file
	// loaded; env vars override individual fields on top of it, so note when any
	// PQCAT_* override is present rather than implying the file is the whole story.
	applyEnvOverrides(cfg)
	if envOverridesPresent() {
		source += " (+ env overrides)"
	}

	// Absolutize a relative database path against home. A relative path (e.g.
	// "./pqcat.db" from a file or PQCAT_DB_PATH) otherwise resolves against the
	// process working directory, which differs between an .app launch (cwd=/)
	// and a terminal launch — silently splitting scan history across two files.
	cfg.Database.Path = absolutizeDBPath(cfg.Database.Path)

	return cfg, source
}

// absolutizeDBPath resolves a relative SQLite path against ~/.pqcat so the same
// history file is opened regardless of the process working directory. Absolute
// paths and the in-memory ":memory:" sentinel are returned unchanged.
func absolutizeDBPath(p string) string {
	if p == "" || p == ":memory:" || filepath.IsAbs(p) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, ".pqcat", filepath.Base(p))
}

// envOverridesPresent reports whether any PQCAT_* config override is set, so
// the reported config source can say so instead of misleadingly naming only a
// file. (Per-field provenance is a larger change; this is the honest minimum.)
func envOverridesPresent() bool {
	for _, k := range []string{
		"PQCAT_FRAMEWORK", "PQCAT_CRITICALITY", "PQCAT_ORGANIZATION", "PQCAT_ENVIRONMENT",
		"PQCAT_REPORT_FORMAT", "PQCAT_BASELINE_DIR", "PQCAT_DATA_RETENTION", "PQCAT_CONFIDENTIAL",
		"PQCAT_WORKERS", "PQCAT_OUTPUT_DIR", "PQCAT_DB_PATH", "PQCAT_SIEM_ENDPOINT",
		"PQCAT_SIEM_FORMAT", "PQCAT_INTEL_SIDECAR", "PQCAT_LISTEN", "PQCAT_API_KEY",
		"PQCAT_RATE_LIMIT", "PQCAT_CORS_ORIGIN",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// getConfigPaths returns config file paths in ascending priority order.
func getConfigPaths() []string {
	var paths []string

	// Paths are merged low-to-high (later wins). Within EACH directory the
	// order is always config.yaml then pqcat.yaml, so pqcat.yaml (the
	// documented canonical filename) consistently wins over a config.yaml in
	// the same directory. Previously the intra-directory order differed by
	// location (config.yaml won in /etc and cwd, pqcat.yaml won in home).

	// Lowest priority: system-wide
	paths = append(paths, "/etc/pqcat/config.yaml", "/etc/pqcat/pqcat.yaml")

	// Medium priority: user home
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".pqcat", "config.yaml"),
			filepath.Join(home, ".pqcat", "pqcat.yaml"),
		)
	}

	// Highest priority: current directory
	paths = append(paths, "config.yaml", "pqcat.yaml")

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
	if src.DataRetention > 0 {
		dst.DataRetention = src.DataRetention
	}
	if src.Confidential {
		dst.Confidential = true
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
	if src.Server.APIKey != "" {
		dst.Server.APIKey = src.Server.APIKey
	}
	if src.Server.RateLimit > 0 {
		dst.Server.RateLimit = src.Server.RateLimit
	}
	if src.Server.CORSOrigin != "" {
		dst.Server.CORSOrigin = src.Server.CORSOrigin
	}
	if src.Server.TargetPolicy != "" {
		dst.Server.TargetPolicy = src.Server.TargetPolicy
	}
	// Alerts: previously OMITTED here, so every alerts: block in a config file
	// was silently discarded and alerts never fired. Merge the whole struct
	// when the file defines any channel or trigger (these are compound/pointer
	// fields; a field-by-field merge would be brittle and error-prone).
	if len(src.Alerts.Webhooks) > 0 || src.Alerts.Slack != nil || src.Alerts.CDM != nil ||
		src.Alerts.Email != nil || src.Alerts.AlertOnScan || src.Alerts.AlertOnDrift ||
		src.Alerts.AlertOnRed || src.Alerts.ScoreDropMin > 0 {
		dst.Alerts = src.Alerts
	}
	// Branding: previously OMITTED here, so custom logo/accent/tagline/footer/
	// classification from a config file never reached the PDF generator.
	if src.Branding.LogoPath != "" || src.Branding.AccentColor != "" ||
		src.Branding.OrgName != "" || src.Branding.Tagline != "" ||
		src.Branding.CoverPage != nil || src.Branding.FooterText != "" ||
		src.Branding.Classification != "" {
		dst.Branding = src.Branding
	}
}

// applyEnvOverrides reads PQCAT_* environment variables.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PQCAT_FRAMEWORK"); v != "" {
		cfg.Framework = v
	}
	// Previously missing env layers — the documented "env > file" precedence
	// did not actually exist for these settings.
	if v := os.Getenv("PQCAT_CRITICALITY"); v != "" {
		cfg.Criticality = v
	}
	if v := os.Getenv("PQCAT_ORGANIZATION"); v != "" {
		cfg.Organization = v
	}
	if v := os.Getenv("PQCAT_ENVIRONMENT"); v != "" {
		cfg.Environment = v
	}
	if v := os.Getenv("PQCAT_REPORT_FORMAT"); v != "" {
		cfg.ReportFormat = v
	}
	if v := os.Getenv("PQCAT_BASELINE_DIR"); v != "" {
		cfg.BaselineDir = v
	}
	if v := os.Getenv("PQCAT_DATA_RETENTION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DataRetention = n
		}
	}
	if v := os.Getenv("PQCAT_CONFIDENTIAL"); v == "true" || v == "1" {
		cfg.Confidential = true
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
	if v := os.Getenv("PQCAT_API_KEY"); v != "" {
		cfg.Server.APIKey = v
	}
	if v := os.Getenv("PQCAT_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.RateLimit = n
		}
	}
	if v := os.Getenv("PQCAT_CORS_ORIGIN"); v != "" {
		cfg.Server.CORSOrigin = v
	}
	// Sensitive values — prefer env vars over plaintext config files
	if v := os.Getenv("PQCAT_SIEM_TOKEN"); v != "" {
		cfg.SIEM.Token = v
	}
	if v := os.Getenv("PQCAT_TLS_CERT"); v != "" {
		cfg.Server.CertFile = v
	}
	if v := os.Getenv("PQCAT_TLS_KEY"); v != "" {
		cfg.Server.KeyFile = v
	}
}

// GenerateTemplate writes a well-documented example config file.
// Detects the OS and uses platform-appropriate default paths.
func GenerateTemplate(path string) error {
	dataDir := "/var/lib/pqcat"
	intelPath := "/etc/pqcat/pqcat-intel.json"

	// Use ~/.pqcat on non-Linux platforms (macOS, Windows)
	if home, err := os.UserHomeDir(); err == nil {
		switch runtime.GOOS {
		case "linux":
			// Linux: keep /var/lib/pqcat for system-wide deployments
		default:
			// macOS, Windows, etc.: use home directory
			dataDir = filepath.Join(home, ".pqcat")
			intelPath = filepath.Join(home, ".pqcat", "pqcat-intel.json")
		}
	}

	template := fmt.Sprintf(`# PQCAT Configuration
# Soqucoin Labs Inc. — Post-Quantum Cryptography Compliance Assessment Tool
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
output_dir: "%s/reports"
baseline_dir: "%s/baselines"
report_format: json        # json, pdf, html

# SIEM integration
siem:
  format: cef              # splunk, elk, cef
  endpoint: "syslog://siem.example.com:514"
  # token: "your-splunk-hec-token"  # Uncomment for Splunk HEC

# Threat intelligence
intel:
  sidecar: "%s"
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
  path: "%s/pqcat.db"

# REST API server (Pro edition only)
# server:
#   listen: "localhost:8443"
#   tls: true
#   cert_file: "/etc/pqcat/tls/cert.pem"
#   key_file: "/etc/pqcat/tls/key.pem"
`, dataDir, dataDir, intelPath, dataDir)
	return os.WriteFile(path, []byte(template), 0644)
}

// ValidationIssue represents a single config validation problem.
type ValidationIssue struct {
	Field    string
	Message  string
	Severity string // "error" or "warning"
}

// Validate checks the configuration for structural and semantic correctness.
func Validate(cfg *Config) []ValidationIssue {
	var issues []ValidationIssue

	// Framework validation
	validFrameworks := map[string]bool{
		"cnsa2": true, "nsm10": true, "sp800131a": true,
		"fisma": true, "fedramp": true, "pci": true,
		"sox": true, "nydfs": true, "swift": true,
		"hipaa": true, "cmmc": true,
	}
	if cfg.Framework != "" && !validFrameworks[cfg.Framework] {
		issues = append(issues, ValidationIssue{
			Field:    "framework",
			Message:  fmt.Sprintf("unknown framework '%s' (valid: cnsa2, nsm10, sp800131a, fisma, fedramp, pci, sox, nydfs, swift, hipaa, cmmc)", cfg.Framework),
			Severity: "error",
		})
	}

	// Workers validation
	if cfg.Workers < 1 || cfg.Workers > 500 {
		issues = append(issues, ValidationIssue{
			Field:    "workers",
			Message:  fmt.Sprintf("workers=%d out of valid range 1-500", cfg.Workers),
			Severity: "error",
		})
	} else if cfg.Workers > 100 {
		issues = append(issues, ValidationIssue{
			Field:    "workers",
			Message:  fmt.Sprintf("workers=%d is high — may cause rate-limiting or connection failures", cfg.Workers),
			Severity: "warning",
		})
	}

	// TLS cert files (if TLS is enabled)
	if cfg.Server.TLS {
		if cfg.Server.CertFile == "" {
			issues = append(issues, ValidationIssue{
				Field:    "server.cert_file",
				Message:  "TLS enabled but no cert_file specified",
				Severity: "error",
			})
		} else if _, err := os.Stat(cfg.Server.CertFile); os.IsNotExist(err) {
			issues = append(issues, ValidationIssue{
				Field:    "server.cert_file",
				Message:  fmt.Sprintf("cert file not found: %s", cfg.Server.CertFile),
				Severity: "error",
			})
		}
		if cfg.Server.KeyFile == "" {
			issues = append(issues, ValidationIssue{
				Field:    "server.key_file",
				Message:  "TLS enabled but no key_file specified",
				Severity: "error",
			})
		} else if _, err := os.Stat(cfg.Server.KeyFile); os.IsNotExist(err) {
			issues = append(issues, ValidationIssue{
				Field:    "server.key_file",
				Message:  fmt.Sprintf("key file not found: %s", cfg.Server.KeyFile),
				Severity: "error",
			})
		}
	}

	// SIEM format validation
	if cfg.SIEM.Format != "" {
		validFormats := map[string]bool{"splunk": true, "elk": true, "cef": true, "qradar": true, "sentinel": true}
		if !validFormats[cfg.SIEM.Format] {
			issues = append(issues, ValidationIssue{
				Field:    "siem.format",
				Message:  fmt.Sprintf("unknown SIEM format '%s' (valid: splunk, elk, cef, qradar, sentinel)", cfg.SIEM.Format),
				Severity: "error",
			})
		}
	}

	// Intel sidecar path
	if cfg.Intel.Sidecar != "" {
		if _, err := os.Stat(cfg.Intel.Sidecar); os.IsNotExist(err) {
			issues = append(issues, ValidationIssue{
				Field:    "intel.sidecar",
				Message:  fmt.Sprintf("intel sidecar file not found: %s", cfg.Intel.Sidecar),
				Severity: "warning",
			})
		}
	}

	// Data retention
	if cfg.DataRetention > 0 && cfg.DataRetention < 5 {
		issues = append(issues, ValidationIssue{
			Field:    "data_retention",
			Message:  fmt.Sprintf("data_retention=%d years — HNDL threats require minimum 5-year retention", cfg.DataRetention),
			Severity: "warning",
		})
	}

	// Output directory
	if cfg.OutputDir != "" && cfg.OutputDir != "." {
		if _, err := os.Stat(cfg.OutputDir); os.IsNotExist(err) {
			issues = append(issues, ValidationIssue{
				Field:    "output_dir",
				Message:  fmt.Sprintf("output directory does not exist: %s", cfg.OutputDir),
				Severity: "warning",
			})
		}
	}

	return issues
}
