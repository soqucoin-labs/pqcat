package models

import "time"

// ScanResult represents the output of a single scan operation.
type ScanResult struct {
	Target    string            `json:"target"`
	ScanType  string            `json:"scan_type"` // "tls", "ssh", "sbom", "pki", "code"
	Timestamp time.Time         `json:"timestamp"`
	Assets    []CryptoAsset     `json:"assets"`
	Duration  time.Duration     `json:"duration_ns"`
	Error     string            `json:"error,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
}

// CryptoAsset represents a single cryptographic asset discovered during scanning.
type CryptoAsset struct {
	ID          string            `json:"id"`
	Type        AssetType         `json:"type"`
	Algorithm   string            `json:"algorithm"`
	KeySize     int               `json:"key_size,omitempty"`
	Zone        Zone              `json:"zone"`
	Location    string            `json:"location"`
	Details     map[string]string `json:"details,omitempty"`
	Expiry      *time.Time        `json:"expiry,omitempty"`
	Criticality Criticality       `json:"criticality"`
}

// Zone represents the quantum vulnerability classification.
type Zone string

const (
	ZoneRed    Zone = "RED"    // Quantum vulnerable — immediate risk
	ZoneYellow Zone = "YELLOW" // Transitional — hybrid or oversized classical
	ZoneGreen  Zone = "GREEN"  // CNSA 2.0 compliant
)

// AssetType categorizes the cryptographic asset.
type AssetType string

const (
	AssetTLSCert    AssetType = "tls_certificate"
	AssetTLSCipher  AssetType = "tls_cipher_suite"
	AssetSSHHostKey AssetType = "ssh_host_key"
	AssetSSHKEX     AssetType = "ssh_kex"
	AssetSBOMDep    AssetType = "sbom_dependency"
	AssetPKICert    AssetType = "pki_certificate"
	AssetCodeCrypto AssetType = "code_crypto_call"
	AssetHSMModule  AssetType = "hsm_module"
)

// Criticality represents the importance of an asset.
type Criticality string

const (
	CriticalityStandard Criticality = "STANDARD"
	CriticalityHVA      Criticality = "HVA" // High Value Asset
	CriticalityNSS      Criticality = "NSS" // National Security System
)

// ComplianceScore represents the normalized compliance assessment.
type ComplianceScore struct {
	Overall      float64             `json:"overall"`   // 0-100 normalized
	Framework    string              `json:"framework"` // "nsm10", "cnsa2", "sp800131a"
	ZoneCounts   map[Zone]int        `json:"zone_counts"`
	TotalAssets  int                 `json:"total_assets"`
	TopActions   []MigrationAction   `json:"top_actions"`
	NextDeadline *ComplianceDeadline `json:"next_deadline,omitempty"`
}

// MigrationAction represents a prioritized remediation step.
type MigrationAction struct {
	Priority    int    `json:"priority"`
	Description string `json:"description"`
	AssetCount  int    `json:"asset_count"`
	Complexity  string `json:"complexity"` // "LOW", "MEDIUM", "HIGH"
	Urgency     string `json:"urgency"`    // "IMMEDIATE", "SHORT_TERM", "LONG_TERM"
}

// ComplianceDeadline tracks upcoming regulatory milestones.
type ComplianceDeadline struct {
	Framework string    `json:"framework"`
	Milestone string    `json:"milestone"`
	Deadline  time.Time `json:"deadline"`
	DaysLeft  int       `json:"days_left"`
}

// Report is the top-level structure for the Crypto Bill of Health.
type Report struct {
	Title     string            `json:"title"`
	Agency    string            `json:"agency"`
	ScanDate  time.Time         `json:"scan_date"`
	Version   string            `json:"version"`
	Results   []ScanResult      `json:"results"`
	Scores    []ComplianceScore `json:"scores"`
	Generated time.Time         `json:"generated"`
}
