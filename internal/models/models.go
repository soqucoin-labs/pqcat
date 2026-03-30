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
	ID             string            `json:"id"`
	Type           AssetType         `json:"type"`
	Algorithm      string            `json:"algorithm"`
	KeySize        int               `json:"key_size,omitempty"`
	Zone           Zone              `json:"zone"`
	Location       string            `json:"location"`
	Details        map[string]string `json:"details,omitempty"`
	Expiry         *time.Time        `json:"expiry,omitempty"`
	Criticality    Criticality       `json:"criticality"`
	DataRetention  time.Duration     `json:"data_retention,omitempty"`  // CCE: retention period for HNDL
	HNDLMultiplier float64           `json:"hndl_multiplier,omitempty"` // CCE: computed HNDL weight
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
	AssetSSHCipher  AssetType = "ssh_cipher"
	AssetSSHMAC     AssetType = "ssh_mac"
	AssetSBOMDep    AssetType = "sbom_dependency"
	AssetPKICert    AssetType = "pki_certificate"
	AssetCodeCrypto AssetType = "code_crypto_call"
	AssetHSMModule  AssetType = "hsm_module"
	AssetConfig     AssetType = "config_setting"
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
	Overall          float64             `json:"overall"`          // 0-100 normalized risk score
	QuantumExposure  float64             `json:"quantum_exposure"` // 0-100 percentage of RED assets
	Framework        string              `json:"framework"`        // "nsm10", "cnsa2", "sp800131a"
	ZoneCounts       map[Zone]int        `json:"zone_counts"`
	TotalAssets      int                 `json:"total_assets"`
	TopActions       []MigrationAction   `json:"top_actions"`
	NextDeadline     *ComplianceDeadline `json:"next_deadline,omitempty"`
	ConfidentialMode string              `json:"confidential_mode,omitempty"` // CCE: "full", "anonymized", "aggregate"
	FrameworkResults []FrameworkResult   `json:"framework_results,omitempty"` // CCE: per-framework detail
}

// FrameworkResult holds per-framework assessment output.
type FrameworkResult struct {
	Framework  string `json:"framework"`
	Control    string `json:"control"` // e.g. "§3.6", "SC.L2-3.13.11"
	Status     string `json:"status"`  // "PASS", "FAIL", "PARTIAL"
	Zone       Zone   `json:"zone"`
	Rationale  string `json:"rationale"`
	IsAdvisory bool   `json:"is_advisory"` // true for SOX, SWIFT
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
	Title            string            `json:"title"`
	Agency           string            `json:"agency"`
	ScanDate         time.Time         `json:"scan_date"`
	Version          string            `json:"version"`
	Results          []ScanResult      `json:"results"`
	Scores           []ComplianceScore `json:"scores"`
	Generated        time.Time         `json:"generated"`
	ScoringVersion   string            `json:"scoring_version"`             // CCE: "1.0", "1.1-hndl" (GAP-02)
	EngineVersion    string            `json:"engine_version"`              // CCE: PQCAT binary version
	Environment      string            `json:"environment,omitempty"`       // CCE: production/staging/dev (UX-BLIND-03)
	RetentionSource  string            `json:"retention_source,omitempty"`  // CCE: "user_provided"/"policy_file" (GAP-04)
	ScanCoverage     float64           `json:"scan_coverage,omitempty"`     // CCE: reachable/attempted (GAP-03)
	Disclaimer       string            `json:"disclaimer"`                  // CCE: legal disclaimer (GAP-07)
	ProofHash        string            `json:"proof_hash,omitempty"`        // Phase 2: SHA-384 of ZK proof
	SealSig          string            `json:"seal_sig,omitempty"`          // CCE: Dilithium report seal (hex)
	SealPubKey       string            `json:"seal_pub_key,omitempty"`      // CCE: ML-DSA-44 public key (hex, GAP-08)
	SealAlgorithm    string            `json:"seal_algorithm,omitempty"`    // CCE: "ML-DSA-44" (FIPS 204)
	Organization     string            `json:"organization,omitempty"`      // CCE Phase 2: customer name (UX-BLIND-05)
	OrganizationLogo string            `json:"organization_logo,omitempty"` // CCE Phase 2: logo path (UX-BLIND-05)
	CustomTitle      string            `json:"custom_title,omitempty"`      // CCE Phase 2: report title override (UX-BLIND-05)
}
