// Package scanner provides cryptographic asset discovery modules.
// tls_deep_models.go defines the enriched data types for --deep TLS scanning.
package scanner

import (
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// DeepTLSResult holds the comprehensive TLS assessment produced by ScanTLSDeep.
// This structure is JSON-serializable and designed to exceed SSL Labs output depth
// while adding quantum-risk classification unavailable in any other tool.
type DeepTLSResult struct {
	Target   string        `json:"target"`
	Port     string        `json:"port"`
	ScanMode string        `json:"scan_mode"` // "deep"
	Duration time.Duration `json:"duration_ns"`

	// Protocol support matrix — tests TLS 1.0, 1.1, 1.2, 1.3, SSLv3, SSLv2
	Protocols map[string]*ProtocolResult `json:"protocols"`

	// Every cipher suite the server accepts, with per-component quantum classification
	CipherSuites []CipherSuiteResult `json:"cipher_suites"`

	// Full certificate chain with SANs, fingerprints, SCTs, OCSP
	CertificateChain []CertificateDetail `json:"certificate_chain"`

	// HTTP security headers (HSTS, server, etc.)
	HTTPSecurity *HTTPSecurityResult `json:"http_security,omitempty"`

	// Server behavior
	ServerPreference bool   `json:"server_preference"` // true if server chooses cipher order
	ServerHeader     string `json:"server_header,omitempty"`

	// Quantum risk summary
	QuantumSummary QuantumSummary `json:"quantum_summary"`

	// Prioritized remediation actions with CNSA 2.0 references
	Remediation []RemediationAction `json:"remediation"`

	// Sprint 1 enhancements — Blindspot fixes
	ExportNullProbes  *ExportNullProbeResult `json:"export_null_probes,omitempty"`  // Blindspot 14
	TLSCompression    *TLSCompressionResult  `json:"tls_compression,omitempty"`     // Blindspot 5
	CertHNDLExposures []*CertHNDLExposure    `json:"cert_hndl_exposures,omitempty"` // Blindspot 7
	OCSPAnalysis      *OCSPAnalysis          `json:"ocsp_analysis,omitempty"`       // Blindspot 3
	SCTAnalysis       *SCTAnalysis           `json:"sct_analysis,omitempty"`        // Blindspot 4
	CAARecords        *CAAResult             `json:"caa_records,omitempty"`         // Blindspot 12
	CNSA2Gap          *CNSA2ComplianceGap    `json:"cnsa2_gap,omitempty"`           // CROSS-2

	// Sprint 2 enhancements — Competitive parity + crown jewel
	KeyExchangeGroups     *KeyExchangeGroupsResult   `json:"key_exchange_groups,omitempty"`   // Blindspot 2
	SecureRenegotiation   *SecureRenegotiationResult `json:"secure_renegotiation,omitempty"`  // Blindspot 6
	PQKeyExchangeDetected bool                       `json:"pq_key_exchange_detected"`        // Blindspot 1 (THE CROWN JEWEL)
	PQKeyExchangeGroup    string                     `json:"pq_key_exchange_group,omitempty"` // Which PQ group was found
}

// ProtocolResult records whether a specific TLS/SSL version is supported.
type ProtocolResult struct {
	Supported bool        `json:"supported"`
	Zone      models.Zone `json:"zone"`
	Reason    string      `json:"reason"`
}

// CipherSuiteResult describes a single cipher suite the server accepts.
type CipherSuiteResult struct {
	ID       uint16 `json:"id"`       // TLS cipher suite ID (e.g., 0x1301)
	IDHex    string `json:"id_hex"`   // Hex string (e.g., "0x1301")
	Name     string `json:"name"`     // Full name (e.g., "TLS_AES_256_GCM_SHA384")
	Protocol string `json:"protocol"` // Protocol where accepted (e.g., "TLS 1.3")
	Strength string `json:"strength"` // "strong", "acceptable", "weak", "insecure"

	// Per-component breakdown
	KeyExchange     string      `json:"key_exchange"` // "ECDHE", "RSA", "DHE"
	KeyExchangeZone models.Zone `json:"key_exchange_zone"`
	Authentication  string      `json:"authentication"` // "RSA", "ECDSA"
	AuthZone        models.Zone `json:"authentication_zone"`
	BulkCipher      string      `json:"bulk_cipher"` // "AES-256-GCM", "ChaCha20-Poly1305"
	BulkCipherZone  models.Zone `json:"bulk_cipher_zone"`
	MAC             string      `json:"mac,omitempty"` // "SHA384" (empty for AEAD)
	MACZone         models.Zone `json:"mac_zone,omitempty"`
	KeySize         int         `json:"key_size"` // Effective key size in bits
	ForwardSecrecy  bool        `json:"forward_secrecy"`

	// Overall quantum zone (worst of all components)
	OverallZone models.Zone `json:"overall_zone"`
	Reason      string      `json:"reason"`
}

// CertificateDetail provides enriched certificate information.
type CertificateDetail struct {
	Depth     int    `json:"depth"`
	Version   int    `json:"version"` // X.509 version (usually 3)
	Subject   string `json:"subject"`
	SubjectCN string `json:"subject_cn"`
	Issuer    string `json:"issuer"`
	IssuerCN  string `json:"issuer_cn"`
	IssuerOrg string `json:"issuer_org"`
	Serial    string `json:"serial"`

	// Subject Alternative Names — critical for multi-domain certs
	SANs []string `json:"sans,omitempty"`

	// Validity
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	IsExpired     bool      `json:"is_expired"`

	// Fingerprints
	FingerprintSHA256 string `json:"fingerprint_sha256"`

	// Signature
	SignatureAlgorithm string      `json:"signature_algorithm"`
	SignatureZone      models.Zone `json:"signature_zone"`
	SignatureReason    string      `json:"signature_reason"`

	// Public key
	PublicKeyAlgorithm string      `json:"public_key_algorithm"`
	PublicKeyZone      models.Zone `json:"public_key_zone"`
	PublicKeyReason    string      `json:"public_key_reason"`
	KeySize            int         `json:"key_size"`

	// Chain metadata
	IsCA                bool     `json:"is_ca"`
	IsSelfSigned        bool     `json:"is_self_signed"`
	SCTPresent          bool     `json:"sct_present"`
	OCSPStapled         bool     `json:"ocsp_stapled"`
	OCSPResponderURL    string   `json:"ocsp_responder_url,omitempty"`
	CRLDistributionURLs []string `json:"crl_distribution_urls,omitempty"`

	// Key usage
	KeyUsage    []string `json:"key_usage,omitempty"`
	ExtKeyUsage []string `json:"ext_key_usage,omitempty"`
}

// HTTPSecurityResult captures security-relevant HTTP headers.
type HTTPSecurityResult struct {
	HSTS          *HSTSResult `json:"hsts,omitempty"`
	ServerHeader  string      `json:"server_header,omitempty"`
	XFrameOptions string      `json:"x_frame_options,omitempty"`
	XContentType  string      `json:"x_content_type_options,omitempty"`
	CSP           string      `json:"content_security_policy,omitempty"`
}

// HSTSResult describes HTTP Strict Transport Security configuration.
type HSTSResult struct {
	Enabled           bool `json:"enabled"`
	MaxAge            int  `json:"max_age"`
	IncludeSubdomains bool `json:"include_subdomains"`
	Preload           bool `json:"preload"`
}

// QuantumSummary provides the high-level quantum risk assessment.
type QuantumSummary struct {
	OverallZone      models.Zone         `json:"overall_zone"`
	TotalAlgorithms  int                 `json:"total_algorithms"`
	ZoneCounts       map[models.Zone]int `json:"zone_counts"`
	CriticalFinding  string              `json:"critical_finding"`
	HNDLExposure     string              `json:"hndl_exposure"`
	ProtocolsVuln    int                 `json:"protocols_quantum_vulnerable"`
	CipherSuitesVuln int                 `json:"cipher_suites_quantum_vulnerable"`
	CertsVuln        int                 `json:"certificates_quantum_vulnerable"`
}

// RemediationAction is a prioritized, actionable fix with regulatory references.
type RemediationAction struct {
	Priority   int         `json:"priority"`
	Action     string      `json:"action"`
	Impact     string      `json:"impact"`
	Complexity string      `json:"complexity"` // "LOW", "MEDIUM", "HIGH"
	Urgency    string      `json:"urgency"`    // "IMMEDIATE", "SHORT_TERM", "LONG_TERM"
	Reference  string      `json:"reference"`  // CNSA 2.0, NIST SP reference
	Zone       models.Zone `json:"zone"`
	AssetCount int         `json:"asset_count"`
}

// DeepScanEstimate provides pre-scan intelligence for large target sets.
type DeepScanEstimate struct {
	TotalTargets      int           `json:"total_targets"`
	ReachableTargets  int           `json:"reachable_targets"`
	EstimatedDuration time.Duration `json:"estimated_duration_ns"`
	EstimatedHuman    string        `json:"estimated_duration_human"` // "~15 minutes"
	Workers           int           `json:"workers"`
}
