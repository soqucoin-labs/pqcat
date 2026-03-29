// Package scanner provides enhanced PKI certificate analysis for quantum risk.
//
// This module extends the base PKI scanner with:
// - Key usage / extended key usage quantum risk classification (PKI-4)
// - HNDL exposure window per certificate (reuses Sprint 1 calculation)
// - Cross-signed certificate detection (PKI-5)
// - Certificate validity period compliance (CA/Browser Forum Baseline)
// - CRL distribution point analysis (PKI-2)
// - Enhanced chain-of-trust quantum risk scoring
package scanner

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// PKI-4: Key Usage Quantum Risk Classification
// ──────────────────────────────────────────────────────────────────────────────

// KeyUsageRisk describes the quantum risk implications of a certificate's key usage.
type KeyUsageRisk struct {
	KeyUsages       []string    `json:"key_usages"`
	ExtKeyUsages    []string    `json:"ext_key_usages"`
	SigningRisk     string      `json:"signing_risk"`    // "IMMEDIATE" — signatures forgeable NOW with quantum
	EncryptionRisk  string      `json:"encryption_risk"` // "HNDL" — encrypted data harvestable for later decryption
	IsSigningKey    bool        `json:"is_signing_key"`
	IsEncryptionKey bool        `json:"is_encryption_key"`
	IsCAKey         bool        `json:"is_ca_key"`
	QuantumImpact   string      `json:"quantum_impact"` // Summary sentence
	Zone            models.Zone `json:"zone"`
}

// classifyKeyUsageRisk analyzes a certificate's key usage extensions to
// determine the *nature* of quantum risk — not just whether the algorithm
// is vulnerable, but how it's used and what the consequences are.
//
// Key insight: A signing key (digitalSignature) is vulnerable to FORGERY NOW
// once quantum arrives. An encryption key (keyEncipherment) creates HNDL risk
// because data encrypted today can be harvested and decrypted later.
// A CA key (keyCertSign) is the WORST — it can forge entire chains.
func classifyKeyUsageRisk(cert *x509.Certificate) *KeyUsageRisk {
	result := &KeyUsageRisk{
		KeyUsages:    make([]string, 0),
		ExtKeyUsages: make([]string, 0),
	}

	// Parse standard key usages (bit flags)
	ku := cert.KeyUsage
	usageMap := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "digitalSignature",
		x509.KeyUsageContentCommitment: "contentCommitment",
		x509.KeyUsageKeyEncipherment:   "keyEncipherment",
		x509.KeyUsageDataEncipherment:  "dataEncipherment",
		x509.KeyUsageKeyAgreement:      "keyAgreement",
		x509.KeyUsageCertSign:          "keyCertSign",
		x509.KeyUsageCRLSign:           "cRLSign",
		x509.KeyUsageEncipherOnly:      "encipherOnly",
		x509.KeyUsageDecipherOnly:      "decipherOnly",
	}

	for flag, name := range usageMap {
		if ku&flag != 0 {
			result.KeyUsages = append(result.KeyUsages, name)
		}
	}

	// Parse extended key usages
	ekuMap := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageServerAuth:      "serverAuth",
		x509.ExtKeyUsageClientAuth:      "clientAuth",
		x509.ExtKeyUsageCodeSigning:     "codeSigning",
		x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping:    "timeStamping",
		x509.ExtKeyUsageOCSPSigning:     "ocspSigning",
	}

	for eku, name := range ekuMap {
		for _, extKU := range cert.ExtKeyUsage {
			if eku == extKU {
				result.ExtKeyUsages = append(result.ExtKeyUsages, name)
			}
		}
	}

	// Determine risk profiles
	result.IsSigningKey = (ku&x509.KeyUsageDigitalSignature != 0) ||
		(ku&x509.KeyUsageContentCommitment != 0)
	result.IsEncryptionKey = (ku&x509.KeyUsageKeyEncipherment != 0) ||
		(ku&x509.KeyUsageDataEncipherment != 0) ||
		(ku&x509.KeyUsageKeyAgreement != 0)
	result.IsCAKey = (ku&x509.KeyUsageCertSign != 0) || cert.IsCA

	// Classify the public key algorithm
	pubKeyAlgo, _ := extractPubKeyInfo(cert)
	baseZone := classifier.Classify(pubKeyAlgo)

	// Determine impact based on usage type
	var impacts []string

	if result.IsCAKey {
		result.SigningRisk = "CRITICAL"
		result.EncryptionRisk = "CRITICAL"
		impacts = append(impacts, "CA key — quantum adversary can forge entire certificate chains")
		result.Zone = models.ZoneRed
	} else {
		if result.IsSigningKey {
			if baseZone == models.ZoneRed {
				result.SigningRisk = "IMMEDIATE"
				impacts = append(impacts, "signing key uses quantum-vulnerable algorithm — signatures forgeable with quantum computer")
			} else if baseZone == models.ZoneYellow {
				result.SigningRisk = "FUTURE"
				impacts = append(impacts, "signing key needs monitoring for quantum readiness")
			} else {
				result.SigningRisk = "LOW"
			}
		}

		if result.IsEncryptionKey {
			if baseZone == models.ZoneRed {
				result.EncryptionRisk = "HNDL"
				impacts = append(impacts, "encryption key creates Harvest Now Decrypt Later (HNDL) exposure")
			} else if baseZone == models.ZoneYellow {
				result.EncryptionRisk = "MONITOR"
				impacts = append(impacts, "encryption key may need PQ migration before data lifetime expires")
			} else {
				result.EncryptionRisk = "LOW"
			}
		}

		result.Zone = baseZone
	}

	// Check for code signing EKU — these are extra critical
	for _, name := range result.ExtKeyUsages {
		if name == "codeSigning" && baseZone == models.ZoneRed {
			impacts = append(impacts, "code signing key — quantum adversary can sign malicious code")
			result.SigningRisk = "CRITICAL"
		}
		if name == "ocspSigning" && baseZone == models.ZoneRed {
			impacts = append(impacts, "OCSP signing key — quantum adversary can forge revocation status")
			result.SigningRisk = "CRITICAL"
		}
	}

	if len(impacts) > 0 {
		result.QuantumImpact = strings.Join(impacts, "; ")
	} else {
		result.QuantumImpact = "No quantum-sensitive key usage detected"
	}

	return result
}

// ──────────────────────────────────────────────────────────────────────────────
// PKI-5: Cross-Signed Certificate Detection
// ──────────────────────────────────────────────────────────────────────────────

// CrossSignInfo describes a certificate that may be cross-signed or has chain anomalies.
type CrossSignInfo struct {
	IsCrossSigned     bool        `json:"is_cross_signed"`
	IsSelfSigned      bool        `json:"is_self_signed"`
	SubjectKeyID      string      `json:"subject_key_id"`
	AuthorityKeyID    string      `json:"authority_key_id"`
	IssuerMismatch    bool        `json:"issuer_mismatch"`     // Issuer CN != AKI source
	ChainAlgoMismatch bool        `json:"chain_algo_mismatch"` // Chain uses mixed algorithms
	WeakestChainAlgo  string      `json:"weakest_chain_algo,omitempty"`
	Zone              models.Zone `json:"zone"`
	Warning           string      `json:"warning,omitempty"`
}

// detectCrossSignInfo analyzes a certificate chain for cross-signing patterns
// and algorithm consistency.
//
// Cross-signed certificates are a quantum risk because:
// 1. The cross-sign path may use a weaker algorithm than the primary path
// 2. An attacker only needs to break the weakest path to forge the chain
// 3. Cross-signing from a classical root to a PQ intermediate undermines the PQ security
func detectCrossSignInfo(certs []*x509.Certificate) []CrossSignInfo {
	results := make([]CrossSignInfo, len(certs))

	for i, cert := range certs {
		info := CrossSignInfo{}

		// Self-signed check
		info.IsSelfSigned = cert.AuthorityKeyId == nil ||
			equalBytes(cert.SubjectKeyId, cert.AuthorityKeyId)

		// Subject/Authority key IDs
		info.SubjectKeyID = fmt.Sprintf("%x", cert.SubjectKeyId)
		info.AuthorityKeyID = fmt.Sprintf("%x", cert.AuthorityKeyId)

		// Cross-sign detection: issuer DN doesn't match any cert in the provided chain
		if !info.IsSelfSigned && len(certs) > 1 {
			issuerFound := false
			for _, other := range certs {
				if equalBytes(other.SubjectKeyId, cert.AuthorityKeyId) {
					issuerFound = true
					break
				}
			}
			if !issuerFound {
				info.IsCrossSigned = true
				info.Warning = "Certificate may be cross-signed — issuer not in provided chain. Cross-sign path may use a weaker algorithm."
			}
		}

		// Algorithm consistency within the chain
		if i > 0 {
			prevSigAlgo := certs[i-1].SignatureAlgorithm.String()
			thisSigAlgo := cert.SignatureAlgorithm.String()
			prevZone := classifier.Classify(prevSigAlgo)
			thisZone := classifier.Classify(thisSigAlgo)

			if prevZone != thisZone {
				info.ChainAlgoMismatch = true
				if thisZone == models.ZoneRed || prevZone == models.ZoneRed {
					info.WeakestChainAlgo = thisSigAlgo
					if prevZone == models.ZoneRed {
						info.WeakestChainAlgo = prevSigAlgo
					}
					info.Warning = fmt.Sprintf("Chain algorithm mismatch: %s (%s) vs %s (%s) — quantum security limited by weakest link",
						prevSigAlgo, prevZone, thisSigAlgo, thisZone)
				}
			}
		}

		// Overall zone: worst-case from all detected issues
		info.Zone = models.ZoneGreen
		if info.ChainAlgoMismatch || info.IsCrossSigned {
			info.Zone = models.ZoneYellow
		}
		if info.ChainAlgoMismatch && info.WeakestChainAlgo != "" {
			info.Zone = classifier.Classify(info.WeakestChainAlgo)
		}

		results[i] = info
	}

	return results
}

// equalBytes compares two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ──────────────────────────────────────────────────────────────────────────────
// PKI-2: CRL Distribution Point Analysis
// ──────────────────────────────────────────────────────────────────────────────

// CRLAnalysis captures quantum risk of CRL distribution infrastructure.
type CRLAnalysis struct {
	HasCRLDistPoints bool        `json:"has_crl_dist_points"`
	DistPoints       []string    `json:"dist_points,omitempty"`
	UsesHTTP         bool        `json:"uses_http"` // HTTP (not HTTPS) = MitM risk
	Zone             models.Zone `json:"zone"`
	Warning          string      `json:"warning,omitempty"`
}

// analyzeCRLDistPoints checks certificate CRL distribution points.
//
// CRL distribution points represent a quantum risk surface because:
// 1. CRLs are signed — a quantum adversary can forge CRL signatures
// 2. HTTP distribution points are vulnerable to MitM replacement
// 3. Revoked-cert suppression: adversary could forge a CRL that omits a revocation
func analyzeCRLDistPoints(cert *x509.Certificate) *CRLAnalysis {
	result := &CRLAnalysis{
		DistPoints: make([]string, 0),
	}

	if len(cert.CRLDistributionPoints) == 0 {
		result.Zone = models.ZoneYellow
		result.Warning = "No CRL distribution points — revocation checking relies solely on OCSP"
		return result
	}

	result.HasCRLDistPoints = true

	for _, dp := range cert.CRLDistributionPoints {
		result.DistPoints = append(result.DistPoints, dp)
		if strings.HasPrefix(dp, "http://") {
			result.UsesHTTP = true
		}
	}

	// The CRL itself is signed with the CA's key — check if the CA's sig algo is quantum-safe
	sigAlgo := cert.SignatureAlgorithm.String()
	sigZone := classifier.Classify(sigAlgo)

	if result.UsesHTTP && sigZone == models.ZoneRed {
		result.Zone = models.ZoneRed
		result.Warning = fmt.Sprintf("CRL served over HTTP with quantum-vulnerable signature (%s) — adversary can forge+replace CRL via MitM", sigAlgo)
	} else if sigZone == models.ZoneRed {
		result.Zone = models.ZoneRed
		result.Warning = fmt.Sprintf("CRL signed with quantum-vulnerable algorithm (%s) — adversary can forge revocation status", sigAlgo)
	} else if result.UsesHTTP {
		result.Zone = models.ZoneYellow
		result.Warning = "CRL served over HTTP — vulnerable to MitM but signature algorithm is quantum-resistant"
	} else {
		result.Zone = models.ZoneGreen
	}

	return result
}

// ──────────────────────────────────────────────────────────────────────────────
// Certificate Validity Compliance
// ──────────────────────────────────────────────────────────────────────────────

// CertValidityCheck assesses certificate lifetime against industry baselines.
type CertValidityCheck struct {
	TotalDays       int         `json:"total_days"`
	RemainingDays   int         `json:"remaining_days"`
	IsExpired       bool        `json:"is_expired"`
	ExceedsBaseline bool        `json:"exceeds_baseline"` // >398 days violates CA/B Forum BR
	ExceedsFederal  bool        `json:"exceeds_federal"`  // >825 days exceeds federal recommendations
	Zone            models.Zone `json:"zone"`
	Warning         string      `json:"warning,omitempty"`
}

// checkCertValidity evaluates a certificate's validity period against compliance baselines.
func checkCertValidity(cert *x509.Certificate) *CertValidityCheck {
	totalDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	remainingDays := int(cert.NotAfter.Sub(timeNow()).Hours() / 24)
	if remainingDays < 0 {
		remainingDays = 0
	}

	result := &CertValidityCheck{
		TotalDays:       totalDays,
		RemainingDays:   remainingDays,
		IsExpired:       remainingDays <= 0,
		ExceedsBaseline: totalDays > 398,
		ExceedsFederal:  totalDays > 825,
	}

	switch {
	case result.IsExpired:
		result.Zone = models.ZoneRed
		result.Warning = "Certificate expired"
	case result.ExceedsFederal && !cert.IsCA:
		result.Zone = models.ZoneYellow
		result.Warning = fmt.Sprintf("Certificate validity (%d days) exceeds federal recommendations (825 days) — increases HNDL exposure window", totalDays)
	case result.ExceedsBaseline && !cert.IsCA:
		result.Zone = models.ZoneYellow
		result.Warning = fmt.Sprintf("Certificate validity (%d days) exceeds CA/Browser Forum Baseline (398 days)", totalDays)
	default:
		result.Zone = models.ZoneGreen
	}

	return result
}

// timeNow is a package-level variable for testability.
var timeNow = timeNowReal

func timeNowReal() time.Time { return time.Now() }

// ──────────────────────────────────────────────────────────────────────────────
// Enhanced PKI Result Structure
// ──────────────────────────────────────────────────────────────────────────────

// PKIEnhancedResult extends a single certificate analysis with deep quantum context.
type PKIEnhancedResult struct {
	// Base info
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	SerialNumber  string `json:"serial_number"`
	Position      string `json:"position"` // leaf, intermediate, root
	SignatureAlgo string `json:"signature_algo"`
	PublicKeyAlgo string `json:"public_key_algo"`
	KeySize       int    `json:"key_size"`

	// Sprint enhancements
	KeyUsageRisk  *KeyUsageRisk      `json:"key_usage_risk"`
	HNDLExposure  *CertHNDLExposure  `json:"hndl_exposure"`
	CRLAnalysis   *CRLAnalysis       `json:"crl_analysis"`
	ValidityCheck *CertValidityCheck `json:"validity_check"`
	CrossSignInfo *CrossSignInfo     `json:"cross_sign_info,omitempty"`
}

// AnalyzePKIEnhanced performs the enhanced PKI analysis on a set of certificates.
// This represents the deep-dive quantum assessment — beyond what any other scanner does.
func AnalyzePKIEnhanced(certs []*x509.Certificate, quantumYear int) []PKIEnhancedResult {
	results := make([]PKIEnhancedResult, len(certs))

	// Detect cross-sign patterns across the chain
	crossSignInfos := detectCrossSignInfo(certs)

	for i, cert := range certs {
		position := "leaf"
		if cert.IsCA {
			if cert.Issuer.CommonName == cert.Subject.CommonName {
				position = "root"
			} else {
				position = "intermediate"
			}
		}

		pubKeyAlgo, keySize := extractPubKeyInfo(cert)

		results[i] = PKIEnhancedResult{
			Subject:       cert.Subject.CommonName,
			Issuer:        cert.Issuer.CommonName,
			SerialNumber:  cert.SerialNumber.String(),
			Position:      position,
			SignatureAlgo: cert.SignatureAlgorithm.String(),
			PublicKeyAlgo: pubKeyAlgo,
			KeySize:       keySize,

			KeyUsageRisk:  classifyKeyUsageRisk(cert),
			HNDLExposure:  calculateCertHNDLExposure(cert, quantumYear),
			CRLAnalysis:   analyzeCRLDistPoints(cert),
			ValidityCheck: checkCertValidity(cert),
		}

		if i < len(crossSignInfos) {
			results[i].CrossSignInfo = &crossSignInfos[i]
		}
	}

	return results
}
