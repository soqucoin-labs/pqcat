// Package classifier provides algorithm classification against CNSA 2.0 and federal PQC standards.
package classifier

import (
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// Classify returns the Zone (RED/YELLOW/GREEN) for a given algorithm string.
func Classify(algorithm string) models.Zone {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))

	if isGreen(alg) {
		return models.ZoneGreen
	}
	if isYellow(alg) {
		return models.ZoneYellow
	}
	if isSymmetricSafe(alg) {
		return models.ZoneGreen
	}
	return models.ZoneRed
}

// ClassifyWithReason returns the zone plus a human-readable justification.
func ClassifyWithReason(algorithm string) (models.Zone, string) {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))

	if isGreen(alg) {
		return models.ZoneGreen, "CNSA 2.0 compliant — approved post-quantum algorithm"
	}
	if isYellow(alg) {
		return models.ZoneYellow, "Transitional — hybrid or insufficient security level for NSS"
	}

	reason := "Quantum vulnerable — broken by Shor's algorithm on a cryptographically relevant quantum computer"
	if containsAny(alg, []string{"AES", "SHA-256", "SHA-384", "SHA-512", "SHA3"}) {
		reason = "Symmetric/hash algorithm — quantum resistant via Grover's (halved security), but not a PQC signature/KEM"
	}

	return models.ZoneRed, reason
}

// isGreen checks if the algorithm is CNSA 2.0 / FIPS 203/204/205 compliant.
func isGreen(alg string) bool {
	greenAlgorithms := []string{
		// FIPS 203 — Key Encapsulation
		"ML-KEM-768", "ML-KEM-1024", "MLKEM768", "MLKEM1024",
		"KYBER768", "KYBER1024", // Legacy names
		// FIPS 204 — Digital Signatures
		"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "MLDSA44", "MLDSA65", "MLDSA87",
		"DILITHIUM2", "DILITHIUM3", "DILITHIUM5", // Legacy names
		// FIPS 205 — Hash-Based Signatures
		"SLH-DSA-128S", "SLH-DSA-128F", "SLH-DSA-192S", "SLH-DSA-192F",
		"SLH-DSA-256S", "SLH-DSA-256F",
		"SPHINCS+", // Legacy name
		// SP 800-208 — Stateful Hash-Based Signatures
		"LMS", "XMSS", "HSS",
	}
	return containsAny(alg, greenAlgorithms)
}

// isYellow checks if the algorithm is transitional (hybrid or Level 1 only).
func isYellow(alg string) bool {
	// Hybrid combinations
	if strings.Contains(alg, "+") || strings.Contains(alg, "HYBRID") {
		return true
	}

	yellowAlgorithms := []string{
		// ML-KEM-512 is Level 1 only — insufficient for NSS but acceptable transitionally
		"ML-KEM-512", "MLKEM512", "KYBER512",
	}
	return containsAny(alg, yellowAlgorithms)
}

// isSymmetricSafe checks if the algorithm is a symmetric cipher or hash function.
// Symmetric algorithms are not broken by Shor's algorithm — Grover's provides a
// quadratic speedup (halving effective security) but they remain safe.
// CNSA 2.0 approves AES-256 and SHA-384+.
//
// IMPORTANT: Algorithms like "ECDSA-SHA384" contain "SHA-384" but are asymmetric
// signature schemes — these must NOT be classified as symmetric-safe.
func isSymmetricSafe(alg string) bool {
	// Reject if the algorithm contains any asymmetric prefix
	asymmetricPrefixes := []string{"ECDSA", "RSA", "ECDH", "ED25519", "DSA", "DH-"}
	if containsAny(alg, asymmetricPrefixes) {
		return false
	}

	safeAlgorithms := []string{
		// Symmetric ciphers — quantum resistant
		"AES-256", "AES-128", "AES-192",
		"CHACHA20", "POLY1305",
		// Hash functions — quantum resistant (standalone)
		"SHA-256", "SHA-384", "SHA-512", "SHA3",
		"HMAC",
	}
	return containsAny(alg, safeAlgorithms)
}

// containsAny checks if the algorithm string contains any of the given substrings.
func containsAny(alg string, candidates []string) bool {
	for _, c := range candidates {
		if strings.Contains(alg, c) {
			return true
		}
	}
	return false
}

// RiskScore returns a numeric risk score for a zone (used in compliance scoring).
//
//	GREEN  = 0
//	YELLOW = 6
//	RED    = 10
func RiskScore(zone models.Zone) float64 {
	switch zone {
	case models.ZoneGreen:
		return 0
	case models.ZoneYellow:
		return 6
	case models.ZoneRed:
		return 10
	default:
		return 10
	}
}
