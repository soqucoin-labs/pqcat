// Package classifier provides algorithm classification against CNSA 2.0 and federal PQC standards.
package classifier

import (
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// Classify returns the Zone (RED/YELLOW/GREEN) for a given algorithm string.
func Classify(algorithm string) models.Zone {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))

	// Hybrid/transitional is checked BEFORE green: a hybrid such as
	// "RSA+ML-KEM-768" or "X25519MLKEM768" contains a green PQ name but still
	// offers a classical, Shor-breakable component, so it is transitional, not
	// fully quantum-safe (M19). GREEN means no classical KEX/signature remains.
	if isYellow(alg) {
		return models.ZoneYellow
	}
	if isGreen(alg) {
		return models.ZoneGreen
	}
	if isSymmetricSafe(alg) {
		return models.ZoneGreen
	}
	return models.ZoneRed
}

// ClassifyWithReason returns the zone plus a human-readable justification.
func ClassifyWithReason(algorithm string) (models.Zone, string) {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))

	// Hybrid/transitional first (M19): a classical+PQ combination is not fully
	// quantum-safe while the classical half remains negotiable.
	if isYellow(alg) {
		return models.ZoneYellow, "Transitional — hybrid or insufficient security level for NSS"
	}
	if isGreen(alg) {
		// M22: keep GREEN, but do not over-claim CNSA 2.0 for algorithms that are
		// quantum-safe yet not CNSA-preferred. Falcon (FN-DSA) is NIST-standardized
		// and quantum-safe; CNSA 2.0 simply prefers ML-DSA/SLH-DSA for signatures.
		if containsAny(alg, []string{"FALCON"}) {
			return models.ZoneGreen, "Quantum-safe (NIST-standardized FN-DSA/Falcon); CNSA 2.0 prefers ML-DSA/SLH-DSA for signatures"
		}
		return models.ZoneGreen, "NIST-approved post-quantum algorithm (CNSA 2.0)"
	}

	// Check for classically broken or deprecated algorithms
	if containsAny(alg, []string{"MD2", "MD4", "MD5", "SHA-0", "SHA0", "SHA-1", "SHA1", "DES", "3DES", "RC2", "RC4", "BLOWFISH"}) {
		return models.ZoneRed, "Classically broken or deprecated — prohibited by all modern standards"
	}
	if containsAny(alg, []string{"RIPEMD"}) {
		return models.ZoneRed, "RIPEMD-160 is below CNSA 2.0 minimum hash security — retire"
	}
	if containsAny(alg, []string{"TLS-1.0", "TLS-1.1", "SSL-3.0", "SSL-2.0"}) {
		return models.ZoneRed, "Deprecated TLS/SSL protocol version — prohibited by NIST SP 800-52 Rev. 2"
	}
	if containsAny(alg, []string{"WEAK-RNG"}) {
		return models.ZoneRed, "Non-cryptographic PRNG — must use CSPRNG for key generation, nonces, and secrets"
	}

	// Symmetric/hash algorithms are quantum resistant (Grover halves security, but remains safe)
	if isSymmetricSafe(alg) {
		return models.ZoneGreen, "Symmetric/hash algorithm — quantum resistant (Grover halves security, AES-256→128-bit equivalent)"
	}

	reason := "Quantum vulnerable — broken by Shor's algorithm on a cryptographically relevant quantum computer"
	if containsAny(alg, []string{"SCHNORR"}) {
		reason = "Schnorr signatures use ECC — broken by Shor's algorithm on a CRQC"
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
		// Falcon — NIST PQC alternate standard
		"FALCON-512", "FALCON-1024", "FALCON",
		// SP 800-208 — Stateful Hash-Based Signatures
		"LMS", "XMSS", "HSS",
	}
	return containsAny(alg, greenAlgorithms)
}

// isYellow checks if the algorithm is transitional (hybrid or Level 1 only).
func isYellow(alg string) bool {
	// Explicit hybrid markers. A '+' counts as a hybrid separator only when it sits
	// BETWEEN two components (e.g. "RSA+ML-KEM-768"); a trailing '+' is part of a
	// name like "SPHINCS+" (legacy SLH-DSA) and must not read as hybrid.
	if i := strings.Index(alg, "+"); i > 0 && i < len(alg)-1 {
		return true
	}
	if strings.Contains(alg, "HYBRID") {
		return true
	}

	// Implicit hybrid: a PQ algorithm named together with a classical asymmetric
	// one, even without a '+' (e.g. the TLS group "X25519MLKEM768"). While the
	// classical half is negotiable it is still Shor-breakable attack surface, so
	// this is transitional, not fully quantum-safe (M19; matches the M38 GREEN
	// definition on the scanner/remediation surfaces).
	classical := []string{"X25519", "X448", "RSA", "ECDH", "ECDSA", "SECP", "P-256", "P-384", "P-521", "CURVE25519", "ED25519", "DH-"}
	pq := []string{"ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "SLH-DSA", "SPHINCS", "FALCON"}
	if containsAny(alg, classical) && containsAny(alg, pq) {
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
	asymmetricPrefixes := []string{
		"ECDSA", "RSA", "ECDH", "ED25519", "ED448", "DSA", "DH-",
		"SCHNORR", "SECP256K1", "X25519", "X448", "CURVE25519",
		// Classical asymmetric encryption/KEM schemes — Shor-breakable key
		// establishment. Without these, names like "ECIES-AES-256-GCM" or
		// "ElGamal/AES-256" ride the AES-256 substring to a false GREEN (M21).
		"ECIES", "ELGAMAL", "PAILLIER", "RABIN", "CRAMER-SHOUP", "GOLDWASSER",
	}
	if containsAny(alg, asymmetricPrefixes) {
		return false
	}

	// Reject classically broken algorithms and deprecated protocols. "SHA1"
	// (dashless) is listed alongside "SHA-1" so MAC/composite names like
	// "HMAC-SHA1" are caught rather than riding the "HMAC" safe substring (M20).
	brokenAlgorithms := []string{"MD2", "MD4", "MD5", "SHA-0", "SHA0", "SHA-1", "SHA1", "DES", "3DES", "RC2", "RC4", "BLOWFISH", "RIPEMD", "TLS-1.0", "TLS-1.1", "SSL-3.0", "SSL-2.0"}
	if containsAny(alg, brokenAlgorithms) {
		return false
	}

	safeAlgorithms := []string{
		// Symmetric ciphers — quantum resistant
		"AES-256", "AES-128", "AES-192",
		"CHACHA20", "POLY1305", "XSALSA20",
		// Non-cryptographic hashes (safe)
		"SIPHASH", "MUHASH",
		// Hash functions — quantum resistant (standalone)
		"SHA-256", "SHA-384", "SHA-512", "SHA3",
		"SHAKE",
		"HMAC",
		// Password hashing / KDFs — symmetric, quantum resistant
		"BCRYPT", "ARGON2", "SCRYPT", "PBKDF2",
		// Cryptographically Secure PRNGs — quantum resistant
		"CSPRNG",
		// NOTE: EVP-CRYPTO intentionally excluded — OpenSSL EVP wraps both
		// quantum-safe and quantum-vulnerable algorithms. Unresolved EVP
		// usage must classify as YELLOW (unknown), not GREEN.
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
