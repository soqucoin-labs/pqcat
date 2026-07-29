package classifier

import (
	"testing"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// TestClassify_GreenAlgorithms verifies CNSA 2.0 compliant algorithms are GREEN.
func TestClassify_GreenAlgorithms(t *testing.T) {
	greenCases := []struct{ algo string }{
		{"ML-KEM-768"}, {"ML-KEM-1024"}, {"MLKEM768"}, {"MLKEM1024"},
		{"KYBER768"}, {"KYBER1024"},
		{"ML-DSA-44"}, {"ML-DSA-65"}, {"ML-DSA-87"},
		{"DILITHIUM2"}, {"DILITHIUM3"}, {"DILITHIUM5"},
		{"SLH-DSA-128S"}, {"SLH-DSA-256F"},
		{"SPHINCS+"},
		{"LMS"}, {"XMSS"}, {"HSS"},
	}

	for _, tc := range greenCases {
		zone := Classify(tc.algo)
		if zone != models.ZoneGreen {
			t.Errorf("Classify(%q) = %s, want GREEN", tc.algo, zone)
		}
	}
}

// TestClassify_RedAlgorithms verifies quantum-vulnerable algorithms are RED.
func TestClassify_RedAlgorithms(t *testing.T) {
	redCases := []struct{ algo string }{
		{"RSA-2048"}, {"RSA-4096"},
		{"ECDSA-P256"}, {"ECDSA-P384"},
		{"Ed25519"},
		{"DSA-1024"},
		{"ECDHE-RSA"},
	}

	for _, tc := range redCases {
		zone := Classify(tc.algo)
		if zone != models.ZoneRed {
			t.Errorf("Classify(%q) = %s, want RED", tc.algo, zone)
		}
	}
}

// TestClassify_YellowAlgorithms verifies transitional algorithms are YELLOW.
func TestClassify_YellowAlgorithms(t *testing.T) {
	yellowCases := []struct{ algo string }{
		{"ML-KEM-512"}, {"MLKEM512"}, {"KYBER512"},
		{"HYBRID-RSA"}, // Hybrid keyword without a green algo name
	}

	for _, tc := range yellowCases {
		zone := Classify(tc.algo)
		if zone != models.ZoneYellow {
			t.Errorf("Classify(%q) = %s, want YELLOW", tc.algo, zone)
		}
	}
}

// TestClassify_SymmetricSafe verifies symmetric algorithms classified correctly.
func TestClassify_SymmetricSafe(t *testing.T) {
	greenSymmetric := []string{"AES-256", "AES-128", "CHACHA20", "SHA-256", "SHA-384", "SHA-512"}
	for _, algo := range greenSymmetric {
		zone := Classify(algo)
		if zone != models.ZoneGreen {
			t.Errorf("Classify(%q) = %s, want GREEN (symmetric-safe)", algo, zone)
		}
	}
}

// TestClassify_ECDSAWithHashNotSymmetric ensures ECDSA-SHA384 is not green.
func TestClassify_ECDSAWithHashNotSymmetric(t *testing.T) {
	dangerous := []string{"ECDSA-SHA384", "ECDSA-SHA256", "RSA-SHA512"}
	for _, algo := range dangerous {
		zone := Classify(algo)
		if zone == models.ZoneGreen {
			t.Errorf("Classify(%q) = GREEN — asymmetric algorithms must not be classified as symmetric-safe", algo)
		}
	}
}

// TestClassify_CaseInsensitive verifies case-insensitive matching.
func TestClassify_CaseInsensitive(t *testing.T) {
	cases := []struct {
		algo string
		want models.Zone
	}{
		{"ml-kem-768", models.ZoneGreen},
		{"Ml-Dsa-65", models.ZoneGreen},
		{"rsa-2048", models.ZoneRed},
		{"aes-256", models.ZoneGreen},
	}

	for _, tc := range cases {
		zone := Classify(tc.algo)
		if zone != tc.want {
			t.Errorf("Classify(%q) = %s, want %s", tc.algo, zone, tc.want)
		}
	}
}

// TestRiskScore verifies numeric risk scores per zone.
func TestRiskScore(t *testing.T) {
	cases := []struct {
		zone models.Zone
		want float64
	}{
		{models.ZoneGreen, 0},
		{models.ZoneYellow, 6},
		{models.ZoneRed, 10},
	}

	for _, tc := range cases {
		score := RiskScore(tc.zone)
		if score != tc.want {
			t.Errorf("RiskScore(%s) = %.0f, want %.0f", tc.zone, score, tc.want)
		}
	}
}

// TestClassifyWithReason verifies reason strings are returned.
func TestClassifyWithReason(t *testing.T) {
	zone, reason := ClassifyWithReason("RSA-2048")
	if zone != models.ZoneRed {
		t.Errorf("ClassifyWithReason(RSA-2048) zone = %s, want RED", zone)
	}
	if reason == "" {
		t.Error("ClassifyWithReason(RSA-2048) returned empty reason")
	}

	zone, reason = ClassifyWithReason("ML-KEM-768")
	if zone != models.ZoneGreen {
		t.Errorf("ClassifyWithReason(ML-KEM-768) zone = %s, want GREEN", zone)
	}
	if reason == "" {
		t.Error("ClassifyWithReason(ML-KEM-768) returned empty reason")
	}
}

// ═══════════════════════════════════════════════════════════════════
// v2.0.0 GAP-7: New algorithm string coverage
// ═══════════════════════════════════════════════════════════════════

// TestClassify_V2_WeakRNG_CSPRNG verifies WEAK-RNG is RED and CSPRNG is GREEN.
func TestClassify_V2_WeakRNG_CSPRNG(t *testing.T) {
	cases := []struct {
		algo string
		want models.Zone
	}{
		{"WEAK-RNG", models.ZoneRed},
		{"CSPRNG", models.ZoneGreen},
	}
	for _, tc := range cases {
		zone := Classify(tc.algo)
		if zone != tc.want {
			t.Errorf("Classify(%q) = %s, want %s", tc.algo, zone, tc.want)
		}
	}
}

// TestClassify_V2_PasswordHashing verifies password KDFs are GREEN (symmetric).
func TestClassify_V2_PasswordHashing(t *testing.T) {
	greenKDFs := []string{"Bcrypt", "Argon2", "Scrypt", "PBKDF2", "PBKDF2-SHA256"}
	for _, algo := range greenKDFs {
		zone := Classify(algo)
		if zone != models.ZoneGreen {
			t.Errorf("Classify(%q) = %s, want GREEN — password KDFs are quantum resistant", algo, zone)
		}
	}
}

// TestClassify_V2_DeprecatedProtocols verifies deprecated TLS/SSL is RED.
func TestClassify_V2_DeprecatedProtocols(t *testing.T) {
	redProtocols := []string{"TLS-1.0", "TLS-1.1", "SSL-3.0", "SSL-2.0"}
	for _, algo := range redProtocols {
		zone := Classify(algo)
		if zone != models.ZoneRed {
			t.Errorf("Classify(%q) = %s, want RED — deprecated protocol", algo, zone)
		}
	}
}

// TestClassify_V2_QuantumVulnerableAsymmetric verifies additional asymmetric algorithms are RED.
func TestClassify_V2_QuantumVulnerableAsymmetric(t *testing.T) {
	redAsymmetric := []string{
		"DH-2048", "X25519", "X448", "Ed448", "DSA-2048",
		"ECDH-P256", "ECDH-secp256k1", "ECDSA-secp256k1",
		"Schnorr-secp256k1",
	}
	for _, algo := range redAsymmetric {
		zone := Classify(algo)
		if zone != models.ZoneRed {
			t.Errorf("Classify(%q) = %s, want RED — quantum vulnerable asymmetric", algo, zone)
		}
	}
}

// TestClassify_V2_NonCryptoHashes verifies SipHash, MuHash are GREEN (symmetric).
func TestClassify_V2_NonCryptoHashes(t *testing.T) {
	greenHashes := []string{"SipHash", "MuHash-3072"}
	for _, algo := range greenHashes {
		zone := Classify(algo)
		if zone != models.ZoneGreen {
			t.Errorf("Classify(%q) = %s, want GREEN — non-crypto hash", algo, zone)
		}
	}
}

// TestClassify_V2_SymmetricCiphers verifies expanded symmetric ciphers are GREEN.
func TestClassify_V2_SymmetricCiphers(t *testing.T) {
	greenCiphers := []string{
		"ChaCha20-Poly1305", "XSalsa20-Poly1305", "Poly1305",
		"AES-256-GCM", "AES-256-CBC", "AES-128-CBC",
		"HMAC-SHA256", "HMAC-SHA512",
	}
	for _, algo := range greenCiphers {
		zone := Classify(algo)
		if zone != models.ZoneGreen {
			t.Errorf("Classify(%q) = %s, want GREEN — symmetric/HMAC cipher", algo, zone)
		}
	}
}

// TestClassify_V2_BrokenClassical verifies classically broken algorithms are RED.
func TestClassify_V2_BrokenClassical(t *testing.T) {
	redBroken := []string{
		"MD5", "SHA-1", "DES", "3DES", "RC4", "Blowfish", "RIPEMD-160",
	}
	for _, algo := range redBroken {
		zone := Classify(algo)
		if zone != models.ZoneRed {
			t.Errorf("Classify(%q) = %s, want RED — classically broken", algo, zone)
		}
	}
}

// TestClassify_V2_EVPCrypto verifies EVP-Crypto placeholder is NOT classified
// as GREEN — OpenSSL EVP wraps both quantum-safe and quantum-vulnerable algorithms.
func TestClassify_V2_EVPCrypto(t *testing.T) {
	zone := Classify("EVP-Crypto")
	if zone == models.ZoneGreen {
		t.Errorf("Classify(EVP-Crypto) = GREEN, but EVP wraps unsafe algorithms — expected YELLOW or RED")
	}
}

// TestClassifyWithReason_V2_Consistency ensures ClassifyWithReason returns the same
// zone as Classify for all algorithm strings. This was GAP-6 — previously
// ClassifyWithReason("AES-256") returned RED while Classify("AES-256") returned GREEN.
func TestClassifyWithReason_V2_Consistency(t *testing.T) {
	testAlgorithms := []string{
		// GREEN
		"ML-KEM-768", "ML-DSA-65", "SLH-DSA-128S", "LMS",
		"AES-256", "SHA-256", "HMAC-SHA256", "Bcrypt", "CSPRNG",
		"ChaCha20", "SipHash",
		// YELLOW
		"ML-KEM-512", "HYBRID-RSA",
		// RED
		"RSA-2048", "ECDSA-P256", "Ed25519", "DH-2048",
		"MD5", "SHA-1", "DES", "RC4", "WEAK-RNG", "TLS-1.0",
	}

	for _, algo := range testAlgorithms {
		zoneClassify := Classify(algo)
		zoneWithReason, reason := ClassifyWithReason(algo)
		if zoneClassify != zoneWithReason {
			t.Errorf("INCONSISTENCY: Classify(%q)=%s but ClassifyWithReason(%q)=(%s, %q)",
				algo, zoneClassify, algo, zoneWithReason, reason)
		}
		if reason == "" {
			t.Errorf("ClassifyWithReason(%q) returned empty reason", algo)
		}
	}
}
