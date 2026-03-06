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
