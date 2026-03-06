package compliance

import (
	"testing"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// TestScore_EmptyAssets verifies empty scan returns 100.
func TestScore_EmptyAssets(t *testing.T) {
	score := Score(nil, FrameworkCNSA2)
	if score.Overall != 100 {
		t.Errorf("Score(nil) = %.1f, want 100.0", score.Overall)
	}
	if score.TotalAssets != 0 {
		t.Errorf("Score(nil).TotalAssets = %d, want 0", score.TotalAssets)
	}
}

// TestScore_AllGreen verifies all-green assets score 100.
func TestScore_AllGreen(t *testing.T) {
	assets := []models.CryptoAsset{
		{Algorithm: "ML-KEM-768", Zone: models.ZoneGreen, Type: models.AssetTLSCert},
		{Algorithm: "ML-DSA-65", Zone: models.ZoneGreen, Type: models.AssetTLSCert},
	}
	score := Score(assets, FrameworkCNSA2)
	if score.Overall != 100 {
		t.Errorf("Score(all-green) = %.1f, want 100.0", score.Overall)
	}
}

// TestScore_AllRed verifies all-red assets score low.
func TestScore_AllRed(t *testing.T) {
	assets := []models.CryptoAsset{
		{Algorithm: "RSA-2048", Zone: models.ZoneRed, Type: models.AssetTLSCert, Criticality: models.CriticalityStandard},
		{Algorithm: "ECDSA-P256", Zone: models.ZoneRed, Type: models.AssetTLSCert, Criticality: models.CriticalityStandard},
	}

	for _, fw := range []Framework{FrameworkNSM10, FrameworkCNSA2, FrameworkSP800131A, FrameworkFISMA, FrameworkFedRAMP} {
		score := Score(assets, fw)
		if score.Overall >= 95 {
			t.Errorf("Score(all-red, %s) = %.1f, want < 95", fw, score.Overall)
		}
	}
}

// TestScore_CriticalityWeighting verifies NSS assets produce lower scores than STANDARD.
func TestScore_CriticalityWeighting(t *testing.T) {
	standard := []models.CryptoAsset{
		{Zone: models.ZoneRed, Type: models.AssetTLSCert, Criticality: models.CriticalityStandard},
	}
	nss := []models.CryptoAsset{
		{Zone: models.ZoneRed, Type: models.AssetTLSCert, Criticality: models.CriticalityNSS},
	}

	scoreStd := Score(standard, FrameworkCNSA2)
	scoreNSS := Score(nss, FrameworkCNSA2)

	if scoreNSS.Overall >= scoreStd.Overall {
		t.Errorf("NSS score (%.1f) should be lower than STANDARD score (%.1f)", scoreNSS.Overall, scoreStd.Overall)
	}
}

// TestScore_ZoneCounts verifies zone counting.
func TestScore_ZoneCounts(t *testing.T) {
	assets := []models.CryptoAsset{
		{Zone: models.ZoneRed}, {Zone: models.ZoneRed}, {Zone: models.ZoneRed},
		{Zone: models.ZoneYellow},
		{Zone: models.ZoneGreen}, {Zone: models.ZoneGreen},
	}

	score := Score(assets, FrameworkCNSA2)
	if score.ZoneCounts[models.ZoneRed] != 3 {
		t.Errorf("red count = %d, want 3", score.ZoneCounts[models.ZoneRed])
	}
	if score.ZoneCounts[models.ZoneYellow] != 1 {
		t.Errorf("yellow count = %d, want 1", score.ZoneCounts[models.ZoneYellow])
	}
	if score.ZoneCounts[models.ZoneGreen] != 2 {
		t.Errorf("green count = %d, want 2", score.ZoneCounts[models.ZoneGreen])
	}
	if score.TotalAssets != 6 {
		t.Errorf("total = %d, want 6", score.TotalAssets)
	}
}

// TestScore_AllFrameworks verifies all 5 frameworks produce valid scores.
func TestScore_AllFrameworks(t *testing.T) {
	assets := []models.CryptoAsset{
		{Zone: models.ZoneRed, Type: models.AssetTLSCert, Criticality: models.CriticalityStandard},
	}

	frameworks := []Framework{FrameworkNSM10, FrameworkCNSA2, FrameworkSP800131A, FrameworkFISMA, FrameworkFedRAMP}
	for _, fw := range frameworks {
		score := Score(assets, fw)
		if score.Overall < 0 || score.Overall > 100 {
			t.Errorf("Score(%s) = %.1f, out of [0,100] range", fw, score.Overall)
		}
		if score.Framework != string(fw) {
			t.Errorf("Score(%s).Framework = %s", fw, score.Framework)
		}
	}
}

// TestScore_PerAssetUrgency verifies CNSA 2.0 per-asset urgency differentiation.
func TestScore_PerAssetUrgency(t *testing.T) {
	// SBOM deps have earlier CNSA 2.0 deadline (2025, past due) than TLS (2027)
	sbom := []models.CryptoAsset{
		{Zone: models.ZoneRed, Type: models.AssetSBOMDep, Criticality: models.CriticalityStandard},
	}
	tls := []models.CryptoAsset{
		{Zone: models.ZoneRed, Type: models.AssetTLSCert, Criticality: models.CriticalityStandard},
	}

	scoreSBOM := Score(sbom, FrameworkCNSA2)
	scoreTLS := Score(tls, FrameworkCNSA2)

	// SBOM should score lower because its deadline has already passed (3.5x urgency)
	if scoreSBOM.Overall >= scoreTLS.Overall {
		t.Errorf("SBOM score (%.1f) should be lower than TLS score (%.1f) due to past-due CNSA 2.0 deadline",
			scoreSBOM.Overall, scoreTLS.Overall)
	}
}

// TestNextDeadline verifies deadline milestones for all frameworks.
func TestNextDeadline(t *testing.T) {
	frameworks := []Framework{FrameworkNSM10, FrameworkCNSA2, FrameworkSP800131A, FrameworkFISMA, FrameworkFedRAMP}
	for _, fw := range frameworks {
		dl := nextDeadline(fw)
		// At least some deadlines should still be upcoming
		if dl != nil {
			if dl.DaysLeft <= 0 {
				t.Logf("Framework %s: deadline %s has passed (%d days)", fw, dl.Milestone, dl.DaysLeft)
			}
			if dl.Framework != string(fw) {
				t.Errorf("nextDeadline(%s).Framework = %s", fw, dl.Framework)
			}
		}
	}
}
