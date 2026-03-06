// Package compliance provides PQC readiness scoring against federal frameworks.
package compliance

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// Framework identifies a compliance framework for scoring.
type Framework string

const (
	FrameworkNSM10     Framework = "nsm10"
	FrameworkCNSA2     Framework = "cnsa2"
	FrameworkSP800131A Framework = "sp800131a"
	FrameworkFISMA     Framework = "fisma"
	FrameworkFedRAMP   Framework = "fedramp"
)

// Score calculates a normalized 0-100 compliance score for a set of assets
// against the specified framework.
//
// Formula:
//
//	Score = 100 - (Σ(risk × urgency × criticality) / Σ(max_risk × max_urgency × max_criticality)) × 100
func Score(assets []models.CryptoAsset, framework Framework) models.ComplianceScore {
	if len(assets) == 0 {
		return models.ComplianceScore{
			Overall:     100,
			Framework:   string(framework),
			ZoneCounts:  map[models.Zone]int{models.ZoneGreen: 0, models.ZoneYellow: 0, models.ZoneRed: 0},
			TotalAssets: 0,
		}
	}

	// Count zones
	counts := map[models.Zone]int{
		models.ZoneGreen:  0,
		models.ZoneYellow: 0,
		models.ZoneRed:    0,
	}

	var weightedRisk float64
	var maxWeightedRisk float64

	for _, asset := range assets {
		counts[asset.Zone]++

		risk := classifier.RiskScore(asset.Zone)
		urgency := timelineUrgency(framework, asset.Type)
		crit := criticalityWeight(asset.Criticality)

		weightedRisk += risk * urgency * crit
		maxWeightedRisk += 10.0 * 3.0 * 3.0 // max possible per asset
	}

	var overall float64
	if maxWeightedRisk > 0 {
		overall = 100.0 - (weightedRisk/maxWeightedRisk)*100.0
	}
	overall = math.Round(overall*10) / 10 // One decimal place

	// Generate migration actions
	actions := generateActions(assets)

	// Find next deadline
	deadline := nextDeadline(framework)

	return models.ComplianceScore{
		Overall:      overall,
		Framework:    string(framework),
		ZoneCounts:   counts,
		TotalAssets:  len(assets),
		TopActions:   actions,
		NextDeadline: deadline,
	}
}

// timelineUrgency returns a multiplier based on framework deadline proximity.
// For CNSA 2.0, urgency varies per asset type (different deadlines for TLS vs firmware vs HSM).
func timelineUrgency(framework Framework, assetType ...models.AssetType) float64 {
	now := time.Now()

	// CNSA 2.0 has per-category deadlines
	if framework == FrameworkCNSA2 && len(assetType) > 0 {
		return cnsa2AssetUrgency(now, assetType[0])
	}

	deadlines := map[Framework]time.Time{
		FrameworkNSM10:     time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), // Migration plan due
		FrameworkCNSA2:     time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC), // Web/cloud due (default)
		FrameworkSP800131A: time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC), // Algorithm deprecation
		FrameworkFISMA:     time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC),  // FY27 PQC assessment
		FrameworkFedRAMP:   time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC), // Rev 5 PQC baseline
	}

	dl, ok := deadlines[framework]
	if !ok {
		return 1.0
	}

	return urgencyFromDeadline(now, dl)
}

// cnsa2AssetUrgency returns CNSA 2.0-specific urgency per asset category.
// CNSA 2.0 deadlines:
//   - Software/firmware signatures: 2025 (code signing, SBOM deps)
//   - Web browsers and cloud services: 2027 (TLS, SSH)
//   - PKI infrastructure and HSMs: 2030
//   - All remaining systems: 2033
func cnsa2AssetUrgency(now time.Time, aType models.AssetType) float64 {
	var deadline time.Time

	switch aType {
	case models.AssetCodeCrypto, models.AssetSBOMDep:
		deadline = time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC) // Software/firmware sigs
	case models.AssetTLSCert, models.AssetTLSCipher, models.AssetSSHHostKey, models.AssetSSHKEX:
		deadline = time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC) // Web/cloud
	case models.AssetPKICert, models.AssetHSMModule:
		deadline = time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC) // Infrastructure
	default:
		deadline = time.Date(2033, 12, 31, 0, 0, 0, 0, time.UTC) // All systems
	}

	return urgencyFromDeadline(now, deadline)
}

// urgencyFromDeadline calculates urgency multiplier from time remaining.
func urgencyFromDeadline(now time.Time, deadline time.Time) float64 {
	yearsLeft := deadline.Sub(now).Hours() / (24 * 365.25)
	switch {
	case yearsLeft < 0:
		return 3.5 // Past due — maximum urgency
	case yearsLeft < 1:
		return 3.0
	case yearsLeft < 3:
		return 2.0
	default:
		return 1.0
	}
}

// criticalityWeight converts Criticality to a numeric multiplier.
func criticalityWeight(c models.Criticality) float64 {
	switch c {
	case models.CriticalityNSS:
		return 3.0
	case models.CriticalityHVA:
		return 2.0
	default:
		return 1.0
	}
}

// generateActions creates prioritized migration recommendations from assets.
func generateActions(assets []models.CryptoAsset) []models.MigrationAction {
	// Group RED assets by algorithm
	algoGroups := make(map[string][]models.CryptoAsset)
	for _, a := range assets {
		if a.Zone == models.ZoneRed {
			algoGroups[a.Algorithm] = append(algoGroups[a.Algorithm], a)
		}
	}

	var actions []models.MigrationAction
	for algo, group := range algoGroups {
		actions = append(actions, models.MigrationAction{
			Description: fmt.Sprintf("Migrate %d %s assets to PQC equivalent", len(group), algo),
			AssetCount:  len(group),
			Complexity:  migrationComplexity(algo),
			Urgency:     "IMMEDIATE",
		})
	}

	// Sort by asset count descending
	sort.Slice(actions, func(i, j int) bool {
		return actions[i].AssetCount > actions[j].AssetCount
	})

	// Assign priorities and limit to top 5
	for i := range actions {
		actions[i].Priority = i + 1
	}
	if len(actions) > 5 {
		actions = actions[:5]
	}

	return actions
}

// migrationComplexity estimates effort based on the algorithm being replaced.
func migrationComplexity(algo string) string {
	alg := strings.ToUpper(algo)
	switch {
	case strings.Contains(alg, "RSA") && strings.Contains(alg, "KEX"):
		return "HIGH" // Key exchange changes affect protocol
	case strings.Contains(alg, "RSA"):
		return "MEDIUM" // Certificate re-issuance
	case strings.Contains(alg, "ECDSA"), strings.Contains(alg, "ECDHE"):
		return "MEDIUM"
	case strings.Contains(alg, "ED25519"):
		return "LOW" // Usually SSH keys, easy to rotate
	case strings.Contains(alg, "DSA"):
		return "LOW" // Long deprecated
	default:
		return "MEDIUM"
	}
}

// nextDeadline returns the nearest compliance deadline for a framework.
func nextDeadline(framework Framework) *models.ComplianceDeadline {
	now := time.Now()

	type deadline struct {
		milestone string
		date      time.Time
	}

	frameworkDeadlines := map[Framework][]deadline{
		FrameworkNSM10: {
			{"Cryptographic inventory complete", time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)},
			{"Migration plan submitted", time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)},
		},
		FrameworkCNSA2: {
			{"Software/firmware signatures migrated", time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)},
			{"Web and cloud services migrated", time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)},
			{"All systems migrated", time.Date(2033, 12, 31, 0, 0, 0, 0, time.UTC)},
		},
		FrameworkSP800131A: {
			{"Deprecated algorithms retired", time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)},
		},
		FrameworkFISMA: {
			{"Annual FISMA assessment with PQC inventory", time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)},
			{"OMB M-23-02 PQC migration plan submitted", time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)},
			{"PQC implementation progress reported to OMB", time.Date(2028, 9, 30, 0, 0, 0, 0, time.UTC)},
		},
		FrameworkFedRAMP: {
			{"FedRAMP Rev 5 baselines assessed for PQC gaps", time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)},
			{"CSP PQC transition plan in SSP/POA&M", time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)},
			{"FedRAMP PQC baseline requirements enforced", time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC)},
		},
	}

	dls, ok := frameworkDeadlines[framework]
	if !ok {
		return nil
	}

	for _, dl := range dls {
		if dl.date.After(now) {
			daysLeft := int(dl.date.Sub(now).Hours() / 24)
			return &models.ComplianceDeadline{
				Framework: string(framework),
				Milestone: dl.milestone,
				Deadline:  dl.date,
				DaysLeft:  daysLeft,
			}
		}
	}

	return nil
}
