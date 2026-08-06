// hndl_engine.go implements the HNDL Risk Quantification Engine.
//
// Patent: PQCAT-P002 — Automated quantification of Harvest Now, Decrypt Later
// (HNDL) exposure risk using a multi-factor scoring model that combines:
//   - Cryptographic algorithm strength (from scan results)
//   - Data sensitivity classification (FIPS 199)
//   - Data retention requirements (regulatory framework)
//   - Quantum computing timeline projections
//
// This is the DEFINING FEATURE that separates a PQC compliance tool from a
// generic TLS scanner. No other tool quantifies per-asset HNDL exposure as
// a numeric score.
//
// Formula: HNDL_Risk = f(crypto_strength × data_sensitivity × exposure_window × attack_surface)
//
// Copyright (c) 2026 Soqucoin Labs Inc. All rights reserved.
package scanner

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// HNDL Framework Profiles
// ──────────────────────────────────────────────────────────────────────────────

// HNDLProfile defines quantum timeline and data retention parameters for a
// specific regulatory framework.
type HNDLProfile struct {
	QuantumYear   int    `json:"quantum_year"`
	RetentionDays int    `json:"retention_days"` // -1 = indefinite (treated as 36500 = 100 years)
	Name          string `json:"name"`
	// Framework-specific CNSA 2.0 enforcement milestones
	EnforcementYear int `json:"enforcement_year,omitempty"`
}

// hndlFrameworkProfiles maps framework identifiers to their HNDL parameters.
// Quantum year estimates are based on NIST/NSA published guidance and industry consensus.
// NOTE: this is the HNDL *Risk Score* engine (a 0-100 composite with a
// per-framework threat horizon), which is a DIFFERENT metric from the HNDL
// *Exposure Multiplier* in internal/compliance/hndl.go (a retention-driven
// 1.0-6.0 companion weight anchored to the CNSA 2.0 2035 planning horizon).
// They intentionally differ: this models framework-specific threat-arrival
// years; the multiplier models the mandate planning horizon. Surfaces must
// label them distinctly ("HNDL Risk Score" vs "HNDL Exposure ×") so the two
// are never read as the same number. Retention days reflect regulatory minima.
var hndlFrameworkProfiles = map[string]HNDLProfile{
	// Federal / Defense
	"cnsa2":   {QuantumYear: 2033, RetentionDays: 3650, EnforcementYear: 2033, Name: "CNSA 2.0 (NSA)"},
	"fisma":   {QuantumYear: 2035, RetentionDays: 36500, EnforcementYear: 2035, Name: "FISMA (federal indefinite)"}, // Essentially indefinite
	"fedramp": {QuantumYear: 2033, RetentionDays: 2555, EnforcementYear: 2033, Name: "FedRAMP"},
	"cmmc":    {QuantumYear: 2033, RetentionDays: 3650, EnforcementYear: 2033, Name: "CMMC Level 3"},

	// Financial
	"pci":   {QuantumYear: 2030, RetentionDays: 365, EnforcementYear: 2030, Name: "PCI DSS 4.0"},
	"sox":   {QuantumYear: 2032, RetentionDays: 2555, EnforcementYear: 2032, Name: "SOX"},
	"nydfs": {QuantumYear: 2030, RetentionDays: 1825, EnforcementYear: 2030, Name: "NYDFS 500"},
	"swift": {QuantumYear: 2030, RetentionDays: 1825, EnforcementYear: 2030, Name: "SWIFT CSP"},

	// Healthcare
	"hipaa": {QuantumYear: 2032, RetentionDays: 2190, EnforcementYear: 2032, Name: "HIPAA"},

	// Timeline scenarios (no specific framework)
	"aggressive":   {QuantumYear: 2029, RetentionDays: 3650, Name: "Aggressive timeline (2029)"},
	"conservative": {QuantumYear: 2037, RetentionDays: 1825, Name: "Conservative timeline (2037)"},
}

// GetHNDLProfile returns the HNDL profile for a framework identifier.
// Returns the cnsa2 profile as default if the framework is not found.
func GetHNDLProfile(framework string) HNDLProfile {
	framework = strings.ToLower(strings.TrimSpace(framework))
	if p, ok := hndlFrameworkProfiles[framework]; ok {
		return p
	}
	return hndlFrameworkProfiles["cnsa2"] // Default: CNSA 2.0
}

// IsValidHNDLFramework reports whether framework has a defined HNDL profile.
// Callers that accept a user-supplied framework should validate with this and
// reject unknowns rather than letting GetHNDLProfile silently default to CNSA 2.0.
func IsValidHNDLFramework(framework string) bool {
	_, ok := hndlFrameworkProfiles[strings.ToLower(strings.TrimSpace(framework))]
	return ok
}

// ListHNDLFrameworks returns all available framework identifiers.
func ListHNDLFrameworks() []string {
	keys := make([]string, 0, len(hndlFrameworkProfiles))
	for k := range hndlFrameworkProfiles {
		keys = append(keys, k)
	}
	return keys
}

// ──────────────────────────────────────────────────────────────────────────────
// HNDL Engine Input/Output Types
// ──────────────────────────────────────────────────────────────────────────────

// HNDLSensitivity represents FIPS 199 data classification levels.
type HNDLSensitivity string

const (
	HNDLSensitivityLow      HNDLSensitivity = "LOW"
	HNDLSensitivityModerate HNDLSensitivity = "MODERATE"
	HNDLSensitivityHigh     HNDLSensitivity = "HIGH"
)

// ParseHNDLSensitivity converts a string to HNDLSensitivity.
func ParseHNDLSensitivity(s string) HNDLSensitivity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH", "H":
		return HNDLSensitivityHigh
	case "LOW", "L":
		return HNDLSensitivityLow
	default:
		return HNDLSensitivityModerate
	}
}

// HNDLAsset represents a single cryptographic asset for HNDL assessment.
type HNDLAsset struct {
	Name       string      `json:"name"`
	Algorithm  string      `json:"algorithm"`
	Zone       models.Zone `json:"zone"`
	KeyBits    int         `json:"key_bits,omitempty"`
	ExpiryDays int         `json:"expiry_days"` // -1 if N/A (e.g., key exchange has no expiry)
	Source     string      `json:"source"`      // "tls", "ssh", "pki", "code", "config"
}

// HNDLEngineInput contains all inputs for the HNDL risk calculation.
type HNDLEngineInput struct {
	Sensitivity HNDLSensitivity `json:"sensitivity"`
	Framework   string          `json:"framework"`
	Profile     HNDLProfile     `json:"profile"`
	Assets      []HNDLAsset     `json:"assets"`
	// Optional overrides
	CustomRetentionDays int `json:"custom_retention_days,omitempty"` // 0 = use profile default
	CustomQuantumYear   int `json:"custom_quantum_year,omitempty"`   // 0 = use profile default
}

// HNDLAssetRisk is the per-asset HNDL risk assessment.
type HNDLAssetRisk struct {
	Name           string `json:"name"`
	Algorithm      string `json:"algorithm"`
	Zone           string `json:"zone"`
	Source         string `json:"source"`
	HNDLWindowDays int    `json:"hndl_window_days"` // Days of exposure past quantum timeline
	Risk           string `json:"risk"`             // CRITICAL, HIGH, MODERATE, LOW, NONE
}

// HNDLEngineResult is the complete HNDL risk assessment output.
type HNDLEngineResult struct {
	// Aggregate score
	OverallScore int    `json:"overall_score"` // 0-100
	RiskLevel    string `json:"risk_level"`    // CRITICAL, HIGH, MODERATE, LOW

	// Input parameters (for reproducibility)
	Profile     HNDLProfile     `json:"profile"`
	Sensitivity HNDLSensitivity `json:"sensitivity"`
	Framework   string          `json:"framework"`

	// Component scores (transparent breakdown)
	CryptoScore      int `json:"crypto_score"`      // 0-40
	SensitivityScore int `json:"sensitivity_score"` // 0-30
	ExposureScore    int `json:"exposure_score"`    // 0-20
	SurfaceScore     int `json:"surface_score"`     // 0-10

	// Key metrics
	ExposureWindowDays int `json:"exposure_window_days"` // Max days of HNDL exposure
	DaysUntilQuantum   int `json:"days_until_quantum"`
	VulnerableAssets   int `json:"vulnerable_assets"`
	TotalAssets        int `json:"total_assets"`
	PQCompliantAssets  int `json:"pq_compliant_assets"`

	// Human-readable output
	Summary         string   `json:"summary"`
	Recommendations []string `json:"recommendations"`

	// Per-asset breakdown
	PerAssetRisk []HNDLAssetRisk `json:"per_asset_risk,omitempty"`
}

// ──────────────────────────────────────────────────────────────────────────────
// HNDL Engine Core
// ──────────────────────────────────────────────────────────────────────────────

// CalculateHNDLRisk computes the aggregate HNDL risk score.
//
// The scoring formula is a weighted composite of four factors:
//
//	Crypto Strength (0-40):  How quantum-vulnerable are the discovered algorithms?
//	Data Sensitivity (0-30): How valuable is the protected data? (FIPS 199)
//	Exposure Window (0-20):  How long is data at risk past the quantum timeline?
//	Attack Surface (0-10):   How many vulnerable endpoints exist?
//
// Total: 0-100. Risk levels: CRITICAL (>80), HIGH (>60), MODERATE (>40), LOW (≤40)
//
// Patent: PQCAT-P002 claim 1 — Time-domain risk scoring
func CalculateHNDLRisk(input HNDLEngineInput) *HNDLEngineResult {
	result := &HNDLEngineResult{
		Framework:   input.Framework,
		Sensitivity: input.Sensitivity,
		TotalAssets: len(input.Assets),
	}

	// Resolve effective profile (apply overrides)
	profile := input.Profile
	if input.CustomQuantumYear > 0 {
		profile.QuantumYear = input.CustomQuantumYear
	}
	if input.CustomRetentionDays > 0 {
		profile.RetentionDays = input.CustomRetentionDays
	}
	// Treat indefinite (-1) as 100 years
	if profile.RetentionDays < 0 {
		profile.RetentionDays = 36500
	}
	result.Profile = profile

	now := time.Now()
	daysUntilQuantum := int(time.Date(profile.QuantumYear, 1, 1, 0, 0, 0, 0, time.UTC).Sub(now).Hours() / 24)
	if daysUntilQuantum < 0 {
		daysUntilQuantum = 0
	}
	result.DaysUntilQuantum = daysUntilQuantum

	// ── Factor 1: Crypto Strength (0-40) ─────────────────────────────────
	// Weighted average of asset quantum zones:
	//   RED = 1.0, YELLOW = 0.5, GREEN = 0.0
	// Score = (weighted_avg * 40)
	var redCount, yellowCount, greenCount int
	for _, asset := range input.Assets {
		switch asset.Zone {
		case models.ZoneRed:
			redCount++
		case models.ZoneYellow:
			yellowCount++
		case models.ZoneGreen:
			greenCount++
		}
	}
	result.VulnerableAssets = redCount + yellowCount
	result.PQCompliantAssets = greenCount

	cryptoWeighted := 0.0
	if len(input.Assets) > 0 {
		cryptoWeighted = (float64(redCount)*1.0 + float64(yellowCount)*0.5) / float64(len(input.Assets))
	}
	result.CryptoScore = int(math.Round(cryptoWeighted * 40))

	// ── Factor 2: Data Sensitivity (0-30) ────────────────────────────────
	// FIPS 199 classification:
	//   HIGH = 30 (classified, financial PII, health records)
	//   MODERATE = 20 (business confidential, internal data)
	//   LOW = 10 (public-facing, marketing)
	switch input.Sensitivity {
	case HNDLSensitivityHigh:
		result.SensitivityScore = 30
	case HNDLSensitivityModerate:
		result.SensitivityScore = 20
	case HNDLSensitivityLow:
		result.SensitivityScore = 10
	}

	// ── Factor 3: Exposure Window (0-20) ─────────────────────────────────
	// How long does data remain decryptable AFTER quantum computers arrive?
	// exposure_window = max(0, data_retention_days - days_until_quantum)
	//
	// Patent: PQCAT-P002 claim 2 — Per-asset HNDL exposure window
	exposureWindow := profile.RetentionDays - daysUntilQuantum
	if exposureWindow < 0 {
		exposureWindow = 0
	}
	result.ExposureWindowDays = exposureWindow

	switch {
	case exposureWindow > 3650: // >10 years of exposure
		result.ExposureScore = 20
	case exposureWindow > 1825: // >5 years
		result.ExposureScore = 15
	case exposureWindow > 365: // >1 year
		result.ExposureScore = 10
	case exposureWindow > 0:
		result.ExposureScore = 5
	default:
		result.ExposureScore = 0
	}

	// ── Factor 4: Attack Surface (0-10) ──────────────────────────────────
	// How many quantum-vulnerable assets were discovered?
	switch {
	case redCount > 50:
		result.SurfaceScore = 10
	case redCount > 20:
		result.SurfaceScore = 7
	case redCount > 5:
		result.SurfaceScore = 4
	case redCount > 0:
		result.SurfaceScore = 2
	default:
		result.SurfaceScore = 0
	}

	// ── Aggregate Score ──────────────────────────────────────────────────
	result.OverallScore = result.CryptoScore + result.SensitivityScore + result.ExposureScore + result.SurfaceScore
	if result.OverallScore > 100 {
		result.OverallScore = 100
	}

	switch {
	case result.OverallScore > 80:
		result.RiskLevel = "CRITICAL"
	case result.OverallScore > 60:
		result.RiskLevel = "HIGH"
	case result.OverallScore > 40:
		result.RiskLevel = "MODERATE"
	default:
		result.RiskLevel = "LOW"
	}

	// ── Per-Asset Risk Breakdown ─────────────────────────────────────────
	// Patent: PQCAT-P002 claim 2 — Per-asset HNDL exposure window
	for _, asset := range input.Assets {
		// HNDL exposure window is driven by how long the DATA stays sensitive
		// (retention), NOT by certificate expiry (Wave 3b, ruling Decision 2).
		// A 90-day cert protecting 25-year data still has a 25-year HNDL window,
		// so the previous "cap by cert expiry" — which collapsed the window to ~0
		// for normal short-lived certs — is removed.
		assetWindow := profile.RetentionDays - daysUntilQuantum
		if assetWindow < 0 {
			assetWindow = 0
		}

		risk := "NONE"
		if asset.Zone == models.ZoneGreen {
			risk = "NONE"
			assetWindow = 0
		} else {
			switch {
			case assetWindow > 365*3:
				risk = "CRITICAL"
			case assetWindow > 365:
				risk = "HIGH"
			case assetWindow > 0:
				risk = "MODERATE"
			default:
				risk = "LOW"
			}
		}

		result.PerAssetRisk = append(result.PerAssetRisk, HNDLAssetRisk{
			Name:           asset.Name,
			Algorithm:      asset.Algorithm,
			Zone:           string(asset.Zone),
			Source:         asset.Source,
			HNDLWindowDays: assetWindow,
			Risk:           risk,
		})
	}

	// ── Summary ──────────────────────────────────────────────────────────
	result.Summary = generateHNDLSummary(result)
	result.Recommendations = generateHNDLRecommendations(result)

	return result
}

// ──────────────────────────────────────────────────────────────────────────────
// Summary and Recommendations Generation
// ──────────────────────────────────────────────────────────────────────────────

func generateHNDLSummary(r *HNDLEngineResult) string {
	pqPct := 0.0
	if r.TotalAssets > 0 {
		pqPct = float64(r.PQCompliantAssets) / float64(r.TotalAssets) * 100
	}

	var parts []string

	// Risk headline
	switch r.RiskLevel {
	case "CRITICAL":
		parts = append(parts, fmt.Sprintf("CRITICAL HNDL RISK (Score: %d/100)", r.OverallScore))
	case "HIGH":
		parts = append(parts, fmt.Sprintf("HIGH HNDL RISK (Score: %d/100)", r.OverallScore))
	case "MODERATE":
		parts = append(parts, fmt.Sprintf("MODERATE HNDL RISK (Score: %d/100)", r.OverallScore))
	case "LOW":
		parts = append(parts, fmt.Sprintf("LOW HNDL RISK (Score: %d/100)", r.OverallScore))
	}

	// Asset summary
	parts = append(parts, fmt.Sprintf("%d of %d cryptographic assets are quantum-vulnerable (%.0f%% PQ-compliant).",
		r.VulnerableAssets, r.TotalAssets, pqPct))

	// Exposure window
	if r.ExposureWindowDays > 0 {
		years := float64(r.ExposureWindowDays) / 365.25
		parts = append(parts, fmt.Sprintf(
			"At %s sensitivity with %s timelines, data captured today will be decryptable in ~%.1f years (%d-day exposure window past %d quantum horizon).",
			r.Sensitivity, r.Profile.Name, years, r.ExposureWindowDays, r.Profile.QuantumYear))
	} else {
		parts = append(parts, fmt.Sprintf(
			"Data retention period (%d days) expires before the %d quantum timeline. Direct HNDL exposure is limited, but sensitive data may persist in backups or archives.",
			r.Profile.RetentionDays, r.Profile.QuantumYear))
	}

	return strings.Join(parts, " ")
}

func generateHNDLRecommendations(r *HNDLEngineResult) []string {
	var recs []string

	if r.CryptoScore >= 30 {
		recs = append(recs, "Deploy ML-KEM hybrid key exchange (X25519+ML-KEM-768) on all TLS/SSH endpoints — this is the single highest-impact mitigation for HNDL attacks (CNSA 2.0 §3.1)")
	}

	if r.CryptoScore >= 20 {
		recs = append(recs, "Migrate server certificates to ML-DSA-65 or hybrid signatures — eliminates quantum forgery risk for authentication (CNSA 2.0 §4.2, required by 2030 for NSS)")
	}

	if r.ExposureScore >= 15 {
		recs = append(recs, fmt.Sprintf("URGENT: %d-day HNDL exposure window exceeds 5 years — prioritize PQ migration for systems handling %s-sensitivity data",
			r.ExposureWindowDays, r.Sensitivity))
	}

	if r.SurfaceScore >= 7 {
		recs = append(recs, fmt.Sprintf("Reduce attack surface: %d quantum-vulnerable assets detected — implement a phased migration plan with quarterly milestones",
			r.VulnerableAssets))
	}

	if r.SensitivityScore >= 30 {
		recs = append(recs, "HIGH sensitivity data classification requires immediate HNDL mitigation — consider data-at-rest re-encryption with AES-256 and PQ key wrapping")
	}

	if r.CryptoScore > 0 {
		recs = append(recs, "Rotate all encryption keys to CNSA 2.0-approved algorithms (AES-256 minimum for symmetric, ML-KEM-768+ for key exchange)")
	}

	// Always recommend monitoring
	recs = append(recs, "Establish continuous PQ compliance monitoring — re-scan quarterly to track HNDL risk score trend and migration progress")

	return recs
}

// ──────────────────────────────────────────────────────────────────────────────
// CLI Display Helper
// ──────────────────────────────────────────────────────────────────────────────

// FormatHNDLCLI returns a formatted string for CLI display of HNDL results.
func FormatHNDLCLI(r *HNDLEngineResult) string {
	var sb strings.Builder

	// Header bar
	riskEmoji := "🟢"
	switch r.RiskLevel {
	case "CRITICAL":
		riskEmoji = "🔴"
	case "HIGH":
		riskEmoji = "🟠"
	case "MODERATE":
		riskEmoji = "🟡"
	}

	sb.WriteString(fmt.Sprintf("\n%s HNDL Risk Score: %d/100 (%s)\n", riskEmoji, r.OverallScore, r.RiskLevel))
	sb.WriteString(fmt.Sprintf("   Framework: %s | Sensitivity: %s | Quantum Year: %d\n",
		r.Profile.Name, r.Sensitivity, r.Profile.QuantumYear))
	sb.WriteString(fmt.Sprintf("   Days until quantum: %d | Exposure window: %d days\n",
		r.DaysUntilQuantum, r.ExposureWindowDays))
	sb.WriteString("\n")

	// Score breakdown
	sb.WriteString("   Score Breakdown:\n")
	sb.WriteString(fmt.Sprintf("   ├─ Crypto Strength:   %2d / 40  (%d RED, %d YELLOW, %d GREEN assets)\n",
		r.CryptoScore, r.VulnerableAssets-countYellow(r), countYellow(r), r.PQCompliantAssets))
	sb.WriteString(fmt.Sprintf("   ├─ Data Sensitivity:  %2d / 30  (FIPS 199: %s)\n",
		r.SensitivityScore, r.Sensitivity))
	sb.WriteString(fmt.Sprintf("   ├─ Exposure Window:   %2d / 20  (%d days past quantum horizon)\n",
		r.ExposureScore, r.ExposureWindowDays))
	sb.WriteString(fmt.Sprintf("   └─ Attack Surface:    %2d / 10  (%d vulnerable assets)\n",
		r.SurfaceScore, r.VulnerableAssets))
	sb.WriteString("\n")

	// Recommendations
	if len(r.Recommendations) > 0 {
		sb.WriteString("   Recommendations:\n")
		for i, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("   %d. %s\n", i+1, rec))
		}
	}

	return sb.String()
}

func countYellow(r *HNDLEngineResult) int {
	count := 0
	for _, a := range r.PerAssetRisk {
		if a.Zone == string(models.ZoneYellow) {
			count++
		}
	}
	return count
}
