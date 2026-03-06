// Package scanner provides quantum computing threat intelligence.
// Tracks quantum computing milestones, estimates Q-Day timelines,
// and adjusts risk assessment based on adversary capability forecasts.
package scanner

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"time"
)

// ThreatIntel represents the current quantum threat landscape.
type ThreatIntel struct {
	LastUpdated     time.Time              `json:"last_updated"`
	QDayEstimate    QDayForecast           `json:"qday_estimate"`
	Milestones      []QuantumMilestone     `json:"milestones"`
	RiskAdjustments []ThreatRiskAdjustment `json:"risk_adjustments"`
	AdversaryStatus AdversaryAssessment    `json:"adversary_status"`
	KeyInsights     []string               `json:"key_insights"`
}

// QDayForecast provides estimated timelines for cryptographically relevant quantum computers.
type QDayForecast struct {
	OptimisticYear   int     `json:"optimistic_year"`   // Earliest credible estimate
	MedianYear       int     `json:"median_year"`       // Most likely estimate
	ConservativeYear int     `json:"conservative_year"` // Latest credible estimate
	Confidence       float64 `json:"confidence"`        // 0-1 confidence in median
	Source           string  `json:"source"`
	LastRevised      string  `json:"last_revised"`
}

// QuantumMilestone tracks a significant quantum computing achievement.
type QuantumMilestone struct {
	Date          string `json:"date"`
	Entity        string `json:"entity"`
	Achievement   string `json:"achievement"`
	Impact        string `json:"impact"` // "LOW", "MEDIUM", "HIGH"
	LogicalQubits int    `json:"logical_qubits,omitempty"`
}

// ThreatRiskAdjustment recommends score modifications based on threat intel.
type ThreatRiskAdjustment struct {
	AlgorithmClass string  `json:"algorithm_class"` // "RSA", "ECDSA", "AES"
	AdjustmentPct  float64 `json:"adjustment_pct"`  // Percentage to increase urgency
	Reason         string  `json:"reason"`
}

// AdversaryAssessment summarizes nation-state quantum capabilities.
type AdversaryAssessment struct {
	Tier1                  []string `json:"tier_1"`                    // Active quantum programs with significant funding
	Tier2                  []string `json:"tier_2"`                    // Developing quantum capabilities
	HarvestNowDecryptLater bool     `json:"harvest_now_decrypt_later"` // HNDL active
	EstimatedHNDLSince     int      `json:"estimated_hndl_since"`      // Year
}

// GetThreatIntel returns the current quantum threat intelligence assessment.
// This uses a curated static database that should be updated with each PQCAT release.
// Future versions will support live feeds from CISA, NIST, and quantum research aggregators.
func GetThreatIntel() *ThreatIntel {
	return &ThreatIntel{
		LastUpdated: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		QDayEstimate: QDayForecast{
			OptimisticYear:   2030,
			MedianYear:       2035,
			ConservativeYear: 2040,
			Confidence:       0.65,
			Source:           "Aggregate of RAND, Global Risk Institute, Quantum Economic Development Consortium estimates",
			LastRevised:      "March 2026",
		},
		Milestones: []QuantumMilestone{
			{
				Date:          "2024-12-09",
				Entity:        "Google",
				Achievement:   "Willow chip: 105 physical qubits, exponential error reduction with scale",
				Impact:        "MEDIUM",
				LogicalQubits: 0,
			},
			{
				Date:        "2024-08-14",
				Entity:      "NIST",
				Achievement: "Published final PQC standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)",
				Impact:      "HIGH",
			},
			{
				Date:          "2024-05-23",
				Entity:        "Microsoft",
				Achievement:   "Achieved first logical qubit with Majorana-based topological approach",
				Impact:        "MEDIUM",
				LogicalQubits: 1,
			},
			{
				Date:          "2024-02-01",
				Entity:        "IBM",
				Achievement:   "Heron processor: 133 qubits with 10x performance improvement in error mitigation",
				Impact:        "MEDIUM",
				LogicalQubits: 0,
			},
			{
				Date:          "2023-12-04",
				Entity:        "IBM",
				Achievement:   "Condor: 1,121 superconducting qubits (largest to date)",
				Impact:        "LOW",
				LogicalQubits: 0,
			},
			{
				Date:          "2023-06-15",
				Entity:        "QuEra",
				Achievement:   "48 logical qubits via neutral atom platform with error correction",
				Impact:        "MEDIUM",
				LogicalQubits: 48,
			},
			{
				Date:        "2022-01-19",
				Entity:      "White House",
				Achievement: "NSM-10 signed: Federal agencies directed to inventory and migrate crypto",
				Impact:      "HIGH",
			},
			{
				Date:        "2022-09-01",
				Entity:      "NSA",
				Achievement: "CNSA 2.0 published: Timeline for federal PQC migration",
				Impact:      "HIGH",
			},
		},
		RiskAdjustments: []ThreatRiskAdjustment{
			{
				AlgorithmClass: "RSA",
				AdjustmentPct:  15.0,
				Reason:         "RSA is the primary target of Shor's algorithm. Progress in error correction accelerates timeline for factoring.",
			},
			{
				AlgorithmClass: "ECDSA",
				AdjustmentPct:  15.0,
				Reason:         "ECDLP equally vulnerable to Shor's. Smaller key sizes mean fewer qubits required to break.",
			},
			{
				AlgorithmClass: "Ed25519",
				AdjustmentPct:  12.0,
				Reason:         "EdDSA over Curve25519 vulnerable to quantum. Widely used in SSH — broad attack surface.",
			},
			{
				AlgorithmClass: "AES-128",
				AdjustmentPct:  5.0,
				Reason:         "Grover's halves symmetric security. AES-128 drops to 64-bit effective. AES-256 recommended.",
			},
			{
				AlgorithmClass: "AES-256",
				AdjustmentPct:  0.0,
				Reason:         "AES-256 provides 128-bit post-quantum security. No adjustment needed.",
			},
		},
		AdversaryStatus: AdversaryAssessment{
			Tier1: []string{
				"China (significant state investment, >$15B estimated)",
				"United States (DARPA, DOE national labs, private sector)",
				"European Union (Quantum Flagship, >1B EUR)",
			},
			Tier2: []string{
				"Russia (limited public programs, classified efforts unknown)",
				"United Kingdom (National Quantum Computing Centre)",
				"Canada (significant academic and private sector programs)",
				"Japan (Riken, national quantum strategy)",
				"South Korea (Samsung, government quantum plan)",
			},
			HarvestNowDecryptLater: true,
			EstimatedHNDLSince:     2015,
		},
		KeyInsights: []string{
			"Harvest-now-decrypt-later (HNDL) is active: classified data encrypted today with RSA/ECDSA can be stored and decrypted when quantum computers mature.",
			"Error correction breakthroughs (Google Willow, QuEra) suggest logical qubit counts are scaling faster than physical qubit counts.",
			"China's quantum computing investment exceeds $15B — classified programs may be further ahead than public demonstrations suggest.",
			"NIST PQC standards are final (Aug 2024). There are no more excuses to delay migration planning.",
			"The migration itself takes 3-7 years for large enterprises. Starting in 2026 means finishing by 2029-2033 — within CNSA 2.0 deadlines.",
		},
	}
}

// CalculateThreatMultiplier returns a risk multiplier based on current threat intel.
// Applied to the overall score to factor in adversary capability progression.
func CalculateThreatMultiplier(intel *ThreatIntel) float64 {
	now := time.Now()
	currentYear := now.Year()

	// How close are we to Q-Day median?
	yearsToQDay := float64(intel.QDayEstimate.MedianYear - currentYear)

	if yearsToQDay <= 0 {
		return 1.5 // Past estimated Q-Day
	}

	// Logarithmic urgency: closer to Q-Day = higher multiplier
	// At 10+ years: multiplier ≈ 1.0
	// At 5 years: multiplier ≈ 1.15
	// At 3 years: multiplier ≈ 1.25
	// At 1 year: multiplier ≈ 1.4
	multiplier := 1.0 + (0.5 / math.Exp(yearsToQDay/5.0))

	// Factor in HNDL — if active, data is already being harvested
	if intel.AdversaryStatus.HarvestNowDecryptLater {
		multiplier += 0.05
	}

	return math.Round(multiplier*100) / 100
}

// WriteThreatIntelJSON writes the threat intel assessment to a JSON file.
func WriteThreatIntelJSON(path string, intel *ThreatIntel) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(intel)
}

// PrintThreatIntelTerminal displays threat intel in the terminal.
func PrintThreatIntelTerminal(intel *ThreatIntel) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("  QUANTUM THREAT INTELLIGENCE BRIEFING")
	fmt.Printf("  Last Updated: %s\n", intel.LastUpdated.Format("January 2006"))
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println()

	// Q-Day forecast
	fmt.Println("  Q-DAY FORECAST (Cryptographically Relevant Quantum Computer)")
	fmt.Printf("    Optimistic:   %d\n", intel.QDayEstimate.OptimisticYear)
	fmt.Printf("    Median:       %d  (%.0f%% confidence)\n", intel.QDayEstimate.MedianYear, intel.QDayEstimate.Confidence*100)
	fmt.Printf("    Conservative: %d\n", intel.QDayEstimate.ConservativeYear)
	fmt.Printf("    Source: %s\n", intel.QDayEstimate.Source)
	fmt.Println()

	// Adversary status
	fmt.Println("  ADVERSARY ASSESSMENT")
	fmt.Println("  Tier 1 (Active programs, significant funding):")
	for _, a := range intel.AdversaryStatus.Tier1 {
		fmt.Printf("    • %s\n", a)
	}
	if intel.AdversaryStatus.HarvestNowDecryptLater {
		fmt.Printf("  ⚠ HNDL ACTIVE: Nation-state collection of encrypted data estimated since %d\n",
			intel.AdversaryStatus.EstimatedHNDLSince)
	}
	fmt.Println()

	// Recent milestones
	fmt.Println("  RECENT MILESTONES")
	sorted := make([]QuantumMilestone, len(intel.Milestones))
	copy(sorted, intel.Milestones)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Date > sorted[j].Date
	})
	for _, m := range sorted[:min(5, len(sorted))] {
		fmt.Printf("    [%s] %s: %s\n", m.Impact, m.Date, m.Achievement)
	}
	fmt.Println()

	// Risk multiplier
	multiplier := CalculateThreatMultiplier(intel)
	fmt.Printf("  RISK MULTIPLIER: %.2fx (applied to urgency calculations)\n", multiplier)
	fmt.Println()

	// Key insights
	fmt.Println("  KEY INSIGHTS")
	for i, insight := range intel.KeyInsights {
		fmt.Printf("    %d. %s\n", i+1, insight)
	}
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println()
}

