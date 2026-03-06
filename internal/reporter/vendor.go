// Package reporter provides vendor supply chain PQC risk analysis.
// Aggregates SBOM findings per vendor/supplier and produces a
// risk matrix showing each vendor's quantum readiness posture.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// VendorReport is the complete supply chain risk analysis.
type VendorReport struct {
	GeneratedAt   time.Time        `json:"generated_at"`
	Target        string           `json:"target"`
	TotalVendors  int              `json:"total_vendors"`
	HighRiskCount int              `json:"high_risk_count"`
	Vendors       []VendorScore    `json:"vendors"`
	RiskBreakdown VendorRiskMatrix `json:"risk_breakdown"`
}

// VendorScore represents a single vendor's PQC risk posture.
type VendorScore struct {
	VendorName   string   `json:"vendor_name"`
	Components   int      `json:"components"`
	TotalAssets  int      `json:"total_assets"`
	RedAssets    int      `json:"red_assets"`
	YellowAssets int      `json:"yellow_assets"`
	GreenAssets  int      `json:"green_assets"`
	PQCScore     float64  `json:"pqc_score"`
	RiskLevel    string   `json:"risk_level"` // "CRITICAL", "HIGH", "MODERATE", "LOW"
	TopIssues    []string `json:"top_issues"`
}

// VendorRiskMatrix summarizes vendor risk distribution.
type VendorRiskMatrix struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
}

// GenerateVendorReport analyzes scan results and groups findings by vendor.
// For SBOM scans, vendors are extracted from component metadata.
// For TLS/PKI scans, vendors are extracted from certificate issuers.
func GenerateVendorReport(result *models.ScanResult) *VendorReport {
	report := &VendorReport{
		GeneratedAt: time.Now(),
		Target:      result.Target,
	}

	// Group assets by vendor
	vendorAssets := make(map[string][]models.CryptoAsset)

	for _, asset := range result.Assets {
		vendor := extractVendor(asset)
		vendorAssets[vendor] = append(vendorAssets[vendor], asset)
	}

	// Score each vendor
	for vendorName, assets := range vendorAssets {
		vs := VendorScore{
			VendorName:  vendorName,
			TotalAssets: len(assets),
		}

		// Track unique components
		components := make(map[string]bool)
		issues := make(map[string]int)

		for _, a := range assets {
			switch a.Zone {
			case models.ZoneRed:
				vs.RedAssets++
				issues[a.Algorithm]++
			case models.ZoneYellow:
				vs.YellowAssets++
			case models.ZoneGreen:
				vs.GreenAssets++
			}
			if a.Location != "" {
				components[a.Location] = true
			}
		}

		vs.Components = len(components)
		if vs.Components == 0 {
			vs.Components = 1
		}

		// Calculate score (same formula as compliance)
		if vs.TotalAssets > 0 {
			vs.PQCScore = 100.0 * (1.0 - float64(vs.RedAssets*10+vs.YellowAssets*6)/float64(vs.TotalAssets*10))
			if vs.PQCScore < 0 {
				vs.PQCScore = 0
			}
		}

		// Risk level
		switch {
		case vs.PQCScore >= 80:
			vs.RiskLevel = "LOW"
			report.RiskBreakdown.Low++
		case vs.PQCScore >= 60:
			vs.RiskLevel = "MODERATE"
			report.RiskBreakdown.Moderate++
		case vs.PQCScore >= 40:
			vs.RiskLevel = "HIGH"
			report.RiskBreakdown.High++
			report.HighRiskCount++
		default:
			vs.RiskLevel = "CRITICAL"
			report.RiskBreakdown.Critical++
			report.HighRiskCount++
		}

		// Top issues
		type issueCount struct {
			algo  string
			count int
		}
		var sortedIssues []issueCount
		for algo, count := range issues {
			sortedIssues = append(sortedIssues, issueCount{algo, count})
		}
		sort.Slice(sortedIssues, func(i, j int) bool {
			return sortedIssues[i].count > sortedIssues[j].count
		})
		for i, ic := range sortedIssues {
			if i >= 3 {
				break
			}
			vs.TopIssues = append(vs.TopIssues, fmt.Sprintf("%dx %s", ic.count, ic.algo))
		}

		report.Vendors = append(report.Vendors, vs)
	}

	// Sort by score ascending (worst vendors first)
	sort.Slice(report.Vendors, func(i, j int) bool {
		return report.Vendors[i].PQCScore < report.Vendors[j].PQCScore
	})

	report.TotalVendors = len(report.Vendors)
	return report
}

// extractVendor determines the vendor/supplier from asset metadata.
func extractVendor(asset models.CryptoAsset) string {
	// Check details map first
	if asset.Details != nil {
		if vendor, ok := asset.Details["vendor"]; ok && vendor != "" {
			return vendor
		}
		if publisher, ok := asset.Details["publisher"]; ok && publisher != "" {
			return publisher
		}
		if issuer, ok := asset.Details["issuer"]; ok && issuer != "" {
			return issuer
		}
	}

	// For TLS/PKI, extract from certificate issuer in location
	if asset.Type == models.AssetTLSCert || asset.Type == models.AssetPKICert {
		loc := asset.Location
		// Extract cert name portion like "cert 0: WE1" → "WE1"
		if idx := strings.Index(loc, "cert "); idx >= 0 {
			sub := loc[idx:]
			if colonIdx := strings.Index(sub, ": "); colonIdx >= 0 {
				name := sub[colonIdx+2:]
				if endIdx := strings.IndexAny(name, ")"); endIdx >= 0 {
					return strings.TrimSpace(name[:endIdx])
				}
				return strings.TrimSpace(name)
			}
		}
	}

	// For SBOM, extract from component name
	if asset.Type == models.AssetSBOMDep {
		if asset.Details != nil {
			if comp, ok := asset.Details["component"]; ok {
				// Extract org from component like "org.bouncycastle:bcprov-jdk15on" → "org.bouncycastle"
				if colonIdx := strings.Index(comp, ":"); colonIdx >= 0 {
					return comp[:colonIdx]
				}
				return comp
			}
		}
	}

	// Fallback: extract hostname or basename from location
	loc := asset.Location
	if hostIdx := strings.Index(loc, ":"); hostIdx > 0 {
		return loc[:hostIdx]
	}

	return "Unknown"
}

// WriteVendorJSON writes the vendor risk report to JSON.
func WriteVendorJSON(path string, report *VendorReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// PrintVendorTerminal prints a vendor risk summary to terminal.
func PrintVendorTerminal(report *VendorReport) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("  VENDOR SUPPLY CHAIN PQC RISK ANALYSIS")
	fmt.Printf("  PQCAT v%s\n", version)
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Printf("  Target:    %s\n", report.Target)
	fmt.Printf("  Vendors:   %d analyzed\n", report.TotalVendors)
	fmt.Printf("  High Risk: %d vendors\n", report.HighRiskCount)
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Println()

	fmt.Println("  RISK MATRIX")
	fmt.Printf("  ● CRITICAL: %d   ● HIGH: %d   ● MODERATE: %d   ● LOW: %d\n",
		report.RiskBreakdown.Critical, report.RiskBreakdown.High,
		report.RiskBreakdown.Moderate, report.RiskBreakdown.Low)
	fmt.Println()

	fmt.Println("  VENDOR DETAIL")
	fmt.Println("  ────────────────────────────────────────────────────────")
	for _, v := range report.Vendors {
		marker := "●"
		switch v.RiskLevel {
		case "CRITICAL":
			marker = "◉"
		case "HIGH":
			marker = "●"
		}
		fmt.Printf("  %s %-30s  Score: %3.0f  [%s]\n", marker, v.VendorName, v.PQCScore, v.RiskLevel)
		if len(v.TopIssues) > 0 {
			fmt.Printf("    Issues: %s\n", strings.Join(v.TopIssues, ", "))
		}
	}
	fmt.Println("  ────────────────────────────────────────────────────────")
	fmt.Println()
}
