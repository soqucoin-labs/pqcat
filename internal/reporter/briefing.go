// Package reporter provides executive briefing PDF generation.
// Creates a C-suite-ready strategic summary distinct from the tactical
// Crypto Bill of Health. Focuses on business risk, budget impact,
// and board-level recommendations.
package reporter

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// GenerateExecutiveBriefing creates a zero-dependency PDF executive briefing.
// Content: risk posture, budget impact, regulatory exposure, board recommendations.
func GenerateExecutiveBriefing(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// ── PDF 1.4 raw construction ──────────────────────────────────
	var objects []string
	var offsets []int
	pos := 0

	write := func(s string) {
		offsets = append(offsets, pos)
		n, _ := f.WriteString(s)
		pos += n
	}

	header := "%PDF-1.4\n"
	f.WriteString(header)
	pos = len(header)

	// Object 1: Catalog
	write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	objects = append(objects, "1")

	// Object 2: Pages
	write("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	objects = append(objects, "2")

	// Object 3: Page
	write("3 0 obj\n<< /Type /Page /Parent 2 0 R\n   /MediaBox [0 0 612 792]\n   /Contents 4 0 R\n   /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n")
	objects = append(objects, "3")

	// Build content stream
	now := time.Now()
	content := buildBriefingContent(result, score, now)

	write(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(content), content))
	objects = append(objects, "4")

	// Font objects
	write("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")
	objects = append(objects, "5")

	write("6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
	objects = append(objects, "6")

	// Cross-reference table
	xrefOffset := pos
	f.WriteString("xref\n")
	f.WriteString(fmt.Sprintf("0 %d\n", len(objects)+1))
	f.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		f.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}

	f.WriteString("trailer\n")
	f.WriteString(fmt.Sprintf("<< /Size %d /Root 1 0 R >>\n", len(objects)+1))
	f.WriteString("startxref\n")
	f.WriteString(fmt.Sprintf("%d\n", xrefOffset))
	f.WriteString("%%EOF\n")

	return nil
}

func buildBriefingContent(result *models.ScanResult, score *models.ComplianceScore, now time.Time) string {
	var sb strings.Builder

	// ── Page setup ──
	sb.WriteString("BT\n")

	// Title block — heavy professional header
	y := 730.0
	sb.WriteString(fmt.Sprintf("/F1 22 Tf\n72 %.0f Td\n(EXECUTIVE BRIEFING) Tj\n", y))
	y -= 28
	sb.WriteString(fmt.Sprintf("/F1 14 Tf\n0 -28 Td\n(Post-Quantum Cryptography Readiness Assessment) Tj\n"))
	y -= 20
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -20 Td\n(Prepared by Soqucoin Labs Inc. | PQCAT v%s | %s) Tj\n",
		version, now.Format("January 2, 2006")))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 9 Tf\n0 -14 Td\n(CONFIDENTIAL - FOR AUTHORIZED RECIPIENTS ONLY) Tj\n"))

	// Horizontal rule
	sb.WriteString("ET\n")
	y -= 10
	sb.WriteString(fmt.Sprintf("0.7 0.7 0.7 RG\n72 %.0f m 540 %.0f l S\n", y, y))
	y -= 25

	// ── Section 1: Risk Posture Summary ──
	sb.WriteString("BT\n")
	sb.WriteString(fmt.Sprintf("/F1 13 Tf\n72 %.0f Td\n(1. RISK POSTURE SUMMARY) Tj\n", y))
	y -= 20

	riskLevel := "MODERATE"
	riskColor := "amber"
	switch {
	case score.Overall >= 80:
		riskLevel = "LOW"
		riskColor = "green"
	case score.Overall >= 60:
		riskLevel = "MODERATE"
		riskColor = "amber"
	case score.Overall >= 40:
		riskLevel = "HIGH"
		riskColor = "red"
	default:
		riskLevel = "CRITICAL"
		riskColor = "red"
	}

	sb.WriteString(fmt.Sprintf("/F2 11 Tf\n0 -20 Td\n(Overall PQC Readiness: %.0f/100   |   Risk Level: %s \\(%s\\)) Tj\n",
		score.Overall, riskLevel, riskColor))
	y -= 16

	redCount := score.ZoneCounts[models.ZoneRed]
	yellowCount := score.ZoneCounts[models.ZoneYellow]
	greenCount := score.ZoneCounts[models.ZoneGreen]

	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -16 Td\n(Quantum-Vulnerable Assets: %d   |   Transitional: %d   |   Compliant: %d   |   Total: %d) Tj\n",
		redCount, yellowCount, greenCount, score.TotalAssets))
	y -= 16

	// Exposure statement
	exposurePct := 0.0
	if score.TotalAssets > 0 {
		exposurePct = float64(redCount) / float64(score.TotalAssets) * 100
	}
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -16 Td\n(%.0f%% of discovered cryptographic assets are vulnerable to quantum attack.) Tj\n", exposurePct))
	y -= 30

	// ── Section 2: Regulatory Exposure ──
	sb.WriteString(fmt.Sprintf("/F1 13 Tf\n0 -30 Td\n(2. REGULATORY EXPOSURE) Tj\n"))
	y -= 18

	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -18 Td\n(NSM-10: Migration plan required by Dec 2026. Non-compliance risks OMB reporting deficiency.) Tj\n"))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -14 Td\n(CNSA 2.0: Software/firmware by 2025, web/cloud by 2027, all systems by 2033.) Tj\n"))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -14 Td\n(FIPS 140-3: Modules using deprecated algorithms will lose validation status.) Tj\n"))

	if score.NextDeadline != nil {
		y -= 14
		sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -14 Td\n(Next milestone: %s in %d days.) Tj\n",
			score.NextDeadline.Milestone, score.NextDeadline.DaysLeft))
	}
	y -= 30

	// ── Section 3: Budget Impact Assessment ──
	sb.WriteString(fmt.Sprintf("/F1 13 Tf\n0 -30 Td\n(3. BUDGET IMPACT ASSESSMENT) Tj\n"))
	y -= 18

	// Estimate costs based on asset counts
	certCost := redCount * 500   // avg cert re-issuance
	infraCost := redCount * 2000 // infrastructure migration
	laborCost := redCount * 8000 // per-asset labor
	totalCost := certCost + infraCost + laborCost

	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -18 Td\n(Estimated migration cost for %d quantum-vulnerable assets:) Tj\n", redCount))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -14 Td\n(  Certificate re-issuance:  $%s) Tj\n", formatCurrency(certCost)))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -14 Td\n(  Infrastructure updates:   $%s) Tj\n", formatCurrency(infraCost)))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -14 Td\n(  Engineering labor:        $%s) Tj\n", formatCurrency(laborCost)))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F1 10 Tf\n0 -14 Td\n(  ESTIMATED TOTAL:          $%s) Tj\n", formatCurrency(totalCost)))
	y -= 14
	sb.WriteString(fmt.Sprintf("/F2 9 Tf\n0 -14 Td\n(Estimates based on federal agency migration benchmarks. Actual costs vary by system complexity.) Tj\n"))
	y -= 30

	// ── Section 4: Board Recommendations ──
	sb.WriteString(fmt.Sprintf("/F1 13 Tf\n0 -30 Td\n(4. BOARD RECOMMENDATIONS) Tj\n"))
	y -= 18

	recommendations := []string{
		"Authorize PQC migration program with dedicated program manager and FY27 budget allocation.",
		"Prioritize migration of public-facing TLS/SSH infrastructure (highest regulatory urgency).",
		"Establish continuous cryptographic monitoring to detect posture drift between assessments.",
		"Engage CMVP-validated PQC module vendors for HSM and key management upgrades.",
		"Submit updated cryptographic inventory to OMB per NSM-10 annual reporting requirement.",
	}

	for i, rec := range recommendations {
		sb.WriteString(fmt.Sprintf("/F2 10 Tf\n0 -18 Td\n(%d. %s) Tj\n", i+1, rec))
		y -= 18
	}

	// ── Section 5: Classification Note ──
	y -= 20
	sb.WriteString(fmt.Sprintf("/F2 8 Tf\n0 -20 Td\n(This assessment was generated by PQCAT, a post-quantum compliance tool developed by Soqucoin Labs Inc.) Tj\n"))
	y -= 12
	sb.WriteString(fmt.Sprintf("/F2 8 Tf\n0 -12 Td\n(SDVOSB sole-source eligible per FAR 19.1406. Contact: info@soqucoin.com) Tj\n"))

	sb.WriteString("ET\n")
	return sb.String()
}

// formatCurrency formats an integer as a comma-separated currency string.
func formatCurrency(amount int) string {
	s := fmt.Sprintf("%d", amount)
	if len(s) <= 3 {
		return s
	}

	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
