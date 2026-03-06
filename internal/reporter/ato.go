// Package reporter provides ATO compliance report generation.
// Generates structured compliance sections for federal Authority to Operate
// (ATO) packages, including NIST 800-53 control mapping, FIPS 140-3 module
// validation status, PQC migration plan templates, and POA&M entries.
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

// ATOReport represents a complete ATO compliance report package.
type ATOReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	SystemName      string              `json:"system_name"`
	ScanSummary     ATOScanSummary      `json:"scan_summary"`
	CryptoInventory []ATOCryptoEntry    `json:"crypto_inventory"`
	ControlMapping  []ATOControlMapping `json:"control_mapping"`
	FIPSStatus      []ATOFIPSEntry      `json:"fips_status"`
	MigrationPlan   []ATOMigrationItem  `json:"migration_plan"`
	POAMEntries     []ATOPOAMEntry      `json:"poam_entries"`
	RiskSummary     ATORiskSummary      `json:"risk_summary"`
}

// ATOScanSummary provides scan metadata for the ATO package.
type ATOScanSummary struct {
	ScanDate     time.Time `json:"scan_date"`
	ScanDuration string    `json:"scan_duration"`
	TotalAssets  int       `json:"total_assets"`
	RedCount     int       `json:"red_count"`
	YellowCount  int       `json:"yellow_count"`
	GreenCount   int       `json:"green_count"`
	OverallScore float64   `json:"overall_score"`
	Framework    string    `json:"framework"`
}

// ATOCryptoEntry represents a single cryptographic asset in the inventory.
type ATOCryptoEntry struct {
	AssetID     string `json:"asset_id"`
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"key_size,omitempty"`
	Zone        string `json:"zone"`
	Location    string `json:"location"`
	Criticality string `json:"criticality"`
	MustMigrate bool   `json:"must_migrate"`
	Deadline    string `json:"deadline,omitempty"`
}

// ATOControlMapping maps scan findings to NIST 800-53 controls.
type ATOControlMapping struct {
	ControlID   string `json:"control_id"`
	ControlName string `json:"control_name"`
	Family      string `json:"family"`
	Status      string `json:"status"` // "SATISFIED", "PARTIALLY_SATISFIED", "NOT_SATISFIED"
	Finding     string `json:"finding"`
	Evidence    string `json:"evidence"`
}

// ATOFIPSEntry tracks FIPS 140-3 module validation status.
type ATOFIPSEntry struct {
	ModuleName    string `json:"module_name"`
	Algorithm     string `json:"algorithm"`
	FIPSStatus    string `json:"fips_status"` // "VALIDATED", "PENDING", "NOT_VALIDATED", "HISTORICAL"
	CertNumber    string `json:"cert_number,omitempty"`
	QuantumStatus string `json:"quantum_status"` // "VULNERABLE", "TRANSITIONAL", "COMPLIANT"
}

// ATOMigrationItem represents a step in the PQC migration plan.
type ATOMigrationItem struct {
	Priority    int    `json:"priority"`
	Phase       string `json:"phase"` // "IMMEDIATE", "SHORT_TERM", "LONG_TERM"
	Action      string `json:"action"`
	AssetCount  int    `json:"asset_count"`
	Complexity  string `json:"complexity"`
	Deadline    string `json:"deadline"`
	Responsible string `json:"responsible"` // "SYSTEM_OWNER", "VENDOR", "INFRASTRUCTURE"
}

// ATOPOAMEntry is a Plan of Action and Milestones entry.
type ATOPOAMEntry struct {
	POAMID        string `json:"poam_id"`
	Weakness      string `json:"weakness"`
	ControlID     string `json:"control_id"`
	RiskLevel     string `json:"risk_level"` // "HIGH", "MODERATE", "LOW"
	Remediation   string `json:"remediation"`
	ScheduledDate string `json:"scheduled_date"`
	Status        string `json:"status"` // "OPEN", "IN_PROGRESS", "CLOSED"
	Milestone     string `json:"milestone"`
}

// ATORiskSummary provides an overall risk assessment.
type ATORiskSummary struct {
	OverallRisk    string   `json:"overall_risk"` // "HIGH", "MODERATE", "LOW"
	KeyFindings    []string `json:"key_findings"`
	Recommendation string   `json:"recommendation"`
}

// NIST 800-53 controls relevant to PQC compliance.
var nistControls = []struct {
	ID     string
	Name   string
	Family string
	Desc   string
}{
	{"SC-13", "Cryptographic Protection", "System and Communications Protection", "Use of FIPS-validated cryptographic mechanisms"},
	{"SC-12", "Cryptographic Key Establishment and Management", "System and Communications Protection", "Key establishment and management techniques"},
	{"SC-8", "Transmission Confidentiality and Integrity", "System and Communications Protection", "Protection of information during transmission"},
	{"SC-28", "Protection of Information at Rest", "System and Communications Protection", "Protection of stored information"},
	{"IA-7", "Cryptographic Module Authentication", "Identification and Authentication", "Mechanisms for authentication to cryptographic modules"},
	{"SC-17", "Public Key Infrastructure Certificates", "System and Communications Protection", "PKI certificates from approved service provider"},
	{"SA-4", "Acquisition Process", "System and Services Acquisition", "Include security requirements in acquisition contracts"},
	{"RA-5", "Vulnerability Monitoring and Scanning", "Risk Assessment", "Vulnerability scanning and monitoring"},
	{"CA-8", "Penetration Testing", "Assessment, Authorization, and Monitoring", "Penetration testing of systems"},
	{"PM-30", "Supply Chain Risk Management Strategy", "Program Management", "Supply chain risk management"},
}

// GenerateATOReport creates a complete ATO compliance report from scan results.
func GenerateATOReport(result *models.ScanResult, score *models.ComplianceScore, systemName string) *ATOReport {
	report := &ATOReport{
		GeneratedAt: time.Now(),
		SystemName:  systemName,
	}

	// Scan summary
	report.ScanSummary = ATOScanSummary{
		ScanDate:     result.Timestamp,
		ScanDuration: result.Duration.String(),
		TotalAssets:  len(result.Assets),
		OverallScore: score.Overall,
		Framework:    score.Framework,
	}
	if score.ZoneCounts != nil {
		report.ScanSummary.RedCount = score.ZoneCounts[models.ZoneRed]
		report.ScanSummary.YellowCount = score.ZoneCounts[models.ZoneYellow]
		report.ScanSummary.GreenCount = score.ZoneCounts[models.ZoneGreen]
	}

	// Build crypto inventory
	for _, asset := range result.Assets {
		entry := ATOCryptoEntry{
			AssetID:     asset.ID,
			Algorithm:   asset.Algorithm,
			KeySize:     asset.KeySize,
			Zone:        string(asset.Zone),
			Location:    asset.Location,
			Criticality: string(asset.Criticality),
			MustMigrate: asset.Zone == models.ZoneRed,
		}
		if asset.Zone == models.ZoneRed {
			entry.Deadline = "2027-12-31" // CNSA 2.0 web/cloud deadline
		}
		report.CryptoInventory = append(report.CryptoInventory, entry)
	}

	// NIST 800-53 control mapping
	report.ControlMapping = mapToNISTControls(result, score)

	// FIPS 140-3 status
	report.FIPSStatus = assessFIPSStatus(result)

	// Migration plan
	report.MigrationPlan = buildMigrationPlan(score)

	// POA&M entries
	report.POAMEntries = buildPOAM(result, score)

	// Risk summary
	report.RiskSummary = assessRisk(score)

	return report
}

// mapToNISTControls maps scan findings to NIST 800-53 controls.
func mapToNISTControls(result *models.ScanResult, score *models.ComplianceScore) []ATOControlMapping {
	var mappings []ATOControlMapping

	redCount := 0
	if score.ZoneCounts != nil {
		redCount = score.ZoneCounts[models.ZoneRed]
	}

	for _, ctrl := range nistControls {
		status := "SATISFIED"
		finding := "All cryptographic assets meet CNSA 2.0 requirements."
		evidence := fmt.Sprintf("PQCAT scan on %s: %d assets classified GREEN.",
			result.Timestamp.Format("2006-01-02"), score.ZoneCounts[models.ZoneGreen])

		switch ctrl.ID {
		case "SC-13":
			if redCount > 0 {
				status = "NOT_SATISFIED"
				finding = fmt.Sprintf("%d cryptographic assets use quantum-vulnerable algorithms.", redCount)
				evidence = fmt.Sprintf("PQCAT scan identified %d RED-zone assets requiring migration to FIPS 203/204/205 algorithms.", redCount)
			} else if score.ZoneCounts[models.ZoneYellow] > 0 {
				status = "PARTIALLY_SATISFIED"
				finding = fmt.Sprintf("%d assets in transitional hybrid mode.", score.ZoneCounts[models.ZoneYellow])
				evidence = "Hybrid algorithms detected. Full migration pending."
			}
		case "SC-12":
			if redCount > 0 {
				status = "PARTIALLY_SATISFIED"
				finding = "Key establishment mechanisms include quantum-vulnerable algorithms."
				evidence = fmt.Sprintf("PQCAT scan: %d assets using classical key exchange (RSA, ECDH, X25519).", redCount)
			}
		case "SC-8":
			hasTLS := false
			hasSSH := false
			for _, a := range result.Assets {
				if a.Type == models.AssetTLSCipher || a.Type == models.AssetTLSCert {
					hasTLS = true
				}
				if a.Type == models.AssetSSHHostKey || a.Type == models.AssetSSHKEX {
					hasSSH = true
				}
			}
			if hasTLS || hasSSH {
				if redCount > 0 {
					status = "PARTIALLY_SATISFIED"
					finding = "Transport encryption uses quantum-vulnerable algorithms."
				}
				evidence = fmt.Sprintf("TLS: %v, SSH: %v scanned.", hasTLS, hasSSH)
			}
		case "SC-17":
			hasPKI := false
			for _, a := range result.Assets {
				if a.Type == models.AssetPKICert {
					hasPKI = true
					break
				}
			}
			if hasPKI && redCount > 0 {
				status = "PARTIALLY_SATISFIED"
				finding = "PKI certificates use quantum-vulnerable signature algorithms."
				evidence = "Certificate chain analysis reveals classical signature algorithms."
			}
		case "RA-5":
			status = "SATISFIED"
			finding = "Automated cryptographic vulnerability scanning performed."
			evidence = fmt.Sprintf("PQCAT v%s scan completed on %s. Score: %.0f/100.", version, result.Timestamp.Format("2006-01-02"), score.Overall)
		case "PM-30":
			hasSBOM := false
			for _, a := range result.Assets {
				if a.Type == models.AssetSBOMDep {
					hasSBOM = true
					break
				}
			}
			if hasSBOM {
				if redCount > 0 {
					status = "PARTIALLY_SATISFIED"
					finding = "SBOM analysis reveals quantum-vulnerable dependencies in supply chain."
				} else {
					finding = "SBOM analysis confirms supply chain PQC compliance."
				}
				evidence = fmt.Sprintf("PQCAT SBOM analysis: %d dependencies assessed.", len(result.Assets))
			}
		}

		mappings = append(mappings, ATOControlMapping{
			ControlID:   ctrl.ID,
			ControlName: ctrl.Name,
			Family:      ctrl.Family,
			Status:      status,
			Finding:     finding,
			Evidence:    evidence,
		})
	}

	return mappings
}

// assessFIPSStatus determines FIPS 140-3 validation status for detected algorithms.
func assessFIPSStatus(result *models.ScanResult) []ATOFIPSEntry {
	// Track unique algorithms
	seen := make(map[string]bool)
	var entries []ATOFIPSEntry

	for _, asset := range result.Assets {
		if seen[asset.Algorithm] {
			continue
		}
		seen[asset.Algorithm] = true

		entry := ATOFIPSEntry{
			ModuleName: asset.Location,
			Algorithm:  asset.Algorithm,
		}

		algo := strings.ToUpper(asset.Algorithm)

		// Classify FIPS status based on algorithm
		switch {
		case strings.Contains(algo, "ML-KEM") || strings.Contains(algo, "ML-DSA") || strings.Contains(algo, "SLH-DSA"):
			entry.FIPSStatus = "PENDING" // FIPS 203/204/205 published but modules still validating
			entry.QuantumStatus = "COMPLIANT"
		case strings.Contains(algo, "AES") || strings.Contains(algo, "SHA-256") || strings.Contains(algo, "SHA-384") ||
			strings.Contains(algo, "SHA-512") || strings.Contains(algo, "HMAC") || strings.Contains(algo, "CHACHA20"):
			entry.FIPSStatus = "VALIDATED"
			entry.QuantumStatus = "COMPLIANT" // Symmetric = quantum safe at sufficient key sizes
		case strings.Contains(algo, "RSA") || strings.Contains(algo, "ECDSA") || strings.Contains(algo, "ED25519") ||
			strings.Contains(algo, "X25519") || strings.Contains(algo, "ECDH"):
			entry.FIPSStatus = "VALIDATED" // Currently FIPS-validated but quantum-vulnerable
			entry.QuantumStatus = "VULNERABLE"
		default:
			entry.FIPSStatus = "NOT_VALIDATED"
			entry.QuantumStatus = "VULNERABLE"
		}

		entries = append(entries, entry)
	}

	return entries
}

// buildMigrationPlan creates a phased PQC migration plan from compliance actions.
func buildMigrationPlan(score *models.ComplianceScore) []ATOMigrationItem {
	var plan []ATOMigrationItem

	for i, action := range score.TopActions {
		phase := "LONG_TERM"
		deadline := "2033-12-31"
		responsible := "SYSTEM_OWNER"

		switch {
		case strings.Contains(action.Description, "RSA") || strings.Contains(action.Description, "ECDSA"):
			phase = "SHORT_TERM"
			deadline = "2027-12-31"
			if strings.Contains(action.Description, "certificate") || strings.Contains(action.Description, "cert") {
				responsible = "INFRASTRUCTURE"
			}
		case strings.Contains(action.Description, "Ed25519") || strings.Contains(action.Description, "X25519"):
			phase = "SHORT_TERM"
			deadline = "2028-12-31"
		case strings.Contains(action.Description, "SSH"):
			phase = "IMMEDIATE"
			deadline = "2027-06-30"
			responsible = "INFRASTRUCTURE"
		}

		if action.Urgency == "IMMEDIATE" {
			phase = "IMMEDIATE"
		}

		plan = append(plan, ATOMigrationItem{
			Priority:    i + 1,
			Phase:       phase,
			Action:      action.Description,
			AssetCount:  action.AssetCount,
			Complexity:  action.Complexity,
			Deadline:    deadline,
			Responsible: responsible,
		})
	}

	return plan
}

// buildPOAM generates Plan of Action and Milestones entries.
func buildPOAM(result *models.ScanResult, score *models.ComplianceScore) []ATOPOAMEntry {
	var entries []ATOPOAMEntry

	// Group RED assets by algorithm for POA&M
	algoCounts := make(map[string]int)
	for _, asset := range result.Assets {
		if asset.Zone == models.ZoneRed {
			algoCounts[asset.Algorithm]++
		}
	}

	// Sort algorithms by count (descending)
	type algoCount struct {
		algo  string
		count int
	}
	var sorted []algoCount
	for algo, count := range algoCounts {
		sorted = append(sorted, algoCount{algo, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	for i, ac := range sorted {
		riskLevel := "MODERATE"
		controlID := "SC-13"
		scheduledDate := "2027-12-31"

		if strings.Contains(ac.algo, "SHA1") {
			riskLevel = "HIGH"
			scheduledDate = "2026-12-31" // SHA-1 already deprecated
		} else if strings.Contains(ac.algo, "RSA-1024") || strings.Contains(ac.algo, "DES") {
			riskLevel = "HIGH"
			scheduledDate = "2026-06-30"
		}

		if ac.count > 10 {
			riskLevel = "HIGH"
		}

		entries = append(entries, ATOPOAMEntry{
			POAMID:        fmt.Sprintf("PQC-%04d", i+1),
			Weakness:      fmt.Sprintf("%d assets using quantum-vulnerable %s algorithm", ac.count, ac.algo),
			ControlID:     controlID,
			RiskLevel:     riskLevel,
			Remediation:   fmt.Sprintf("Migrate %s to CNSA 2.0 approved algorithm (ML-KEM/ML-DSA/SLH-DSA)", ac.algo),
			ScheduledDate: scheduledDate,
			Status:        "OPEN",
			Milestone:     fmt.Sprintf("Complete %s migration across %d assets", ac.algo, ac.count),
		})
	}

	return entries
}

// assessRisk provides an overall risk assessment.
func assessRisk(score *models.ComplianceScore) ATORiskSummary {
	risk := ATORiskSummary{}

	switch {
	case score.Overall >= 80:
		risk.OverallRisk = "LOW"
		risk.Recommendation = "System demonstrates strong PQC readiness. Continue monitoring for remaining transitional assets and verify vendor PQC timeline commitments."
	case score.Overall >= 60:
		risk.OverallRisk = "MODERATE"
		risk.Recommendation = "System has significant quantum-vulnerable assets requiring migration. Prioritize high-value assets and establish vendor engagement for PQC-enabled products."
	case score.Overall >= 40:
		risk.OverallRisk = "HIGH"
		risk.Recommendation = "System is substantially quantum-vulnerable. Immediate action required: initiate PQC migration program, engage vendors on CNSA 2.0 timeline, and allocate dedicated resources."
	default:
		risk.OverallRisk = "CRITICAL"
		risk.Recommendation = "System is critically exposed to quantum threats. Emergency PQC migration program required. Consider interim risk acceptance with compensating controls while migration is underway."
	}

	redCount := 0
	if score.ZoneCounts != nil {
		redCount = score.ZoneCounts[models.ZoneRed]
	}

	risk.KeyFindings = []string{
		fmt.Sprintf("PQC Readiness Score: %.0f/100 (%s risk)", score.Overall, risk.OverallRisk),
		fmt.Sprintf("%d quantum-vulnerable cryptographic assets identified", redCount),
		fmt.Sprintf("%d total cryptographic assets inventoried", score.TotalAssets),
	}

	if score.NextDeadline != nil {
		risk.KeyFindings = append(risk.KeyFindings,
			fmt.Sprintf("Next compliance deadline: %s (%d days)", score.NextDeadline.Milestone, score.NextDeadline.DaysLeft))
	}

	return risk
}

// WriteATOJSON writes the ATO report to a JSON file.
func WriteATOJSON(path string, report *ATOReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
