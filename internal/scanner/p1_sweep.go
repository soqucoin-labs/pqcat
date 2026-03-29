// p1_sweep.go — Final P1 Clean Sweep: SSH-5, HSM-3, CROSS-2
//
// SSH-5:   Server banner capture → extract software name + version
// HSM-3:   PQC readiness per vendor update → version-aware PQC capability
// CROSS-2: CNSA 2.0 compliance gap score → days-until-enforcement + PQ coverage %
//
// NOTE: PKI-4 (key usage classification) is already implemented in pki_enhanced.go
package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SSH-5: Server Banner Capture & Version Extraction
// ═══════════════════════════════════════════════════════════════════════════════
//
// SSH servers announce their software in the version exchange:
//   SSH-2.0-OpenSSH_9.6
//   SSH-2.0-dropbear_2022.83
//   SSH-2.0-libssh-0.10.5
//
// We extract: product name, version, OS (if present), and PQ recommendation.

// SSHBannerInfo contains parsed SSH server banner information.
type SSHBannerInfo struct {
	Raw     string // Full banner string
	Product string // e.g., "OpenSSH"
	Version string // e.g., "9.6"
	OS      string // e.g., "Ubuntu-3ubuntu0.10"
	PQReady bool   // true if version supports PQ KEX
}

// ParseSSHBanner parses an SSH version banner into structured info.
func ParseSSHBanner(banner string) *SSHBannerInfo {
	info := &SSHBannerInfo{Raw: banner}

	// Strip SSH-2.0- or SSH-1.99- prefix
	bannerBody := banner
	for _, prefix := range []string{"SSH-2.0-", "SSH-1.99-", "SSH-1.5-"} {
		if strings.HasPrefix(banner, prefix) {
			bannerBody = strings.TrimPrefix(banner, prefix)
			break
		}
	}

	// Parse product and version from common formats
	switch {
	case strings.HasPrefix(bannerBody, "OpenSSH"):
		info.Product = "OpenSSH"
		info.Version, info.OS = parseOpenSSHVersion(bannerBody)
		info.PQReady = isOpenSSHPQReady(info.Version)
	case strings.HasPrefix(bannerBody, "dropbear"):
		info.Product = "Dropbear"
		parts := strings.SplitN(bannerBody, "_", 2)
		if len(parts) == 2 {
			info.Version = parts[1]
		}
	case strings.HasPrefix(bannerBody, "libssh"):
		info.Product = "libssh"
		parts := strings.SplitN(bannerBody, "-", 2)
		if len(parts) == 2 {
			info.Version = parts[1]
		}
	case strings.HasPrefix(bannerBody, "Cisco"):
		info.Product = "Cisco IOS SSH"
		info.Version = bannerBody
	case strings.HasPrefix(bannerBody, "ROSSSH"):
		info.Product = "Mikrotik RouterOS"
		info.Version = bannerBody
	default:
		info.Product = bannerBody
	}

	return info
}

// parseOpenSSHVersion extracts version and OS from "OpenSSH_9.6p1 Ubuntu-3ubuntu0.10".
func parseOpenSSHVersion(body string) (version, osInfo string) {
	// Strip "OpenSSH_"
	rest := strings.TrimPrefix(body, "OpenSSH_")

	// Split on space for OS info
	parts := strings.SplitN(rest, " ", 2)
	version = parts[0]
	if len(parts) > 1 {
		osInfo = parts[1]
	}

	return version, osInfo
}

// isOpenSSHPQReady checks if an OpenSSH version supports PQ key exchange.
// OpenSSH 9.0+ supports sntrup761x25519-sha512@openssh.com by default.
func isOpenSSHPQReady(version string) bool {
	v := parseVersion(version)
	if v == nil {
		return false
	}
	// OpenSSH 9.0+ includes sntrup761 hybrid KEX
	return v.major >= 9
}

// EnrichSSHWithBanner adds banner-derived information to SSH scan results.
func EnrichSSHWithBanner(assets []models.CryptoAsset, banner string) []models.CryptoAsset {
	if banner == "" {
		return assets
	}

	info := ParseSSHBanner(banner)

	// Add banner info to all SSH assets
	for i := range assets {
		if assets[i].Details == nil {
			assets[i].Details = make(map[string]string)
		}
		assets[i].Details["ssh_banner"] = info.Raw
		assets[i].Details["ssh_product"] = info.Product
		assets[i].Details["ssh_version"] = info.Version
		if info.OS != "" {
			assets[i].Details["ssh_os"] = info.OS
		}
		assets[i].Details["ssh_pq_kex"] = fmt.Sprintf("%v", info.PQReady)
	}

	// Add a synthetic asset for the SSH server itself
	serverZone := models.ZoneYellow
	if info.PQReady {
		serverZone = models.ZoneGreen
	}

	serverAsset := models.CryptoAsset{
		ID:        "ssh-server-banner",
		Algorithm: fmt.Sprintf("SSH-Server:%s-%s", info.Product, info.Version),
		Type:      models.AssetSSHHostKey,
		Zone:      serverZone,
		Details: map[string]string{
			"ssh_banner":  info.Raw,
			"ssh_product": info.Product,
			"ssh_version": info.Version,
			"ssh_pq_kex":  fmt.Sprintf("%v", info.PQReady),
		},
	}
	if info.OS != "" {
		serverAsset.Details["ssh_os"] = info.OS
	}
	if info.PQReady {
		serverAsset.Details["pq_capability"] = "sntrup761x25519-sha512@openssh.com"
	}

	return append(assets, serverAsset)
}

// ═══════════════════════════════════════════════════════════════════════════════
// HSM-3: PQC Readiness Per Vendor Update
// ═══════════════════════════════════════════════════════════════════════════════
//
// HSM firmware versions that support PQC algorithms (via preview/beta):
//   - Thales Luna 7.8+ → ML-KEM preview (via Thales PQC SDK)
//   - Entrust nShield 13+ → PQC key wrapping preview
//   - AWS CloudHSM → ML-KEM via FIPS 203 (preview region)
//   - Azure Managed HSM → PQC key import preview (Nov 2024)
//   - Google Cloud HSM → No PQC support yet
//   - YubiKey 5.7+ → Ed25519 only (not PQ)
//   - SoftHSM → No PQC (reference implementation)

// HSMPQCStatus describes PQC readiness for a specific HSM vendor/version.
type HSMPQCStatus struct {
	Vendor       string
	MinVersion   string // Minimum version for PQC support
	PQAlgorithms []string
	Status       string // "production", "preview", "beta", "none"
	Notes        string
}

// hsmPQCReadiness maps vendor names to their PQC support status.
var hsmPQCReadiness = []HSMPQCStatus{
	{
		Vendor:       "Thales Luna",
		MinVersion:   "7.8",
		PQAlgorithms: []string{"ML-KEM-768", "ML-DSA-65"},
		Status:       "preview",
		Notes:        "PQC SDK required. FIPS 140-3 validation pending.",
	},
	{
		Vendor:       "nCipher/Entrust nShield",
		MinVersion:   "13.0",
		PQAlgorithms: []string{"ML-KEM-768"},
		Status:       "preview",
		Notes:        "PQC key wrapping via CodeSafe. Limited algorithm set.",
	},
	{
		Vendor:       "AWS CloudHSM",
		MinVersion:   "5.10",
		PQAlgorithms: []string{"ML-KEM-768", "ML-KEM-1024"},
		Status:       "preview",
		Notes:        "Available in us-east-1 preview. FIPS 203 compliance.",
	},
	{
		Vendor:       "Azure Managed HSM",
		MinVersion:   "2024.11",
		PQAlgorithms: []string{"ML-KEM-768"},
		Status:       "preview",
		Notes:        "PQC key import preview. Not yet FIPS validated for PQ.",
	},
	{
		Vendor:       "Google Cloud HSM",
		MinVersion:   "",
		PQAlgorithms: nil,
		Status:       "none",
		Notes:        "No PQC support announced. Classical only.",
	},
	{
		Vendor:       "YubiKey (PIV)",
		MinVersion:   "",
		PQAlgorithms: nil,
		Status:       "none",
		Notes:        "Ed25519 support in 5.7+ but no PQ. Hardware constraint.",
	},
	{
		Vendor:       "SoftHSM",
		MinVersion:   "",
		PQAlgorithms: nil,
		Status:       "none",
		Notes:        "Reference implementation. No PQC support planned.",
	},
	{
		Vendor:       "HashiCorp Vault",
		MinVersion:   "",
		PQAlgorithms: nil,
		Status:       "none",
		Notes:        "Software-based. No PQC transit engine support yet.",
	},
}

// GetHSMPQCStatus returns the PQC readiness status for a given HSM vendor.
func GetHSMPQCStatus(vendor string) *HSMPQCStatus {
	vendorLower := strings.ToLower(vendor)
	for _, s := range hsmPQCReadiness {
		if strings.Contains(vendorLower, strings.ToLower(s.Vendor)) ||
			strings.Contains(strings.ToLower(s.Vendor), vendorLower) {
			return &s
		}
	}
	return nil
}

// EnrichHSMWithPQCStatus adds PQC readiness information to HSM scan results.
func EnrichHSMWithPQCStatus(assets []models.CryptoAsset) []models.CryptoAsset {
	for i := range assets {
		if assets[i].Type != models.AssetHSMModule {
			continue
		}

		vendor := assets[i].Details["vendor"]
		if vendor == "" {
			continue
		}

		status := GetHSMPQCStatus(vendor)
		if status == nil {
			assets[i].Details["pqc_status"] = "unknown"
			continue
		}

		assets[i].Details["pqc_status"] = status.Status
		assets[i].Details["pqc_notes"] = status.Notes

		if status.Status == "preview" || status.Status == "beta" {
			assets[i].Details["pqc_min_version"] = status.MinVersion
			assets[i].Details["pqc_algorithms"] = strings.Join(status.PQAlgorithms, ", ")
			// Don't change zone to GREEN for preview — still not production-validated
		}
	}

	return assets
}

// ═══════════════════════════════════════════════════════════════════════════════
// CROSS-2: CNSA 2.0 Compliance Gap Score
// ═══════════════════════════════════════════════════════════════════════════════
//
// CNSA 2.0 Timeline (NSA):
//   - 2025: Begin PQ transition for software/firmware signing
//   - 2030: PQ required for all key establishment (TLS, VPN, SSH)
//   - 2033: PQ required for ALL NSS (National Security Systems) crypto
//   - 2035: Complete deprecation of classical-only crypto
//
// We compute:
//   1. Days until each enforcement deadline
//   2. Current PQ coverage percentage
//   3. Gap analysis: what needs to change by when

// CNSA2Timeline represents the CNSA 2.0 enforcement milestones.
type CNSA2Timeline struct {
	SoftwareSigning  time.Time // 2025 — PQ for code/firmware signing
	KeyEstablishment time.Time // 2030 — PQ for TLS/VPN/SSH key exchange
	FullNSS          time.Time // 2033 — PQ for all NSS crypto
	ClassicalEnd     time.Time // 2035 — Complete classical deprecation
}

// DefaultCNSA2Timeline returns the official CNSA 2.0 enforcement dates.
func DefaultCNSA2Timeline() CNSA2Timeline {
	return CNSA2Timeline{
		SoftwareSigning:  time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
		KeyEstablishment: time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
		FullNSS:          time.Date(2033, 12, 31, 0, 0, 0, 0, time.UTC),
		ClassicalEnd:     time.Date(2035, 12, 31, 0, 0, 0, 0, time.UTC),
	}
}

// CNSA2GapScore represents the CNSA 2.0 compliance gap analysis.
type CNSA2GapScore struct {
	// Coverage metrics
	TotalAssets   int     // Total crypto assets scanned
	PQAssets      int     // Assets using PQ-safe algorithms
	ClassicalOnly int     // Assets using classical-only algorithms
	PQCoverage    float64 // Percentage of assets that are PQ-safe (0.0–100.0)

	// Timeline gaps
	DaysToSigning  int // Days until software signing enforcement
	DaysToKEX      int // Days until key establishment enforcement
	DaysToFullNSS  int // Days until full NSS enforcement
	DaysToClassEnd int // Days until classical deprecation

	// Risk assessment
	OverallRisk     string // "COMPLIANT", "ON_TRACK", "AT_RISK", "CRITICAL"
	Recommendations []string
}

// ComputeCNSA2Gap computes the CNSA 2.0 compliance gap from scan results.
func ComputeCNSA2Gap(assets []models.CryptoAsset) *CNSA2GapScore {
	return ComputeCNSA2GapAt(assets, time.Now().UTC())
}

// ComputeCNSA2GapAt computes the CNSA 2.0 compliance gap at a specific time.
// This variant exists for deterministic testing.
func ComputeCNSA2GapAt(assets []models.CryptoAsset, now time.Time) *CNSA2GapScore {
	timeline := DefaultCNSA2Timeline()

	score := &CNSA2GapScore{
		DaysToSigning:  clampDays(timeline.SoftwareSigning.Sub(now)),
		DaysToKEX:      clampDays(timeline.KeyEstablishment.Sub(now)),
		DaysToFullNSS:  clampDays(timeline.FullNSS.Sub(now)),
		DaysToClassEnd: clampDays(timeline.ClassicalEnd.Sub(now)),
	}

	// Count PQ vs classical assets
	for _, a := range assets {
		// Skip meta-assets (SBOM quality, policy assessments, CNSA2 itself)
		if a.Algorithm == "SBOM-QUALITY" ||
			strings.HasPrefix(a.Algorithm, "CryptoPolicy:") ||
			a.Algorithm == "CNSA2.0-Compliance" {
			continue
		}
		score.TotalAssets++
		if a.Zone == models.ZoneGreen {
			score.PQAssets++
		} else {
			score.ClassicalOnly++
		}
	}

	// Compute coverage
	if score.TotalAssets > 0 {
		score.PQCoverage = float64(score.PQAssets) / float64(score.TotalAssets) * 100.0
	}

	// Risk assessment
	score.OverallRisk = assessCNSA2Risk(score)
	score.Recommendations = generateCNSA2Recommendations(score)

	return score
}

// clampDays converts a duration to days, clamping negative values to 0.
func clampDays(d time.Duration) int {
	days := int(d.Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// assessCNSA2Risk determines overall CNSA 2.0 compliance risk.
func assessCNSA2Risk(score *CNSA2GapScore) string {
	switch {
	case score.PQCoverage >= 95.0:
		return "COMPLIANT"
	case score.PQCoverage >= 50.0 && score.DaysToFullNSS > 365*3:
		return "ON_TRACK"
	case score.PQCoverage >= 10.0 && score.DaysToFullNSS > 365:
		return "AT_RISK"
	default:
		return "CRITICAL"
	}
}

// generateCNSA2Recommendations produces actionable recommendations.
func generateCNSA2Recommendations(score *CNSA2GapScore) []string {
	var recs []string

	if score.DaysToSigning == 0 {
		recs = append(recs, "CNSA 2.0 software signing deadline has PASSED — immediate PQ signing migration required")
	} else if score.DaysToSigning < 365 {
		recs = append(recs, fmt.Sprintf("Software signing PQ transition due in %d days — begin ML-DSA migration NOW", score.DaysToSigning))
	}

	if score.PQCoverage < 10.0 {
		recs = append(recs, fmt.Sprintf("CRITICAL: Only %.1f%% PQ coverage — %d of %d assets still use quantum-vulnerable crypto",
			score.PQCoverage, score.ClassicalOnly, score.TotalAssets))
	} else if score.PQCoverage < 50.0 {
		recs = append(recs, fmt.Sprintf("%.1f%% PQ coverage — accelerate hybrid TLS deployment (X25519MLKEM768)",
			score.PQCoverage))
	}

	if score.DaysToKEX > 0 && score.DaysToKEX < 365*3 {
		recs = append(recs, fmt.Sprintf("Key establishment enforcement in %d days — prioritize TLS/SSH/VPN PQ key exchange", score.DaysToKEX))
	}

	if score.ClassicalOnly > 0 {
		recs = append(recs, fmt.Sprintf("%d assets require PQ migration before CNSA 2.0 enforcement (2033)",
			score.ClassicalOnly))
	}

	if len(recs) == 0 {
		recs = append(recs, "Strong PQ coverage — continue monitoring for new crypto assets")
	}

	return recs
}

// CNSA2GapAsset creates a synthetic CryptoAsset representing the CNSA 2.0 gap score.
func CNSA2GapAsset(score *CNSA2GapScore) models.CryptoAsset {
	zone := models.ZoneRed
	switch score.OverallRisk {
	case "COMPLIANT":
		zone = models.ZoneGreen
	case "ON_TRACK":
		zone = models.ZoneYellow
	case "AT_RISK":
		zone = models.ZoneYellow
	}

	return models.CryptoAsset{
		ID:        "cnsa2-compliance-gap",
		Algorithm: "CNSA2.0-Compliance",
		Type:      models.AssetConfig,
		Zone:      zone,
		Details: map[string]string{
			"total_assets":          fmt.Sprintf("%d", score.TotalAssets),
			"pq_assets":             fmt.Sprintf("%d", score.PQAssets),
			"classical_assets":      fmt.Sprintf("%d", score.ClassicalOnly),
			"pq_coverage":           fmt.Sprintf("%.1f%%", score.PQCoverage),
			"days_to_signing":       fmt.Sprintf("%d", score.DaysToSigning),
			"days_to_kex":           fmt.Sprintf("%d", score.DaysToKEX),
			"days_to_full_nss":      fmt.Sprintf("%d", score.DaysToFullNSS),
			"days_to_classical_end": fmt.Sprintf("%d", score.DaysToClassEnd),
			"overall_risk":          score.OverallRisk,
			"recommendations":       strings.Join(score.Recommendations, " | "),
		},
		Criticality: models.CriticalityNSS,
	}
}
