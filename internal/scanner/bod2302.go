// bod2302.go — CROSS-4: CISA BOD 23-02 Export Format
//
// Binding Operational Directive 23-02 requires federal agencies to inventory
// all internet-facing networked management interfaces with specific fields.
//
// PQCAT extends the standard BOD 23-02 inventory with quantum risk columns,
// making it the first BOD 23-02-compliant export that also tracks PQC readiness.
//
// Reference: https://www.cisa.gov/news-events/directives/binding-operational-directive-23-02
package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// BOD2302Asset represents a single asset in the BOD 23-02 inventory format.
// Fields are aligned with CISA's required reporting fields plus PQCAT extensions.
type BOD2302Asset struct {
	// ── BOD 23-02 Required Fields ──
	IPAddress        string `json:"ip_address"`         // IPv4 or IPv6 address
	Hostname         string `json:"hostname"`           // DNS name or "[bare IP]"
	Port             string `json:"port"`               // Service port (443, 22, etc.)
	Protocol         string `json:"protocol"`           // "TLS", "SSH", "HTTPS"
	Service          string `json:"service"`            // "web", "ssh", "smtp"
	SoftwareName     string `json:"software_name"`      // "OpenSSH", "nginx", etc.
	SoftwareVersion  string `json:"software_version"`   // "9.6p1", "1.25.4", etc.
	IsInternetFacing bool   `json:"is_internet_facing"` // BOD 23-02 scope filter
	AgencyComponent  string `json:"agency_component"`   // Org unit (user-provided)
	DiscoveryDate    string `json:"discovery_date"`     // ISO 8601
	LastSeenDate     string `json:"last_seen_date"`     // ISO 8601

	// ── PQCAT Quantum Risk Extensions ──
	CryptoAlgorithm string `json:"crypto_algorithm"`           // "RSA-2048", "ML-KEM-768"
	KeySize         int    `json:"key_size,omitempty"`         // Key size in bits
	QuantumZone     string `json:"quantum_zone"`               // "RED", "YELLOW", "GREEN"
	HNDLRisk        string `json:"hndl_risk,omitempty"`        // "CRITICAL", "HIGH", etc.
	PQReady         bool   `json:"pq_ready"`                   // Is this asset PQ-safe?
	CNSA2Status     string `json:"cnsa2_status"`               // "COMPLIANT", "AT_RISK", etc.
	MigrationAction string `json:"migration_action,omitempty"` // Recommended fix

	// ── Asset Provenance ──
	AssetID   string `json:"asset_id"`   // PQCAT internal asset ID
	AssetType string `json:"asset_type"` // "tls_certificate", "ssh_host_key"
	ScanType  string `json:"scan_type"`  // "tls", "ssh", "code"
}

// BOD2302Export contains the full export with metadata.
type BOD2302Export struct {
	ExportVersion string         `json:"export_version"` // "1.0"
	ExportDate    string         `json:"export_date"`    // ISO 8601
	Generator     string         `json:"generator"`      // "PQCAT v2.x.x"
	TotalAssets   int            `json:"total_assets"`
	PQReadyCount  int            `json:"pq_ready_count"`
	PQReadyPct    float64        `json:"pq_ready_pct"`
	Assets        []BOD2302Asset `json:"assets"`
}

// GenerateBOD2302Export converts PQCAT scan results into BOD 23-02 format.
func GenerateBOD2302Export(results []models.ScanResult, agencyComponent string, version string) *BOD2302Export {
	export := &BOD2302Export{
		ExportVersion: "1.0",
		ExportDate:    time.Now().UTC().Format(time.RFC3339),
		Generator:     fmt.Sprintf("PQCAT %s", version),
		Assets:        make([]BOD2302Asset, 0),
	}

	for _, result := range results {
		for _, asset := range result.Assets {
			bodAsset := mapAssetToBOD2302(asset, result, agencyComponent)
			export.Assets = append(export.Assets, bodAsset)
			export.TotalAssets++
			if bodAsset.PQReady {
				export.PQReadyCount++
			}
		}
	}

	if export.TotalAssets > 0 {
		export.PQReadyPct = float64(export.PQReadyCount) / float64(export.TotalAssets) * 100.0
	}

	return export
}

// mapAssetToBOD2302 converts a single CryptoAsset into a BOD2302Asset.
func mapAssetToBOD2302(asset models.CryptoAsset, result models.ScanResult, agency string) BOD2302Asset {
	now := time.Now().UTC().Format(time.RFC3339)

	bod := BOD2302Asset{
		// Provenance
		AssetID:   asset.ID,
		AssetType: string(asset.Type),
		ScanType:  result.ScanType,

		// BOD 23-02 required
		Hostname:         extractHostname(result.Target),
		IPAddress:        extractIP(result.Target),
		Port:             extractPort(result.Target, result.ScanType),
		Protocol:         mapScanTypeToProtocol(result.ScanType),
		Service:          mapScanTypeToService(result.ScanType),
		IsInternetFacing: true, // PQCAT scans network-reachable targets
		AgencyComponent:  agency,
		DiscoveryDate:    result.Timestamp.UTC().Format(time.RFC3339),
		LastSeenDate:     now,

		// PQCAT extensions
		CryptoAlgorithm: asset.Algorithm,
		KeySize:         asset.KeySize,
		QuantumZone:     string(asset.Zone),
		PQReady:         asset.Zone == models.ZoneGreen,
		CNSA2Status:     mapZoneToCNSA2Status(asset.Zone),
	}

	// Extract software info from asset details
	if v, ok := asset.Details["ssh_product"]; ok {
		bod.SoftwareName = v
	}
	if v, ok := asset.Details["ssh_version"]; ok {
		bod.SoftwareVersion = v
	}
	if v, ok := asset.Details["server"]; ok {
		bod.SoftwareName = v
	}

	// HNDL risk from PKI enrichment
	if v, ok := asset.Details["hndl_risk"]; ok {
		bod.HNDLRisk = v
	}

	// Migration recommendations
	bod.MigrationAction = recommendMigration(asset)

	return bod
}

// extractHostname pulls the hostname from a scan target like "soqu.org:443".
func extractHostname(target string) string {
	// Handle bracketed IPv6: [2001:db8::1]:443
	if strings.HasPrefix(target, "[") {
		if idx := strings.Index(target, "]:"); idx >= 0 {
			return target[1:idx]
		}
		return strings.Trim(target, "[]")
	}
	// IPv4/hostname:port
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		return target[:idx]
	}
	return target
}

// extractIP returns the IP address portion, or the hostname if not an IP.
func extractIP(target string) string {
	host := extractHostname(target)
	// If it looks like an IP, return it; otherwise empty (DNS-only target)
	return host
}

// extractPort pulls the port from a target string.
func extractPort(target string, scanType string) string {
	// Bracketed IPv6
	if strings.HasPrefix(target, "[") {
		if idx := strings.Index(target, "]:"); idx >= 0 {
			return target[idx+2:]
		}
	}
	// host:port
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		port := target[idx+1:]
		if port != "" {
			return port
		}
	}
	// Default by scan type
	switch scanType {
	case "tls":
		return "443"
	case "ssh":
		return "22"
	default:
		return ""
	}
}

// mapScanTypeToProtocol maps PQCAT scan types to BOD 23-02 protocol names.
func mapScanTypeToProtocol(scanType string) string {
	switch {
	case strings.HasPrefix(scanType, "tls"):
		return "TLS"
	case strings.HasPrefix(scanType, "ssh"):
		return "SSH"
	case scanType == "pki":
		return "X.509"
	default:
		return strings.ToUpper(scanType)
	}
}

// mapScanTypeToService maps scan types to BOD 23-02 service categories.
func mapScanTypeToService(scanType string) string {
	switch {
	case strings.HasPrefix(scanType, "tls"):
		return "web"
	case strings.HasPrefix(scanType, "ssh"):
		return "ssh"
	case scanType == "pki":
		return "pki"
	case scanType == "code":
		return "application"
	case scanType == "sbom":
		return "software_inventory"
	case scanType == "config":
		return "configuration"
	case scanType == "hsm":
		return "key_management"
	default:
		return scanType
	}
}

// mapZoneToCNSA2Status maps quantum zones to CNSA 2.0 compliance status.
func mapZoneToCNSA2Status(zone models.Zone) string {
	switch zone {
	case models.ZoneGreen:
		return "COMPLIANT"
	case models.ZoneYellow:
		return "IN_TRANSITION"
	case models.ZoneRed:
		return "NON_COMPLIANT"
	default:
		return "UNKNOWN"
	}
}

// recommendMigration generates a short migration recommendation for an asset.
func recommendMigration(asset models.CryptoAsset) string {
	if asset.Zone == models.ZoneGreen {
		return "" // Already PQ-safe
	}

	algo := strings.ToUpper(asset.Algorithm)

	switch {
	case strings.Contains(algo, "RSA"):
		return "Migrate to ML-DSA-65 (FIPS 204) for signing, ML-KEM-768 (FIPS 203) for key exchange"
	case strings.Contains(algo, "ECDSA") || strings.Contains(algo, "ECDH"):
		return "Migrate to ML-DSA-65 (FIPS 204) for signing, ML-KEM-768 (FIPS 203) for key exchange"
	case strings.Contains(algo, "DSA"):
		return "Migrate to ML-DSA-65 (FIPS 204)"
	case strings.Contains(algo, "DH"):
		return "Migrate to ML-KEM-768 (FIPS 203)"
	case strings.Contains(algo, "3DES") || strings.Contains(algo, "DES"):
		return "Replace with AES-256-GCM"
	case strings.Contains(algo, "SHA-1") || strings.Contains(algo, "MD5"):
		return "Replace with SHA-384 or SHA-512"
	case strings.Contains(algo, "RC4"):
		return "Replace with AES-256-GCM immediately"
	default:
		if asset.Zone == models.ZoneRed {
			return "Evaluate PQ-safe alternative per CNSA 2.0 guidance"
		}
		return "Monitor for CNSA 2.0 compliance timeline"
	}
}

// ── Export Formatters ──

// WriteBOD2302JSON writes the export as JSON to the given writer.
func WriteBOD2302JSON(w io.Writer, export *BOD2302Export) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(export)
}

// WriteBOD2302CSV writes the export as CSV to the given writer.
// CSV format is preferred by most federal inventory systems.
func WriteBOD2302CSV(w io.Writer, export *BOD2302Export) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header row
	header := []string{
		"IP Address", "Hostname", "Port", "Protocol", "Service",
		"Software Name", "Software Version", "Internet Facing",
		"Agency Component", "Discovery Date", "Last Seen Date",
		"Crypto Algorithm", "Key Size", "Quantum Zone",
		"HNDL Risk", "PQ Ready", "CNSA 2.0 Status",
		"Migration Action", "Asset ID", "Asset Type", "Scan Type",
	}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	for _, a := range export.Assets {
		row := []string{
			a.IPAddress, a.Hostname, a.Port, a.Protocol, a.Service,
			a.SoftwareName, a.SoftwareVersion, fmt.Sprintf("%v", a.IsInternetFacing),
			a.AgencyComponent, a.DiscoveryDate, a.LastSeenDate,
			a.CryptoAlgorithm, fmt.Sprintf("%d", a.KeySize), a.QuantumZone,
			a.HNDLRisk, fmt.Sprintf("%v", a.PQReady), a.CNSA2Status,
			a.MigrationAction, a.AssetID, a.AssetType, a.ScanType,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	return nil
}
