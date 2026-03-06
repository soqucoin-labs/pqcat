// Package reporter provides SIEM integration output formats.
// Exports scan results to Splunk HEC, ELK/OpenSearch bulk JSON,
// and CEF (Common Event Format) for syslog ingestion.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ──────────────────────────────────────────────────────────────
// Splunk HTTP Event Collector (HEC) Format
// ──────────────────────────────────────────────────────────────

// SplunkEvent represents a single Splunk HEC event.
type SplunkEvent struct {
	Time       int64       `json:"time"`
	Host       string      `json:"host,omitempty"`
	Source     string      `json:"source"`
	Sourcetype string      `json:"sourcetype"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

// SplunkCryptoEvent is the event payload for a crypto finding.
type SplunkCryptoEvent struct {
	ScanType    string  `json:"scan_type"`
	Target      string  `json:"target"`
	Algorithm   string  `json:"algorithm"`
	Zone        string  `json:"zone"`
	Location    string  `json:"location"`
	AssetType   string  `json:"asset_type"`
	KeySize     int     `json:"key_size,omitempty"`
	Criticality string  `json:"criticality"`
	Score       float64 `json:"overall_score"`
	Framework   string  `json:"framework"`
}

// WriteSplunkHEC writes scan results in Splunk HEC JSON format.
// Each crypto asset becomes a separate event for granular indexing.
func WriteSplunkHEC(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)

	for _, asset := range result.Assets {
		event := SplunkEvent{
			Time:       result.Timestamp.Unix(),
			Host:       result.Target,
			Source:     "pqcat",
			Sourcetype: "pqcat:crypto:finding",
			Event: SplunkCryptoEvent{
				ScanType:    result.ScanType,
				Target:      result.Target,
				Algorithm:   asset.Algorithm,
				Zone:        string(asset.Zone),
				Location:    asset.Location,
				AssetType:   string(asset.Type),
				KeySize:     asset.KeySize,
				Criticality: string(asset.Criticality),
				Score:       score.Overall,
				Framework:   score.Framework,
			},
		}

		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("failed to encode Splunk event: %w", err)
		}
	}

	// Summary event
	summaryEvent := SplunkEvent{
		Time:       result.Timestamp.Unix(),
		Host:       result.Target,
		Source:     "pqcat",
		Sourcetype: "pqcat:crypto:summary",
		Event: map[string]interface{}{
			"scan_type":    result.ScanType,
			"target":       result.Target,
			"total_assets": len(result.Assets),
			"red_count":    score.ZoneCounts[models.ZoneRed],
			"yellow_count": score.ZoneCounts[models.ZoneYellow],
			"green_count":  score.ZoneCounts[models.ZoneGreen],
			"score":        score.Overall,
			"framework":    score.Framework,
			"duration_ms":  result.Duration.Milliseconds(),
		},
	}

	return encoder.Encode(summaryEvent)
}

// ──────────────────────────────────────────────────────────────
// ELK / OpenSearch Bulk JSON Format
// ──────────────────────────────────────────────────────────────

// ELKBulkIndex is the Elasticsearch bulk API index action.
type ELKBulkIndex struct {
	Index struct {
		IndexName string `json:"_index"`
	} `json:"index"`
}

// ELKDocument represents a document for Elasticsearch.
type ELKDocument struct {
	Timestamp   string  `json:"@timestamp"`
	ScanType    string  `json:"scan_type"`
	Target      string  `json:"target"`
	Algorithm   string  `json:"algorithm"`
	Zone        string  `json:"zone"`
	Location    string  `json:"location"`
	AssetType   string  `json:"asset_type"`
	KeySize     int     `json:"key_size,omitempty"`
	Criticality string  `json:"criticality"`
	Score       float64 `json:"overall_score"`
	Framework   string  `json:"framework"`
	DurationMs  int64   `json:"duration_ms"`
}

// WriteELKBulk writes scan results in Elasticsearch bulk API format.
// Compatible with ELK Stack, OpenSearch, and Amazon OpenSearch Service.
func WriteELKBulk(path string, result *models.ScanResult, score *models.ComplianceScore, indexName string) error {
	if indexName == "" {
		indexName = fmt.Sprintf("pqcat-findings-%s", time.Now().Format("2006.01"))
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetEscapeHTML(false)

	for _, asset := range result.Assets {
		// Action line
		action := ELKBulkIndex{}
		action.Index.IndexName = indexName
		if err := encoder.Encode(action); err != nil {
			return err
		}

		// Document line
		doc := ELKDocument{
			Timestamp:   result.Timestamp.Format(time.RFC3339),
			ScanType:    result.ScanType,
			Target:      result.Target,
			Algorithm:   asset.Algorithm,
			Zone:        string(asset.Zone),
			Location:    asset.Location,
			AssetType:   string(asset.Type),
			KeySize:     asset.KeySize,
			Criticality: string(asset.Criticality),
			Score:       score.Overall,
			Framework:   score.Framework,
			DurationMs:  result.Duration.Milliseconds(),
		}
		if err := encoder.Encode(doc); err != nil {
			return err
		}
	}

	return nil
}

// ──────────────────────────────────────────────────────────────
// CEF (Common Event Format) for Syslog
// ──────────────────────────────────────────────────────────────

// WriteCEF writes scan results in ArcSight CEF (Common Event Format).
// Format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
func WriteCEF(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, asset := range result.Assets {
		severity := cefSeverity(asset.Zone)
		sigID := cefSignatureID(asset.Algorithm)
		name := fmt.Sprintf("PQC Finding: %s", asset.Algorithm)

		extensions := []string{
			fmt.Sprintf("src=%s", result.Target),
			fmt.Sprintf("cs1=%s", asset.Algorithm),
			"cs1Label=Algorithm",
			fmt.Sprintf("cs2=%s", string(asset.Zone)),
			"cs2Label=Zone",
			fmt.Sprintf("cs3=%s", asset.Location),
			"cs3Label=Location",
			fmt.Sprintf("cs4=%s", string(asset.Type)),
			"cs4Label=AssetType",
			fmt.Sprintf("cs5=%s", string(asset.Criticality)),
			"cs5Label=Criticality",
			fmt.Sprintf("cn1=%.0f", score.Overall),
			"cn1Label=PQCScore",
			fmt.Sprintf("rt=%d", result.Timestamp.UnixMilli()),
		}

		if asset.KeySize > 0 {
			extensions = append(extensions, fmt.Sprintf("cn2=%d", asset.KeySize), "cn2Label=KeySize")
		}

		cefLine := fmt.Sprintf("CEF:0|Soqucoin Labs|PQCAT|%s|%s|%s|%d|%s\n",
			version, sigID, name, severity, strings.Join(extensions, " "))

		if _, err := f.WriteString(cefLine); err != nil {
			return err
		}
	}

	return nil
}

// cefSeverity maps zone to CEF severity (0-10).
func cefSeverity(zone models.Zone) int {
	switch zone {
	case models.ZoneRed:
		return 8
	case models.ZoneYellow:
		return 5
	case models.ZoneGreen:
		return 1
	default:
		return 3
	}
}

// cefSignatureID generates a deterministic signature ID for CEF events.
func cefSignatureID(algorithm string) string {
	algo := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(algo, "RSA"):
		return "PQCAT-RSA-001"
	case strings.Contains(algo, "ECDSA") || strings.Contains(algo, "EC"):
		return "PQCAT-ECDSA-002"
	case strings.Contains(algo, "ED25519"):
		return "PQCAT-ED25519-003"
	case strings.Contains(algo, "AES"):
		return "PQCAT-AES-004"
	case strings.Contains(algo, "SHA"):
		return "PQCAT-SHA-005"
	case strings.Contains(algo, "ML-KEM") || strings.Contains(algo, "ML-DSA"):
		return "PQCAT-PQC-006"
	default:
		return "PQCAT-OTHER-099"
	}
}
