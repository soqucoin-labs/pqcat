// Package scanner provides OpenSCAP result import functionality.
// Parses XCCDF (Extensible Configuration Checklist Description Format) and
// ARF (Asset Reporting Format) result XML files to extract crypto-relevant findings.
// Maps SCAP rule IDs related to encryption, key management, and certificate
// configuration to PQCAT's crypto asset classification system.
package scanner

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ── XCCDF Result XML structures ──

type xccdfTestResult struct {
	XMLName     xml.Name          `xml:"TestResult"`
	Benchmark   string            `xml:"benchmark,attr"`
	StartTime   string            `xml:"start-time,attr"`
	RuleResults []xccdfRuleResult `xml:"rule-result"`
}

type xccdfRuleResult struct {
	IDRef    string       `xml:"idref,attr"`
	Result   string       `xml:"result"`
	Severity string       `xml:"severity,attr"`
	Title    string       `xml:"title"`
	Ident    []xccdfIdent `xml:"ident"`
}

type xccdfIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// ── ARF (Asset Reporting Format) structures ──

type arfReport struct {
	XMLName xml.Name         `xml:"asset-report-collection"`
	Reports []arfReportEntry `xml:"reports>report"`
}

type arfReportEntry struct {
	ID      string           `xml:"id,attr"`
	Content arfReportContent `xml:"content"`
}

type arfReportContent struct {
	TestResult xccdfTestResult `xml:"TestResult"`
}

// Crypto-relevant SCAP rule ID patterns.
// These map STIG, CIS, and NIST rule IDs to cryptographic findings.
var cryptoRulePatterns = []struct {
	pattern   string
	algorithm string
	reason    string
}{
	// TLS/SSL rules
	{"SV-.*_TLS", "TLS", "TLS configuration rule"},
	{"xccdf_.*tls", "TLS", "TLS configuration rule"},
	{"xccdf_.*ssl", "SSL", "SSL/TLS configuration rule"},
	{"SV-.*_SSL", "SSL", "SSL configuration rule"},

	// Encryption rules
	{"SV-.*_encrypt", "AES-256", "Encryption configuration rule"},
	{"xccdf_.*encrypt", "AES-256", "Encryption at-rest rule"},
	{"xccdf_.*cipher", "AES-256", "Cipher configuration rule"},
	{"SV-.*_FIPS", "FIPS-140", "FIPS mode configuration"},

	// Key management
	{"xccdf_.*key_mgmt", "RSA-2048", "Key management configuration"},
	{"xccdf_.*pki", "RSA-2048", "PKI configuration rule"},
	{"SV-.*_PKI", "RSA-2048", "PKI certificate rule"},
	{"xccdf_.*certificate", "RSA-2048", "Certificate management rule"},

	// SSH rules
	{"xccdf_.*ssh", "SSH", "SSH configuration rule"},
	{"SV-.*_SSH", "SSH", "SSH hardening rule"},
	{"xccdf_.*sshd", "Ed25519", "SSHD key configuration"},

	// Cryptographic module rules
	{"xccdf_.*crypto", "RSA-2048", "Cryptographic module rule"},
	{"xccdf_.*hash", "SHA-256", "Hashing configuration rule"},
	{"SV-.*_HASH", "SHA-256", "Hash algorithm rule"},

	// Algorithm-specific
	{"xccdf_.*rsa", "RSA-2048", "RSA key configuration"},
	{"xccdf_.*ecdsa", "ECDSA", "ECDSA configuration"},
	{"xccdf_.*aes", "AES-256", "AES encryption rule"},
	{"xccdf_.*3des", "3DES", "Triple-DES (deprecated) rule"},
	{"xccdf_.*des", "DES", "DES (deprecated) rule"},
	{"xccdf_.*md5", "MD5", "MD5 (deprecated) rule"},
	{"xccdf_.*sha1", "SHA-1", "SHA-1 (deprecated) rule"},
	{"xccdf_.*rc4", "RC4", "RC4 (deprecated) rule"},
}

// ScanSCAP parses an OpenSCAP XCCDF or ARF result XML file and
// extracts crypto-relevant findings as PQCAT assets.
func ScanSCAP(path string) (*models.ScanResult, error) {
	start := time.Now()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read SCAP file: %w", err)
	}

	var ruleResults []xccdfRuleResult

	// Try ARF format first (wraps XCCDF)
	var arf arfReport
	if err := xml.Unmarshal(data, &arf); err == nil && len(arf.Reports) > 0 {
		for _, report := range arf.Reports {
			ruleResults = append(ruleResults, report.Content.TestResult.RuleResults...)
		}
	}

	// Try direct XCCDF TestResult
	if len(ruleResults) == 0 {
		var testResult xccdfTestResult
		if err := xml.Unmarshal(data, &testResult); err == nil {
			ruleResults = testResult.RuleResults
		}
	}

	// Try XCCDF Benchmark wrapper (contains TestResult)
	if len(ruleResults) == 0 {
		type benchmark struct {
			XMLName    xml.Name        `xml:"Benchmark"`
			TestResult xccdfTestResult `xml:"TestResult"`
		}
		var b benchmark
		if err := xml.Unmarshal(data, &b); err == nil {
			ruleResults = b.TestResult.RuleResults
		}
	}

	if len(ruleResults) == 0 {
		return nil, fmt.Errorf("no XCCDF rule results found in %s (supported: XCCDF, ARF)", path)
	}

	// Extract crypto-relevant findings
	var assets []models.CryptoAsset
	for _, rule := range ruleResults {
		asset := matchCryptoRule(rule, path)
		if asset != nil {
			assets = append(assets, *asset)
		}
	}

	result := &models.ScanResult{
		Target:    path,
		ScanType:  "scap",
		Timestamp: start,
		Duration:  time.Since(start),
		Assets:    assets,
	}

	fmt.Fprintf(os.Stderr, "  SCAP import: %d rules parsed, %d crypto-relevant findings extracted\n",
		len(ruleResults), len(assets))

	return result, nil
}

// matchCryptoRule checks if an XCCDF rule result is crypto-relevant
// and converts it to a PQCAT asset if so.
func matchCryptoRule(rule xccdfRuleResult, source string) *models.CryptoAsset {
	ruleID := strings.ToLower(rule.IDRef)
	ruleTitle := strings.ToLower(rule.Title)

	// Check rule ID and title against crypto patterns
	for _, pattern := range cryptoRulePatterns {
		if strings.Contains(ruleID, strings.ToLower(pattern.pattern)) ||
			strings.Contains(ruleTitle, strings.ToLower(pattern.pattern)) {
			return buildSCAPAsset(rule, pattern.algorithm, pattern.reason, source)
		}
	}

	// Also check for crypto keywords in the rule title
	cryptoKeywords := []string{
		"cryptograph", "encrypt", "cipher", "certificate", "tls", "ssl",
		"ssh", "key management", "pki", "fips", "hash", "signature",
		"rsa", "ecdsa", "aes", "des", "sha-", "md5",
	}

	for _, keyword := range cryptoKeywords {
		if strings.Contains(ruleTitle, keyword) || strings.Contains(ruleID, keyword) {
			// Infer algorithm from the keyword
			algo := inferAlgorithmFromKeyword(keyword)
			return buildSCAPAsset(rule, algo, "Crypto-relevant SCAP finding", source)
		}
	}

	return nil
}

func buildSCAPAsset(rule xccdfRuleResult, algorithm, reason, source string) *models.CryptoAsset {
	zone := classifier.Classify(algorithm)

	// Failed rules are more urgent — the system is misconfigured
	criticality := models.CriticalityStandard
	if rule.Result == "fail" {
		criticality = models.CriticalityHVA // Failed crypto rules = high value finding
	}

	// Build CCE/CCI reference if available
	cceRef := ""
	for _, ident := range rule.Ident {
		if strings.Contains(ident.System, "cce") || strings.Contains(ident.System, "cci") {
			cceRef = ident.Value
			break
		}
	}

	location := fmt.Sprintf("SCAP:%s", source)
	if cceRef != "" {
		location = fmt.Sprintf("SCAP:%s [%s]", source, cceRef)
	}

	status := "CONFIGURED"
	if rule.Result == "fail" {
		status = "FAILED"
	} else if rule.Result == "notapplicable" {
		status = "N/A"
	}

	return &models.CryptoAsset{
		Type:        models.AssetCodeCrypto, // SCAP findings classify as code-level crypto
		Algorithm:   algorithm,
		Zone:        zone,
		Location:    location,
		Criticality: criticality,
		Details:     map[string]string{"finding": fmt.Sprintf("[%s] %s: %s (%s)", status, rule.IDRef, reason, rule.Result)},
	}
}

func inferAlgorithmFromKeyword(keyword string) string {
	switch {
	case strings.Contains(keyword, "rsa"):
		return "RSA-2048"
	case strings.Contains(keyword, "ecdsa"):
		return "ECDSA"
	case strings.Contains(keyword, "aes"):
		return "AES-256"
	case strings.Contains(keyword, "des"):
		return "3DES"
	case strings.Contains(keyword, "md5"):
		return "MD5"
	case strings.Contains(keyword, "sha-"):
		return "SHA-256"
	case strings.Contains(keyword, "tls"), strings.Contains(keyword, "ssl"):
		return "TLS"
	case strings.Contains(keyword, "ssh"):
		return "Ed25519"
	case strings.Contains(keyword, "fips"):
		return "FIPS-140"
	case strings.Contains(keyword, "certificate"), strings.Contains(keyword, "pki"):
		return "RSA-2048"
	default:
		return "UNKNOWN"
	}
}
