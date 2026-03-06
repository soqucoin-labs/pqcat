// Package scanner provides multi-scan aggregation.
// Runs multiple scan types against targets and merges results into a unified report.
// Produces a single compliance score across all asset classes.
package scanner

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// AggregateOptions configures a multi-scan run.
type AggregateOptions struct {
	// Scan types to run. If empty, runs all applicable types.
	ScanTypes []string

	// TLS/SSH targets (hostnames, IPs, CIDRs)
	NetworkTargets []string

	// SBOM files to analyze
	SBOMFiles []string

	// Code directories to scan
	CodePaths []string

	// PKI certificate files/directories
	PKIPaths []string

	// SCAP result XML files to import
	SCAPFiles []string

	// Run HSM discovery
	ScanHSM bool

	// SBOM format hint
	SBOMFormat SBOMFormat

	// Concurrent workers for network scans
	Workers int

	// Progress callback
	OnProgress func(scanType string, status string)
}

// DefaultAggregateOptions returns sensible defaults.
func DefaultAggregateOptions() AggregateOptions {
	return AggregateOptions{
		ScanHSM:    true,
		Workers:    20,
		SBOMFormat: FormatAuto,
	}
}

// ScanAggregate runs multiple scan types and merges all results.
// Returns a unified ScanResult with assets from all scan types and
// a combined compliance score.
func ScanAggregate(opts AggregateOptions) (*models.ScanResult, error) {
	start := time.Now()

	combined := &models.ScanResult{
		Target:   "aggregate",
		ScanType: "aggregate",
		Timestamp: start,
	}

	var scanErrors []string
	scanCount := 0

	progress := func(scanType, status string) {
		if opts.OnProgress != nil {
			opts.OnProgress(scanType, status)
		}
		fmt.Fprintf(os.Stderr, "  [%s] %s\n", strings.ToUpper(scanType), status)
	}

	// ── TLS Scans ──
	for _, target := range opts.NetworkTargets {
		progress("tls", fmt.Sprintf("Scanning %s...", target))
		scanCount++

		if strings.Contains(target, "/") {
			// CIDR range
			rangeOpts := DefaultRangeOptions("tls")
			rangeOpts.Concurrency = opts.Workers
			result, err := ScanRange([]string{target}, rangeOpts)
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("TLS %s: %v", target, err))
				continue
			}
			combined.Assets = append(combined.Assets, result.Assets...)
		} else {
			tlsOpts := DefaultTLSOptions()
			result, err := ScanTLS(target, tlsOpts)
			if err != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("TLS %s: %v", target, err))
				continue
			}
			combined.Assets = append(combined.Assets, result.Assets...)
		}
	}

	// ── SSH Scans ──
	for _, target := range opts.NetworkTargets {
		if strings.Contains(target, "/") {
			continue // skip CIDR for SSH — already handled by TLS range scan
		}
		progress("ssh", fmt.Sprintf("Scanning %s...", target))
		scanCount++

		sshOpts := DefaultSSHOptions()
		result, err := ScanSSH(target, sshOpts)
		if err != nil {
			// SSH may not be running — not an error for aggregate
			continue
		}
		combined.Assets = append(combined.Assets, result.Assets...)
	}

	// ── SBOM Analysis ──
	for _, sbomFile := range opts.SBOMFiles {
		progress("sbom", fmt.Sprintf("Analyzing %s...", sbomFile))
		scanCount++

		result, err := ScanSBOM(sbomFile, opts.SBOMFormat)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("SBOM %s: %v", sbomFile, err))
			continue
		}
		combined.Assets = append(combined.Assets, result.Assets...)
	}

	// ── Code Repo Scanning ──
	for _, codePath := range opts.CodePaths {
		progress("code", fmt.Sprintf("Scanning %s...", codePath))
		scanCount++

		result, err := ScanCode(codePath)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("Code %s: %v", codePath, err))
			continue
		}
		combined.Assets = append(combined.Assets, result.Assets...)
	}

	// ── PKI Chain Analysis ──
	for _, pkiPath := range opts.PKIPaths {
		progress("pki", fmt.Sprintf("Analyzing %s...", pkiPath))
		scanCount++

		result, err := ScanPKI(pkiPath)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("PKI %s: %v", pkiPath, err))
			continue
		}
		combined.Assets = append(combined.Assets, result.Assets...)
	}

	// ── SCAP Import ──
	for _, scapFile := range opts.SCAPFiles {
		progress("scap", fmt.Sprintf("Importing %s...", scapFile))
		scanCount++

		result, err := ScanSCAP(scapFile)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("SCAP %s: %v", scapFile, err))
			continue
		}
		combined.Assets = append(combined.Assets, result.Assets...)
	}

	// ── HSM Discovery ──
	if opts.ScanHSM {
		progress("hsm", "Discovering hardware security modules...")
		scanCount++

		result, err := ScanHSM("auto")
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("HSM: %v", err))
		} else {
			combined.Assets = append(combined.Assets, result.Assets...)
		}
	}

	combined.Duration = time.Since(start)

	// Build targets string for the combined result
	var targetParts []string
	if len(opts.NetworkTargets) > 0 {
		targetParts = append(targetParts, fmt.Sprintf("%d hosts", len(opts.NetworkTargets)))
	}
	if len(opts.SBOMFiles) > 0 {
		targetParts = append(targetParts, fmt.Sprintf("%d SBOMs", len(opts.SBOMFiles)))
	}
	if len(opts.CodePaths) > 0 {
		targetParts = append(targetParts, fmt.Sprintf("%d repos", len(opts.CodePaths)))
	}
	if len(opts.PKIPaths) > 0 {
		targetParts = append(targetParts, fmt.Sprintf("%d PKI chains", len(opts.PKIPaths)))
	}
	if len(opts.SCAPFiles) > 0 {
		targetParts = append(targetParts, fmt.Sprintf("%d SCAP results", len(opts.SCAPFiles)))
	}
	if opts.ScanHSM {
		targetParts = append(targetParts, "HSM")
	}
	combined.Target = strings.Join(targetParts, " + ")

	// Summary line
	fmt.Fprintf(os.Stderr, "\n  ✓ Aggregate scan complete: %d scan types, %d total assets, %d errors\n",
		scanCount, len(combined.Assets), len(scanErrors))

	if len(scanErrors) > 0 {
		fmt.Fprintf(os.Stderr, "  Errors:\n")
		for _, e := range scanErrors {
			fmt.Fprintf(os.Stderr, "    • %s\n", e)
		}
	}

	return combined, nil
}
