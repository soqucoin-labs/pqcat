// Package scanner provides watch mode for scheduled recurring scans.
// Runs scans at configurable intervals, saves baselines, and detects
// compliance drift over time. Suitable for cron jobs or daemon mode.
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/compliance"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// WatchConfig configures the watch mode scanner.
type WatchConfig struct {
	Targets     []string
	ScanType    string // "tls", "ssh", "pki", "code", "sbom", "hsm"
	Framework   compliance.Framework
	Interval    time.Duration
	BaselineDir string // Directory to store baselines
	OutputDir   string // Directory for drift reports
	Iterations  int    // 0 = infinite
	OnScan      func(iteration int, result *models.ScanResult, score *models.ComplianceScore)
	OnDrift     func(iteration int, drift *DriftReport)
}

// DefaultWatchConfig returns a sensible default watch configuration.
func DefaultWatchConfig() WatchConfig {
	return WatchConfig{
		Interval:    1 * time.Hour,
		BaselineDir: ".pqcat/baselines",
		OutputDir:   ".pqcat/drift",
		Framework:   compliance.FrameworkCNSA2,
		Iterations:  0, // infinite
	}
}

// Watch runs scans at regular intervals and reports drift.
func Watch(config WatchConfig) error {
	// Ensure directories exist
	if err := os.MkdirAll(config.BaselineDir, 0755); err != nil {
		return fmt.Errorf("cannot create baseline dir: %w", err)
	}
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	// Determine baseline path
	baselinePath := filepath.Join(config.BaselineDir, fmt.Sprintf("baseline-%s.json", config.ScanType))

	iteration := 0
	for {
		iteration++
		if config.Iterations > 0 && iteration > config.Iterations {
			break
		}

		fmt.Fprintf(os.Stderr, "\n[watch] Iteration %d — %s\n", iteration, time.Now().Format("2006-01-02 15:04:05"))

		// Run appropriate scan
		result, err := runScanForWatch(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] Scan error: %v\n", err)
			if config.Iterations > 0 && iteration >= config.Iterations {
				break
			}
			time.Sleep(config.Interval)
			continue
		}

		// Score
		score := compliance.Score(result.Assets, config.Framework)

		// Callback
		if config.OnScan != nil {
			config.OnScan(iteration, result, &score)
		}

		fmt.Fprintf(os.Stderr, "[watch] Score: %.0f/100  |  %d assets  |  RED: %d  |  %s\n",
			score.Overall, len(result.Assets), score.ZoneCounts[models.ZoneRed], result.Duration)

		// Drift detection
		if _, err := os.Stat(baselinePath); err == nil {
			baseline, loadErr := LoadBaseline(baselinePath)
			if loadErr == nil {
				drift := DetectDrift(baseline, result, &score)

				if config.OnDrift != nil {
					config.OnDrift(iteration, drift)
				}

				// Report drift if significant
				if drift.Direction != "STABLE" || len(drift.NewAssets) > 0 || len(drift.RemovedAssets) > 0 {
					PrintDriftTerminal(drift)

					// Save drift report
					driftPath := filepath.Join(config.OutputDir,
						fmt.Sprintf("drift-%s-%s.json", config.ScanType, time.Now().Format("20060102-150405")))
					if wErr := WriteDriftJSON(driftPath, drift); wErr == nil {
						fmt.Fprintf(os.Stderr, "[watch] Drift report saved: %s\n", driftPath)
					}
				} else {
					fmt.Fprintf(os.Stderr, "[watch] No drift detected. Posture stable.\n")
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "[watch] No baseline found. This scan becomes the baseline.\n")
		}

		// Save current scan as new baseline
		if saveErr := SaveBaseline(baselinePath, result, &score); saveErr != nil {
			fmt.Fprintf(os.Stderr, "[watch] Failed to save baseline: %v\n", saveErr)
		}

		// Wait for next iteration
		if config.Iterations > 0 && iteration >= config.Iterations {
			break
		}

		fmt.Fprintf(os.Stderr, "[watch] Next scan in %s...\n", config.Interval)
		time.Sleep(config.Interval)
	}

	return nil
}

// SingleDrift runs a single scan and compares against a baseline file.
// Used for one-shot drift checks without watch mode.
func SingleDrift(baselinePath string, result *models.ScanResult, score *models.ComplianceScore) (*DriftReport, error) {
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("cannot load baseline %s: %w", baselinePath, err)
	}

	drift := DetectDrift(baseline, result, score)
	return drift, nil
}

// runScanForWatch dispatches to the appropriate scanner based on type.
func runScanForWatch(config WatchConfig) (*models.ScanResult, error) {
	target := ""
	if len(config.Targets) > 0 {
		target = config.Targets[0]
	}

	switch config.ScanType {
	case "tls":
		if len(config.Targets) > 1 {
			opts := DefaultRangeOptions("tls")
			return ScanRange(config.Targets, opts)
		}
		opts := DefaultTLSOptions()
		return ScanTLS(target, opts)
	case "ssh":
		if len(config.Targets) > 1 {
			opts := DefaultRangeOptions("ssh")
			return ScanRange(config.Targets, opts)
		}
		opts := DefaultSSHOptions()
		return ScanSSH(target, opts)
	case "pki":
		return ScanPKI(target)
	case "code":
		return ScanCode(target)
	case "sbom":
		return ScanSBOM(target, FormatAuto)
	case "hsm":
		return ScanHSM(target)
	default:
		return nil, fmt.Errorf("unsupported scan type for watch: %s", config.ScanType)
	}
}
