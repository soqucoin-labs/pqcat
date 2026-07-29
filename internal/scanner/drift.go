// Package scanner provides compliance drift detection.
// Compares two scan results (baseline vs current) to detect
// cryptographic posture changes: new vulnerabilities, resolved
// assets, score changes, and emerging risks.
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// DriftReport captures changes between two scans.
type DriftReport struct {
	GeneratedAt   time.Time     `json:"generated_at"`
	BaselineScan  DriftScanMeta `json:"baseline_scan"`
	CurrentScan   DriftScanMeta `json:"current_scan"`
	ScoreChange   float64       `json:"score_change"`
	Direction     string        `json:"direction"` // "IMPROVED", "DEGRADED", "STABLE"
	NewAssets     []DriftAsset  `json:"new_assets"`
	RemovedAssets []DriftAsset  `json:"removed_assets"`
	ChangedAssets []DriftChange `json:"changed_assets"`
	// UnreachableAssets are baseline assets absent from the current scan because
	// their host was unreachable this run — status UNKNOWN, never counted as
	// remediated (Wave 3b, ruling Decision 3A).
	UnreachableAssets []DriftAsset `json:"unreachable_assets,omitempty"`
	NewRedCount       int          `json:"new_red_count"`
	ResolvedCount     int          `json:"resolved_count"`
	UnreachableCount  int          `json:"unreachable_count,omitempty"`
	Summary           string       `json:"summary"`
}

// DriftScanMeta holds metadata about a scan for comparison.
type DriftScanMeta struct {
	Target     string    `json:"target"`
	ScanType   string    `json:"scan_type"`
	Timestamp  time.Time `json:"timestamp"`
	Score      float64   `json:"score"`
	AssetCount int       `json:"asset_count"`
	RedCount   int       `json:"red_count"`
}

// DriftAsset represents a new or removed asset.
type DriftAsset struct {
	Algorithm string `json:"algorithm"`
	Zone      string `json:"zone"`
	Location  string `json:"location"`
}

// DriftChange represents a changed asset.
type DriftChange struct {
	Location     string `json:"location"`
	OldAlgorithm string `json:"old_algorithm"`
	NewAlgorithm string `json:"new_algorithm"`
	OldZone      string `json:"old_zone"`
	NewZone      string `json:"new_zone"`
	ChangeType   string `json:"change_type"` // "UPGRADE", "DOWNGRADE", "ALGORITHM_CHANGE"
}

// StoredScan is the on-disk format for a scan result (for baseline storage).
type StoredScan struct {
	Result models.ScanResult      `json:"result"`
	Score  models.ComplianceScore `json:"score"`
}

// SaveBaseline writes a scan result to disk for future drift comparison.
func SaveBaseline(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	stored := StoredScan{Result: *result, Score: *score}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(stored)
}

// LoadBaseline reads a previously saved scan result from disk.
func LoadBaseline(path string) (*StoredScan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored StoredScan
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, err
	}
	return &stored, nil
}

// DetectDrift compares a current scan against a baseline and reports changes.
func DetectDrift(baseline *StoredScan, current *models.ScanResult, currentScore *models.ComplianceScore) *DriftReport {
	report := &DriftReport{
		GeneratedAt: time.Now(),
		BaselineScan: DriftScanMeta{
			Target:     baseline.Result.Target,
			ScanType:   baseline.Result.ScanType,
			Timestamp:  baseline.Result.Timestamp,
			Score:      baseline.Score.Overall,
			AssetCount: len(baseline.Result.Assets),
		},
		CurrentScan: DriftScanMeta{
			Target:     current.Target,
			ScanType:   current.ScanType,
			Timestamp:  current.Timestamp,
			Score:      currentScore.Overall,
			AssetCount: len(current.Assets),
		},
	}

	if baseline.Score.ZoneCounts != nil {
		report.BaselineScan.RedCount = baseline.Score.ZoneCounts[models.ZoneRed]
	}
	if currentScore.ZoneCounts != nil {
		report.CurrentScan.RedCount = currentScore.ZoneCounts[models.ZoneRed]
	}

	// Score change
	report.ScoreChange = currentScore.Overall - baseline.Score.Overall
	switch {
	case report.ScoreChange > 2:
		report.Direction = "IMPROVED"
	case report.ScoreChange < -2:
		report.Direction = "DEGRADED"
	default:
		report.Direction = "STABLE"
	}

	// Build asset fingerprint maps (location+algorithm = unique key)
	baselineMap := make(map[string]models.CryptoAsset)
	for _, a := range baseline.Result.Assets {
		key := a.Location + "|" + a.Algorithm
		baselineMap[key] = a
	}

	currentMap := make(map[string]models.CryptoAsset)
	for _, a := range current.Assets {
		key := a.Location + "|" + a.Algorithm
		currentMap[key] = a
	}

	// Find new assets (in current but not baseline)
	for key, asset := range currentMap {
		if _, found := baselineMap[key]; !found {
			report.NewAssets = append(report.NewAssets, DriftAsset{
				Algorithm: asset.Algorithm,
				Zone:      string(asset.Zone),
				Location:  asset.Location,
			})
			if asset.Zone == models.ZoneRed {
				report.NewRedCount++
			}
		}
	}

	// Find assets present in the baseline but absent from the current scan. An
	// absent asset whose host was unreachable this run is UNKNOWN, not remediated
	// (Decision 3A); only genuinely-absent assets from reachable hosts are counted
	// as absent/unverified.
	for key, asset := range baselineMap {
		if _, found := currentMap[key]; found {
			continue
		}
		da := DriftAsset{
			Algorithm: asset.Algorithm,
			Zone:      string(asset.Zone),
			Location:  asset.Location,
		}
		if hostUnreachable(asset.Location, current.UnreachableHosts) {
			report.UnreachableAssets = append(report.UnreachableAssets, da)
			report.UnreachableCount++
		} else {
			report.RemovedAssets = append(report.RemovedAssets, da)
			if asset.Zone == models.ZoneRed {
				report.ResolvedCount++
			}
		}
	}

	// Check for zone changes at same location (algorithm swapped)
	baselineByLoc := make(map[string]models.CryptoAsset)
	for _, a := range baseline.Result.Assets {
		baselineByLoc[a.Location] = a
	}
	for _, a := range current.Assets {
		if old, found := baselineByLoc[a.Location]; found && old.Algorithm != a.Algorithm {
			changeType := "ALGORITHM_CHANGE"
			if a.Zone == models.ZoneGreen && old.Zone == models.ZoneRed {
				changeType = "UPGRADE"
			} else if a.Zone == models.ZoneRed && old.Zone == models.ZoneGreen {
				changeType = "DOWNGRADE"
			}
			report.ChangedAssets = append(report.ChangedAssets, DriftChange{
				Location:     a.Location,
				OldAlgorithm: old.Algorithm,
				NewAlgorithm: a.Algorithm,
				OldZone:      string(old.Zone),
				NewZone:      string(a.Zone),
				ChangeType:   changeType,
			})
		}
	}

	// Summary. Absent assets are reported as ABSENT/UNVERIFIED, not "resolved":
	// a baseline asset missing from the current scan may have been remediated OR
	// its host may simply have been unreachable this run (Wave 3b, ruling
	// Decision 3B). We do not claim remediation without positive evidence.
	report.Summary = fmt.Sprintf("Score: %.0f → %.0f (%+.0f, %s). New: %d assets (%d RED). Absent (unverified): %d RED. Unreachable: %d. Changed: %d.",
		baseline.Score.Overall, currentScore.Overall, report.ScoreChange, report.Direction,
		len(report.NewAssets), report.NewRedCount, report.ResolvedCount, report.UnreachableCount, len(report.ChangedAssets))

	return report
}

// WriteDriftJSON writes a drift report to JSON.
// hostUnreachable reports whether an asset's location belongs to a host that was
// unreachable in the current scan. It matches on the full "host:port" and falls
// back to the host portion so a location and an unreachable-target that differ
// only in an implicit port still match.
func hostUnreachable(location string, unreachable []string) bool {
	for _, u := range unreachable {
		if u == location || hostPart(u) == hostPart(location) {
			return true
		}
	}
	return false
}

func hostPart(s string) string {
	if i := strings.LastIndex(s, ":"); i > 0 {
		return s[:i]
	}
	return s
}

func WriteDriftJSON(path string, report *DriftReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// PrintDriftTerminal prints a drift report to the terminal.
func PrintDriftTerminal(report *DriftReport) {
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("  COMPLIANCE DRIFT REPORT")
	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Printf("  Baseline:   %s (%s)\n", report.BaselineScan.Timestamp.Format("2006-01-02"), report.BaselineScan.Target)
	fmt.Printf("  Current:    %s (%s)\n", report.CurrentScan.Timestamp.Format("2006-01-02"), report.CurrentScan.Target)
	fmt.Println("────────────────────────────────────────────────────────────")

	arrow := "→"
	fmt.Printf("\n  Score: %.0f %s %.0f  (%+.0f)  [%s]\n\n",
		report.BaselineScan.Score, arrow, report.CurrentScan.Score, report.ScoreChange, report.Direction)

	fmt.Printf("  Assets: %d %s %d\n", report.BaselineScan.AssetCount, arrow, report.CurrentScan.AssetCount)
	fmt.Printf("  RED:    %d %s %d\n\n", report.BaselineScan.RedCount, arrow, report.CurrentScan.RedCount)

	if len(report.NewAssets) > 0 {
		fmt.Printf("  NEW ASSETS (%d)\n", len(report.NewAssets))
		for _, a := range report.NewAssets {
			fmt.Printf("    + [%s] %s  %s\n", a.Zone, a.Algorithm, a.Location)
		}
		fmt.Println()
	}

	if len(report.RemovedAssets) > 0 {
		fmt.Printf("  ABSENT / UNVERIFIED (%d) — not found in current scan; may be remediated (host was reachable)\n", len(report.RemovedAssets))
		for _, a := range report.RemovedAssets {
			fmt.Printf("    - [%s] %s  %s\n", a.Zone, a.Algorithm, a.Location)
		}
		fmt.Println()
	}

	if len(report.UnreachableAssets) > 0 {
		fmt.Printf("  UNREACHABLE / UNKNOWN (%d) — host not reachable this scan; status unknown, NOT counted as remediated\n", len(report.UnreachableAssets))
		for _, a := range report.UnreachableAssets {
			fmt.Printf("    - [%s] %s  %s\n", a.Zone, a.Algorithm, a.Location)
		}
		fmt.Println()
	}

	if len(report.ChangedAssets) > 0 {
		fmt.Printf("  CHANGED (%d)\n", len(report.ChangedAssets))
		for _, c := range report.ChangedAssets {
			fmt.Printf("    ~ %s: %s [%s] %s %s [%s]  (%s)\n",
				c.Location, c.OldAlgorithm, c.OldZone, arrow, c.NewAlgorithm, c.NewZone, c.ChangeType)
		}
		fmt.Println()
	}

	fmt.Println("────────────────────────────────────────────────────────────")
	fmt.Printf("  %s\n", report.Summary)
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println()
}
