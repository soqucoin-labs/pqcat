// Package reporter formats scan results for human and machine consumption.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

const version = "1.0.0-alpha"

// PrintTerminal renders a scan result with compliance score to the terminal
// in the "Crypto Bill of Health" format.
func PrintTerminal(result *models.ScanResult, score *models.ComplianceScore) {
	w := os.Stdout

	// Zone color codes (ANSI)
	red := "\033[91m"
	yellow := "\033[93m"
	green := "\033[92m"
	cyan := "\033[96m"
	dim := "\033[2m"
	bold := "\033[1m"
	reset := "\033[0m"

	width := 60
	line := strings.Repeat("─", width)
	doubleLine := strings.Repeat("═", width)

	fmt.Fprintf(w, "\n%s%s%s\n", dim, doubleLine, reset)
	fmt.Fprintf(w, "%s  CRYPTO BILL OF HEALTH%s\n", bold, reset)
	fmt.Fprintf(w, "%s  PQCAT v%s%s\n", dim, version, reset)
	fmt.Fprintf(w, "%s%s%s\n", dim, line, reset)
	fmt.Fprintf(w, "  Target:     %s%s%s\n", bold, result.Target, reset)
	fmt.Fprintf(w, "  Scan Type:  %s\n", result.ScanType)
	fmt.Fprintf(w, "  Date:       %s\n", result.Timestamp.Format("2006-01-02 15:04 MST"))
	fmt.Fprintf(w, "  Duration:   %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "%s%s%s\n", dim, line, reset)

	if result.Error != "" {
		fmt.Fprintf(w, "  %sERROR: %s%s\n", red, result.Error, reset)
		fmt.Fprintf(w, "%s%s%s\n\n", dim, doubleLine, reset)
		return
	}

	// Score display
	if score != nil {
		scoreColor := red
		if score.Overall >= 70 {
			scoreColor = green
		} else if score.Overall >= 40 {
			scoreColor = yellow
		}

		fmt.Fprintf(w, "\n  PQC Readiness Score:  %s%s%.0f / 100%s\n\n", bold, scoreColor, score.Overall, reset)

		// Zone breakdown
		redCount := score.ZoneCounts[models.ZoneRed]
		yellowCount := score.ZoneCounts[models.ZoneYellow]
		greenCount := score.ZoneCounts[models.ZoneGreen]

		fmt.Fprintf(w, "  %s● RED%s    Quantum Vulnerable    %s%d assets%s\n", red, reset, bold, redCount, reset)
		fmt.Fprintf(w, "  %s● YLW%s    Transitional          %s%d assets%s\n", yellow, reset, bold, yellowCount, reset)
		fmt.Fprintf(w, "  %s● GRN%s    CNSA 2.0 Compliant    %s%d assets%s\n", green, reset, bold, greenCount, reset)

		// Next deadline
		if score.NextDeadline != nil {
			fmt.Fprintf(w, "\n%s%s%s\n", dim, line, reset)
			fmt.Fprintf(w, "  %sNext Milestone:%s\n", dim, reset)
			fmt.Fprintf(w, "  %s (%s) — %s%d days remaining%s\n",
				score.NextDeadline.Milestone,
				strings.ToUpper(score.NextDeadline.Framework),
				cyan, score.NextDeadline.DaysLeft, reset)
		}

		// Priority actions
		if len(score.TopActions) > 0 {
			fmt.Fprintf(w, "\n%s%s%s\n", dim, line, reset)
			fmt.Fprintf(w, "  %sPriority Actions:%s\n", bold, reset)
			for _, action := range score.TopActions {
				fmt.Fprintf(w, "  %s%d.%s %s %s[%s]%s\n",
					cyan, action.Priority, reset,
					action.Description,
					dim, action.Complexity, reset)
			}
		}
	}

	fmt.Fprintf(w, "\n%s%s%s\n", dim, doubleLine, reset)

	// Asset detail table
	if len(result.Assets) > 0 {
		fmt.Fprintf(w, "\n%s  ASSET DETAIL%s\n", bold, reset)
		fmt.Fprintf(w, "%s%s%s\n", dim, line, reset)

		for _, asset := range result.Assets {
			zoneStr := ""
			switch asset.Zone {
			case models.ZoneRed:
				zoneStr = fmt.Sprintf("%s[RED]%s   ", red, reset)
			case models.ZoneYellow:
				zoneStr = fmt.Sprintf("%s[YLW]%s   ", yellow, reset)
			case models.ZoneGreen:
				zoneStr = fmt.Sprintf("%s[GREEN]%s ", green, reset)
			}

			fmt.Fprintf(w, "  %s %s%-24s%s %s\n", zoneStr, bold, asset.Algorithm, reset, asset.Location)
		}
		fmt.Fprintf(w, "%s%s%s\n\n", dim, line, reset)
	}
}

// PrintJSON outputs scan results and compliance score as JSON to stdout.
func PrintJSON(result *models.ScanResult, score *models.ComplianceScore) error {
	report := models.Report{
		Title:     "PQCAT Crypto Bill of Health",
		ScanDate:  result.Timestamp,
		Version:   version,
		Results:   []models.ScanResult{*result},
		Generated: time.Now(),
	}

	if score != nil {
		report.Scores = []models.ComplianceScore{*score}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// WriteJSON writes the report to a file.
func WriteJSON(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	report := models.Report{
		Title:     "PQCAT Crypto Bill of Health",
		ScanDate:  result.Timestamp,
		Version:   version,
		Results:   []models.ScanResult{*result},
		Generated: time.Now(),
	}

	if score != nil {
		report.Scores = []models.ComplianceScore{*score}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
