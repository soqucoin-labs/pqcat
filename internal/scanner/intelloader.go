// Package scanner provides tiered threat intelligence loading.
// Tier 1: Embedded static data (always available, air-gapped safe)
// Tier 2: Sidecar JSON file (sneakernet updates for air-gapped environments)
// Tier 3: Live feed (connected edition only, controlled by build tags)
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IntelSource describes where the threat intelligence data was loaded from.
type IntelSource string

const (
	IntelSourceEmbedded IntelSource = "EMBEDDED"  // Baked into binary at compile time
	IntelSourceSidecar  IntelSource = "SIDECAR"   // Local JSON file (sneakernet)
	IntelSourceLive     IntelSource = "LIVE_FEED" // Network fetch (connected edition only)
)

// IntelResult wraps the threat intel with provenance metadata.
type IntelResult struct {
	Intel  *ThreatIntel `json:"intel"`
	Source IntelSource  `json:"source"`
	Path   string       `json:"path,omitempty"` // File path if sidecar
	URL    string       `json:"url,omitempty"`  // URL if live feed
	Age    string       `json:"age"`            // Human-readable age of data
}

// LoadThreatIntel loads threat intelligence using the tiered fallback strategy.
// Priority: explicit file > sidecar file > embedded data.
// Live feed is only available in the connected edition (build tag: connected).
func LoadThreatIntel(explicitPath string) *IntelResult {
	// Priority 1: Explicit file path (--intel-file flag)
	if explicitPath != "" {
		if intel, err := loadIntelFile(explicitPath); err == nil {
			return &IntelResult{
				Intel:  intel,
				Source: IntelSourceSidecar,
				Path:   explicitPath,
				Age:    intelAge(intel.LastUpdated),
			}
		}
		fmt.Fprintf(os.Stderr, "[intel] Warning: could not load %s, falling back\n", explicitPath)
	}

	// Priority 2: Sidecar file discovery
	sidecarPaths := getSidecarPaths()
	for _, path := range sidecarPaths {
		if intel, err := loadIntelFile(path); err == nil {
			// Only use if newer than embedded
			embedded := GetThreatIntel()
			if intel.LastUpdated.After(embedded.LastUpdated) {
				return &IntelResult{
					Intel:  intel,
					Source: IntelSourceSidecar,
					Path:   path,
					Age:    intelAge(intel.LastUpdated),
				}
			}
		}
	}

	// Priority 3: Embedded static data (always available)
	embedded := GetThreatIntel()
	return &IntelResult{
		Intel:  embedded,
		Source: IntelSourceEmbedded,
		Age:    intelAge(embedded.LastUpdated),
	}
}

// getSidecarPaths returns the ordered list of paths to check for sidecar intel files.
func getSidecarPaths() []string {
	var paths []string

	// 1. Current working directory
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, "pqcat-intel.json"))
	}

	// 2. Same directory as the binary
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		paths = append(paths, filepath.Join(exeDir, "pqcat-intel.json"))
	}

	// 3. ~/.pqcat/ config directory
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".pqcat", "pqcat-intel.json"),
			filepath.Join(home, ".pqcat", "intel.json"),
		)
	}

	// 4. /etc/pqcat/ (system-wide, common in federal deployments)
	paths = append(paths, "/etc/pqcat/pqcat-intel.json")

	return paths
}

// loadIntelFile reads and parses a threat intel JSON file.
func loadIntelFile(path string) (*ThreatIntel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var intel ThreatIntel
	if err := json.Unmarshal(data, &intel); err != nil {
		return nil, fmt.Errorf("invalid intel format in %s: %w", path, err)
	}

	// Validate minimum fields
	if intel.LastUpdated.IsZero() {
		return nil, fmt.Errorf("missing last_updated in %s", path)
	}

	return &intel, nil
}

// intelAge returns a human-readable age string for the intel data.
func intelAge(lastUpdated time.Time) string {
	age := time.Since(lastUpdated)
	days := int(age.Hours() / 24)

	switch {
	case days == 0:
		return "today"
	case days == 1:
		return "1 day old"
	case days < 30:
		return fmt.Sprintf("%d days old", days)
	case days < 365:
		months := days / 30
		return fmt.Sprintf("%d months old", months)
	default:
		years := days / 365
		return fmt.Sprintf("%d years old", years)
	}
}

// PrintIntelSource displays the intelligence source attribution.
func PrintIntelSource(result *IntelResult) {
	sourceLabel := ""
	switch result.Source {
	case IntelSourceEmbedded:
		sourceLabel = "Embedded (compiled " + result.Intel.LastUpdated.Format("Jan 2006") + ")"
	case IntelSourceSidecar:
		sourceLabel = fmt.Sprintf("Sidecar file: %s", result.Path)
	case IntelSourceLive:
		sourceLabel = fmt.Sprintf("Live feed: %s", result.URL)
	}

	fmt.Fprintf(os.Stderr, "[intel] Source: %s (%s)\n", sourceLabel, result.Age)

	// Warn if stale
	age := time.Since(result.Intel.LastUpdated)
	if age.Hours() > 24*90 { // 90 days
		fmt.Fprintf(os.Stderr, "[intel] ⚠ Intel data is %s — consider updating pqcat-intel.json\n", result.Age)
	}
}

// GenerateSidecarTemplate writes the current embedded intel to a file,
// which operators can then edit/update and deploy as a sidecar.
func GenerateSidecarTemplate(path string) error {
	intel := GetThreatIntel()
	return WriteThreatIntelJSON(path, intel)
}
