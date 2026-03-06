package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGetThreatIntel verifies embedded intel is valid.
func TestGetThreatIntel(t *testing.T) {
	intel := GetThreatIntel()
	if intel == nil {
		t.Fatal("GetThreatIntel() returned nil")
	}
	if intel.QDayEstimate.MedianYear == 0 {
		t.Error("Q-Day median year is 0")
	}
	if intel.QDayEstimate.OptimisticYear >= intel.QDayEstimate.MedianYear {
		t.Error("Optimistic year should be before median")
	}
	if intel.QDayEstimate.MedianYear >= intel.QDayEstimate.ConservativeYear {
		t.Error("Median year should be before conservative")
	}
	if len(intel.Milestones) == 0 {
		t.Error("No milestones in embedded intel")
	}
	if len(intel.RiskAdjustments) == 0 {
		t.Error("No risk adjustments in embedded intel")
	}
	if !intel.AdversaryStatus.HarvestNowDecryptLater {
		t.Error("HNDL should be flagged as active")
	}
}

// TestCalculateThreatMultiplier verifies multiplier is within expected range.
func TestCalculateThreatMultiplier(t *testing.T) {
	intel := GetThreatIntel()
	multiplier := CalculateThreatMultiplier(intel)

	if multiplier < 1.0 {
		t.Errorf("Threat multiplier %.2f is below 1.0", multiplier)
	}
	if multiplier > 2.0 {
		t.Errorf("Threat multiplier %.2f is above 2.0 — unreasonably high", multiplier)
	}
	t.Logf("Current threat multiplier: %.2fx", multiplier)
}

// TestLoadThreatIntel_FallbackToEmbedded verifies fallback works.
func TestLoadThreatIntel_FallbackToEmbedded(t *testing.T) {
	result := LoadThreatIntel("")
	if result == nil {
		t.Fatal("LoadThreatIntel returned nil")
	}
	if result.Source != IntelSourceEmbedded {
		t.Errorf("Expected EMBEDDED source, got %s", result.Source)
	}
	if result.Intel == nil {
		t.Fatal("Intel is nil")
	}
}

// TestLoadThreatIntel_ExplicitFile verifies explicit file loading.
func TestLoadThreatIntel_ExplicitFile(t *testing.T) {
	// Create temp sidecar file
	dir := t.TempDir()
	path := filepath.Join(dir, "test-intel.json")

	intel := GetThreatIntel()
	if err := WriteThreatIntelJSON(path, intel); err != nil {
		t.Fatalf("Failed to write test intel: %v", err)
	}

	result := LoadThreatIntel(path)
	if result.Source != IntelSourceSidecar {
		t.Errorf("Expected SIDECAR source, got %s", result.Source)
	}
	if result.Path != path {
		t.Errorf("Expected path %s, got %s", path, result.Path)
	}
}

// TestLoadThreatIntel_InvalidFile verifies graceful fallback on bad file.
func TestLoadThreatIntel_InvalidFile(t *testing.T) {
	result := LoadThreatIntel("/nonexistent/path.json")
	if result.Source != IntelSourceEmbedded {
		t.Errorf("Expected EMBEDDED fallback, got %s", result.Source)
	}
}

// TestWriteThreatIntelJSON verifies JSON export.
func TestWriteThreatIntelJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.json")

	intel := GetThreatIntel()
	if err := WriteThreatIntelJSON(path, intel); err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("File not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Written file is empty")
	}
}

// TestIsConnectedEdition verifies build tag behavior.
func TestIsConnectedEdition(t *testing.T) {
	// In default (air-gapped) build, should be false
	// In connected build (-tags connected), should be true
	connected := IsConnectedEdition()
	t.Logf("IsConnectedEdition() = %v", connected)
}

// TestIntelAge verifies age string formatting.
func TestIntelAge(t *testing.T) {
	intel := GetThreatIntel()
	age := intelAge(intel.LastUpdated)
	if age == "" {
		t.Error("intelAge returned empty string")
	}
	t.Logf("Embedded intel age: %s", age)
}
