package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Framework != "cnsa2" {
		t.Errorf("Expected default framework 'cnsa2', got '%s'", cfg.Framework)
	}
	if cfg.Criticality != "STANDARD" {
		t.Errorf("Expected default criticality 'STANDARD', got '%s'", cfg.Criticality)
	}
	if cfg.Workers != 20 {
		t.Errorf("Expected default workers 20, got %d", cfg.Workers)
	}
	expectedDB := defaultDatabasePath()
	if cfg.Database.Path != expectedDB {
		t.Errorf("Expected default DB path '%s', got '%s'", expectedDB, cfg.Database.Path)
	}
	if cfg.Server.Listen != "localhost:8443" {
		t.Errorf("Expected default server listen 'localhost:8443', got '%s'", cfg.Server.Listen)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pqcat.yaml")

	content := `organization: "TestOrg"
environment: "staging"
framework: "fisma"
criticality: "HVA"
workers: 8
siem:
  format: "splunk"
  endpoint: "https://splunk.example.com"
database:
  path: "/opt/pqcat/data.db"
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile failed: %v", err)
	}
	if cfg.Organization != "TestOrg" {
		t.Errorf("Expected org 'TestOrg', got '%s'", cfg.Organization)
	}
	if cfg.Framework != "fisma" {
		t.Errorf("Expected framework 'fisma', got '%s'", cfg.Framework)
	}
	if cfg.Criticality != "HVA" {
		t.Errorf("Expected criticality 'HVA', got '%s'", cfg.Criticality)
	}
	if cfg.Workers != 8 {
		t.Errorf("Expected workers 8, got %d", cfg.Workers)
	}
	if cfg.SIEM.Format != "splunk" {
		t.Errorf("Expected SIEM format 'splunk', got '%s'", cfg.SIEM.Format)
	}
	if cfg.Database.Path != "/opt/pqcat/data.db" {
		t.Errorf("Expected DB path '/opt/pqcat/data.db', got '%s'", cfg.Database.Path)
	}
}

func TestMergeConfig(t *testing.T) {
	dst := DefaultConfig()
	src := &Config{
		Organization: "OverrideOrg",
		Framework:    "dod",
		Workers:      4,
	}

	mergeConfig(dst, src)

	if dst.Organization != "OverrideOrg" {
		t.Errorf("Expected merged org 'OverrideOrg', got '%s'", dst.Organization)
	}
	if dst.Framework != "dod" {
		t.Errorf("Expected merged framework 'dod', got '%s'", dst.Framework)
	}
	if dst.Workers != 4 {
		t.Errorf("Expected merged workers 4, got %d", dst.Workers)
	}
	// Non-overridden values should remain default
	if dst.Criticality != "STANDARD" {
		t.Errorf("Expected criticality to remain 'STANDARD', got '%s'", dst.Criticality)
	}
	if dst.Server.Listen != "localhost:8443" {
		t.Errorf("Expected server listen to remain default, got '%s'", dst.Server.Listen)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	cfg := DefaultConfig()

	os.Setenv("PQCAT_FRAMEWORK", "fedramp")
	os.Setenv("PQCAT_WORKERS", "12")
	os.Setenv("PQCAT_DB_PATH", "/data/scan.db")
	defer func() {
		os.Unsetenv("PQCAT_FRAMEWORK")
		os.Unsetenv("PQCAT_WORKERS")
		os.Unsetenv("PQCAT_DB_PATH")
	}()

	applyEnvOverrides(cfg)

	if cfg.Framework != "fedramp" {
		t.Errorf("Expected env framework 'fedramp', got '%s'", cfg.Framework)
	}
	if cfg.Workers != 12 {
		t.Errorf("Expected env workers 12, got %d", cfg.Workers)
	}
	if cfg.Database.Path != "/data/scan.db" {
		t.Errorf("Expected env DB path '/data/scan.db', got '%s'", cfg.Database.Path)
	}
}

func TestGenerateTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pqcat.yaml")
	err := GenerateTemplate(path)
	if err != nil {
		t.Fatalf("GenerateTemplate failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read generated template: %v", err)
	}

	content := string(data)
	if len(content) < 100 {
		t.Errorf("Generated template too short: %d bytes", len(content))
	}
}
