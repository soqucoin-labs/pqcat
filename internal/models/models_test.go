package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestZoneConstants(t *testing.T) {
	zones := []Zone{ZoneRed, ZoneYellow, ZoneGreen}
	expected := []string{"RED", "YELLOW", "GREEN"}
	for i, z := range zones {
		if string(z) != expected[i] {
			t.Errorf("Zone %d: expected %s, got %s", i, expected[i], string(z))
		}
	}
}

func TestAssetTypeConstants(t *testing.T) {
	types := []AssetType{
		AssetTLSCert, AssetTLSCipher, AssetSSHHostKey, AssetSSHKEX,
		AssetSBOMDep, AssetPKICert, AssetCodeCrypto, AssetHSMModule,
	}
	if len(types) != 8 {
		t.Errorf("Expected 8 asset types, got %d", len(types))
	}
	for _, at := range types {
		if string(at) == "" {
			t.Error("AssetType is empty string")
		}
	}
}

func TestCriticalityConstants(t *testing.T) {
	if string(CriticalityStandard) != "STANDARD" {
		t.Errorf("Expected STANDARD, got %s", CriticalityStandard)
	}
	if string(CriticalityHVA) != "HVA" {
		t.Errorf("Expected HVA, got %s", CriticalityHVA)
	}
	if string(CriticalityNSS) != "NSS" {
		t.Errorf("Expected NSS, got %s", CriticalityNSS)
	}
}

func TestScanResultJSON(t *testing.T) {
	ts := time.Date(2026, 3, 6, 12, 0, 0, 0, time.UTC)
	result := ScanResult{
		Target:    "example.com",
		ScanType:  "tls",
		Timestamp: ts,
		Assets: []CryptoAsset{
			{Algorithm: "RSA-2048", Zone: ZoneRed, Location: "example.com:443", KeySize: 2048, Criticality: CriticalityStandard},
			{Algorithm: "ML-KEM-768", Zone: ZoneGreen, Location: "example.com:443", Criticality: CriticalityHVA},
		},
		Duration: 500 * time.Millisecond,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Target != "example.com" {
		t.Errorf("Target mismatch: %s", decoded.Target)
	}
	if len(decoded.Assets) != 2 {
		t.Fatalf("Expected 2 assets, got %d", len(decoded.Assets))
	}
	if decoded.Assets[0].Zone != ZoneRed {
		t.Errorf("Asset 0 zone: expected RED, got %s", decoded.Assets[0].Zone)
	}
	if decoded.Assets[1].Criticality != CriticalityHVA {
		t.Errorf("Asset 1 criticality: expected HVA, got %s", decoded.Assets[1].Criticality)
	}
}

func TestComplianceScoreJSON(t *testing.T) {
	score := ComplianceScore{
		Overall:   85.5,
		Framework: "cnsa2",
		ZoneCounts: map[Zone]int{
			ZoneRed:    2,
			ZoneYellow: 1,
			ZoneGreen:  5,
		},
		TotalAssets: 8,
		TopActions: []MigrationAction{
			{Priority: 1, Description: "Replace RSA-2048", AssetCount: 2, Complexity: "MEDIUM", Urgency: "IMMEDIATE"},
		},
		NextDeadline: &ComplianceDeadline{
			Framework: "cnsa2",
			Milestone: "PQC Migration Complete",
			Deadline:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			DaysLeft:  1395,
		},
	}

	data, err := json.Marshal(score)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ComplianceScore
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Overall != 85.5 {
		t.Errorf("Score: expected 85.5, got %f", decoded.Overall)
	}
	if decoded.ZoneCounts[ZoneRed] != 2 {
		t.Errorf("Red count: expected 2, got %d", decoded.ZoneCounts[ZoneRed])
	}
	if decoded.NextDeadline == nil {
		t.Fatal("NextDeadline is nil")
	}
	if decoded.NextDeadline.DaysLeft != 1395 {
		t.Errorf("DaysLeft: expected 1395, got %d", decoded.NextDeadline.DaysLeft)
	}
}

func TestReportJSON(t *testing.T) {
	report := Report{
		Title:   "PQCAT Crypto Bill of Health",
		Agency:  "TestAgency",
		Version: "1.0.0",
		Results: []ScanResult{
			{Target: "test.gov", ScanType: "tls", Timestamp: time.Now()},
		},
		Scores: []ComplianceScore{
			{Overall: 72.0, Framework: "fisma", ZoneCounts: map[Zone]int{ZoneRed: 3, ZoneGreen: 7}, TotalAssets: 10},
		},
		Generated: time.Now(),
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) < 100 {
		t.Errorf("Report JSON too short: %d bytes", len(data))
	}

	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Title != "PQCAT Crypto Bill of Health" {
		t.Errorf("Title mismatch: %s", decoded.Title)
	}
	if len(decoded.Results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(decoded.Results))
	}
}
