// Package store provides SQLite-based scan history storage.
// Uses modernc.org/sqlite (pure Go, no CGO) for zero-dependency deployment.
// The .db file is portable across air gaps — copy to USB for offline analysis.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// DB wraps the SQLite database connection.
type DB struct {
	db *sql.DB
}

// Open creates or opens a SQLite database at the given path.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("cannot open database: %w", err)
	}

	// Enable WAL mode for better concurrent read performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("cannot set WAL mode: %w", err)
	}
	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("cannot enable foreign keys: %w", err)
	}

	store := &DB{db: db}
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return store, nil
}

// Close closes the database connection.
func (s *DB) Close() error {
	return s.db.Close()
}

// migrate creates tables if they don't exist.
func (s *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		target      TEXT NOT NULL,
		scan_type   TEXT NOT NULL,
		framework   TEXT NOT NULL DEFAULT 'cnsa2',
		score       REAL NOT NULL DEFAULT 0,
		asset_count INTEGER NOT NULL DEFAULT 0,
		red_count   INTEGER NOT NULL DEFAULT 0,
		yellow_count INTEGER NOT NULL DEFAULT 0,
		green_count  INTEGER NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		organization TEXT,
		environment  TEXT,
		metadata    TEXT,
		created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS assets (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
		algorithm   TEXT NOT NULL,
		zone        TEXT NOT NULL,
		asset_type  TEXT NOT NULL,
		location    TEXT NOT NULL,
		criticality TEXT NOT NULL DEFAULT 'STANDARD',
		key_size    INTEGER DEFAULT 0,
		details     TEXT,
		created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS baselines (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		scan_id     INTEGER NOT NULL REFERENCES scans(id),
		description TEXT,
		created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS drift_events (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		baseline_id INTEGER NOT NULL REFERENCES baselines(id),
		scan_id     INTEGER NOT NULL REFERENCES scans(id),
		change_type TEXT NOT NULL,
		asset_algorithm TEXT,
		asset_location  TEXT,
		old_zone    TEXT,
		new_zone    TEXT,
		details     TEXT,
		created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS remediation (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		asset_id    INTEGER REFERENCES assets(id),
		scan_id     INTEGER NOT NULL REFERENCES scans(id),
		status      TEXT NOT NULL DEFAULT 'OPEN',
		priority    TEXT NOT NULL DEFAULT 'MEDIUM',
		assigned_to TEXT,
		due_date    DATE,
		closed_date DATE,
		notes       TEXT,
		poam_id     TEXT,
		created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
		updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
	CREATE INDEX IF NOT EXISTS idx_assets_zone ON assets(zone);
	CREATE INDEX IF NOT EXISTS idx_drift_baseline ON drift_events(baseline_id);
	CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation(status);
	CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
	CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);

	-- POA&M export view: maps directly to OMB POA&M template fields
	CREATE VIEW IF NOT EXISTS poam_export AS
	SELECT
		r.poam_id AS "POA&M ID",
		a.algorithm AS "Weakness/Vulnerability",
		a.location AS "System/Asset",
		a.zone AS "Risk Level",
		r.status AS "Status",
		r.priority AS "Priority",
		r.assigned_to AS "Responsible Party",
		r.due_date AS "Scheduled Completion",
		r.closed_date AS "Actual Completion",
		r.notes AS "Milestones/Comments",
		s.framework AS "Framework",
		s.created_at AS "Discovery Date"
	FROM remediation r
	JOIN assets a ON r.asset_id = a.id
	JOIN scans s ON r.scan_id = s.id
	WHERE r.status != 'CLOSED';

	-- Score trending view
	CREATE VIEW IF NOT EXISTS score_trend AS
	SELECT
		target,
		framework,
		score,
		asset_count,
		red_count,
		yellow_count,
		green_count,
		created_at
	FROM scans
	ORDER BY created_at DESC;
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveScan persists a scan result and all its assets.
func (s *DB) SaveScan(result *models.ScanResult, framework string, score float64, org, env string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Count zones
	red, yellow, green := 0, 0, 0
	for _, a := range result.Assets {
		switch a.Zone {
		case models.ZoneRed:
			red++
		case models.ZoneYellow:
			yellow++
		case models.ZoneGreen:
			green++
		}
	}

	res, err := tx.Exec(`
		INSERT INTO scans (target, scan_type, framework, score, asset_count, red_count, yellow_count, green_count, duration_ms, organization, environment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.Target, result.ScanType, framework, score,
		len(result.Assets), red, yellow, green,
		result.Duration.Milliseconds(), org, env,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to save scan: %w", err)
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	// Save assets
	stmt, err := tx.Prepare(`
		INSERT INTO assets (scan_id, algorithm, zone, asset_type, location, criticality, key_size, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, a := range result.Assets {
		detailsJSON, _ := json.Marshal(a.Details)
		_, err := stmt.Exec(scanID, a.Algorithm, string(a.Zone), string(a.Type),
			a.Location, string(a.Criticality), a.KeySize, string(detailsJSON))
		if err != nil {
			return 0, fmt.Errorf("failed to save asset: %w", err)
		}
	}

	return scanID, tx.Commit()
}

// GetScans returns recent scans, most recent first.
func (s *DB) GetScans(limit int) ([]ScanSummary, error) {
	rows, err := s.db.Query(`
		SELECT id, target, scan_type, framework, score, asset_count,
		       red_count, yellow_count, green_count, duration_ms, created_at
		FROM scans ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanSummary
	for rows.Next() {
		var scan ScanSummary
		err := rows.Scan(&scan.ID, &scan.Target, &scan.ScanType, &scan.Framework,
			&scan.Score, &scan.AssetCount, &scan.RedCount, &scan.YellowCount,
			&scan.GreenCount, &scan.DurationMS, &scan.CreatedAt)
		if err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

// GetScanAssets returns all assets for a given scan.
func (s *DB) GetScanAssets(scanID int64) ([]AssetRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, algorithm, zone, asset_type, location, criticality, key_size, details
		FROM assets WHERE scan_id = ? ORDER BY zone, algorithm`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []AssetRecord
	for rows.Next() {
		var a AssetRecord
		err := rows.Scan(&a.ID, &a.Algorithm, &a.Zone, &a.AssetType,
			&a.Location, &a.Criticality, &a.KeySize, &a.Details)
		if err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, nil
}

// GetScoreTrend returns score history for a target.
func (s *DB) GetScoreTrend(target string, limit int) ([]ScoreTrendPoint, error) {
	rows, err := s.db.Query(`
		SELECT score, red_count, yellow_count, green_count, created_at
		FROM scans WHERE target = ? ORDER BY created_at DESC LIMIT ?`, target, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trend []ScoreTrendPoint
	for rows.Next() {
		var p ScoreTrendPoint
		err := rows.Scan(&p.Score, &p.Red, &p.Yellow, &p.Green, &p.Timestamp)
		if err != nil {
			return nil, err
		}
		trend = append(trend, p)
	}
	return trend, nil
}

// ScanSummary is a lightweight scan record for listings.
type ScanSummary struct {
	ID          int64     `json:"id"`
	Target      string    `json:"target"`
	ScanType    string    `json:"scan_type"`
	Framework   string    `json:"framework"`
	Score       float64   `json:"score"`
	AssetCount  int       `json:"asset_count"`
	RedCount    int       `json:"red_count"`
	YellowCount int       `json:"yellow_count"`
	GreenCount  int       `json:"green_count"`
	DurationMS  int64     `json:"duration_ms"`
	CreatedAt   time.Time `json:"created_at"`
}

// AssetRecord represents a stored asset.
type AssetRecord struct {
	ID          int64  `json:"id"`
	Algorithm   string `json:"algorithm"`
	Zone        string `json:"zone"`
	AssetType   string `json:"asset_type"`
	Location    string `json:"location"`
	Criticality string `json:"criticality"`
	KeySize     int    `json:"key_size"`
	Details     string `json:"details"`
}

// ScoreTrendPoint is a single data point for score trending.
type ScoreTrendPoint struct {
	Score     float64   `json:"score"`
	Red       int       `json:"red"`
	Yellow    int       `json:"yellow"`
	Green     int       `json:"green"`
	Timestamp time.Time `json:"timestamp"`
}
