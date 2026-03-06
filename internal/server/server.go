//go:build connected

// Package server provides an HTTP REST API for PQCAT Pro edition.
// Only compiled when using: go build -tags connected
// Air-gapped edition has ZERO server code in the binary.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/compliance"
	"github.com/soqucoin-labs/pqcat/internal/config"
	"github.com/soqucoin-labs/pqcat/internal/models"
	"github.com/soqucoin-labs/pqcat/internal/reporter"
	"github.com/soqucoin-labs/pqcat/internal/scanner"
	"github.com/soqucoin-labs/pqcat/internal/store"
)

// Server holds the HTTP server configuration and dependencies.
type Server struct {
	cfg *config.Config
	db  *store.DB
	mux *http.ServeMux
}

// New creates a new Server with all routes registered.
func New(cfg *config.Config, db *store.DB) *Server {
	s := &Server{cfg: cfg, db: db, mux: http.NewServeMux()}
	s.registerRoutes()
	return s
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	addr := s.cfg.Server.Listen
	if addr == "" {
		addr = "localhost:8443"
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ╔═══════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "  ║  PQCAT Pro — REST API & Dashboard         ║\n")
	fmt.Fprintf(os.Stderr, "  ║  Listening: http://%s          ║\n", padRight(addr, 14))
	fmt.Fprintf(os.Stderr, "  ║  API Docs:  http://%s/api      ║\n", padRight(addr, 10))
	fmt.Fprintf(os.Stderr, "  ║  Press Ctrl+C to stop                    ║\n")
	fmt.Fprintf(os.Stderr, "  ╚═══════════════════════════════════════════╝\n")
	fmt.Fprintf(os.Stderr, "\n")

	server := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if s.cfg.Server.TLS && s.cfg.Server.CertFile != "" {
		return server.ListenAndServeTLS(s.cfg.Server.CertFile, s.cfg.Server.KeyFile)
	}
	return server.ListenAndServe()
}

func (s *Server) registerRoutes() {
	// API endpoints
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/scans", s.handleScans)
	s.mux.HandleFunc("/api/scans/", s.handleScanDetail)
	s.mux.HandleFunc("/api/scan", s.handleRunScan)
	s.mux.HandleFunc("/api/trend", s.handleTrend)
	s.mux.HandleFunc("/api", s.handleAPIDocs)

	// Dashboard (embedded SPA)
	s.mux.HandleFunc("/", s.handleDashboard)
}

// ── API Handlers ──────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status":  "ok",
		"version": "1.0.0-alpha",
		"edition": "pro",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	scans, err := s.db.GetScans(limit)
	if err != nil {
		writeError(w, 500, "Failed to query scans: "+err.Error())
		return
	}
	writeJSON(w, scans)
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Missing scan ID", 400)
		return
	}
	scanID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		writeError(w, 400, "Invalid scan ID")
		return
	}

	assets, err := s.db.GetScanAssets(scanID)
	if err != nil {
		writeError(w, 500, "Failed to query assets: "+err.Error())
		return
	}
	writeJSON(w, assets)
}

func (s *Server) handleRunScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed — POST required", 405)
		return
	}

	var req struct {
		Target    string `json:"target"`
		ScanType  string `json:"scan_type"`
		Framework string `json:"framework"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "Invalid request: "+err.Error())
		return
	}

	if req.Target == "" || req.ScanType == "" {
		writeError(w, 400, "target and scan_type are required")
		return
	}
	if req.Framework == "" {
		req.Framework = s.cfg.Framework
	}

	// Run the scan
	var result *models.ScanResult
	var scanErr error

	switch req.ScanType {
	case "tls":
		opts := scanner.DefaultTLSOptions()
		result, scanErr = scanner.ScanTLS(req.Target, opts)
	case "ssh":
		opts := scanner.DefaultSSHOptions()
		result, scanErr = scanner.ScanSSH(req.Target, opts)
	case "code":
		result, scanErr = scanner.ScanCode(req.Target)
	case "pki":
		result, scanErr = scanner.ScanPKI(req.Target)
	case "hsm":
		result, scanErr = scanner.ScanHSM(req.Target)
	default:
		writeError(w, 400, "unsupported scan type: "+req.ScanType)
		return
	}

	if scanErr != nil && (result == nil || len(result.Assets) == 0) {
		writeError(w, 500, "Scan failed: "+scanErr.Error())
		return
	}

	// Score
	fw := compliance.Framework(req.Framework)
	score := compliance.Score(result.Assets, fw)

	// Save to DB
	scanID, saveErr := s.db.SaveScan(result, req.Framework, score.Overall,
		s.cfg.Organization, s.cfg.Environment)

	response := map[string]interface{}{
		"scan_id": scanID,
		"target":  result.Target,
		"score":   score.Overall,
		"assets":  len(result.Assets),
		"red":     score.ZoneCounts[models.ZoneRed],
		"yellow":  score.ZoneCounts[models.ZoneYellow],
		"green":   score.ZoneCounts[models.ZoneGreen],
	}
	if saveErr != nil {
		response["db_error"] = saveErr.Error()
	}

	writeJSON(w, response)
}

func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeError(w, 400, "target parameter required")
		return
	}
	limit := 30
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}

	trend, err := s.db.GetScoreTrend(target, limit)
	if err != nil {
		writeError(w, 500, "Failed to query trend: "+err.Error())
		return
	}
	writeJSON(w, trend)
}

func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	docs := map[string]interface{}{
		"name":    "PQCAT Pro API",
		"version": "1.0.0-alpha",
		"endpoints": []map[string]string{
			{"method": "GET", "path": "/api/health", "description": "Health check"},
			{"method": "GET", "path": "/api/scans?limit=50", "description": "List recent scans"},
			{"method": "GET", "path": "/api/scans/{id}", "description": "Get scan assets"},
			{"method": "POST", "path": "/api/scan", "description": "Run a new scan"},
			{"method": "GET", "path": "/api/trend?target=X&limit=30", "description": "Score trend for a target"},
		},
	}
	writeJSON(w, docs)
}

// ── Dashboard ──────────────────────────────────────

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Generate dashboard with live data
	scans, _ := s.db.GetScans(20)

	scansJSON, _ := json.Marshal(scans)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PQCAT Pro — Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0f;--surface:#12131a;--border:#1e2030;--text:#e0e0e0;--dim:#888;
--green:#00ff9d;--yellow:#ffd700;--red:#ff4757;--accent:#00ff9d}
body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text)}
.container{max-width:1200px;margin:0 auto;padding:1.5rem}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:0.8rem 0}
header .container{display:flex;justify-content:space-between;align-items:center}
.logo{color:var(--accent);font-weight:700;font-size:1.1rem}
.logo span{color:var(--text)}
.badge{background:rgba(0,255,157,0.1);border:1px solid var(--accent);color:var(--accent);
padding:0.2rem 0.6rem;border-radius:3px;font-size:0.7rem;font-weight:600}
h1{font-size:1.5rem;margin:1.5rem 0 1rem}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1rem 0}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem}
.card-value{font-size:2rem;font-weight:700}
.card-label{color:var(--dim);font-size:0.8rem;margin-top:0.3rem}
table{width:100%%;border-collapse:collapse;margin:1rem 0;font-size:0.85rem}
th{text-align:left;padding:0.6rem;background:var(--surface);color:var(--dim);font-weight:500;
border-bottom:2px solid var(--border);font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em}
td{padding:0.5rem 0.6rem;border-bottom:1px solid var(--border)}
tr:hover td{background:rgba(0,255,157,0.02)}
.score{font-weight:700}.green{color:var(--green)}.yellow{color:var(--yellow)}.red{color:var(--red)}
.scan-btn{background:var(--accent);color:var(--bg);border:none;padding:0.5rem 1rem;
border-radius:4px;font-weight:600;cursor:pointer;font-size:0.85rem}
.scan-btn:hover{opacity:0.9}
input{background:var(--surface);border:1px solid var(--border);color:var(--text);
padding:0.5rem;border-radius:4px;font-size:0.85rem;width:200px}
select{background:var(--surface);border:1px solid var(--border);color:var(--text);
padding:0.5rem;border-radius:4px;font-size:0.85rem}
.scan-form{display:flex;gap:0.5rem;align-items:center;margin:1rem 0}
footer{text-align:center;padding:1.5rem;color:var(--dim);font-size:0.7rem;margin-top:2rem;
border-top:1px solid var(--border)}
</style></head><body>
<header><div class="container">
<div class="logo">PQCAT <span>Pro Dashboard</span></div>
<span class="badge">CONNECTED EDITION</span>
</div></header>
<div class="container">
<h1>Recent Scans</h1>
<div class="scan-form">
<input id="target" placeholder="Target (e.g., example.com)" />
<select id="scan-type"><option value="tls">TLS</option><option value="ssh">SSH</option>
<option value="code">Code</option><option value="pki">PKI</option><option value="hsm">HSM</option></select>
<button class="scan-btn" onclick="runScan()">Run Scan</button>
<span id="status"></span>
</div>
<div class="grid" id="stats"></div>
<table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Framework</th>
<th>Score</th><th>Assets</th><th>Red</th><th>Yellow</th><th>Green</th><th>Date</th></tr></thead>
<tbody id="scans"></tbody></table>
</div>
<footer>PQCAT™ Pro — Soqucoin Labs Inc. · Connected Edition</footer>
<script>
let scans=%s;
function render(){
const tbody=document.getElementById('scans');tbody.innerHTML='';
scans.forEach(s=>{
const cls=s.score>=80?'green':s.score>=50?'yellow':'red';
const d=new Date(s.created_at).toLocaleString();
tbody.innerHTML+='<tr><td>'+s.id+'</td><td>'+s.target+'</td><td>'+s.scan_type+'</td>'+
'<td>'+s.framework+'</td><td class="score '+cls+'">'+s.score.toFixed(1)+'</td>'+
'<td>'+s.asset_count+'</td><td class="red">'+s.red_count+'</td>'+
'<td class="yellow">'+s.yellow_count+'</td><td class="green">'+s.green_count+'</td>'+
'<td>'+d+'</td></tr>';
});
const stats=document.getElementById('stats');
const total=scans.length;const avg=total?scans.reduce((a,s)=>a+s.score,0)/total:0;
const totalAssets=scans.reduce((a,s)=>a+s.asset_count,0);
const totalRed=scans.reduce((a,s)=>a+s.red_count,0);
stats.innerHTML='<div class="card"><div class="card-value">'+total+'</div><div class="card-label">Total Scans</div></div>'+
'<div class="card"><div class="card-value '+(avg>=80?'green':'red')+'">'+avg.toFixed(0)+'</div><div class="card-label">Avg Score</div></div>'+
'<div class="card"><div class="card-value">'+totalAssets+'</div><div class="card-label">Assets Discovered</div></div>'+
'<div class="card"><div class="card-value red">'+totalRed+'</div><div class="card-label">Vulnerable Assets</div></div>';
}
async function runScan(){
const t=document.getElementById('target').value;const st=document.getElementById('scan-type').value;
if(!t){alert('Enter a target');return;}
document.getElementById('status').textContent='Scanning...';
try{const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({target:t,scan_type:st,framework:'cnsa2'})});
const d=await r.json();if(r.ok){scans.unshift({id:d.scan_id,target:d.target,scan_type:st,
framework:'cnsa2',score:d.score,asset_count:d.assets,red_count:d.red,yellow_count:d.yellow,
green_count:d.green,created_at:new Date().toISOString()});render();
document.getElementById('status').textContent='✓ Score: '+d.score.toFixed(1);}
else{document.getElementById('status').textContent='Error: '+d.error;}}
catch(e){document.getElementById('status').textContent='Error: '+e.message;}
}
render();
</script></body></html>`, string(scansJSON))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// ── Helpers ──────────────────────────────────────

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func padRight(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

// Ensure reporter is available for future HTML export via API
var _ = reporter.GenerateHTML
