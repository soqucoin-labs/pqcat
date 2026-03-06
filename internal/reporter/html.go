// Package reporter provides self-contained HTML report generation.
// Produces a single .html file with inline CSS/JS and all scan data embedded.
// No external dependencies — opens in any browser, even offline.
// Designed for air-gap transfer: scan on classified system → copy report.html → view anywhere.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// GenerateHTML creates a self-contained interactive HTML report.
func GenerateHTML(path string, result *models.ScanResult, score *models.ComplianceScore) error {
	assetsJSON, _ := json.Marshal(result.Assets)
	scoreJSON, _ := json.Marshal(score)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQCAT — Crypto Bill of Health | %s</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0f;--surface:#12131a;--border:#1e2030;--text:#e0e0e0;--dim:#888;
--green:#00ff9d;--yellow:#ffd700;--red:#ff4757;--accent:#00ff9d}
body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:2rem}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:1rem 0}
header .container{display:flex;justify-content:space-between;align-items:center}
.logo{color:var(--accent);font-weight:700;font-size:1.1rem;text-decoration:none}
.logo span{color:var(--text)}
.meta{color:var(--dim);font-size:0.8rem}
h1{font-size:2rem;font-weight:700;margin:2rem 0 0.5rem;letter-spacing:-0.03em}
h2{font-size:1.3rem;font-weight:600;margin:2rem 0 1rem;color:var(--accent);
border-bottom:1px solid var(--border);padding-bottom:0.5rem}
.score-hero{text-align:center;padding:3rem 0;background:var(--surface);
border:1px solid var(--border);border-radius:12px;margin:2rem 0}
.score-number{font-size:5rem;font-weight:700;line-height:1}
.score-label{color:var(--dim);margin-top:0.3rem;font-size:0.9rem}
.score-green{color:var(--green)} .score-yellow{color:var(--yellow)} .score-red{color:var(--red)}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
padding:1.2rem;text-align:center}
.stat-value{font-size:1.8rem;font-weight:700}
.stat-label{color:var(--dim);font-size:0.75rem;margin-top:0.2rem}
.red{color:var(--red)} .yellow{color:var(--yellow)} .green{color:var(--green)}
table{width:100%%;border-collapse:collapse;font-size:0.85rem;margin:1rem 0}
th{text-align:left;padding:0.7rem 1rem;background:var(--surface);color:var(--dim);
font-weight:500;border-bottom:2px solid var(--border);font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05em}
td{padding:0.6rem 1rem;border-bottom:1px solid var(--border)}
tr:hover{background:rgba(0,255,157,0.02)}
.zone-badge{display:inline-block;padding:0.15rem 0.6rem;border-radius:3px;font-size:0.7rem;
font-weight:600;letter-spacing:0.05em}
.zone-RED{background:rgba(255,71,87,0.15);color:var(--red)}
.zone-YELLOW{background:rgba(255,215,0,0.15);color:var(--yellow)}
.zone-GREEN{background:rgba(0,255,157,0.15);color:var(--green)}
.filters{display:flex;gap:0.5rem;margin:1rem 0;flex-wrap:wrap}
.filter-btn{padding:0.4rem 0.8rem;background:var(--surface);border:1px solid var(--border);
color:var(--text);border-radius:4px;cursor:pointer;font-size:0.8rem}
.filter-btn.active{border-color:var(--accent);color:var(--accent)}
.filter-btn:hover{border-color:var(--accent)}
.priority-list{margin:1rem 0}
.priority-item{padding:0.8rem 1rem;background:var(--surface);border-left:3px solid var(--red);
margin:0.5rem 0;border-radius:0 4px 4px 0;font-size:0.9rem}
footer{text-align:center;padding:2rem 0;color:var(--dim);font-size:0.75rem;
border-top:1px solid var(--border);margin-top:3rem}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}}
.hidden{display:none}
.chart-bar{display:flex;height:24px;border-radius:4px;overflow:hidden;margin:1rem 0}
.chart-segment{height:100%%;transition:width 0.3s}
</style>
</head>
<body>
<header>
<div class="container">
<a class="logo" href="#">PQCAT <span>Crypto Bill of Health</span></a>
<div class="meta">Generated %s · PQCAT v1.0</div>
</div>
</header>
<div class="container">
<h1>%s</h1>
<p style="color:var(--dim)">Scan Type: %s · Framework: %s · Duration: %s</p>

<div class="score-hero">
<div class="score-number %s">%d</div>
<div class="score-label">PQC Readiness Score</div>
</div>

<div class="stats-grid">
<div class="stat-card"><div class="stat-value">%d</div><div class="stat-label">Total Assets</div></div>
<div class="stat-card"><div class="stat-value red">%d</div><div class="stat-label">Quantum Vulnerable</div></div>
<div class="stat-card"><div class="stat-value yellow">%d</div><div class="stat-label">Transitional</div></div>
<div class="stat-card"><div class="stat-value green">%d</div><div class="stat-label">CNSA 2.0 Compliant</div></div>
</div>

<div class="chart-bar">
<div class="chart-segment" style="width:%s;background:var(--red)"></div>
<div class="chart-segment" style="width:%s;background:var(--yellow)"></div>
<div class="chart-segment" style="width:%s;background:var(--green)"></div>
</div>

<h2>Priority Actions</h2>
<div class="priority-list" id="priorities"></div>

<h2>Asset Inventory</h2>
<div class="filters">
<button class="filter-btn active" onclick="filterAssets('all')">All</button>
<button class="filter-btn" onclick="filterAssets('RED')">Red</button>
<button class="filter-btn" onclick="filterAssets('YELLOW')">Yellow</button>
<button class="filter-btn" onclick="filterAssets('GREEN')">Green</button>
</div>
<table>
<thead><tr><th>Zone</th><th>Algorithm</th><th>Location</th><th>Type</th><th>Criticality</th></tr></thead>
<tbody id="asset-table"></tbody>
</table>

<h2>Compliance Details</h2>
<div id="compliance-details"></div>
</div>

<footer>
<p>PQCAT™ — Post-Quantum Compliance Assessment Tool</p>
<p>© 2026 Soqucoin Labs Inc. · 228 Park Ave S, Pmb 85451, New York, NY 10003</p>
<p style="margin-top:0.5rem">This report is self-contained. No network connection required to view.</p>
</footer>

<script>
const assets=%s;
const score=%s;

function renderAssets(filter){
const tbody=document.getElementById('asset-table');
tbody.innerHTML='';
const filtered=filter==='all'?assets:assets.filter(a=>a.zone===filter);
filtered.forEach(a=>{
const tr=document.createElement('tr');
tr.innerHTML='<td><span class="zone-badge zone-'+a.zone+'">'+a.zone+'</span></td>'+
'<td>'+a.algorithm+'</td><td>'+a.location+'</td><td>'+a.type+'</td>'+
'<td>'+a.criticality+'</td>';
tbody.appendChild(tr);
});
}

function filterAssets(zone){
document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
event.target.classList.add('active');
renderAssets(zone);
}

function renderPriorities(){
const container=document.getElementById('priorities');
const redAssets=assets.filter(a=>a.zone==='RED');
const grouped={};
redAssets.forEach(a=>{if(!grouped[a.algorithm])grouped[a.algorithm]=0;grouped[a.algorithm]++;});
const sorted=Object.entries(grouped).sort((a,b)=>b[1]-a[1]).slice(0,10);
sorted.forEach(([algo,count])=>{
const div=document.createElement('div');
div.className='priority-item';
div.textContent='Migrate '+count+' '+algo+' asset'+(count>1?'s':'')+' to PQC equivalent';
container.appendChild(div);
});
if(sorted.length===0){container.innerHTML='<p style="color:var(--green)">✓ No quantum-vulnerable assets detected.</p>';}
}

function renderCompliance(){
const container=document.getElementById('compliance-details');
let html='<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>';
html+='<tr><td>Framework</td><td>'+score.framework+'</td></tr>';
html+='<tr><td>Overall Score</td><td>'+score.overall.toFixed(1)+' / 100</td></tr>';
html+='<tr><td>Total Assets</td><td>'+score.total_assets+'</td></tr>';
if(score.next_deadline){
html+='<tr><td>Next Milestone</td><td>'+score.next_deadline.milestone+'</td></tr>';
html+='<tr><td>Days Remaining</td><td>'+score.next_deadline.days_left+'</td></tr>';
}
html+='</tbody></table>';
container.innerHTML=html;
}

renderAssets('all');
renderPriorities();
renderCompliance();
</script>
</body>
</html>`,
		// Template values
		result.Target,
		time.Now().Format("January 2, 2006 15:04 MST"),
		result.Target,
		result.ScanType,
		score.Framework,
		result.Duration.Round(time.Millisecond).String(),
		scoreColorClass(score.Overall),
		int(score.Overall),
		score.TotalAssets,
		score.ZoneCounts[models.ZoneRed],
		score.ZoneCounts[models.ZoneYellow],
		score.ZoneCounts[models.ZoneGreen],
		zonePercent(score.ZoneCounts[models.ZoneRed], score.TotalAssets),
		zonePercent(score.ZoneCounts[models.ZoneYellow], score.TotalAssets),
		zonePercent(score.ZoneCounts[models.ZoneGreen], score.TotalAssets),
		string(assetsJSON),
		string(scoreJSON),
	)

	return os.WriteFile(path, []byte(html), 0644)
}

func scoreColorClass(score float64) string {
	switch {
	case score >= 80:
		return "score-green"
	case score >= 50:
		return "score-yellow"
	default:
		return "score-red"
	}
}

func zonePercent(count, total int) string {
	if total == 0 {
		return "0%"
	}
	pct := float64(count) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", pct)
}
