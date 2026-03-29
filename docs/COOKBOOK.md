# PQCAT Cookbook — Common Workflows

Practical recipes for each persona. Copy-paste these commands to get results fast.

---

## For Carlos (CISO) — "Show me our risk"

### Quick Risk Dashboard

```bash
# Scan your domain and get an instant compliance score
pqcat scan tls yourcompany.com --framework cnsa2

# Generate a branded board-ready PDF
pqcat scan tls yourcompany.com --framework cnsa2 --briefing board-report.pdf

# Want all formats at once for your team?
pqcat scan tls yourcompany.com --all-reports
```

### Track Risk Over Time

```bash
# Save a baseline
pqcat scan tls yourcompany.com --save-baseline baseline.json

# Compare against baseline next quarter
pqcat scan tls yourcompany.com --baseline baseline.json

# View scan history
pqcat history
pqcat history diff 1 5    # Compare scan #1 to scan #5
```

---

## For Priya (Security Analyst) — "Prove compliance before the ATO deadline"

### Federal ATO Assessment Workflow

```bash
# Step 1: Full scan against FISMA requirements
pqcat scan tls agency.gov --framework fisma --all-reports --save-db

# Step 2: Generate OSCAL assessment results for OMB/CISA submission
pqcat scan tls agency.gov --oscal assessment.json

# Step 3: Generate CBOM for asset inventory
pqcat scan tls agency.gov --cbom cbom.json

# Step 4: Create the executive briefing PDF
pqcat scan tls agency.gov --briefing executive-brief.pdf
```

### Multi-Target Assessment

```bash
# Scan your entire subnet
pqcat scan tls 10.0.0.0/24 --workers 50 --framework fedramp --html subnet-report.html

# Scan SSH infrastructure
pqcat scan ssh 10.0.0.1,10.0.0.2,10.0.0.3

# Scan your code repositories
pqcat scan code ./backend/ ./frontend/ ./microservices/
```

### Continuous Monitoring

```bash
# Set up drift monitoring with Slack alerts
pqcat scan tls agency.gov --watch 3600    # Check every hour

# Configure alerts in pqcat.yaml:
```

```yaml
alerts:
  - type: webhook
    endpoint: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    events: ["score_drop", "new_red_asset", "cert_expiry"]
  - type: email
    endpoint: "security-team@agency.gov"
    events: ["score_drop"]
```

---

## For Marcus (DevSecOps) — "Machine-parseable output in my pipeline"

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
name: PQC Compliance
on: [push]
jobs:
  pqcat-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Install PQCAT
        run: curl -sSL https://install.pqcat.io | sh

      - name: Scan
        run: pqcat scan tls production.example.com --json results.json --quiet

      - name: Check Score
        run: |
          SCORE=$(jq '.overall_score' results.json)
          if (( $(echo "$SCORE < 70" | bc -l) )); then
            echo "FAIL: PQC score $SCORE below threshold"
            exit 1
          fi

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: pqcat-report
          path: results.json
```

### Machine-Readable Output

```bash
# JSON for parsing
pqcat scan tls target.com --json --quiet > results.json

# Exit code reflects score
pqcat scan tls target.com --quiet
echo $?   # 0 = pass, 1 = fail (below 70)

# CBOM for asset inventory systems
pqcat scan tls target.com --cbom inventory.json
```

### API Integration (Pro)

```bash
# Trigger scan via API
curl -X POST https://pqcat-server:8443/api/scan \
  -H "X-PQCAT-Token: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"tls","target":"example.com","framework":"cnsa2"}'

# Poll results
curl -H "X-PQCAT-Token: $API_KEY" https://pqcat-server:8443/api/results?scan_id=42
```

---

## For James (CTO/Executive) — "One-pager for the board"

### Generate a Board-Ready Report

```bash
# Branded executive briefing with your org logo
pqcat scan tls company.com --briefing board-report.pdf
```

Configure branding in `pqcat.yaml`:
```yaml
branding:
  logo_path: "./company-logo.jpeg"
  accent_color: "#003366"
  organization_full: "Acme Corp — Office of the CISO"
  classification: "TLP:GREEN"
```

### Compare Quarter Over Quarter

```bash
pqcat history diff 1 12    # Compare Q1 scan to Q4 scan
```

---

## For Danna (IT Admin) — "Tell me what's wrong and what to do"

### First Day Setup

```bash
# Step 1: Install
curl -sSL https://install.pqcat.io | sh

# Step 2: Run the interactive wizard
pqcat quickstart

# Step 3: Check system health
pqcat doctor
```

### Understanding Results

The compliance score is 0-100:
- **80-100** (Green) — PQ Compliant. Assets use quantum-safe algorithms.
- **50-79** (Yellow) — Transitional. Hybrid or migration path exists.
- **0-49** (Red) — Quantum Vulnerable. Needs immediate attention.

### Get Help

```bash
pqcat help intro          # Overview and concepts
pqcat help scoring        # How scores work
pqcat help frameworks     # Available compliance frameworks
pqcat help errors         # Error code reference
pqcat help examples       # Command examples
```

---

## For The Intern — "My boss told me to install this"

### Windows Quick Setup

1. Open PowerShell as Administrator
2. Run: `irm https://install.pqcat.io/windows | iex`
3. Run: `pqcat quickstart`
4. Follow the prompts — it will ask what you want to scan and do it for you

### macOS/Linux Quick Setup

1. Open Terminal
2. Run: `curl -sSL https://install.pqcat.io | sh`
3. Run: `pqcat quickstart`

That's it. The wizard handles everything else.

---

## Common Configuration Recipes

### Air-Gap / SCIF Deployment

```yaml
# pqcat.yaml — no network egress
framework: cnsa2
organization: "Classified Environment"
scanner:
  workers: 2
  timeout: 60s
```

Build and transfer the Enclave edition (zero outbound network code):
```bash
go build ./cmd/pqcat/     # Not -tags connected!
```

### Multi-Framework Compliance

```bash
# Run the same scan against different frameworks
pqcat scan tls bank.com --framework pci --pdf pci-report.pdf
pqcat scan tls bank.com --framework sox --pdf sox-report.pdf
pqcat scan tls bank.com --framework nydfs --pdf nydfs-report.pdf
```

### Scheduled Scans (Pro Dashboard)

Use the Scheduled Scans tab in the dashboard or the API:

```bash
curl -X POST https://localhost:8443/api/schedules \
  -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"tls","target":"agency.gov","interval":"24h","enabled":true}'
```
