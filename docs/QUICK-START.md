# PQCAT Quick Start

Get scanning in 60 seconds.

## Install

**macOS / Linux:**
```bash
curl -sSL https://install.pqcat.io | sh
```

**Windows (PowerShell):**
```powershell
irm https://install.pqcat.io/windows | iex
```

**Verify installation:**
```bash
pqcat version
pqcat doctor     # Full system health check
```

> **Pro tip:** Run `pqcat quickstart` for an interactive guided setup.

---

## First Scan

```bash
# Auto-detect — PQCAT figures out the scan type
pqcat scan example.com

# Or be explicit:
pqcat scan tls example.com           # TLS deep scan (ciphers, protocols, certs, quantum risk)
pqcat scan ssh 10.0.0.1              # SSH host keys
pqcat scan tls 10.0.0.0/24 --workers 50  # Entire subnet
pqcat scan sbom ./bom.json           # SBOM (CycloneDX/SPDX)
pqcat scan code ./src/               # Source code crypto APIs
pqcat scan pki /etc/ssl/certs/       # PKI X.509 certificates
```

---

## Generate Reports

```bash
# All reports at once (PDF, HTML, CBOM, Executive, OSCAL)
pqcat scan tls example.com --all-reports

# Individual formats
pqcat scan tls example.com --pdf report.pdf
pqcat scan tls example.com --html report.html
pqcat scan tls example.com --briefing exec-brief.pdf
pqcat scan tls example.com --cbom cbom.json
pqcat scan tls example.com --oscal assessment.json
pqcat scan tls example.com --json report.json
```

---

## Scan History & Comparison

```bash
pqcat history                       # List past scans
pqcat history show 42               # Details for scan #42
pqcat history diff 41 42            # Compare two scans side-by-side
```

---

## Alerting & Continuous Monitoring

```bash
# Watch for changes every 60 seconds
pqcat scan tls example.com --watch 60

# Test alert channels
pqcat alert test --webhook https://hooks.slack.com/...
pqcat alert list

# Save/compare baselines
pqcat scan tls example.com --save-baseline baseline.json
pqcat scan tls example.com --baseline baseline.json
```

---

## Start Dashboard (Pro Edition)

```bash
# Start the web dashboard
pqcat serve

# ⚠ First run prints a random admin password to the console!
# Copy it immediately — it is shown only once.

# Open https://localhost:8443 in browser
# Log in with username 'admin' and the printed password

# Enclave edition — terminal dashboard
pqcat dashboard
```

---

## Migration Simulator

```bash
pqcat simulate tls example.com --org-size medium --budget moderate --team-size 3
pqcat simulate tls example.com --target-score 95 --target-date 2027-12-31
```

---

## Keep PQCAT Updated

```bash
pqcat self-update              # Upgrade to latest version
pqcat self-update --check      # Check without installing
```

---

## Key Commands

| Command | Description |
|---|---|
| `scan [type] <target>` | Core scanning (9 types + auto-detect) |
| `serve` | Start web dashboard (Pro) |
| `dashboard` | Terminal dashboard (Enclave TUI) |
| `quickstart` | Interactive first-run wizard |
| `history` | List, show, or diff past scans |
| `alert test/list` | Manage alert channels |
| `simulate <type> <target>` | Model PQC migration timeline |
| `self-update` | Upgrade to latest release |
| `doctor` | System health check |
| `benchmark` | Run cryptographic benchmarks |
| `verify <file>` | Verify report seal integrity |
| `license status/features` | License lifecycle management |
| `config validate/show` | Configuration management |
| `version` | Show version, edition, and license |
| `completion bash/zsh/fish` | Generate shell completions |
| `help <topic>` | Help on frameworks, scoring, errors, examples, privacy, intro |

---

## Configuration

Create `pqcat.yaml` in the current directory:

```yaml
framework: cnsa2
organization: "My Agency"
environment: "production"
scanner:
  workers: 4
  timeout: 30s

# Branded reports (Pro)
branding:
  logo_path: "./logo.jpeg"
  accent_color: "#003366"
  organization_full: "Department of Defense - CISO Office"
  classification: "TLP:AMBER"
```

See `docs/DEPLOYMENT.md` for full configuration reference, `docs/ADMIN-GUIDE.md` for user management and RBAC, `docs/COOKBOOK.md` for common workflows, and `docs/TROUBLESHOOTING.md` for error resolution.
