# PQCAT Quick Start

## Install

```bash
# Step 1: Download from releases
curl -LO https://github.com/soqucoin-labs/pqcat/releases/download/v2.0.1/pqcat-2.0.1-linux-amd64.tar.gz

# Step 2: Extract the binary
tar xzf pqcat-2.0.1-linux-amd64.tar.gz

# Step 3: Install to your PATH
chmod +x pqcat-2.0.1-linux-amd64
sudo mv pqcat-2.0.1-linux-amd64 /usr/local/bin/pqcat

# From source
git clone https://github.com/soqucoin-labs/pqcat.git && cd pqcat
make pro
```

## First Scan

```bash
# Scan a website's TLS configuration
pqcat scan tls example.com

# Scan SSH keys on a server
pqcat scan ssh 10.0.0.1

# Scan an entire subnet (50 workers)
pqcat scan tls 10.0.0.0/24 --workers 50

# Scan an SBOM file
pqcat scan sbom ./bom.json

# Scan source code for crypto APIs
pqcat scan code ./src/

# Scan PKI certificates
pqcat scan pki /etc/ssl/certs/

```

## Generate Reports

```bash
# JSON report (machine-readable)
pqcat scan tls example.com --json --output report.json

# PDF Crypto Bill of Health
pqcat scan tls example.com --pdf report.pdf

# HTML report (self-contained, works offline)
pqcat scan tls example.com --html report.html

# Executive briefing PDF
pqcat scan tls example.com --briefing exec-brief.pdf

# OSCAL assessment results (NIST v1.2.1)
pqcat scan tls example.com --oscal assessment.json

# Cryptographic Bill of Materials (CycloneDX v1.6)
pqcat scan tls example.com --cbom cbom.json
```

## Migration Simulator

```bash
# Model your PQC migration timeline
pqcat simulate tls example.com --org-size medium --budget moderate --team-size 3

# Set a target score and hard deadline
pqcat simulate tls example.com --target-score 95 --target-date 2027-12-31

# Output as JSON for integration
pqcat simulate tls example.com --json --output simulation.json
```

## Start Dashboard

```bash
# Pro edition — web dashboard on :8443
pqcat-pro serve

# ⚠️ First run prints a random admin password to the console!
# Copy it immediately — it is shown only once.

# Open https://localhost:8443 in browser
# Log in with username 'admin' and the printed password

# Enclave edition — terminal dashboard
pqcat dashboard
```

## Continuous Monitoring

```bash
# Watch for changes every 60 seconds
pqcat scan tls example.com --watch 60

# Save a baseline for drift detection
pqcat scan tls example.com --save-baseline baseline.json

# Compare against baseline
pqcat scan tls example.com --baseline baseline.json
```

## Key Commands

| Command | Description |
|---|---|
| `scan tls HOST` | Scan TLS certificates and cipher suites |
| `scan ssh HOST` | Scan SSH host keys |
| `scan sbom FILE` | Analyze SBOM for crypto libraries |
| `scan pki PATH` | Scan PKI certificates |
| `scan code DIR` | Scan source code for crypto APIs |
| `scan hsm [auto]` | Discover HSMs, KMS, keystores |
| `simulate TYPE TARGET` | Model PQC migration timeline |
| `serve` | Start web dashboard (Pro) |
| `dashboard` | Terminal dashboard (TUI) |
| `benchmark` | Run cryptographic benchmarks |
| `verify FILE` | Verify report seal and integrity |
| `quickstart` | Interactive first-run wizard |
| `version` | Show version and edition |

## Configuration

Create `pqcat.yaml` in the current directory:

```yaml
framework: cnsa2
organization: "My Agency"
environment: "production"
scanner:
  workers: 4
  timeout: 30s
```

See `docs/DEPLOYMENT.md` for full configuration reference, and `docs/ADMIN-GUIDE.md` for user management and RBAC setup.
