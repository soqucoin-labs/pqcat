# PQCAT Quick Start

## Install

```bash
# From release
curl -LO https://github.com/soqucoin-labs/pqcat/releases/latest/download/pqcat-pro_$(uname -s)_$(uname -m).tar.gz
tar xzf pqcat-pro_*.tar.gz && chmod +x pqcat-pro
sudo mv pqcat-pro /usr/local/bin/

# From source
git clone https://github.com/soqucoin-labs/pqcat.git && cd pqcat
make build-pro
```

## First Scan

```bash
# Scan a website's TLS configuration
pqcat-pro scan tls --target example.com

# Scan SSH keys on a server
pqcat-pro scan ssh --target 10.0.0.1

# Scan an entire subnet
pqcat-pro scan cidr --target 10.0.0.0/24

# Scan an SBOM file
pqcat-pro scan sbom --target ./bom.json

# Run all applicable scanners
pqcat-pro scan all --target example.com
```

## Generate Reports

```bash
# HTML report (self-contained, works offline)
pqcat-pro report --format html --output report.html

# PDF Crypto Bill of Health
pqcat-pro report --format pdf --output cboh.pdf

# JSON (machine-readable)
pqcat-pro report --format json --output scan.json
```

## Start Dashboard

```bash
# Pro edition — web dashboard on :8443
pqcat-pro serve

# ⚠️ First run prints a random admin password to the console!
# Copy it immediately — it is shown only once.

# Open http://localhost:8443 in browser
# Log in with username 'admin' and the printed password
# You will be prompted to change the password on first login

# Enclave edition — terminal dashboard
pqcat dashboard
```

## Key Commands

| Command | Description |
|---|---|
| `scan tls --target HOST` | Scan TLS certificates |
| `scan ssh --target HOST` | Scan SSH host keys |
| `scan sbom --target FILE` | Analyze SBOM for crypto libs |
| `scan cidr --target CIDR` | Scan IP range |
| `scan code --target DIR` | Scan source code |
| `scan all --target HOST` | Run all applicable scanners |
| `report --format pdf` | Generate PDF report |
| `serve` | Start web dashboard (Pro) |
| `dashboard` | Terminal dashboard (TUI) |
| `version` | Show version and edition |

## Configuration

Create `pqcat.yaml` in the current directory:

```yaml
framework: cnsa2
organization: "My Agency"
scanner:
  workers: 4
  timeout: 30s
```

See `docs/DEPLOYMENT.md` for full configuration reference, and `docs/ADMIN-GUIDE.md` for user management and RBAC setup.
