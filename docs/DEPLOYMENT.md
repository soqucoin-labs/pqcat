# PQCAT Deployment Guide

## Prerequisites

- Go 1.25+ (build only — not needed at runtime)
- Target: Linux amd64/arm64, macOS amd64/arm64, Windows amd64

## Quick Deploy

### One-Line Install (Recommended)

**macOS / Linux:**
```bash
curl -sSL https://install.pqcat.io | sh
```

**Windows (PowerShell — run as Administrator):**
```powershell
irm https://install.pqcat.io/windows | iex
```

The installer auto-detects your OS and architecture, downloads the correct binary, verifies the SHA-256 checksum, and adds `pqcat` to your PATH.

### Windows MSI (Enterprise)

For Group Policy / SCCM / Intune deployment, download the `.msi` from the [releases page](https://github.com/soqucoin-labs/pqcat/releases). The MSI installs to `C:\Program Files\PQCAT\`, adds to PATH, and registers in Add/Remove Programs.

### Manual Binary Download

```bash
# Download from GitHub releases
curl -LO https://github.com/soqucoin-labs/pqcat/releases/latest/download/pqcat-linux-amd64.tar.gz

# Extract and install
tar xzf pqcat-linux-amd64.tar.gz
chmod +x pqcat
sudo mv pqcat /usr/local/bin/

# Verify
pqcat version
pqcat doctor
```

## Upgrade

```bash
pqcat self-update              # Download and install latest version
pqcat self-update --check      # Check for updates without installing
```

## Build from Source

```bash
git clone https://github.com/soqucoin-labs/pqcat-engine.git
cd pqcat-engine

# Enclave edition (air-gap safe, zero outbound network)
go build ./cmd/pqcat/

# Pro edition (REST API + dashboard + RBAC)
go build -tags connected ./cmd/pqcat/

# Verify static binary (Linux)
file pqcat && ldd pqcat  # should show "statically linked"
```

## Docker Deployment

```bash
# Using docker-compose (recommended)
cp pqcat.yaml.example pqcat.yaml   # edit config
docker compose up -d

# Manual Docker
docker build --target pro -t pqcat .
docker run -d -p 8443:8443 -v pqcat-data:/data pqcat serve
```

## Federal / Air-Gap Deployment

### SCIF / IL4-IL5 Environments

1. Build the **Enclave** edition on an approved build machine
2. Transfer binary via approved media (USB, optical)
3. No network egress — the Enclave binary has zero outbound network code (compiler-verified via build tags)

```bash
# On build machine
go build ./cmd/pqcat/
shasum -a 384 pqcat > pqcat.sha384

# On target (air-gapped)
shasum -a 384 -c pqcat.sha384
./pqcat scan tls 10.0.0.0/24
./pqcat dashboard   # TUI terminal dashboard
```

### Configuration

```yaml
# /etc/pqcat/pqcat.yaml
framework: cnsa2
organization: "Department of Example"
environment: "Production IL4"
scanner:
  workers: 8
  timeout: 30s
server:
  listen: "127.0.0.1:8443"
  api_key: "${PQCAT_API_KEY}"    # Set via environment variable
  rate_limit: 120                 # requests/minute per IP
  cors_origin: "https://dashboard.example.gov"
siem:
  endpoint: "https://splunk.example.gov:8088"
  format: splunk

# Branded reports (Pro)
branding:
  logo_path: "/etc/pqcat/agency-logo.jpeg"
  accent_color: "#003366"
  organization_full: "Department of Example — CISO Office"
  classification: "TLP:AMBER"
```

### Configuration Precedence (highest → lowest)

1. CLI flags (`--framework cnsa2`)
2. Environment variables (`PQCAT_FRAMEWORK=cnsa2`)
3. `--config` flag path
4. `./pqcat.yaml` (current directory)
5. `~/.pqcat/config.yaml`
6. `/etc/pqcat/pqcat.yaml`

### Environment Variable Overrides

| Variable | Description |
|---|---|
| `PQCAT_API_KEY` | API authentication key |
| `PQCAT_RATE_LIMIT` | Rate limit (requests/minute) |
| `PQCAT_FRAMEWORK` | Compliance framework |
| `PQCAT_LISTEN` | Server listen address |
| `PQCAT_DB_PATH` | SQLite database path |
| `PQCAT_SIEM_ENDPOINT` | SIEM forwarding endpoint |
| `PQCAT_SIEM_FORMAT` | SIEM format (splunk/elk/cef) |
| `PQCAT_SIEM_TOKEN` | SIEM authentication token (secret — env only) |
| `PQCAT_TLS_CERT` | Path to TLS certificate (secret — env only) |
| `PQCAT_TLS_KEY` | Path to TLS private key (secret — env only) |
| `PQCAT_CORS_ORIGIN` | Allowed CORS origin |
| `PQCAT_AUDIT_KEY` | HMAC key for audit log integrity (hex, secret — env only) |

## Security Hardening

### First-Run Admin Setup

On first launch, PQCAT auto-generates a random admin account and prints the credentials to the console. **Copy the password immediately** — it is shown only once. You will be forced to change it on first login.

### Role-Based Access Control

PQCAT Pro includes three roles: **viewer** (read-only), **analyst** (scan + report), **admin** (full access including user management).

See [ADMIN-GUIDE.md](ADMIN-GUIDE.md) for full RBAC configuration and user management.

### API Authentication

All API endpoints require authentication (except `/api/health`):

```bash
# Session-based (interactive)
curl -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'

# API key (automation)
curl -H "X-PQCAT-Token: your-key" https://localhost:8443/api/stats

# Bearer token
curl -H "Authorization: Bearer your-key" https://localhost:8443/api/stats
```

### Rate Limiting

Per-IP token-bucket rate limiter. Returns `429 Too Many Requests` with `Retry-After` header when exceeded.

### TLS Termination

PQCAT Pro auto-generates a self-signed TLS certificate on first run. For production, use a reverse proxy (nginx, Caddy, HAProxy) or provide your own certificates:

```bash
# Via environment variables
PQCAT_TLS_CERT=/etc/pki/tls/certs/pqcat.pem \
PQCAT_TLS_KEY=/etc/pki/tls/private/pqcat.key \
pqcat serve
```

## Health Check

```bash
curl -k https://localhost:8443/api/health
# {"status":"ok","version":"2.3.0","edition":"Pro"}
```

## Uninstall

**macOS / Linux:**
```bash
sudo rm /usr/local/bin/pqcat
rm -rf ~/.pqcat/
```

**Windows:**
Use Add/Remove Programs, or:
```powershell
Remove-Item "$env:ProgramFiles\PQCAT" -Recurse -Force
```

## Code Signing

Release binaries are verified via SHA-256 checksums published alongside each release. The install script verifies checksums automatically.

```bash
shasum -a 256 -c checksums.sha256
```
