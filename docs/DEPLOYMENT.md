# PQCAT Deployment Guide

## Prerequisites

- Go 1.25+ (build only — not needed at runtime)
- Target: Linux amd64/arm64, macOS, or Windows

## Quick Deploy (Binary)

```bash
# Download from releases
curl -LO https://github.com/soqucoin-labs/pqcat/releases/latest/download/pqcat-pro_linux_amd64.tar.gz
tar xzf pqcat-pro_linux_amd64.tar.gz
chmod +x pqcat-pro

# Verify checksum
sha256sum -c pqcat-pro_linux_amd64.tar.gz.sha256

# Run
./pqcat-pro scan tls --target example.com
./pqcat-pro serve  # Start dashboard on :8443
```

## Build from Source

```bash
git clone https://github.com/soqucoin-labs/pqcat.git
cd pqcat

# Pro edition (REST API + dashboard)
make build-pro

# Enclave edition (air-gap safe, zero outbound network)
make build-enclave

# Verify static binary
file pqcat && ldd pqcat  # should show "statically linked"
```

## Docker Deployment

```bash
# Using docker-compose (recommended)
cp pqcat.yaml.example pqcat.yaml   # edit config
docker compose up -d

# Manual Docker
docker build --target pro -t pqcat-pro .
docker run -d -p 8443:8443 -v pqcat-data:/data pqcat-pro serve
```

## Federal / Air-Gap Deployment

### SCIF / IL4-IL5 Environments

1. Build the **Enclave** edition on an approved build machine
2. Transfer binary via approved media (USB, optical)
3. No network egress — the Enclave binary has zero outbound network code (compiler-verified via build tags)

```bash
# On build machine
make build-enclave
sha256sum pqcat > pqcat.sha256

# On target (air-gapped)
sha256sum -c pqcat.sha256
./pqcat scan tls --target 10.0.0.0/24
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
```

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
curl -X POST http://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'

# API key (automation)
curl -H "X-PQCAT-Token: your-key" http://localhost:8443/api/stats

# Bearer token
curl -H "Authorization: Bearer your-key" http://localhost:8443/api/stats
```

### Rate Limiting

Per-IP token-bucket rate limiter. Returns `429 Too Many Requests` with `Retry-After` header when exceeded.

### TLS Termination

For production, use a reverse proxy (nginx, Caddy, HAProxy) for TLS termination:

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/pki/tls/certs/pqcat.pem;
    ssl_certificate_key /etc/pki/tls/private/pqcat.key;
    location / {
        proxy_pass http://127.0.0.1:8443;
    }
}
```

## Health Check

```bash
curl http://localhost:8443/api/health
# {"status":"ok","version":"1.0.0","edition":"Pro"}
```

## Code Signing

Release binaries should be verified via SHA-256 checksums published alongside each release:

```bash
sha256sum -c checksums.txt
```

For organizational signing, add GPG signatures:

```bash
make release-sign  # Signs all artifacts with GPG key
gpg --verify pqcat-pro_linux_amd64.tar.gz.sig
```
