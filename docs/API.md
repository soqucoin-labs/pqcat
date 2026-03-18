# PQCAT Pro API Reference

Base URL: `http://localhost:8443/api`

All responses are JSON unless otherwise noted. Scan-dependent endpoints accept an optional `?scan_id=N` parameter to override the default (latest scan).

## Authentication

PQCAT Pro requires authentication on all API endpoints (except `/api/health` and the dashboard login endpoint).

### Session Authentication (Interactive)

```bash
# Login — returns session token + sets HttpOnly cookie
curl -X POST http://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<password>"}'

# Response
{
  "token": "<64-char hex session token>",
  "username": "admin",
  "role": "admin",
  "force_change": false,
  "expires_at": "2026-03-10T16:00:00Z"
}
```

Use the session token in subsequent requests:
```bash
curl -H "X-PQCAT-Session: <token>" http://localhost:8443/api/stats
```

Sessions expire after **8 hours** of inactivity. Cookies are `HttpOnly`, `Secure`, `SameSite=Strict`.

### API Key Authentication (Automation)

For CI/CD and scripted access, use the API key configured in `pqcat.yaml`:

```bash
curl -H "X-PQCAT-Token: your-api-key" http://localhost:8443/api/stats
# or
curl -H "Authorization: Bearer your-api-key" http://localhost:8443/api/stats
```

API key authentication grants **admin** privileges.

## Auth Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Authenticate and create session |
| POST | `/api/auth/logout` | End session and clear cookie |
| GET | `/api/auth/me` | Get current user info (user_id, username, role) |
| POST | `/api/auth/password` | Change own password (min 12 chars) |

## Endpoints

### Health & Stats

| Method | Path | Min Role | Description |
|---|---|---|---|
| GET | `/api/health` | (none) | Health check — `{"status":"ok","edition":"pro"}` |
| GET | `/api/stats` | viewer | Dashboard aggregate: total scans, avg score, assets by zone |

### Scans

| Method | Path | Min Role | Description |
|---|---|---|---|
| POST | `/api/scan` | analyst | Run a new scan |
| GET | `/api/scans?limit=50` | viewer | List recent scans (newest first) |
| GET | `/api/scans/{id}` | viewer | Get asset inventory for a specific scan |
| GET | `/api/targets` | viewer | List distinct scan targets |
| GET | `/api/trend?target=X&limit=30` | viewer | Score trend for a target over time |

#### POST `/api/scan` — Run Scan

```json
{
  "target": "soqucoin.com",
  "scan_type": "tls|ssh|sbom|pki|code|hsm|cidr",
  "framework": "cnsa2|fisma|fedramp|dod|nist",
  "criticality": "STANDARD|HVA|NSS"
}
```

**Scan types:**
- `tls` — TLS/SSL certificate chain and cipher suite analysis
- `ssh` — SSH key exchange and host key algorithm analysis  
- `sbom` — CycloneDX/SPDX dependency analysis (180+ library database)
- `pki` — Certificate authority chain walking
- `code` — Source code scanning with 579 crypto patterns across 39 file types
- `hsm` — Hardware security module key discovery
- `cidr` — Subnet-wide TLS/SSH range scanning

**Response:**
```json
{
  "scan_id": 5,
  "target": "soqucoin.com",
  "score": 81.0,
  "assets": 7,
  "red": 6,
  "yellow": 0,
  "green": 1,
  "duration_ms": 231
}
```

### Assets

| Method | Path | Min Role | Description |
|---|---|---|---|
| GET | `/api/assets?zone=RED` | viewer | Cross-scan asset inventory, optional zone filter |

### Compliance

| Method | Path | Min Role | Description |
|---|---|---|---|
| GET | `/api/ato?scan_id=N` | viewer | ATO compliance package: NIST 800-53 controls |
| GET | `/api/vendor?scan_id=N` | viewer | Vendor supply chain risk: per-vendor PQC readiness |
| GET | `/api/poam` | viewer | POA&M entries across all scans |
| PUT | `/api/poam` | analyst | Update POA&M item status |

### Reports & Export

| Method | Path | Min Role | Description |
|---|---|---|---|
| POST | `/api/report` | analyst | Generate downloadable report |
| GET | `/api/siem/export?format=splunk&scan_id=N` | analyst | SIEM export (Splunk/ELK/CEF) |

#### POST `/api/report` — Generate Report

```json
{
  "scan_id": 5,
  "format": "html|pdf|json|briefing|ato"
}
```

### Intel & Config

| Method | Path | Min Role | Description |
|---|---|---|---|
| GET | `/api/intel` | viewer | Threat intelligence timeline |
| GET | `/api/config` | admin | Current config (organization, framework, SIEM) |
| GET | `/api/baselines` | viewer | Saved baseline scans for drift detection |
| POST | `/api/baselines` | analyst | Save a baseline |
| POST | `/api/compare` | analyst | Compare two scans |

### Admin (admin role only)

| Method | Path | Description |
|---|---|---|
| GET/POST/PUT/DELETE | `/api/users` | User management (CRUD) |
| GET | `/api/audit-log?limit=100` | View audit log entries |
| GET | `/api/audit-log/verify` | Verify HMAC chain integrity |
| GET | `/metrics` | Prometheus-compatible metrics |

#### GET `/api/audit-log/verify` — HMAC Chain Integrity

```json
{
  "intact": true,
  "verified_count": 47,
  "broken_at_entry": 0
}
```

If `intact` is `false`, `broken_at_entry` identifies the first tampered row.

### Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/` | Web dashboard (login required) |
| GET | `/api` | API endpoint listing |

## Error Responses

All errors follow this format:
```json
{
  "error": "descriptive error message"
}
```

HTTP status codes: `200` (success), `400` (bad request), `401` (unauthorized), `403` (forbidden), `404` (not found), `405` (method not allowed), `429` (rate limited), `500` (internal error).
