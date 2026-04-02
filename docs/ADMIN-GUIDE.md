# PQCAT Pro — Administrator Guide

## Overview

This guide covers administration tasks for the PQCAT Pro edition: user management, role-based access control, audit logging, and security configuration.

---

## First Run Setup

On first launch, PQCAT generates a random admin account and prints the credentials to the console:

```
  ╔═══════════════════════════════════════════╗
  ║  FIRST RUN — Admin Account Created        ║
  ║  Username: admin                          ║
  ║  Password: <32-character random hex>      ║
  ║  ⚠ CHANGE THIS PASSWORD IMMEDIATELY!     ║
  ╚═══════════════════════════════════════════╝
```

**Copy this password.** It is shown only once. Log in immediately and change it.

---

## Role-Based Access Control (RBAC)

### Roles

| Role | Permissions |
|------|-------------|
| **admin** | Full access: user management, config, scans, reports, audit log |
| **analyst** | Operational: run scans, generate reports, SIEM export, manage schedules/alerts |
| **viewer** | Read-only: view dashboards, scans, assets, baselines, threat intel |

### Route Protection

| Endpoint | Minimum Role |
|----------|-------------|
| `GET /api/health`, `GET /api/stats`, `GET /api/scans` | viewer |
| `GET /api/assets`, `GET /api/targets`, `GET /api/poam` | viewer |
| `GET /api/intel`, `GET /api/baselines`, `GET /api/vendor` | viewer |
| `POST /api/scan`, `POST /api/report` | analyst |
| `POST /api/siem/export`, `POST /api/compare` | analyst |
| `GET/POST /api/schedules`, `GET/POST /api/alerts` | analyst |
| `POST /api/ato` | analyst |
| `GET/POST/PUT/DELETE /api/config` | admin |
| `GET/POST/PUT/DELETE /api/users` | admin |
| `GET /api/audit-log` | admin |

---

## Authentication

### Session-Based (Dashboard)

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
  "force_change": true,
  "expires_at": "2026-03-10T16:00:00Z"
}
```

Sessions expire after **8 hours** of inactivity.

### API Key (Automation)

For CI/CD and scripted access, use the API key configured in `pqcat.yaml`:

```yaml
server:
  api_key: "your-secret-api-key-here"
```

```bash
curl -H "X-PQCAT-Token: your-secret-api-key-here" http://localhost:8443/api/stats
# or
curl -H "Authorization: Bearer your-secret-api-key-here" http://localhost:8443/api/stats
```

API key authentication grants **admin** privileges.

---

## User Management

### Create User (Admin Only)

```bash
curl -X POST http://localhost:8443/api/users \
  -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"jdoe","password":"securepassword12","role":"analyst"}'
```

Password requirements: minimum **12 characters**.

### List Users

```bash
curl http://localhost:8443/api/users -H "X-PQCAT-Session: <token>"
```

### Update User Role

```bash
curl -X PUT http://localhost:8443/api/users \
  -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"id":2,"role":"admin"}'
```

### Disable/Enable User

```bash
curl -X PUT http://localhost:8443/api/users \
  -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"id":2,"enabled":false}'
```

### Delete User

```bash
curl -X DELETE "http://localhost:8443/api/users?id=2" \
  -H "X-PQCAT-Session: <token>"
```

### Change Own Password

```bash
curl -X POST http://localhost:8443/api/auth/password \
  -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"new_password":"newsecurepassword"}'
```

---

## Audit Log

Every authentication event and access denial is recorded:

| Action | Description |
|--------|-------------|
| `LOGIN` | Successful authentication |
| `LOGIN_FAILED` | Failed authentication attempt |
| `LOGOUT` | Session ended |
| `PASSWORD_CHANGED` | User changed their password |
| `USER_CREATED` | New user account created |
| `USER_UPDATED` | User role or status changed |
| `USER_DELETED` | User account removed |
| `ACCESS_DENIED` | RBAC blocked an unauthorized request |

### View Audit Log

```bash
curl "http://localhost:8443/api/audit-log?limit=50" \
  -H "X-PQCAT-Session: <admin-token>"
```

### Verify Audit Integrity

The audit log is HMAC-SHA256 chained — each entry's integrity hash covers the previous entry. Tampering with any row breaks the chain.

```bash
curl "http://localhost:8443/api/audit-log/verify" \
  -H "X-PQCAT-Session: <admin-token>"

# Response
{"intact":true,"verified_count":47,"broken_at_entry":0}
```

If `intact` is `false`, `broken_at_entry` identifies the first tampered entry.

## Security Configuration

### `pqcat.yaml` Server Section

```yaml
server:
  listen: "0.0.0.0:8443"        # Listen address
  api_key: "<secret>"            # API key for automation
  rate_limit: 120                # Requests per minute per IP
  cors_origin: "https://app.example.com"
  tls: true                      # Enable HTTPS
  cert_file: "/etc/pqcat/cert.pem"
  key_file: "/etc/pqcat/key.pem"
```

### Security Headers (Automatic)

All responses include:

- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

### Session Cookie Security

- `HttpOnly` — not accessible via JavaScript
- `Secure` — only sent over HTTPS
- `SameSite=Strict` — no cross-origin requests

---

## Operational Procedures

### Routine Maintenance

1. **Review audit log** weekly for unusual access patterns
2. **Rotate API keys** quarterly by updating `pqcat.yaml` and restarting
3. **Disable inactive users** rather than deleting (preserves audit trail)
4. **Monitor rate-limit 429s** in the server log for potential abuse

### Incident Response

1. **Compromised credentials**: Disable the user account immediately via API, rotate API key if affected
2. **Brute force detection**: Rate limiter will throttle per-IP; review audit log for repeated `LOGIN_FAILED` events
3. **Session hijacking**: Sessions are 256-bit random tokens with 8h TTL; cookies are HttpOnly/Secure/SameSite=Strict

---

## Environment Variable Overrides

Sensitive configuration values should be set via environment variables rather than plaintext config files:

| Variable | Description |
|----------|-------------|
| `PQCAT_API_KEY` | API authentication key |
| `PQCAT_SIEM_TOKEN` | SIEM authentication token |
| `PQCAT_TLS_CERT` | Path to TLS certificate |
| `PQCAT_TLS_KEY` | Path to TLS private key |
| `PQCAT_AUDIT_KEY` | HMAC key for audit log integrity (hex-encoded, min 16 bytes) |
| `PQCAT_CORS_ORIGIN` | Allowed CORS origin |

If `PQCAT_AUDIT_KEY` is not set, a random key is generated at startup. **To preserve audit chain verification across restarts, set this env var.**

---

## Confidential Compliance Engine (CCE)

The CCE provides privacy-preserving assessment evidence through a 3-layer architecture:

| Layer | Mechanism | CLI Flag | Purpose |
|-------|-----------|----------|---------|
| **1** | Asset Anonymization | `--confidential` | BLAKE2b-hashed locations with ephemeral salt |
| **2** | Aggregate-Only Mode | `--aggregate-only` | Strip individual assets, preserve only zone counts and scores |
| **3** | ML-DSA-44 Report Seal | *(automatic)* | FIPS 204 post-quantum digital signature on all CCE reports |

### Usage

```bash
# Anonymized scan — share results without exposing asset names/IPs
pqcat scan tls agency.gov --confidential --save-db

# Aggregate-only — share compliance scores without inventory
pqcat scan tls agency.gov --aggregate-only --save-db

# Full HNDL risk assessment
pqcat scan tls agency.gov --data-retention 25y --q-day-year 2035 --confidential
```

The **CCE Evidence** tab in the Pro dashboard displays sealed report history, privacy architecture reference, and HNDL risk methodology documentation.

---

## Migration Simulator

Model PQC migration timelines from the dashboard or CLI:

```bash
pqcat simulate tls agency.gov \
  --org-size medium \
  --budget moderate \
  --team-size 4 \
  --target-score 95 \
  --framework cnsa2
```

### Parameters

| Parameter | Options | Description |
|-----------|---------|-------------|
| `--org-size` | small, medium, large, enterprise | Number of cryptographic assets to migrate |
| `--budget` | constrained, moderate, aggressive | Resource allocation level |
| `--team-size` | 1–100 | Number of security engineers available |
| `--target-score` | 50–100 | Desired compliance score |
| `--framework` | cnsa2, nsm10, fisma, fedramp, pci | Compliance framework for migration targets |

The simulator uses the latest scan data to estimate migration phases, person-months, and projected score improvements.

---

## Scheduled Scans & Alerts

### Automated Recurring Scans

```bash
# CLI: watch mode (reruns every 6 hours)
pqcat scan tls agency.gov --watch 6h

# API: create recurring schedule
curl -X POST http://localhost:8443/api/schedules \
  -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"tls","target":"agency.gov","interval":"24h","enabled":true}'
```

### Alert Channels

Configure webhooks, Slack, email, or CDM alerts in `pqcat.yaml`:

```yaml
alerts:
  - type: webhook
    endpoint: "https://hooks.slack.com/services/..."
    events: ["score_drop", "new_red_asset", "cert_expiry"]
  - type: email
    endpoint: "security-team@agency.gov"
    events: ["score_drop"]
```

The **Scheduled Scans** tab in the Pro dashboard provides a form-based interface for managing schedules and alert channels.

---

## Notification Center

The Pro dashboard includes a persistent notification center (bell icon in the header). Notifications are generated automatically by:

- **Scan completions** — severity based on compliance score (≥80 = success, 50-79 = warning, <50 = critical)
- **Drift alerts** — when continuous monitoring detects score changes
- **License events** — expiring or expired license warnings
- **System events** — scheduled scan failures, database errors

### Notification Management

**Dashboard:** Click the bell icon to view the notification panel. Mark individual or all notifications as read. Dismiss individual or clear all.

**API:**
```bash
# List notifications + unread count
curl -H "X-PQCAT-Session: <token>" https://localhost:8443/api/notifications

# Mark all as read
curl -X POST -H "X-PQCAT-Session: <token>" \
  -H "Content-Type: application/json" \
  -d '{"action":"mark_all_read"}' \
  https://localhost:8443/api/notifications
```

Notifications are polled every 30 seconds in the dashboard. Clicking a scan notification navigates directly to the scan result in the History tab.

---

## Branded Reports

Customize PDF reports with your organization's branding:

```yaml
# pqcat.yaml
branding:
  logo_path: "/path/to/logo.jpeg"       # JPEG, PNG, or SVG
  accent_color: "#003366"                # Hex color for headings and borders
  organization_full: "Department of Defense — CISO Office"
  classification: "TLP:AMBER"            # Displayed on cover page and headers
```

Branded reports include:
- Full-bleed cover page with organization name and logo
- Accent-colored section headers and divider lines
- TLP classification label on every page
- "Prepared for" attribution with date and scan metadata

---

*PQCAT Pro v2.6.3 — Soqucoin Labs Inc.*
