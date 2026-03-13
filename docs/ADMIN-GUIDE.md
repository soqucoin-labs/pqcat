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

*PQCAT Pro — Soqucoin Labs Inc.*
