# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.1.x | ✅ Active |
| 1.0.x | ⚠️ Security fixes only |

## Reporting a Vulnerability

If you discover a security vulnerability in PQCAT, please report it responsibly:

1. **Email**: security@soqu.org
2. **Subject**: `[PQCAT-SEC] Brief description`
3. **Include**: Steps to reproduce, impact assessment, affected component

**Do NOT** create a public GitHub issue for security vulnerabilities.

### Response Timeline

| Stage | Target |
|---|---|
| Acknowledgment | 48 hours |
| Triage | 5 business days |
| Fix (Critical) | 72 hours |
| Fix (High) | 14 days |
| Fix (Medium/Low) | Next release |

## Security Architecture

PQCAT is designed with federal deployment in mind:

### Enclave Edition (Air-Gapped)
- **Zero outbound network code** — compiler-enforced via Go build tags
- **No CGO**: Pure Go, no C dependencies, no shared library loading
- **Static Binary**: Single executable, no runtime dependencies
- **Database**: SQLite (pure Go driver), portable across air gaps
- **Reports**: Self-contained HTML/PDF — no external resource loading

### Pro Edition (Connected)
- **RBAC**: Three roles (viewer, analyst, admin) with route-level enforcement
- **Session Authentication**: 256-bit random tokens, HttpOnly/Secure/SameSite=Strict cookies, 8-hour TTL
- **First-Run Admin**: Cryptographically random 32-character password with mandatory change on first login
- **Timing-Attack Resistant**: Constant-time API key comparison, dummy bcrypt for unknown usernames
- **Tamper-Proof Audit Log**: HMAC-SHA256 chained entries — modifying any row breaks the verifiable chain
- **ML-DSA-44 Report Seals**: FIPS 204 post-quantum digital signatures on assessment reports
- **Security Headers**: Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Rate Limiting**: Per-IP token-bucket with configurable RPM
- **Prometheus Metrics**: Admin-only `/metrics` endpoint for operational observability
- **Env-Only Secrets**: Sensitive values (SIEM tokens, TLS certificates, audit HMAC keys) are read from environment variables — never stored in plaintext config files

### Password Security
- Bcrypt hashing with default cost (10 rounds)
- 12-character minimum password length
- Force-change flag on first-run admin accounts

## Scope

The PQCAT scanner (this repository) is open source under Apache 2.0.
The compliance engine is proprietary. Security issues in both are covered by this policy.

## Contact

**Soqucoin Labs Inc.**  
228 Park Ave S, Pmb 85451, New York, NY 10003  
security@soqu.org
