# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.1.x | ✅ Active |
| 1.0.x | ✅ Active |

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
- **Nothing listens** — no HTTP server, no API, no dashboard in the Enclave binary, enforced by Go build tags and checkable with `go tool nm pqcat | grep 'http.(*Server)'`
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

## Verifying a Release

Every release carries SHA-384 checksums and a post-quantum signature over them.

```bash
gh release download vX.Y.Z -p 'SHA384SUMS*'
go run ./tools/pqsign/ verify SHA384SUMS      # ML-DSA-65, FIPS 204
sha384sum -c SHA384SUMS --ignore-missing      # then check your download
```

The signature is ML-DSA-65 and the current signing key fingerprint is
`2721aaf399c5b42768d0d797`. `pqsign verify` also accepts signatures made under the
retired Ed25519 placeholder used before 2026-08, so older releases remain
checkable, and it reports those as NOT post-quantum rather than letting them pass
as if they were.

### Why the release key is not in CI

The release signing key lives only on a signer's machine. It is deliberately not
held in CI secrets: a key available to a workflow is a key available to anything
that can influence that workflow, and a tool whose purpose is assessing other
people's key management should not hand its own root of trust to a build runner.

So the pipeline builds and publishes, and signing is a separate human step:

```bash
make sign-release TAG=vX.Y.Z
```

That script downloads the manifest **as published for that tag**, signs those
exact bytes locally, verifies the signature before uploading, and re-verifies the
uploaded copy against the published manifest afterwards. Signing a locally
regenerated manifest would sign different bytes, because a local build produces
different binaries and therefore different checksums, and the signature would
verify against nothing anyone downloads. `make sign-pq` does sign local
checksums, for locally distributed builds, and says so.

## Scope

The PQCAT scanner (this repository) is open source under Apache 2.0.
The compliance engine is proprietary. Security issues in both are covered by this policy.

## Contact

**Soqucoin Labs Inc.**  
228 Park Ave S, Pmb 85451, New York, NY 10003  
security@soqu.org
