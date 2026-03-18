# PQCAT — Post-Quantum Cryptography Compliance Assessment Tool

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev)

**Built by Soqucoin Labs Inc.** — the team that migrated a production blockchain from ECDSA to NIST FIPS 204 (ML-DSA). Not theory — proven implementation.

---

## What Is PQCAT?

PQCAT discovers every cryptographic asset across your infrastructure, classifies quantum vulnerability, scores compliance readiness, and delivers federal-grade reports — all from a single binary with zero runtime dependencies.

```
pqcat scan tls agency.gov --framework fisma --html report.html --save-db
```

**Output:** A scored Crypto Bill of Health with Quantum Vulnerable / Transitional / PQ Compliant zone breakdown, POA&M entries, and framework-specific migration recommendations.

## Two Editions

| Feature | Enclave (Air-Gapped) | Pro (Connected) |
|---|---|---|
| CLI scanner (7 modules) | ✓ | ✓ |
| TUI terminal dashboard | ✓ | ✓ |
| Self-contained HTML reports | ✓ | ✓ |
| SQLite scan history & POA&M | ✓ | ✓ |
| REST API + web dashboard | — | ✓ |
| Role-based access control (RBAC) | — | ✓ |
| User management & audit logging | — | ✓ |
| Prometheus observability (`/metrics`) | — | ✓ |
| ML-DSA-44 report seals (FIPS 204) | — | ✓ |
| Live threat intelligence | — | ✓ |

The scanner is open-source (Apache 2.0). The Pro edition (compliance engine, dashboard, RBAC, reporting) is distributed as [pre-built signed binaries](https://github.com/soqucoin-labs/pqcat/releases).

## Quick Start

```bash
# Build
make

# Scan
./pqcat scan tls example.com --framework nist

# Full assessment with report
./pqcat scan tls example.com --framework fisma --html cboh.html --save-db

# Terminal dashboard
./pqcat dashboard

# Generate org config
./pqcat config init
```

## Scanner Modules

| Module | Command | Description |
|---|---|---|
| TLS/SSL | `scan tls` | Certificate chain, cipher suites, signature algorithms |
| SSH | `scan ssh` | Key exchange, host key types |
| SBOM | `scan sbom` | CycloneDX/SPDX crypto dependency analysis |
| PKI | `scan pki` | Certificate chain walking and CA analysis |
| Code | `scan code` | Source code pattern scanning (579 patterns, 39 file types) |
| HSM/KMS | `scan hsm` | Hardware security module key discovery |
| CIDR | `scan cidr` | Subnet-wide TLS/SSH discovery |


## Build

```bash
make              # Build scanner
make test         # Run unit tests
make sbom         # Generate CycloneDX SBOM
make checksums    # SHA-256 integrity manifest
make release      # Cross-platform release package
make linux-amd64  # Cross-compile for Linux x86_64
```

> **Pro Edition:** The Pro source code is proprietary and not included in this repository. Pre-built Pro binaries are available from [GitHub Releases](https://github.com/soqucoin-labs/pqcat/releases). For enterprise licensing, contact [labs@soqu.org](mailto:labs@soqu.org).

## Security

PQCAT Pro includes enterprise-grade security out of the box:

- **RBAC**: Three roles (viewer, analyst, admin) with route-level enforcement
- **Session Auth**: 256-bit tokens, HttpOnly/Secure/SameSite=Strict cookies, 8h TTL
- **First-Run Admin**: Cryptographically random password, force-change on first login
- **Tamper-Proof Audit Log**: HMAC-SHA256 chained entries with integrity verification
- **ML-DSA-44 Report Seals**: FIPS 204 post-quantum signatures on all reports
- **Prometheus Metrics**: `/metrics` endpoint for operational observability
- **Security Headers**: CSP, HSTS, X-Frame-Options, CORS, rate limiting
- **Env-Only Secrets**: TLS certs, SIEM tokens, audit keys via environment variables

## Documentation

| Document | Description |
|----------|-------------|
| **[Quick Start](docs/QUICK-START.md)** | Install, first scan, generate reports — get running in 5 minutes |
| **[Deployment Guide](docs/DEPLOYMENT.md)** | Binary install, Docker, air-gap deployment, systemd, hardening |
| **[Architecture](docs/ARCHITECTURE.md)** | Four-layer design, package structure, build tags |
| **[API Reference](docs/API.md)** | REST API endpoints, authentication, session management (Pro) |
| **[Admin Guide](docs/ADMIN-GUIDE.md)** | RBAC, user management, audit logging, security configuration (Pro) |
| **[Standard Operations Procedure](docs/PQCAT-SOP-001.md)** | Federal-grade SOP: installation, configuration, operations, maintenance |
| **[Changelog](CHANGELOG.md)** | Version history and release notes |
| **[Contributing](CONTRIBUTING.md)** | Development setup, testing, build commands |
| **[Security Policy](SECURITY.md)** | Vulnerability reporting, security architecture |

## Architecture

```
┌── Discovery Layer ──────────────── Open Source (Apache 2.0) ──┐
│  7 scanner modules + algorithm classifier + data models       │
├── Intelligence Layer ────────────── Proprietary ──────────────┤
│  Compliance engine + scoring + threat intel                   │
├── Security Layer ─────────────────────────────────────────────┤
│  RBAC · Session Auth · HMAC Audit · Rate Limiting · CSP      │
├── Delivery Layer ─────────────────────────────────────────────┤
│  PDF · HTML · JSON · SIEM · TUI · REST API · Prometheus      │
└───────────────────────────────────────────────────────────────┘
```

The **scanner** (this repository) is open source under Apache 2.0. The **compliance engine** is proprietary and distributed as compiled binaries under license.

## Compliance Frameworks

### Federal / Defense

| Framework | `--framework` | Scope |
|-----------|---------------|-------|
| **CNSA 2.0** | `cnsa2` | NSA Commercial National Security Algorithm Suite 2.0 |
| **NSM-10** | `nsm10` | National Security Memorandum — inventory and migration plans |
| **FISMA** | `fisma` | NIST 800-53 federal agency compliance |
| **FedRAMP** | `fedramp` | Cloud service provider authorization |
| **NIST SP 800-131A** | `sp800131a` | Cryptographic algorithm deprecation guidance |
| **CMMC** | `cmmc` | Cybersecurity Maturity Model Certification (DoD supply chain) |

### Financial / Healthcare

| Framework | `--framework` | Scope |
|-----------|---------------|-------|
| **PCI DSS** | `pci` | Payment Card Industry Data Security Standard |
| **SOX** | `sox` | Sarbanes-Oxley Act — financial reporting controls |
| **HIPAA** | `hipaa` | Health Insurance Portability and Accountability Act |
| **NYDFS** | `nydfs` | NY Department of Financial Services cybersecurity regulation |
| **SWIFT CSP** | `swift` | SWIFT Customer Security Programme |

## License

The PQCAT scanner is licensed under the [Apache License 2.0](LICENSE).

The compliance engine (scoring, reporting, REST API) is proprietary software. Contact labs@soqu.org for licensing.

## About

**Soqucoin Labs Inc.**  
228 Park Ave S, Pmb 85451, New York, NY 10003  
[soqucoin.com](https://soqucoin.com) · labs@soqu.org
