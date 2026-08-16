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

*That line needs Enclave or Pro, which are free to download. The Scanner built
from this repository does discovery and classification; see Quick Start below.*

**Output:** A scored Crypto Bill of Health with Quantum Vulnerable / Transitional / PQ Compliant zone breakdown, POA&M entries, and framework-specific migration recommendations.

## Three builds, and this repository is one of them

⚠️ **Building this repository gives you the Scanner, which is neither of the
other two.** The Scanner is the Apache-2.0 open-source build: discovery and
classification. It has no scoring, no reports and no evidence layer, and every
flag belonging to those exits with a message saying so.

Enclave and Pro are pre-built and downloadable from
[the public release](https://github.com/soqucoin-labs/pqcat/releases/latest).
Enclave is the free product: every capability, bounded by a 25-host scope limit
per scan until you license it.

| Feature | Scanner (this repo) | Enclave | Pro |
|---|---|---|---|
| CLI scanning + classification | ✓ | ✓ | ✓ |
| JSON / plain-text output | ✓ | ✓ | ✓ |
| Shell completions (bash/zsh/fish) | ✓ | ✓ | ✓ |
| System health check (`pqcat doctor`) | — | ✓ | ✓ |
| Compliance scoring + frameworks | — | ✓ | ✓ |
| Self-contained HTML and PDF reports | — | ✓ | ✓ |
| SQLite scan history & comparison | — | ✓ | ✓ |
| Evidence layer (coins, binding, disclosure) | — | ✓ | ✓ |
| TUI terminal dashboard | — | ✓ | ✓ |
| Update check (`pqcat update`) | — | ✓ | ✓ |
| REST API + web dashboard | — | — | ✓ |
| 4 persona views (CISO/Auditor/CIO/Exec) | — | — | ✓ |
| Notification center | — | — | ✓ |
| Role-based access control (RBAC) | — | — | ✓ |
| User management & HMAC audit logging | — | — | ✓ |
| Branded PDF reports (logo, cover page) | — | — | ✓ |
| Prometheus observability (`/metrics`) | — | — | ✓ |
| ML-DSA-44 report seals (FIPS 204) | — | — | ✓ |
| Scheduled scans & alert webhooks | — | — | ✓ |
| Confidential Compliance Engine (CCE) | — | — | ✓ |
| Section 508 / WCAG 2.1 AA accessible | — | — | ✓ |

All three builds come off one engine, and the Scanner's source is what lives
here. Enclave compiles with **zero network code** beyond scan targets, which the
compiler guarantees rather than a setting: there is no server in the binary to
turn off. Pro adds that server. Both carry the proprietary compliance engine and
are [published as pre-built binaries](https://github.com/soqucoin-labs/pqcat/releases/latest)
alongside the Scanner archives.

## Quick Start

Everything here runs on the build this repository produces. Commands that need
Enclave or Pro are in the section below, kept separate on purpose: they exit
with an error on a Scanner build, and a quick start whose first command fails is
worse than no quick start.

```bash
# Build the Scanner
make

# Scan (auto-deep for single targets)
./pqcat scan tls example.com

# Machine-readable output
./pqcat scan tls example.com --json

# Generate an org config template
./pqcat config init
```

### The same scan, with scoring and a report

Scoring, frameworks, reports and the evidence layer are not compiled into the
Scanner. Download Enclave, which is free, and the same target produces a scored
Crypto Bill of Health:

```bash
# From https://github.com/soqucoin-labs/pqcat/releases/latest
pqcat scan tls example.com --framework fisma --html cboh.html --save-db
```

Unlicensed Enclave covers up to 25 hosts per scan. `pqcat license trial` starts a
free 14-day evaluation that raises it, needs no registration, and validates
offline.

## Scanner Modules

| Module | Command | Description |
|---|---|---|
| TLS/SSL | `scan tls` | **Deep scan**: full cipher enumeration, protocol probing, ML-KEM detection, quantum classification |
| SSH | `scan ssh` | Key exchange, host key types |
| SBOM | `scan sbom` | CycloneDX/SPDX crypto dependency analysis |
| PKI | `scan pki` | Certificate chain walking and CA analysis |
| Code | `scan code` | Source code pattern scanning (564 patterns, 39 file types) |
| Config | `scan config` | Configuration file analysis (nginx, Apache, OpenSSL, SSH) for weak crypto settings |
| HSM/KMS | `scan hsm` | Hardware security module key discovery |
| SCAP | `scan scap` | SCAP/XCCDF benchmark results for crypto policy compliance |
| Image | `scan image` | Container image (Docker, OCI) scanning for embedded crypto libraries |
| CIDR | `scan tls <cidr>` | Subnet-wide TLS and SSH discovery across network ranges |
| Cloud (CSP) | `scan cloud aws` | AWS KMS, ACM, ELB, S3, Route 53, IAM crypto discovery |


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

## TLS Deep Scan

PQCAT's deep scan mode provides **SSL Labs-grade TLS assessment** with quantum-risk classification in a single binary, air-gap safe.

```bash
# Deep scan (default for single targets)
pqcat scan tls example.com

# Explicit deep mode for network ranges
pqcat scan tls 10.0.0.0/24 --deep

# Force fast mode (single-connection, ~1s)
pqcat scan tls example.com --fast
```

**What deep scan detects:**
- Full cipher suite enumeration (20+ suites per target)
- Protocol version matrix (TLS 1.0–1.3, SSLv3, SSLv2)
- Raw TCP probes for legacy protocols (SSLv3/SSLv2, export ciphers)
- Complete certificate chain with SANs, fingerprints, OCSP, SCTs
- HTTP security headers (HSTS, CSP, X-Frame-Options)
- Server cipher preference detection
- **Every component classified**: RED (quantum-vulnerable) / GREEN (quantum-safe)
- Prioritized remediation actions with CNSA 2.0 / NIST references

## HNDL Risk Engine (v2.6.0)

Patent-pending per-asset "Harvest Now, Decrypt Later" exposure scoring.

- Time-weighted quantum risk based on data sensitivity, retention period, and estimated Q-Day timeline
- Per-asset HNDL multiplier integrated into compliance scoring
- Surfaces in scan results, reports, and the Pro dashboard

## Confidential Compliance Engine (CCE)

Prove compliance without revealing your infrastructure. Patent-pending privacy-preserving assessments.

```bash
pqcat scan tls agency.gov --confidential --framework fisma
```

- **Asset Anonymization**: BLAKE2b-salted identifiers replace hostnames and IPs
- **Aggregate-Only Reporting**: Statistical summaries, zero individual asset detail
- **Verifiable Score Binding**: Transparent hash-based proof (Merkle commitment + Fiat-Shamir, SHA-384, no trusted setup) that binds a published score to its committed finding set. A holder of the findings can verify the opening; tampering with a finding or the score is detected

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
│  11 scanner modules + algorithm classifier + data models      │
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
