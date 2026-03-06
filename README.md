# PQCAT — Post-Quantum Cryptography Compliance Assessment Tool

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)

**Built by Soqucoin Labs Inc.** — the team that migrated a production blockchain from ECDSA to NIST FIPS 204 (ML-DSA). Not theory — proven implementation.

---

## What Is PQCAT?

PQCAT discovers every cryptographic asset across your infrastructure, classifies quantum vulnerability, scores compliance readiness, and delivers federal-grade reports — all from a single binary with zero runtime dependencies.

```
pqcat scan tls agency.gov --framework fisma --html report.html --save-db
```

**Output:** A scored Crypto Bill of Health with RED/YELLOW/GREEN zone breakdown, POA&M entries, and framework-specific migration recommendations.

## Two Editions

| Feature | Enclave (Air-Gapped) | Pro (Connected) |
|---|---|---|
| CLI scanner (9 modules) | ✓ | ✓ |
| TUI terminal dashboard | ✓ | ✓ |
| Self-contained HTML reports | ✓ | ✓ |
| SQLite scan history & POA&M | ✓ | ✓ |
| REST API + web dashboard | — | ✓ |
| Live threat intelligence | — | ✓ |

Both editions are built from this codebase. The Enclave edition compiles with **zero network code** beyond scan targets — guaranteed by the compiler.

## Quick Start

```bash
# Build
make all

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
| Code | `scan code` | Source code pattern scanning (60+ regex) |
| HSM/KMS | `scan hsm` | Hardware security module key discovery |
| CIDR | `scan cidr` | Subnet-wide TLS/SSH discovery |
| OpenSCAP | `scan scap` | Import XCCDF results for PQC assessment |
| Aggregate | `scan all` | Run all applicable modules |

## Build

```bash
make airgap       # Enclave (air-gapped) edition
make pro          # Pro (connected) edition
make test         # Run unit tests
make sbom         # Generate CycloneDX SBOM
make checksums    # SHA-256 integrity manifest
make release      # Full release package
```

## Configuration

PQCAT uses YAML with a 6-level precedence chain:

```
CLI flags > env vars > --config file > ./pqcat.yaml > ~/.pqcat/config.yaml > /etc/pqcat/pqcat.yaml
```

Generate a documented template: `pqcat config init`

See [docs/PQCAT-SOP-001.md](docs/PQCAT-SOP-001.md) for the full Standard Operations Procedure.

## Architecture

```
┌── Discovery Layer ──────────────── Open Source (Apache 2.0) ──┐
│  9 scanner modules + algorithm classifier + data models       │
├── Intelligence Layer ────────────── Proprietary ──────────────┤
│  Compliance engine + scoring + threat intel                   │
├── Delivery Layer ─────────────────────────────────────────────┤
│  PDF · HTML · JSON · SIEM · TUI · REST API                   │
└───────────────────────────────────────────────────────────────┘
```

The **scanner** (this repository) is open source under Apache 2.0. The **compliance engine** is proprietary and distributed as compiled binaries under license.

## Compliance Frameworks

- **FISMA** — NIST 800-53 federal agency compliance
- **FedRAMP** — Cloud service provider authorization
- **DoD** — CNSA 2.0 Department of Defense
- **NIST** — General 800-131A guidance
- **CNSA** — NSA Commercial National Security Algorithm Suite 2.0

## License

The PQCAT scanner is licensed under the [Apache License 2.0](LICENSE).

The compliance engine (scoring, reporting, REST API) is proprietary software. Contact labs@soqu.org for licensing.

## About

**Soqucoin Labs Inc.**  
228 Park Ave S, Pmb 85451, New York, NY 10003  
[soqucoin.com](https://soqucoin.com) · labs@soqu.org
