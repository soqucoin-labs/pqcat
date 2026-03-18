# PQCAT Architecture

## Overview

PQCAT uses a four-layer architecture separating discovery, intelligence, security, and delivery concerns.

```
┌──────────────────────────────────────────────────────────┐
│                    DELIVERY LAYER                        │
│  REST API · Web Dashboard · TUI · PDF · HTML · JSON     │
│  SIEM Export (Splunk/ELK/CEF) · Prometheus /metrics     │
├──────────────────────────────────────────────────────────┤
│                    SECURITY LAYER                        │
│  RBAC (3 roles) · Session Auth · API Key Auth           │
│  HMAC-Chained Audit Log · Rate Limiting · CSP           │
│  ML-DSA-44 Report Seals (FIPS 204)                      │
├──────────────────────────────────────────────────────────┤
│                  INTELLIGENCE LAYER                      │
│  Compliance Engine · Scoring · Framework Mapping         │
│  POA&M Tracker · Baseline Drift · Threat Intel          │
│  SQLite Persistence · Scheduled Scans · Alerts          │
├──────────────────────────────────────────────────────────┤
│                   DISCOVERY LAYER                        │
│  TLS · SSH · SBOM · CIDR · PKI · Code · HSM             │
│  Algorithm Classifier (CNSA 2.0 / FIPS mapping)         │
└──────────────────────────────────────────────────────────┘
```

## Package Structure

```
pqcat/
├── cmd/pqcat/          # CLI entrypoint, Cobra commands
├── internal/
│   ├── classifier/     # Algorithm → Zone classification
│   ├── compliance/     # Framework scoring engine
│   ├── config/         # YAML config + env var loader
│   ├── models/         # Core data types (ScanResult, CryptoAsset, etc.)
│   ├── reporter/       # Output: PDF, HTML, JSON, terminal
│   ├── scanner/        # 7 discovery modules
│   ├── server/         # REST API + web dashboard (Pro only)
│   │   ├── server.go         # Core server, routes, dashboard HTML
│   │   ├── server_rbac.go    # RBAC middleware, session auth, user/audit handlers
│   │   └── server_metrics.go # Prometheus /metrics endpoint
│   ├── store/          # SQLite persistence layer
│   │   ├── store.go          # Core schema, scan/asset CRUD
│   │   └── store_rbac.go     # User CRUD, HMAC audit log, session tokens
│   └── tui/            # Terminal UI dashboard (bubbletea)
├── tools/pqsign/       # CLI seal/verify utility
├── docs/               # API, deployment, architecture guides
├── .github/workflows/  # CI/CD pipelines
└── Makefile            # Build, test, release automation
```

## Build Tag Separation

PQCAT ships two editions from the same codebase using Go build tags:

| Edition | Build Tag | Network Code | Use Case |
|---|---|---|---|
| **Enclave** | (default) | Zero outbound | SCIF, IL4/5, classified |
| **Pro** | `connected` | REST API + dashboard | Cloud, on-prem, hybrid enterprise |

The compiler guarantees no network code exists in the Enclave binary.

## Security Middleware Stack (Pro)

```
Request → Security Headers → CORS → Auth (Session/API Key) → RBAC → Rate Limit → Logging → Handler
```

- **Security Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **CORS**: Configurable origin, preflight OPTIONS
- **Auth**: Session token (cookie or `X-PQCAT-Session` header) or API key (`X-PQCAT-Token` / `Bearer`)
- **RBAC**: Three roles — viewer < analyst < admin — enforced at route level
- **Rate Limit**: Per-IP token-bucket, configurable RPM
- **Logging**: Method, path, status, duration, remote IP
- **Audit**: HMAC-SHA256 chained append-only log of all security events

## Data Flow

```
Target → Scanner Module → []CryptoAsset → Classifier → Zone
    → Compliance Engine → Score + Framework Mapping
    → Reporter → PDF / HTML / JSON / SIEM
    → Store (SQLite) → Scan History + POA&M + Baselines + Users + Audit Log
```

## Database Schema (Pro Edition)

| Table | Purpose |
|-------|---------|
| `scans` | Scan metadata (target, type, score, zone counts) |
| `assets` | Discovered crypto assets per scan |
| `baselines` | Named baseline snapshots for drift detection |
| `baseline_assets` | Assets belonging to a baseline |
| `poam_entries` | POA&M entries for compliance findings |
| `users` | RBAC user accounts (bcrypt hashes, roles) |
| `audit_log` | HMAC-chained tamper-proof security event log |
