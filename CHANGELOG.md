# Changelog

All notable changes to PQCAT will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-03-12

### Added
- **9 Scanner Modules**: TLS, SSH, SBOM (180+ libraries), PKI, Code (60+ regex), HSM, CIDR Range, OpenSCAP, Aggregate
- **Compliance Frameworks**: FISMA, FedRAMP, DoD, NIST, CNSA 2.0, PCI DSS, SOX, HIPAA, NYDFS, SWIFT CSP, CMMC with STANDARD/HVA/NSS criticality levels
- **Smart Scan**: "Run All" auto-detects target type (hostname, file, CIDR) and runs applicable scanners
- **Two Editions**: Enclave (air-gapped, zero network code) and Pro (REST API, live threat intel, web dashboard)
- **Dashboard**: 15-tab enterprise Command Center with global scan context selector
- **Report Formats**: HTML, PDF, JSON, Executive Briefing, ATO Package
- **ML-DSA-44 Report Seal**: FIPS 204 post-quantum signatures on assessment reports via Cloudflare CIRCL
- **Role-Based Access Control (RBAC)**: Three roles — admin, analyst, viewer — with route-level enforcement
- **User Management**: CRUD via `/api/users` (admin-only), bcrypt password hashing, 12-character minimum
- **First-Run Admin Setup**: Cryptographically random 32-character admin password with force-change flag
- **Audit Logging**: HMAC-SHA256 chained tamper-proof audit trail with chain integrity verification
- **Session Authentication**: 256-bit random tokens, HttpOnly/Secure/SameSite cookies, 8h TTL
- **Prometheus Metrics**: Admin-only `/metrics` endpoint — 12 operational metrics
- **SIEM Integration**: Splunk HEC, ELK Bulk JSON, CEF Syslog with one-click export
- **Federal Compliance**: NIST 800-53 control mapping, ATO package generator, POA&M tracker
- **Vendor Supply Chain**: Per-vendor PQC readiness scoring and risk matrix
- **Scan History**: Full audit trail with per-scan analysis, comparison, and report generation
- **Threat Intelligence**: Embedded quantum timeline base + live feed (Pro), sidecar JSON (Enclave)
- **Score Trending**: Historical score tracking with visual trend analysis
- **Baselines & Drift**: Save baseline scans and detect cryptographic drift between assessments
- **Configuration**: YAML-based with 6-level precedence chain, org/environment/framework settings
- **SBOM Generation**: CycloneDX SBOM auto-generated in CI via `syft`
- **Environment-Based Secrets**: Sensitive configuration via env vars only
- **Server Test Suite**: 26 httptest-based tests covering auth, RBAC, rate limiting, audit log
- **CI/CD**: Dual test runs (Enclave + Pro), dual `go vet`, `govulncheck`, dual coverage reporting
- **Cross-platform**: macOS (ARM64, x86_64), Linux (AMD64, ARM64), Windows
- **Zero-dependency**: Single static binary, no CGO, no runtime dependencies

### Security
- Air-gap edition contains zero outbound network code — guaranteed by Go compiler build tags
- Timing-attack resistant authentication: constant-time API key comparison, dummy bcrypt for unknown usernames
- RBAC enforced at route level with audit trail on access denials
- HMAC-SHA256 chained audit log — tampering with any entry breaks the verifiable chain
- Secrets via env vars only — never stored in plaintext config files
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- ML-DSA-44 digital signatures on all assessment reports
