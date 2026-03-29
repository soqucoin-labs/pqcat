# Contributing to PQCAT

Thank you for your interest in contributing to PQCAT!

## Development Setup

```bash
# Clone
git clone https://github.com/soqucoin-labs/pqcat.git
cd pqcat

# Build Pro edition (REST API + Dashboard + RBAC)
go build -tags connected -o pqcat-pro ./cmd/pqcat/

# Build Enclave edition (Air-gapped, no network code)
go build -o pqcat ./cmd/pqcat/

# Run tests (Enclave)
go test ./... -count=1

# Run tests (Pro — includes server tests)
go test -tags connected ./internal/server/ -count=1

# Start dashboard (prints admin password on first run)
./pqcat-pro serve
```

## Architecture

| Package | Purpose |
|---|---|
| `cmd/pqcat` | CLI entry point and commands |
| `internal/classifier` | Algorithm → zone classification (Quantum Vulnerable / Transitional / PQ Compliant) |
| `internal/compliance` | Framework scoring (CNSA 2.0, FISMA, FedRAMP, DoD, NIST) |
| `internal/config` | YAML configuration with 6-level precedence chain + env var overrides |
| `internal/models` | Shared types: CryptoAsset, ScanResult, Zone, Criticality |
| `internal/reporter` | Report generators: HTML, PDF, JSON, Executive, ATO |
| `internal/scanner` | 9 scanner modules: TLS (deep scan), SSH, SBOM, PKI, Code, HSM, CIDR, Auto-detect, Simulate |
| `internal/server` | REST API, web dashboard, RBAC, Prometheus metrics (Pro, build tag `connected`) |
| `internal/store` | SQLite persistence, user CRUD, HMAC-chained audit log (pure Go, no CGO) |
| `internal/tui` | Terminal dashboard (Enclave edition) |
| `tools/pqsign` | CLI seal/verify utility for ML-DSA-44 report signatures |

## Build Tags

- **No tags** → Enclave edition (zero outbound network code, guaranteed by Go compiler)
- **`-tags connected`** → Pro edition (REST API, RBAC, webhook alerts, live threat intel)

## Pull Request Guidelines

1. **Tests required** — all new features must include tests
2. **Zero CGO** — no C dependencies, ever. All Go packages must be pure Go
3. **Air-gap safe** — no network code outside `connected` build tag scope
4. **Conventional commits** — `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
5. **One concern per PR** — keep PRs focused and reviewable
6. **RBAC-aware** — new endpoints must specify minimum role in `requireRole()` wrapper

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) — do NOT create a public issue.

## License

Apache 2.0. By contributing, you agree your contributions will be licensed under the same terms.
