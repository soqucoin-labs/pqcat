# PQCAT Build System
# Soqucoin Labs Inc.
#
# Two editions built from the same codebase:
#   Air-Gapped (default): Zero outbound network calls, embedded intel only
#   Connected (Pro):      Live threat intel feed, REST API, web dashboard
#
# Usage:
#   make              Build air-gapped edition (default, federal-safe)
#   make pro          Build connected edition with live feed + dashboard
#   make all          Build both editions
#   make test         Run tests
#   make sbom         Generate PQCAT's own CycloneDX SBOM
#   make checksums    Generate SHA-256 checksums for release
#   make sidecar      Generate intel sidecar template
#   make clean        Remove build artifacts

BINARY_NAME := pqcat
PRO_BINARY  := pqcat-pro
VERSION     := 1.0.0
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")

# Linker flags for version injection
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildDate=$(BUILD_DATE)' \
	-X 'main.GitCommit=$(GIT_COMMIT)'

.PHONY: all airgap pro test sidecar sbom checksums clean help

# Default target: air-gapped edition
all: airgap pro

airgap: ## Build air-gapped edition (default, no network intel)
	@echo "Building PQCAT Air-Gapped Edition v$(VERSION)..."
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS) -X 'main.Edition=Air-Gapped'" \
		-o $(BINARY_NAME) ./cmd/pqcat/
	@echo "✓ Built $(BINARY_NAME) (air-gapped, $$(wc -c < $(BINARY_NAME) | xargs) bytes)"
	@echo "  Zero outbound network capability. Federal-safe."
	@echo "  Subcommands: scan, dashboard, config"

pro: ## Build connected edition with live threat intel + REST API
	@echo "Building PQCAT Pro Edition v$(VERSION)..."
	CGO_ENABLED=0 go build -tags connected \
		-ldflags "$(LDFLAGS) -X 'main.Edition=Pro'" \
		-o $(PRO_BINARY) ./cmd/pqcat/
	@echo "✓ Built $(PRO_BINARY) (connected, $$(wc -c < $(PRO_BINARY) | xargs) bytes)"
	@echo "  Live threat intel feed + REST API + web dashboard enabled."
	@echo "  Subcommands: scan, serve, dashboard, config"

# Cross-compilation for federal deployment
linux-amd64: ## Build for Linux x86_64 (common federal server)
	@echo "Cross-compiling for linux/amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS) -X 'main.Edition=Air-Gapped'" \
		-o $(BINARY_NAME)-linux-amd64 ./cmd/pqcat/
	@echo "✓ Built $(BINARY_NAME)-linux-amd64"

linux-arm64: ## Build for Linux ARM64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS) -X 'main.Edition=Air-Gapped'" \
		-o $(BINARY_NAME)-linux-arm64 ./cmd/pqcat/

windows-amd64: ## Build for Windows x86_64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build \
		-ldflags "$(LDFLAGS) -X 'main.Edition=Air-Gapped'" \
		-o $(BINARY_NAME)-windows-amd64.exe ./cmd/pqcat/

# Release: build all platforms + integrity artifacts
release: ## Build release binaries for all platforms + checksums + SBOM
	@echo "Building release v$(VERSION)..."
	@$(MAKE) linux-amd64
	@$(MAKE) linux-arm64
	@$(MAKE) windows-amd64
	@$(MAKE) airgap
	@$(MAKE) pro
	@$(MAKE) sbom
	@$(MAKE) checksums
	@echo ""
	@echo "Release artifacts:"
	@ls -la $(BINARY_NAME)* pqcat-*.cdx.json SHA256SUMS* 2>/dev/null

sbom: ## Generate PQCAT's own CycloneDX SBOM (eat our own dog food)
	@echo "Generating PQCAT SBOM..."
	@echo '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,' > pqcat-v$(VERSION).cdx.json
	@echo '"metadata":{"component":{"type":"application","name":"pqcat",' >> pqcat-v$(VERSION).cdx.json
	@echo '"version":"$(VERSION)","supplier":{"name":"Soqucoin Labs Inc.",' >> pqcat-v$(VERSION).cdx.json
	@echo '"url":["https://soqucoin.com"]}}},' >> pqcat-v$(VERSION).cdx.json
	@echo '"components":[' >> pqcat-v$(VERSION).cdx.json
	@go list -m -json all 2>/dev/null | \
		python3 -c "import sys,json; \
		mods=[]; \
		buf=''; \
		[buf := buf + l for l in sys.stdin]; \
		parts=buf.replace('}\n{', '}|||{').split('|||'); \
		[mods.append(json.loads(p)) for p in parts if p.strip()]; \
		deps=[m for m in mods if m.get('Indirect') is not True and 'Path' in m and not m['Path'].startswith('github.com/soqucoin')]; \
		entries=['{\"type\":\"library\",\"name\":\"'+d['Path']+'\",\"version\":\"'+d.get('Version','dev')+'\"}' for d in deps]; \
		print(','.join(entries))" >> pqcat-v$(VERSION).cdx.json 2>/dev/null || echo "" >> pqcat-v$(VERSION).cdx.json
	@echo ']}' >> pqcat-v$(VERSION).cdx.json
	@echo "✓ Generated pqcat-v$(VERSION).cdx.json (CycloneDX SBOM)"
	@echo "  Self-scan: ./pqcat scan sbom pqcat-v$(VERSION).cdx.json"

checksums: ## Generate SHA-256 checksums for release binaries
	@echo "Generating checksums..."
	@shasum -a 256 $(BINARY_NAME) $(PRO_BINARY) $(BINARY_NAME)-linux-* $(BINARY_NAME)-windows-* 2>/dev/null > SHA256SUMS || \
		shasum -a 256 $(BINARY_NAME) $(PRO_BINARY) 2>/dev/null > SHA256SUMS
	@echo "✓ Generated SHA256SUMS"
	@cat SHA256SUMS

sidecar: airgap ## Generate intel sidecar template
	./$(BINARY_NAME) scan tls localhost --threatintel pqcat-intel.json 2>/dev/null || true
	@echo "✓ Generated pqcat-intel.json sidecar template"
	@echo "  Edit this file and deploy alongside pqcat binary"

test: ## Run tests
	go test ./... -v -count=1

clean: ## Remove build artifacts
	rm -f $(BINARY_NAME) $(PRO_BINARY)
	rm -f $(BINARY_NAME)-linux-* $(BINARY_NAME)-windows-*
	rm -f pqcat-intel.json pqcat-*.cdx.json SHA256SUMS*
	rm -f pqcat.db

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
