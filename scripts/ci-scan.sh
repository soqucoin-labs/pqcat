#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# PQCAT CI Scanner — Vendor-Agnostic CI/CD Integration Script
#
# Works with: Jenkins, GitLab CI, Azure DevOps, CircleCI, Bamboo, TeamCity,
#             GitHub Actions (prefer the native action), or any CI runner.
#
# This script:
#   1. Downloads and verifies the PQCAT binary for your platform
#   2. Runs a cryptographic scan against specified targets
#   3. Generates reports (HTML, JSON, OSCAL, CBOM, ATO)
#   4. Enforces a minimum PQC readiness threshold
#   5. Returns exit code 0 (pass) or 1 (fail)
#
# Environment Variables:
#   PQCAT_VERSION       Version to download (default: latest)
#   PQCAT_SCAN_TYPE     Scan type: tls, ssh, sbom, pki, code, hsm, scap, all
#   PQCAT_TARGET        Scan target (hostname, file, directory, CIDR)
#   PQCAT_FRAMEWORK     Compliance framework (default: cnsa2)
#   PQCAT_THRESHOLD     Minimum score (0-100, default: 0 = informational)
#   PQCAT_FAIL_ON_RED   Set to "true" to fail on any RED assets
#   PQCAT_OUTPUT_DIR    Directory for reports (default: ./pqcat-reports)
#   PQCAT_FORMATS       Comma-separated output formats (html,json,oscal,cbom,ato)
#   PQCAT_BINARY        Path to existing PQCAT binary (skip download)
#   PQCAT_WORKERS       Concurrent scan workers for batch scans (default: 20)
#
# Usage:
#   # Basic usage — scan source code for crypto APIs
#   PQCAT_SCAN_TYPE=code PQCAT_TARGET=./src/ ./ci-scan.sh
#
#   # Scan TLS with threshold
#   PQCAT_SCAN_TYPE=tls PQCAT_TARGET=api.agency.gov PQCAT_THRESHOLD=80 ./ci-scan.sh
#
#   # Scan SBOM with OSCAL + CBOM output
#   PQCAT_SCAN_TYPE=sbom PQCAT_TARGET=bom.json PQCAT_FORMATS=oscal,cbom ./ci-scan.sh
#
#   # In Jenkinsfile
#   stage('PQC Compliance') {
#     steps {
#       sh '''
#         PQCAT_SCAN_TYPE=tls \
#         PQCAT_TARGET=staging.agency.gov \
#         PQCAT_FRAMEWORK=fisma \
#         PQCAT_THRESHOLD=70 \
#         PQCAT_FORMATS=html,oscal \
#         ./ci-scan.sh
#       '''
#       archiveArtifacts artifacts: 'pqcat-reports/**'
#     }
#   }
#
#   # In .gitlab-ci.yml
#   pqc_compliance:
#     stage: security
#     script:
#       - PQCAT_SCAN_TYPE=tls PQCAT_TARGET=$CI_ENVIRONMENT_URL ./ci-scan.sh
#     artifacts:
#       paths:
#         - pqcat-reports/
#       when: always
#
# Soqucoin Labs Inc. — https://soqucoin.com/pqcat
# ─────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────
VERSION="${PQCAT_VERSION:-latest}"
SCAN_TYPE="${PQCAT_SCAN_TYPE:-code}"
TARGET="${PQCAT_TARGET:-.}"
FRAMEWORK="${PQCAT_FRAMEWORK:-cnsa2}"
THRESHOLD="${PQCAT_THRESHOLD:-0}"
FAIL_ON_RED="${PQCAT_FAIL_ON_RED:-false}"
OUTPUT_DIR="${PQCAT_OUTPUT_DIR:-./pqcat-reports}"
FORMATS="${PQCAT_FORMATS:-html}"
BINARY="${PQCAT_BINARY:-}"
WORKERS="${PQCAT_WORKERS:-20}"

DOWNLOAD_BASE="https://github.com/soqucoin-labs/pqcat/releases"

# ── Logging ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[PQCAT]${NC} $*"; }
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# ── Banner ───────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  PQCAT — Post-Quantum Compliance Assessment Tool             ║"
echo "║  Soqucoin Labs Inc.                                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
log "Scan Type:   ${SCAN_TYPE}"
log "Target:      ${TARGET}"
log "Framework:   ${FRAMEWORK}"
log "Threshold:   ${THRESHOLD}"
log "Output Dir:  ${OUTPUT_DIR}"
log "Formats:     ${FORMATS}"
echo ""

# ── Platform Detection ───────────────────────────────────────────────────
detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    
    case "$arch" in
        x86_64)       arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            fail "Unsupported architecture: ${arch}"
            exit 1
            ;;
    esac
    
    case "$os" in
        linux|darwin) ;;
        mingw*|msys*|cygwin*)
            os="windows"
            ;;
        *)
            fail "Unsupported operating system: ${os}"
            exit 1
            ;;
    esac
    
    echo "${os}-${arch}"
}

# ── Download + Verify ────────────────────────────────────────────────────
download_pqcat() {
    local platform="$1"
    local download_url archive_name

    if [ "$VERSION" = "latest" ]; then
        download_url="${DOWNLOAD_BASE}/latest/download"
    else
        download_url="${DOWNLOAD_BASE}/download/v${VERSION}"
    fi
    
    # Determine expected binary name from release
    if [ "$platform" = "windows-amd64" ]; then
        archive_name="pqcat-${platform}.zip"
    else
        archive_name="pqcat-${platform}.tar.gz"
    fi
    
    local full_url="${download_url}/${archive_name}"
    log "Downloading from ${full_url}..."
    
    if ! curl -fsSL "${full_url}" -o "/tmp/${archive_name}" 2>/dev/null; then
        # Try with version prefix in filename
        local versioned_name
        if [ "$VERSION" != "latest" ]; then
            if [ "$platform" = "windows-amd64" ]; then
                versioned_name="pqcat-${VERSION}-${platform}.zip"
            else
                versioned_name="pqcat-${VERSION}-${platform}.tar.gz"
            fi
            full_url="${download_url}/${versioned_name}"
            log "Retrying with versioned filename: ${full_url}"
            curl -fsSL "${full_url}" -o "/tmp/${archive_name}" || {
                fail "Failed to download PQCAT binary"
                fail "URL: ${full_url}"
                fail "Check releases at: ${DOWNLOAD_BASE}"
                exit 1
            }
        else
            fail "Failed to download PQCAT binary"
            exit 1
        fi
    fi
    
    # Extract
    cd /tmp
    if [[ "${archive_name}" == *.tar.gz ]]; then
        tar xzf "${archive_name}"
    else
        unzip -q "${archive_name}"
    fi
    
    # Find the binary (could be named with version prefix or just pqcat-*)
    local binary_file
    binary_file=$(find /tmp -maxdepth 1 -name "pqcat*" -not -name "*.tar.gz" -not -name "*.zip" -type f | head -1)
    
    if [ -z "$binary_file" ]; then
        fail "Could not find PQCAT binary after extraction"
        exit 1
    fi
    
    chmod +x "$binary_file"
    BINARY="$binary_file"
    
    log "Downloaded: ${BINARY}"
    $BINARY version 2>/dev/null || warn "Could not verify PQCAT version"
}

# ── Run Scan ─────────────────────────────────────────────────────────────
run_scan() {
    mkdir -p "${OUTPUT_DIR}"
    
    local cmd="${BINARY} scan ${SCAN_TYPE} ${TARGET} --framework ${FRAMEWORK} --json"
    
    # Add workers for network scans
    if [[ "${SCAN_TYPE}" =~ ^(tls|ssh|all)$ ]]; then
        cmd="${cmd} --workers ${WORKERS}"
    fi
    
    # Add output format flags
    if echo "${FORMATS}" | grep -qi "html"; then
        cmd="${cmd} --html ${OUTPUT_DIR}/pqcat-report.html"
    fi
    if echo "${FORMATS}" | grep -qi "oscal"; then
        cmd="${cmd} --oscal ${OUTPUT_DIR}/pqcat-oscal.json"
    fi
    if echo "${FORMATS}" | grep -qi "cbom"; then
        cmd="${cmd} --cbom ${OUTPUT_DIR}/pqcat-cbom.json"
    fi
    if echo "${FORMATS}" | grep -qi "ato"; then
        cmd="${cmd} --ato ${OUTPUT_DIR}/pqcat-ato.json"
    fi
    
    # Always save JSON
    cmd="${cmd} --output ${OUTPUT_DIR}/pqcat-results.json"
    
    log "Running: ${cmd}"
    echo ""
    
    # Execute scan — capture stderr (report output) and stdout (JSON)
    eval "${cmd}" 2>&1
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        fail "PQCAT scan failed with exit code ${exit_code}"
        return 1
    fi
    
    echo ""
    return 0
}

# ── Parse Results ────────────────────────────────────────────────────────
evaluate_results() {
    local results_file="${OUTPUT_DIR}/pqcat-results.json"
    
    if [ ! -f "$results_file" ]; then
        warn "Results JSON not found at ${results_file}"
        return 0
    fi
    
    # Parse score and counts
    local score total red
    score=$(python3 -c "
import json, sys
with open('${results_file}') as f:
    data = json.load(f)
scores = data.get('scores', [])
print(int(scores[0].get('overall', 0)) if scores else 0)
" 2>/dev/null || echo "0")

    total=$(python3 -c "
import json, sys
with open('${results_file}') as f:
    data = json.load(f)
results = data.get('results', [])
print(len(results[0].get('assets', [])) if results else 0)
" 2>/dev/null || echo "0")

    red=$(python3 -c "
import json, sys
with open('${results_file}') as f:
    data = json.load(f)
scores = data.get('scores', [])
counts = scores[0].get('zone_counts', {}) if scores else {}
print(counts.get('RED', 0))
" 2>/dev/null || echo "0")
    
    # Summary
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║  Scan Complete                                               ║"
    echo "╠═══════════════════════════════════════════════════════════════╣"
    printf "║  %-14s %s\n" "Score:" "${score}/100"
    printf "║  %-14s %s\n" "Total Assets:" "${total}"
    printf "║  %-14s %s\n" "Vulnerable:" "${red} (RED zone)"
    printf "║  %-14s %s\n" "Framework:" "${FRAMEWORK}"
    printf "║  %-14s %s\n" "Threshold:" "${THRESHOLD}"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Report artifacts
    log "Reports saved to ${OUTPUT_DIR}/:"
    ls -la "${OUTPUT_DIR}/" 2>/dev/null | grep pqcat || true
    echo ""
    
    # Threshold enforcement
    if [ "${THRESHOLD}" -gt 0 ] && [ "${score}" -lt "${THRESHOLD}" ]; then
        fail "PQC readiness score ${score} is BELOW threshold ${THRESHOLD}"
        fail "Review ${OUTPUT_DIR}/pqcat-report.html for remediation actions"
        return 1
    fi
    
    # RED zone enforcement
    if [ "${FAIL_ON_RED}" = "true" ] && [ "${red}" -gt 0 ]; then
        fail "${red} quantum-vulnerable assets detected (PQCAT_FAIL_ON_RED=true)"
        fail "Review ${OUTPUT_DIR}/pqcat-report.html for details"
        return 1
    fi
    
    if [ "${score}" -ge 90 ]; then
        pass "PQC readiness: EXCELLENT (${score}/100)"
    elif [ "${score}" -ge 70 ]; then
        pass "PQC readiness: GOOD (${score}/100)"
    elif [ "${score}" -ge 50 ]; then
        warn "PQC readiness: FAIR (${score}/100) — review priority actions"
    else
        warn "PQC readiness: POOR (${score}/100) — immediate action recommended"
    fi
    
    return 0
}

# ── Main ─────────────────────────────────────────────────────────────────
main() {
    # Step 1: Get PQCAT binary
    if [ -n "$BINARY" ] && [ -x "$BINARY" ]; then
        log "Using existing PQCAT binary: ${BINARY}"
    else
        local platform
        platform=$(detect_platform)
        log "Platform detected: ${platform}"
        download_pqcat "$platform"
    fi
    
    # Step 2: Run scan
    if ! run_scan; then
        exit 1
    fi
    
    # Step 3: Evaluate results
    if ! evaluate_results; then
        exit 1
    fi
    
    log "Done."
}

main "$@"
