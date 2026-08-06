// tls_deep.go implements comprehensive TLS/SSL scanning with full cipher suite
// enumeration, protocol version probing, and certificate enrichment.
//
// Design rationale: Security engineers (e.g., John's feedback) expect a TLS
// assessment tool to report AT LEAST what Qualys SSL Labs shows. PQCAT's
// differentiator is adding quantum-risk classification on every component.
// This file makes PQCAT a superset of SSL Labs: everything they show, plus
// RED/YELLOW/GREEN quantum zones on each algorithm.
//
// Architecture:
//   - Uses Go's crypto/tls for TLS 1.0-1.3 cipher/protocol probing
//   - Uses raw TCP ClientHello for SSLv3/SSLv2 detection (no Go TLS for these)
//   - Worker pool for concurrent cipher probing (default 8 workers)
//   - Certificate enrichment extracted from a single successful connection
//
// Security note: This module connects to remote hosts and probes their TLS
// configuration. In Enclave (air-gap) mode, the HTTP header check is skipped
// but all TLS probing works since it's direct TCP.
package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// DeepTLSScanOptions configures deep scanning behavior.
type DeepTLSScanOptions struct {
	Timeout      time.Duration
	Port         string
	ProbeWorkers int  // Concurrent cipher suite probes (default 8)
	SkipHTTP     bool // Skip HTTP header checks (for Enclave/air-gap)
	SkipLegacy   bool // Skip SSLv2/SSLv3 probing

	// HNDL Risk Quantification Engine (Patent: PQCAT-P002)
	HNDLSensitivity string // FIPS 199: "LOW", "MODERATE", "HIGH" (default: MODERATE)
	HNDLFramework   string // Framework key: "cnsa2", "fisma", "pci", etc. (default: cnsa2)
	HNDLRetention   int    // Custom data retention days (0 = use framework default)
	HNDLQuantumYear int    // Custom quantum timeline year (0 = use framework default)
}

// DefaultDeepTLSOptions returns production defaults for deep scanning.
func DefaultDeepTLSOptions() DeepTLSScanOptions {
	return DeepTLSScanOptions{
		Timeout:         10 * time.Second,
		Port:            "443",
		ProbeWorkers:    8,
		SkipHTTP:        false,
		SkipLegacy:      false,
		HNDLSensitivity: "MODERATE",
		HNDLFramework:   "cnsa2",
	}
}

// ScanTLSDeep performs a comprehensive TLS assessment of the target.
// It enumerates all supported cipher suites and protocol versions,
// enriches certificate details, checks HTTP headers, and classifies
// every component for quantum vulnerability.
func ScanTLSDeep(ctx context.Context, target string, opts DeepTLSScanOptions) (*DeepTLSResult, *models.ScanResult, error) {
	start := time.Now()

	host, port := parseTarget(target, opts.Port)
	addr := net.JoinHostPort(host, port)

	result := &DeepTLSResult{
		Target:    addr,
		Port:      port,
		ScanMode:  "deep",
		Protocols: make(map[string]*ProtocolResult),
	}

	// ── Phase 1: Initial connection (default — usually ECDSA cert) ──
	conn, state, err := connectTLS(ctx, host, port, opts.Timeout, nil, 0, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("initial TLS connection failed: %w", err)
	}
	conn.Close()

	// ── Phase 1b: RSA certificate chain (force RSA-only cipher suites) ──
	// Many servers (Cloudflare, AWS) serve dual certs: ECDSA + RSA.
	// Go's TLS client prefers ECDSA, so we miss the RSA chain without this.
	rsaSuites := []uint16{
		0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
	}
	var rsaState tls.ConnectionState
	rsaConn, rsaSt, rsaErr := connectTLS(ctx, host, port, opts.Timeout, rsaSuites, tls.VersionTLS12, tls.VersionTLS12)
	if rsaErr == nil && rsaConn != nil {
		rsaState = rsaSt
		rsaConn.Close()
	}

	// ── Phase 2: Protocol version probing ──
	probeProtocols(ctx, host, port, opts, result)

	// ── Phase 3: Legacy protocol detection (SSLv3, SSLv2) via raw TCP ──
	if !opts.SkipLegacy {
		probeSSLv3(ctx, host, port, opts.Timeout, result)
		probeSSLv2(ctx, host, port, opts.Timeout, result)
	}

	// ── Phase 4: Cipher suite enumeration (TLS 1.2 only) ──
	probeCipherSuites(ctx, host, port, opts, result)

	// ── Phase 4b: TLS 1.3 cipher suites (hard-registered — Go can't probe individually) ──
	registerTLS13Suites(result)

	// ── Phase 4c: Go-dropped cipher suites (raw TCP probe) ──
	// Go 1.22+ removed these 3 suites from crypto/tls. They still exist on
	// many servers (Cloudflare, AWS). A compliance tool CANNOT silently omit
	// suites that exist — that's a liability gap.
	probeGoDroppedSuites(ctx, host, port, opts, result)

	// ── Phase 5: Server cipher preference detection ──
	result.ServerPreference = detectServerPreference(ctx, host, port, opts.Timeout)

	// ── Phase 6: Certificate chain enrichment ──
	// Enrich default (ECDSA) chain
	enrichCertificateChain(state, result)
	// Enrich RSA chain (dedup by fingerprint)
	if rsaErr == nil {
		enrichRSACertificateChain(rsaState, result)
	}

	// ── Phase 7: HTTP security headers ──
	if !opts.SkipHTTP {
		checkHTTPHeaders(host, port, opts.Timeout, result)
	}

	// ── Phase 7b: Export/NULL cipher probes (Blindspot 14) ──
	// Probes for catastrophically weak cipher suites (export-grade, NULL,
	// anonymous) that are CRITICAL compliance failures. Uses the same
	// raw TCP probe infrastructure as Go-dropped suites.
	result.ExportNullProbes = probeExportNullSuites(ctx, host, port, opts.Timeout)

	// ── Phase 7c: TLS Compression / CRIME detection (Blindspot 5) ──
	// If TLS-level compression is enabled, the CRIME attack can extract
	// session cookies. SSL Labs checks this — we should too.
	result.TLSCompression = probeTLSCompression(ctx, host, port, opts.Timeout)

	// ── Phase 7d: OCSP staple signature analysis (Blindspot 3) ──
	// First scanner in the world to classify OCSP staple signatures for
	// quantum vulnerability. SSL Labs shows stapling status but NOT the
	// signature algorithm's PQ risk.
	if len(state.OCSPResponse) > 0 && len(state.PeerCertificates) > 1 {
		result.OCSPAnalysis = analyzeOCSPStaple(state.OCSPResponse, state.PeerCertificates[1])
	} else if len(state.OCSPResponse) > 0 {
		result.OCSPAnalysis = analyzeOCSPStaple(state.OCSPResponse, nil)
	} else {
		result.OCSPAnalysis = analyzeOCSPStaple(nil, nil)
	}

	// ── Phase 7e: SCT signature analysis (Blindspot 4) ──
	// SCT signature analysis (Blindspot 4): classify Signed Certificate
	// Timestamp signatures for quantum risk. The CT ecosystem relies on
	// ECDSA signatures that are quantum-forgeable.
	result.SCTAnalysis = analyzeSCTs(state.SignedCertificateTimestamps)

	// ── Phase 7f: Certificate HNDL exposure windows (Blindspot 7) ──
	// Calculate per-certificate HNDL risk. Uses 2033 (CNSA 2.0 enforcement
	// year) as the default quantum timeline.
	quantumYear := 2033 // CNSA 2.0 enforcement date
	for _, cert := range state.PeerCertificates {
		exposure := calculateCertHNDLExposure(cert, quantumYear)
		result.CertHNDLExposures = append(result.CertHNDLExposures, exposure)
	}

	// ── Phase 7g: CAA record analysis (Blindspot 12) ──
	// Check which Certificate Authorities can issue certs for this domain.
	if !opts.SkipHTTP { // CAA requires DNS, skip in air-gap mode
		result.CAARecords = checkCAARecords(host)
	}

	// NOTE: Quantum summary and CNSA 2.0 gap moved to AFTER Phase 9
	// (key exchange group probing) so they include ML-KEM and other
	// key exchange groups in their zone counts. See audit issue #1.

	// ── Phase 9: Key Exchange Group Enumeration (Blindspot 2 + 1) ──
	// Probe which named groups/curves the server supports, including
	// ML-KEM/X25519MLKEM768 hybrid PQ groups — THE crown jewel feature.
	result.KeyExchangeGroups = probeKeyExchangeGroups(ctx, host, port, opts.Timeout)

	// Propagate PQ key exchange detection to the top-level result
	if result.KeyExchangeGroups.PQGroupFound {
		result.PQKeyExchangeDetected = true
		// Find the specific PQ group name
		for _, g := range result.KeyExchangeGroups.Groups {
			if g.Supported && g.Zone == models.ZoneGreen {
				result.PQKeyExchangeGroup = g.Name
				break
			}
		}
	}

	// Backup: Try Go's TLS library for PQ detection (works with Go 1.24+)
	// The raw probe may fail if the server rejects our synthetic key_share data,
	// but Go's native TLS client sends valid ML-KEM keys and can negotiate successfully.
	if !result.PQKeyExchangeDetected {
		if pqDetected, pqGroup := detectPQKeyExchangeViaGoTLS(ctx, host, port, opts.Timeout); pqDetected {
			result.PQKeyExchangeDetected = true
			result.PQKeyExchangeGroup = pqGroup

			// Inject the detected PQ group into KeyExchangeGroups so it becomes
			// a CryptoAsset in the report pipeline. The raw probe may have missed it
			// because servers validate ML-KEM encapsulation keys (unlike X25519
			// where any 32 bytes is valid).
			if result.KeyExchangeGroups != nil {
				// Check if the group is already there (just marked unsupported)
				found := false
				for i := range result.KeyExchangeGroups.Groups {
					if result.KeyExchangeGroups.Groups[i].Name == pqGroup {
						result.KeyExchangeGroups.Groups[i].Supported = true
						result.KeyExchangeGroups.Groups[i].Zone = models.ZoneGreen
						result.KeyExchangeGroups.Groups[i].Reason = "PQ-HYBRID: detected via Go TLS negotiation (server supports ML-KEM hybrid key exchange)"
						found = true
						break
					}
				}
				if !found {
					// Add as new entry
					groupID := uint16(0x11EC) // X25519MLKEM768 default
					if pqGroup == "SecP256r1MLKEM768" {
						groupID = 0x11EB
					}
					result.KeyExchangeGroups.Groups = append(result.KeyExchangeGroups.Groups, NamedGroupResult{
						ID:        groupID,
						IDHex:     fmt.Sprintf("0x%04X", groupID),
						Name:      pqGroup,
						Supported: true,
						Zone:      models.ZoneGreen,
						KeyBits:   192,
						Reason:    "PQ-HYBRID: detected via Go TLS negotiation (server supports ML-KEM hybrid key exchange)",
					})
				}
				result.KeyExchangeGroups.PQGroupFound = true
				result.KeyExchangeGroups.OverallZone = models.ZoneGreen
				result.KeyExchangeGroups.Summary = fmt.Sprintf("🟢 PQ-READY: Server supports %s post-quantum hybrid key exchange.", pqGroup)
			}
		}
	}

	// ── Phase 9a: Correct TLS 1.3 cipher suite KEX after group probing ──
	// TLS 1.3 cipher suites were classified with hardcoded "X25519/P-256"
	// KEX because the cipher suite name doesn't include the key exchange.
	// Now that we know the actual negotiated groups, update them.
	if result.PQKeyExchangeDetected && result.PQKeyExchangeGroup != "" {
		// A server that supports no classical group can only ever negotiate
		// the hybrid PQ exchange, so the suite's key-exchange component is
		// compliant. While classical groups are still offered, connections
		// can still be negotiated classically, so the zone stays as
		// classified (the label alone must not flip the verdict).
		// Upgrading the zone requires POSITIVE evidence: at least one supported
		// quantum-safe group, and no supported classical one. Deriving pq-only
		// from the mere absence of a classical group would fail open whenever
		// enumeration returned nothing usable — an empty group list, or a list
		// in which nothing is marked Supported, would satisfy "no classical
		// group found" and silently turn every TLS 1.3 suite GREEN on a server
		// we actually learned nothing about.
		pqOnly := false
		if result.KeyExchangeGroups != nil {
			sawSupportedGreen := false
			sawSupportedClassical := false
			for _, g := range result.KeyExchangeGroups.Groups {
				if !g.Supported {
					continue
				}
				if g.Zone == models.ZoneGreen {
					sawSupportedGreen = true
				} else {
					sawSupportedClassical = true
				}
			}
			pqOnly = sawSupportedGreen && !sawSupportedClassical
		}
		for i := range result.CipherSuites {
			if result.CipherSuites[i].KeyExchange == "X25519/P-256 (TLS 1.3)" {
				result.CipherSuites[i].KeyExchange = fmt.Sprintf("%s (TLS 1.3 PQ-hybrid)", result.PQKeyExchangeGroup)
				if pqOnly {
					result.CipherSuites[i].KeyExchangeZone = models.ZoneGreen
				}
			}
		}
	}

	// ── Phase 9b: Quantum summary and remediation (moved from Phase 8) ──
	// Runs AFTER key exchange probing so QuantumSummary includes ML-KEM
	// and other key exchange groups in zone counts. Fixes audit issue #1.
	computeQuantumSummary(result)
	generateRemediation(result)

	// ── Phase 9c: CNSA 2.0 Compliance Gap (CROSS-2) ──
	if result.QuantumSummary.TotalAlgorithms > 0 {
		pqCompliant := 0
		if counts, ok := result.QuantumSummary.ZoneCounts[models.ZoneGreen]; ok {
			pqCompliant = counts
		}
		result.CNSA2Gap = calculateCNSA2Gap(
			result.QuantumSummary.TotalAlgorithms,
			pqCompliant,
			quantumYear,
		)
	}

	// ── Phase 10: Secure Renegotiation (Blindspot 6) ──
	// Check RFC 5746 renegotiation_info extension / SCSV support.
	result.SecureRenegotiation = checkSecureRenegotiation(ctx, host, port, opts.Timeout)

	// ── Phase 11: HNDL Risk Quantification Engine (Patent: PQCAT-P002) ──
	// Aggregate all discovered cryptographic assets and compute the multi-factor
	// HNDL risk score: crypto_strength × data_sensitivity × exposure_window × attack_surface.
	result.HNDLRisk = computeHNDLFromDeepScan(result, opts)

	// ── Phase 12: DNSSEC Validation (Blindspot 10) ──
	// Check if the domain has DNSSEC deployed, preventing DNS spoofing/cache poisoning.
	// In a quantum threat model, unsigned DNS responses are trivially forgeable
	// once Shor's algorithm can break the CA's PKI.
	if !opts.SkipHTTP { // DNSSEC requires DNS, skip in air-gap mode
		result.DNSSECValidation = checkDNSSEC(host)
	}

	// ── Phase 13: DANE/TLSA Records (Blindspot 11) ──
	// Check for RFC 6698 TLSA records that bind TLS certificates to DNS names.
	// DANE prevents certificate authority compromise attacks by publishing
	// certificate fingerprints in DNSSEC-protected DNS.
	if !opts.SkipHTTP { // DANE requires DNS, skip in air-gap mode
		result.DANETLSARecords = checkDANETLSA(host, port)
	}

	result.Duration = time.Since(start)

	// Convert to standard ScanResult for pipeline compatibility
	scanResult := deepResultToScanResult(result)

	return result, scanResult, nil
}

// EstimateDeepScan does a quick TCP port scan to estimate how long a deep scan
// would take. Wired into `pqcat scan --deep <range>`, which otherwise ran for
// many minutes with nothing on screen to say how many minutes.
//
// The estimate is deliberately cheap: a single TCP connect per host, bounded by
// the same worker limit as the real scan, so the pre-flight cost is a small
// fraction of what it is estimating. It counts reachable hosts rather than
// guessing from the range size, because a /24 with four live hosts and a /24
// that is fully populated are two very different waits.
func EstimateDeepScan(ctx context.Context, targets []string, port string, timeout time.Duration, workers int) *DeepScanEstimate {
	// Accept the same target forms ScanRange does. Estimating over the raw
	// argument list would report "0/1 hosts" for a /24, since expansion happens
	// inside the scan.
	defaultPort := 443
	if p, err := strconv.Atoi(port); err == nil && p > 0 {
		defaultPort = p
	}
	if expanded, err := expandTargets(targets, defaultPort); err == nil && len(expanded) > 0 {
		targets = expanded
	}

	reachable := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	ctx = orBackground(ctx)
	for _, target := range targets {
		if ctxDone(ctx) {
			break
		}
		wg.Add(1)
		// Acquire BEFORE spawning, matching ScanRange. Acquiring inside the
		// goroutine bounds concurrent work but not goroutine count: the loop
		// would spawn one per target immediately and each would sit blocked on
		// the semaphore, so a /16 expanded to 65,536 hosts meant 65,536 live
		// goroutines and their stacks rather than `workers` of them.
		sem <- struct{}{}

		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()

			host, p := parseTarget(t, port)
			addr := net.JoinHostPort(host, p)
			conn, err := dialContext(ctx, "tcp", addr, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				reachable++
				mu.Unlock()
			}
		}(target)
	}
	wg.Wait()

	// Deep scan takes ~20s per target with 8 probe workers.
	// With N concurrent scan workers, total = (reachable / N) * 20s.
	// Zero reachable hosts means zero work, not one round: reporting "~20
	// seconds" for a range where nothing answered would misdescribe a scan that
	// is about to find nothing at all.
	perTarget := 20 * time.Second
	var totalParallel time.Duration
	if reachable > 0 {
		if workers < 1 {
			workers = 1
		}
		rounds := (reachable + workers - 1) / workers // ceiling, not floor+1
		totalParallel = time.Duration(rounds) * perTarget
	}

	return &DeepScanEstimate{
		TotalTargets:      len(targets),
		ReachableTargets:  reachable,
		EstimatedDuration: totalParallel,
		EstimatedHuman:    humanDuration(totalParallel),
		Workers:           workers,
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Protocol probing
// ──────────────────────────────────────────────────────────────────────────────

// probeProtocols tests TLS 1.0, 1.1, 1.2, 1.3 support.
func probeProtocols(ctx context.Context, host, port string, opts DeepTLSScanOptions, result *DeepTLSResult) {
	type versionProbe struct {
		name    string
		version uint16
		zone    models.Zone
		reason  string
	}

	probes := []versionProbe{
		{"tls_1_0", tls.VersionTLS10, models.ZoneRed,
			"Deprecated by RFC 8996 — prohibited by NIST SP 800-52 Rev. 2"},
		{"tls_1_1", tls.VersionTLS11, models.ZoneRed,
			"Deprecated by RFC 8996 — prohibited by NIST SP 800-52 Rev. 2"},
		{"tls_1_2", tls.VersionTLS12, models.ZoneYellow,
			"No post-quantum key exchange available in TLS 1.2"},
		{"tls_1_3", tls.VersionTLS13, models.ZoneYellow,
			"Supports PQ hybrid kex (ML-KEM) via draft-ietf-tls-ml-kem — zone GREEN when PQ kex negotiated"},
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range probes {
		wg.Add(1)
		go func(probe versionProbe) {
			defer wg.Done()
			conn, _, err := connectTLS(ctx, host, port, opts.Timeout, nil, probe.version, probe.version)
			supported := err == nil
			if conn != nil {
				conn.Close()
			}

			mu.Lock()
			result.Protocols[probe.name] = &ProtocolResult{
				Supported: supported,
				Zone:      probe.zone,
				Reason:    probe.reason,
			}
			if !supported {
				result.Protocols[probe.name].Reason = "Not supported (good)"
				if probe.zone == models.ZoneRed {
					result.Protocols[probe.name].Zone = models.ZoneGreen
					result.Protocols[probe.name].Reason = "Deprecated protocol correctly disabled"
				}
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()
}

// ──────────────────────────────────────────────────────────────────────────────
// Cipher suite enumeration
// ──────────────────────────────────────────────────────────────────────────────

// probeCipherSuites tests every known TLS 1.2 cipher suite against the server.
// TLS 1.3 suites are handled separately by registerTLS13Suites() because
// Go's tls.Config.CipherSuites field has NO effect on TLS 1.3 negotiation.
func probeCipherSuites(ctx context.Context, host, port string, opts DeepTLSScanOptions, result *DeepTLSResult) {
	// Gather all cipher suites Go knows about
	allSuites := allCipherSuiteIDs()

	type probeResult struct {
		suiteID uint16
		name    string
		version uint16
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.ProbeWorkers)
	var accepted []probeResult
	seen := make(map[uint16]bool) // Bug fix: dedup by suite ID

	for _, suite := range allSuites {
		// Skip TLS 1.3 suites — Go ignores CipherSuites for TLS 1.3.
		// They are hard-registered via registerTLS13Suites() instead.
		if suite.tls13 {
			continue
		}

		wg.Add(1)
		go func(s cipherSuiteInfo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, state, err := connectTLS(ctx, host, port, opts.Timeout, []uint16{s.id}, tls.VersionTLS12, tls.VersionTLS12)
			if err == nil && conn != nil {
				conn.Close()
				// Bug fix: verify server negotiated the suite we offered,
				// not a different one. With a single-suite offer this should
				// always match, but defense-in-depth.
				if state.CipherSuite != s.id {
					return
				}
				mu.Lock()
				if !seen[state.CipherSuite] {
					seen[state.CipherSuite] = true
					accepted = append(accepted, probeResult{
						suiteID: state.CipherSuite,
						name:    tls.CipherSuiteName(state.CipherSuite),
						version: state.Version,
					})
				}
				mu.Unlock()
			}
		}(suite)
	}
	wg.Wait()

	// Build classified results
	for _, a := range accepted {
		csr := classifyCipherSuite(a.suiteID, a.name, a.version)
		result.CipherSuites = append(result.CipherSuites, csr)
	}
}

// registerTLS13Suites adds the 3 standard TLS 1.3 cipher suites if TLS 1.3 is
// supported. Go hardcodes all 3 as always-available when TLS 1.3 is negotiated
// (see crypto/tls/cipher_suites.go), so if we confirmed TLS 1.3 works in the
// protocol probe phase, all 3 suites are supported.
func registerTLS13Suites(result *DeepTLSResult) {
	// Check if TLS 1.3 is supported from protocol probe results
	p, ok := result.Protocols["tls_1_3"]
	if !ok || !p.Supported {
		return
	}

	tls13Suites := []struct {
		id   uint16
		name string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
	}

	for _, s := range tls13Suites {
		csr := classifyCipherSuite(s.id, s.name, tls.VersionTLS13)
		result.CipherSuites = append(result.CipherSuites, csr)
	}
}

// detectServerPreference checks if the server enforces its own cipher order.
func detectServerPreference(ctx context.Context, host, port string, timeout time.Duration) bool {
	// Connect with default (Go-preferred) order
	conn1, state1, err1 := connectTLS(ctx, host, port, timeout, nil, 0, 0)
	if err1 != nil {
		return false
	}
	suite1 := state1.CipherSuite
	conn1.Close()

	// Connect with reversed order: put the weakest suites first
	reversed := reversedCipherSuiteIDs()
	conn2, state2, err2 := connectTLS(ctx, host, port, timeout, reversed, 0, 0)
	if err2 != nil {
		return false
	}
	suite2 := state2.CipherSuite
	conn2.Close()

	// If the server chose the same suite regardless of client order,
	// it enforces server preference (good practice).
	return suite1 == suite2
}

// ──────────────────────────────────────────────────────────────────────────────
// Certificate enrichment
// ──────────────────────────────────────────────────────────────────────────────

// enrichCertificateChain extracts detailed information from the certificate chain.
func enrichCertificateChain(state tls.ConnectionState, result *DeepTLSResult) {
	for i, cert := range state.PeerCertificates {
		detail := buildCertDetail(i, cert, state)
		result.CertificateChain = append(result.CertificateChain, detail)
	}
}

// enrichRSACertificateChain adds the RSA certificate chain if it differs from
// the already-enriched ECDSA chain. Many servers (Cloudflare, AWS ALB) serve
// dual certificates. Deduplicates by SHA-256 fingerprint.
func enrichRSACertificateChain(state tls.ConnectionState, result *DeepTLSResult) {
	// Build a set of fingerprints we already have
	existing := make(map[string]bool)
	for _, c := range result.CertificateChain {
		existing[c.FingerprintSHA256] = true
	}

	for i, cert := range state.PeerCertificates {
		hash := sha256.Sum256(cert.Raw)
		fp := formatFingerprint(hash[:])
		if existing[fp] {
			continue // Already have this cert from the ECDSA chain
		}
		detail := buildCertDetail(len(result.CertificateChain)+i, cert, state)
		result.CertificateChain = append(result.CertificateChain, detail)
	}
}

// buildCertDetail extracts all fields for a single certificate.
func buildCertDetail(depth int, cert *x509.Certificate, state tls.ConnectionState) CertificateDetail {
	detail := CertificateDetail{
		Depth:     depth,
		Version:   cert.Version,
		Subject:   cert.Subject.String(),
		SubjectCN: cert.Subject.CommonName,
		Issuer:    cert.Issuer.String(),
		IssuerCN:  cert.Issuer.CommonName,
		IssuerOrg: certIssuerOrg(cert),
		Serial:    cert.SerialNumber.String(),
		SANs:      cert.DNSNames,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		IsCA:      cert.IsCA,
		IsSelfSigned: cert.Subject.CommonName == cert.Issuer.CommonName &&
			cert.AuthorityKeyId != nil &&
			cert.SubjectKeyId != nil &&
			string(cert.AuthorityKeyId) == string(cert.SubjectKeyId),
	}

	// Days remaining
	detail.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	detail.IsExpired = time.Now().After(cert.NotAfter)

	// SHA-256 fingerprint
	hash := sha256.Sum256(cert.Raw)
	detail.FingerprintSHA256 = formatFingerprint(hash[:])

	// Signature classification
	sigAlgo := cert.SignatureAlgorithm.String()
	detail.SignatureAlgorithm = sigAlgo
	detail.SignatureZone, detail.SignatureReason = classifier.ClassifyWithReason(sigAlgo)

	// Public key classification
	pubKeyAlgo := describePublicKey(cert)
	detail.PublicKeyAlgorithm = pubKeyAlgo
	detail.PublicKeyZone, detail.PublicKeyReason = classifier.ClassifyWithReason(pubKeyAlgo)
	detail.KeySize = publicKeyBits(cert)

	// SCT (check for OID 1.3.6.1.4.1.11129.2.4.2)
	detail.SCTPresent = false
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.11129.2.4.2" {
			detail.SCTPresent = true
			break
		}
	}

	// OCSP
	if len(cert.OCSPServer) > 0 {
		detail.OCSPResponderURL = cert.OCSPServer[0]
	}
	detail.OCSPStapled = len(state.OCSPResponse) > 0

	// CRL Distribution Points
	detail.CRLDistributionURLs = cert.CRLDistributionPoints

	// Key Usage
	detail.KeyUsage = describeKeyUsage(cert.KeyUsage)
	detail.ExtKeyUsage = describeExtKeyUsage(cert.ExtKeyUsage)

	// IP SANs
	for _, ip := range cert.IPAddresses {
		detail.SANs = append(detail.SANs, ip.String())
	}

	return detail
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP security headers
// ──────────────────────────────────────────────────────────────────────────────

// checkHTTPHeaders performs a single HTTPS HEAD request to extract security headers.
func checkHTTPHeaders(host, port string, timeout time.Duration, result *DeepTLSResult) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	url := fmt.Sprintf("https://%s:%s/", host, port)
	resp, err := client.Head(url)
	if err != nil {
		return // HTTP header check is best-effort
	}
	defer resp.Body.Close()

	httpResult := &HTTPSecurityResult{
		ServerHeader:  resp.Header.Get("Server"),
		XFrameOptions: resp.Header.Get("X-Frame-Options"),
		XContentType:  resp.Header.Get("X-Content-Type-Options"),
		CSP:           resp.Header.Get("Content-Security-Policy"),
	}

	result.ServerHeader = resp.Header.Get("Server")

	// Parse HSTS
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts != "" {
		httpResult.HSTS = parseHSTS(hsts)
	}

	result.HTTPSecurity = httpResult
}

// parseHSTS parses the Strict-Transport-Security header value.
func parseHSTS(value string) *HSTSResult {
	h := &HSTSResult{Enabled: true}
	parts := strings.Split(strings.ToLower(value), ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "max-age=") {
			fmt.Sscanf(p, "max-age=%d", &h.MaxAge)
		}
		if p == "includesubdomains" {
			h.IncludeSubdomains = true
		}
		if p == "preload" {
			h.Preload = true
		}
	}
	return h
}

// ──────────────────────────────────────────────────────────────────────────────
// Quantum summary and remediation
// ──────────────────────────────────────────────────────────────────────────────

// computeQuantumSummary aggregates zone counts across all discovered components.
func computeQuantumSummary(result *DeepTLSResult) {
	zones := map[models.Zone]int{
		models.ZoneRed:    0,
		models.ZoneYellow: 0,
		models.ZoneGreen:  0,
	}
	total := 0
	protocolsVuln := 0
	ciphersVuln := 0
	certsVuln := 0

	// Count protocol zones
	for _, p := range result.Protocols {
		if p.Supported {
			zones[p.Zone]++
			total++
			if p.Zone == models.ZoneRed {
				protocolsVuln++
			}
		}
	}

	// Count cipher suite zones
	for _, cs := range result.CipherSuites {
		zones[cs.OverallZone]++
		total++
		if cs.OverallZone == models.ZoneRed {
			ciphersVuln++
		}
	}

	// Count certificate zones
	for _, cert := range result.CertificateChain {
		zones[cert.SignatureZone]++
		zones[cert.PublicKeyZone]++
		total += 2
		if cert.SignatureZone == models.ZoneRed {
			certsVuln++
		}
		if cert.PublicKeyZone == models.ZoneRed {
			certsVuln++
		}
	}

	// Count key exchange group zones (audit fix: these were skipped before)
	if result.KeyExchangeGroups != nil {
		for _, g := range result.KeyExchangeGroups.Groups {
			if g.Supported {
				zones[g.Zone]++
				total++
				if g.Zone == models.ZoneRed {
					ciphersVuln++ // Count as cipher-equivalent for summary
				}
			}
		}
	}

	// Determine overall zone (worst case)
	overall := models.ZoneGreen
	if zones[models.ZoneYellow] > 0 {
		overall = models.ZoneYellow
	}
	if zones[models.ZoneRed] > 0 {
		overall = models.ZoneRed
	}

	// Critical finding
	criticalFinding := "All cryptographic components are quantum-safe"
	if zones[models.ZoneRed] > 0 {
		criticalFinding = fmt.Sprintf("%d algorithm(s) vulnerable to quantum attack (Shor's algorithm)", zones[models.ZoneRed])
	}

	// HNDL exposure assessment
	hndlExposure := "No quantum exposure — all key exchanges use PQ-safe algorithms"
	if ciphersVuln > 0 {
		hndlExposure = "CRITICAL: All TLS sessions using classical key exchange are recordable for future quantum decryption (Harvest Now, Decrypt Later)"
	}

	result.QuantumSummary = QuantumSummary{
		OverallZone:      overall,
		TotalAlgorithms:  total,
		ZoneCounts:       zones,
		CriticalFinding:  criticalFinding,
		HNDLExposure:     hndlExposure,
		ProtocolsVuln:    protocolsVuln,
		CipherSuitesVuln: ciphersVuln,
		CertsVuln:        certsVuln,
	}
}

// generateRemediation creates prioritized, actionable fix recommendations.
func generateRemediation(result *DeepTLSResult) {
	var actions []RemediationAction
	priority := 1

	// Check for deprecated protocols
	for name, p := range result.Protocols {
		if p.Supported && p.Zone == models.ZoneRed {
			actions = append(actions, RemediationAction{
				Priority:   priority,
				Action:     fmt.Sprintf("Disable %s — deprecated and insecure", strings.ReplaceAll(strings.ToUpper(name), "_", " ")),
				Impact:     "Eliminates downgrade attacks and protocol-level vulnerabilities",
				Complexity: "LOW",
				Urgency:    "IMMEDIATE",
				Reference:  "RFC 8996, NIST SP 800-52 Rev. 2",
				Zone:       models.ZoneRed,
			})
			priority++
		}
	}

	// Check for quantum-vulnerable key exchanges
	kexVuln := 0
	for _, cs := range result.CipherSuites {
		if cs.KeyExchangeZone == models.ZoneRed {
			kexVuln++
		}
	}
	if kexVuln > 0 {
		actions = append(actions, RemediationAction{
			Priority:   priority,
			Action:     "Enable ML-KEM hybrid key exchange (X25519+ML-KEM-768 for TLS 1.3)",
			Impact:     "Protects all new TLS sessions against quantum HNDL attacks",
			Complexity: "LOW",
			Urgency:    "IMMEDIATE",
			Reference:  "CNSA 2.0 §3.1, RFC 9180, draft-ietf-tls-ml-kem",
			Zone:       models.ZoneRed,
			AssetCount: kexVuln,
		})
		priority++
	}

	// Check for quantum-vulnerable certificate signatures
	certVuln := 0
	for _, cert := range result.CertificateChain {
		if cert.SignatureZone == models.ZoneRed || cert.PublicKeyZone == models.ZoneRed {
			certVuln++
		}
	}
	if certVuln > 0 {
		actions = append(actions, RemediationAction{
			Priority:   priority,
			Action:     "Migrate certificates to ML-DSA-65 (FIPS 204) or hybrid RSA+ML-DSA signatures",
			Impact:     "Eliminates quantum forgery risk for server authentication",
			Complexity: "MEDIUM",
			Urgency:    "SHORT_TERM",
			Reference:  "CNSA 2.0 §4.2 — required by 2030 for NSS, NIST SP 800-227",
			Zone:       models.ZoneRed,
			AssetCount: certVuln,
		})
		priority++
	}

	// Check for weak ciphers (non-AEAD)
	weakCiphers := 0
	for _, cs := range result.CipherSuites {
		if strings.Contains(cs.BulkCipher, "CBC") {
			weakCiphers++
		}
	}
	if weakCiphers > 0 {
		actions = append(actions, RemediationAction{
			Priority:   priority,
			Action:     fmt.Sprintf("Remove %d CBC-mode cipher suite(s) — prefer AEAD (GCM, ChaCha20-Poly1305)", weakCiphers),
			Impact:     "Eliminates padding oracle attack surface (BEAST, Lucky13)",
			Complexity: "LOW",
			Urgency:    "SHORT_TERM",
			Reference:  "NIST SP 800-52 Rev. 2 §3.3.1",
			Zone:       models.ZoneYellow,
			AssetCount: weakCiphers,
		})
		priority++
	}

	// HSTS recommendation
	if result.HTTPSecurity != nil && (result.HTTPSecurity.HSTS == nil || !result.HTTPSecurity.HSTS.Enabled) {
		actions = append(actions, RemediationAction{
			Priority:   priority,
			Action:     "Enable HTTP Strict Transport Security (HSTS) with includeSubDomains and preload",
			Impact:     "Prevents SSL stripping attacks and enforces HTTPS-only access",
			Complexity: "LOW",
			Urgency:    "SHORT_TERM",
			Reference:  "RFC 6797, NIST SP 800-52 Rev. 2 §4.2",
			Zone:       models.ZoneYellow,
		})
	}

	result.Remediation = actions
}

// ──────────────────────────────────────────────────────────────────────────────
// Cipher suite classification
// ──────────────────────────────────────────────────────────────────────────────

// classifyCipherSuite breaks down a cipher suite and classifies each component.
func classifyCipherSuite(id uint16, name string, version uint16) CipherSuiteResult {
	csr := CipherSuiteResult{
		ID:       id,
		IDHex:    fmt.Sprintf("0x%04X", id),
		Name:     name,
		Protocol: tlsVersionName(version),
	}

	// Parse components from cipher suite name
	// TLS 1.3 suites: TLS_AES_256_GCM_SHA384  (no kex/auth — handled at protocol level)
	// TLS 1.2 suites: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	if version >= tls.VersionTLS13 {
		// TLS 1.3: key exchange is always ephemeral (X25519/P-256 via supported_groups)
		csr.KeyExchange = "X25519/P-256 (TLS 1.3)"
		csr.Authentication = "Certificate-based"
		csr.ForwardSecrecy = true

		switch {
		case strings.Contains(name, "AES_256_GCM"):
			csr.BulkCipher = "AES-256-GCM"
			csr.KeySize = 256
		case strings.Contains(name, "AES_128_GCM"):
			csr.BulkCipher = "AES-128-GCM"
			csr.KeySize = 128
		case strings.Contains(name, "CHACHA20_POLY1305"):
			csr.BulkCipher = "ChaCha20-Poly1305"
			csr.KeySize = 256
		default:
			csr.BulkCipher = name
			csr.KeySize = 0
		}

		if strings.Contains(name, "SHA384") {
			csr.MAC = "SHA-384 (AEAD)"
		} else {
			csr.MAC = "SHA-256 (AEAD)"
		}
	} else {
		// TLS 1.2 and below — parse from name
		switch {
		case strings.Contains(name, "ECDHE"):
			csr.KeyExchange = "ECDHE"
			csr.ForwardSecrecy = true
		case strings.Contains(name, "DHE") && !strings.Contains(name, "ECDHE"):
			csr.KeyExchange = "DHE"
			csr.ForwardSecrecy = true
		default:
			csr.KeyExchange = "RSA (static)"
			csr.ForwardSecrecy = false
		}

		switch {
		case strings.Contains(name, "ECDSA"):
			csr.Authentication = "ECDSA"
		case strings.Contains(name, "RSA"):
			csr.Authentication = "RSA"
		default:
			csr.Authentication = "unknown"
		}

		switch {
		case strings.Contains(name, "AES_256_GCM"):
			csr.BulkCipher = "AES-256-GCM"
			csr.KeySize = 256
		case strings.Contains(name, "AES_128_GCM"):
			csr.BulkCipher = "AES-128-GCM"
			csr.KeySize = 128
		case strings.Contains(name, "AES_256_CBC"):
			csr.BulkCipher = "AES-256-CBC"
			csr.KeySize = 256
		case strings.Contains(name, "AES_128_CBC"):
			csr.BulkCipher = "AES-128-CBC"
			csr.KeySize = 128
		case strings.Contains(name, "CHACHA20_POLY1305"):
			csr.BulkCipher = "ChaCha20-Poly1305"
			csr.KeySize = 256
		case strings.Contains(name, "3DES"):
			csr.BulkCipher = "3DES-EDE-CBC"
			csr.KeySize = 168
		case strings.Contains(name, "RC4"):
			csr.BulkCipher = "RC4"
			csr.KeySize = 128
		default:
			csr.BulkCipher = "unknown"
		}

		// MAC
		switch {
		case strings.Contains(name, "GCM"), strings.Contains(name, "POLY1305"):
			csr.MAC = "" // AEAD — no separate MAC
		case strings.Contains(name, "SHA384"):
			csr.MAC = "SHA-384"
		case strings.Contains(name, "SHA256"):
			csr.MAC = "SHA-256"
		case strings.Contains(name, "SHA"):
			csr.MAC = "SHA-1"
		}
	}

	// Classify each component for quantum vulnerability
	csr.KeyExchangeZone = classifier.Classify(csr.KeyExchange)
	csr.AuthZone = classifier.Classify(csr.Authentication)
	csr.BulkCipherZone = classifier.Classify(csr.BulkCipher)
	if csr.MAC != "" {
		csr.MACZone = classifier.Classify(csr.MAC)
	} else {
		csr.MACZone = models.ZoneGreen
	}

	// Overall zone = worst component
	csr.OverallZone = worstZone(csr.KeyExchangeZone, csr.AuthZone, csr.BulkCipherZone, csr.MACZone)

	// Strength label
	switch {
	case strings.Contains(csr.BulkCipher, "RC4") || strings.Contains(csr.BulkCipher, "3DES"):
		csr.Strength = "insecure"
	case strings.Contains(csr.BulkCipher, "CBC"):
		csr.Strength = "weak"
	case !csr.ForwardSecrecy:
		csr.Strength = "acceptable"
	default:
		csr.Strength = "strong"
	}

	// Reason
	switch csr.OverallZone {
	case models.ZoneRed:
		csr.Reason = fmt.Sprintf("Key exchange (%s) broken by Shor's algorithm on a CRQC", csr.KeyExchange)
		if strings.Contains(csr.BulkCipher, "RC4") {
			csr.Reason = "RC4 is classically broken — prohibited by all standards"
		}
		if strings.Contains(csr.BulkCipher, "3DES") {
			csr.Reason = "3DES has 64-bit block size — vulnerable to Sweet32 collision attack"
		}
	case models.ZoneYellow:
		csr.Reason = "Transitional — some components have limited quantum resistance"
	case models.ZoneGreen:
		csr.Reason = "All components quantum-resistant"
	}

	return csr
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// connectTLS makes a TLS connection with optional cipher suite and version constraints.
func connectTLS(ctx context.Context, host, port string, timeout time.Duration, suites []uint16, minVer, maxVer uint16) (*tls.Conn, tls.ConnectionState, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	if len(suites) > 0 {
		cfg.CipherSuites = suites
	}
	if minVer > 0 {
		cfg.MinVersion = minVer
	}
	if maxVer > 0 {
		cfg.MaxVersion = maxVer
	}

	addr := net.JoinHostPort(host, port)
	conn, err := dialTLSContext(ctx, "tcp", addr, timeout, cfg)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}

	state := conn.ConnectionState()
	return conn, state, nil
}

type cipherSuiteInfo struct {
	id    uint16
	name  string
	tls13 bool
}

// allCipherSuiteIDs returns every cipher suite Go's TLS library knows about.
func allCipherSuiteIDs() []cipherSuiteInfo {
	var all []cipherSuiteInfo

	// Secure suites
	for _, s := range tls.CipherSuites() {
		isTLS13 := false
		for _, v := range s.SupportedVersions {
			if v == tls.VersionTLS13 {
				isTLS13 = true
			}
		}
		all = append(all, cipherSuiteInfo{id: s.ID, name: s.Name, tls13: isTLS13})
	}

	// Insecure suites (RC4, 3DES, etc.) — critical for completeness
	for _, s := range tls.InsecureCipherSuites() {
		all = append(all, cipherSuiteInfo{id: s.ID, name: s.Name, tls13: false})
	}

	return all
}

// reversedCipherSuiteIDs returns cipher suites in weakest-first order.
func reversedCipherSuiteIDs() []uint16 {
	// Insecure first (to detect server preference)
	var ids []uint16
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// worstZone returns the most critical zone among the given zones.
func worstZone(zones ...models.Zone) models.Zone {
	worst := models.ZoneGreen
	for _, z := range zones {
		if z == models.ZoneRed {
			return models.ZoneRed
		}
		if z == models.ZoneYellow {
			worst = models.ZoneYellow
		}
	}
	return worst
}

// formatFingerprint formats a hash as colon-separated hex (AB:CD:EF:...).
func formatFingerprint(hash []byte) string {
	hexStr := hex.EncodeToString(hash)
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		end := i + 2
		if end > len(hexStr) {
			end = len(hexStr)
		}
		parts = append(parts, strings.ToUpper(hexStr[i:end]))
	}
	return strings.Join(parts, ":")
}

// humanDuration formats a duration for human display.
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("~%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("~%d minutes", int(d.Minutes()))
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	if mins > 0 {
		return fmt.Sprintf("~%dh %dm", hours, mins)
	}
	return fmt.Sprintf("~%d hours", hours)
}

// describeKeyUsage converts x509.KeyUsage bitmask to human-readable strings.
func describeKeyUsage(ku x509.KeyUsage) []string {
	var uses []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		uses = append(uses, "Digital Signature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		uses = append(uses, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		uses = append(uses, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		uses = append(uses, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		uses = append(uses, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		uses = append(uses, "CRL Sign")
	}
	return uses
}

// describeExtKeyUsage converts x509.ExtKeyUsage to human-readable strings.
func describeExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	var uses []string
	for _, u := range eku {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			uses = append(uses, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			uses = append(uses, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			uses = append(uses, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			uses = append(uses, "Email Protection")
		case x509.ExtKeyUsageOCSPSigning:
			uses = append(uses, "OCSP Signing")
		case x509.ExtKeyUsageTimeStamping:
			uses = append(uses, "Time Stamping")
		}
	}
	return uses
}

// deepResultToScanResult converts the deep scan result to a standard ScanResult
// so the existing pipeline (scoring, PDF, CBOM, etc.) works unchanged.
func deepResultToScanResult(deep *DeepTLSResult) *models.ScanResult {
	result := &models.ScanResult{
		Target:    deep.Target,
		ScanType:  "tls",
		Timestamp: time.Now(),
		Duration:  deep.Duration,
		Assets:    make([]models.CryptoAsset, 0),
		Details: map[string]string{
			"scan_mode":           "deep",
			"protocols_supported": countSupportedProtocols(deep),
			"cipher_suites_found": fmt.Sprintf("%d", len(deep.CipherSuites)),
			"server_preference":   fmt.Sprintf("%v", deep.ServerPreference),
		},
	}

	assetIdx := 0

	// Convert cipher suites to CryptoAssets
	for _, cs := range deep.CipherSuites {
		// Key exchange asset
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:          fmt.Sprintf("%s:cipher:%d:kex", deep.Target, assetIdx),
			Type:        models.AssetTLSCipher,
			Algorithm:   cs.KeyExchange,
			KeySize:     cs.KeySize,
			Zone:        cs.KeyExchangeZone,
			Location:    fmt.Sprintf("%s (cipher: %s)", deep.Target, cs.Name),
			Criticality: models.CriticalityStandard,
			Details: map[string]string{
				"cipher_suite": cs.Name,
				"cipher_id":    cs.IDHex,
				"protocol":     cs.Protocol,
				"component":    "key_exchange",
				"strength":     cs.Strength,
			},
		})
		assetIdx++

		// Bulk cipher asset
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:          fmt.Sprintf("%s:cipher:%d:bulk", deep.Target, assetIdx),
			Type:        models.AssetTLSCipher,
			Algorithm:   cs.BulkCipher,
			KeySize:     cs.KeySize,
			Zone:        cs.BulkCipherZone,
			Location:    fmt.Sprintf("%s (cipher: %s)", deep.Target, cs.Name),
			Criticality: models.CriticalityStandard,
			Details: map[string]string{
				"cipher_suite": cs.Name,
				"component":    "bulk_cipher",
			},
		})
		assetIdx++
	}

	// Convert certificates to CryptoAssets
	for _, cert := range deep.CertificateChain {
		// Signature algorithm
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:cert:%d:sig", deep.Target, cert.Depth),
			Type:      models.AssetTLSCert,
			Algorithm: cert.SignatureAlgorithm,
			KeySize:   cert.KeySize,
			Zone:      cert.SignatureZone,
			Location:  fmt.Sprintf("%s (cert %d: %s)", deep.Target, cert.Depth, cert.SubjectCN),
			Details: map[string]string{
				"subject":        cert.SubjectCN,
				"issuer":         cert.IssuerCN,
				"issuer_org":     cert.IssuerOrg,
				"serial":         cert.Serial,
				"not_before":     cert.NotBefore.Format(time.RFC3339),
				"not_after":      cert.NotAfter.Format(time.RFC3339),
				"chain_depth":    fmt.Sprintf("%d", cert.Depth),
				"is_ca":          fmt.Sprintf("%v", cert.IsCA),
				"component":      "signature",
				"fingerprint":    cert.FingerprintSHA256,
				"days_remaining": fmt.Sprintf("%d", cert.DaysRemaining),
			},
			Criticality: models.CriticalityStandard,
		})

		// Public key algorithm
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:cert:%d:pubkey", deep.Target, cert.Depth),
			Type:      models.AssetTLSCert,
			Algorithm: cert.PublicKeyAlgorithm,
			KeySize:   cert.KeySize,
			Zone:      cert.PublicKeyZone,
			Location:  fmt.Sprintf("%s (cert %d: %s)", deep.Target, cert.Depth, cert.SubjectCN),
			Details: map[string]string{
				"subject":   cert.SubjectCN,
				"component": "public_key",
				"sans":      strings.Join(cert.SANs, ", "),
			},
			Criticality: models.CriticalityStandard,
		})
	}

	// Convert key exchange groups to CryptoAssets (Sprint 2: ML-KEM detection)
	// Without this, probed PQ hybrid groups (X25519MLKEM768, etc.) are invisible
	// in reports despite being detected. This was the root cause of ML-KEM not
	// appearing in scan output even when the server supports it.
	if deep.KeyExchangeGroups != nil {
		for _, g := range deep.KeyExchangeGroups.Groups {
			if g.Supported {
				result.Assets = append(result.Assets, models.CryptoAsset{
					ID:          fmt.Sprintf("%s:kex-group:%s", deep.Target, g.Name),
					Type:        models.AssetTLSCipher,
					Algorithm:   g.Name,
					KeySize:     g.KeyBits,
					Zone:        g.Zone,
					Location:    fmt.Sprintf("%s (key exchange group)", deep.Target),
					Criticality: models.CriticalityStandard,
					Details: map[string]string{
						"component":   "key_exchange_group",
						"description": g.Reason,
						"pq_hybrid":   fmt.Sprintf("%v", g.Zone == models.ZoneGreen),
					},
				})
			}
		}
	}

	// Convert export/NULL cipher probes to CryptoAssets (audit fix: issue #2)
	// Any accepted export/NULL/anonymous cipher is a CRITICAL finding that
	// must be visible in reports and counted in compliance scoring.
	if deep.ExportNullProbes != nil {
		for _, suite := range deep.ExportNullProbes.Suites {
			if suite.Supported {
				result.Assets = append(result.Assets, models.CryptoAsset{
					ID:          fmt.Sprintf("%s:export-null:%s", deep.Target, suite.IDHex),
					Type:        models.AssetTLSCipher,
					Algorithm:   suite.Name,
					KeySize:     40, // Export ciphers are 40-bit; NULL is 0-bit
					Zone:        models.ZoneRed,
					Location:    fmt.Sprintf("%s (CRITICAL: %s cipher accepted)", deep.Target, suite.Category),
					Criticality: models.CriticalityHVA,
					Details: map[string]string{
						"component":   "export_null_cipher",
						"category":    suite.Category,
						"description": suite.Reason,
						"critical":    "true",
					},
				})
			}
		}
	}

	// Convert OCSP staple signature to CryptoAsset (audit fix: issue #3)
	// The OCSP responder's signature algorithm is quantum-vulnerable if using
	// RSA or ECDSA — this affects the certificate revocation infrastructure.
	if deep.OCSPAnalysis != nil && deep.OCSPAnalysis.Stapled {
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:          fmt.Sprintf("%s:ocsp:sig", deep.Target),
			Type:        models.AssetTLSCert,
			Algorithm:   deep.OCSPAnalysis.SignatureAlgorithm,
			KeySize:     0, // Signature algorithm, key size depends on CA
			Zone:        deep.OCSPAnalysis.Zone,
			Location:    fmt.Sprintf("%s (OCSP staple signature)", deep.Target),
			Criticality: models.CriticalityStandard,
			Details: map[string]string{
				"component":   "ocsp_signature",
				"status":      deep.OCSPAnalysis.Status,
				"description": deep.OCSPAnalysis.Reason,
			},
		})
	}

	// Convert SCT signatures to CryptoAssets (audit fix: issue #3)
	// Certificate Transparency log signatures are almost universally ECDSA —
	// quantum-vulnerable signatures that protect the entire CT ecosystem.
	if deep.SCTAnalysis != nil {
		for i, sct := range deep.SCTAnalysis.SCTs {
			result.Assets = append(result.Assets, models.CryptoAsset{
				ID:          fmt.Sprintf("%s:sct:%d", deep.Target, i),
				Type:        models.AssetTLSCert,
				Algorithm:   sct.SignatureAlgo,
				KeySize:     0,
				Zone:        sct.Zone,
				Location:    fmt.Sprintf("%s (CT log %s signature)", deep.Target, sct.LogID),
				Criticality: models.CriticalityStandard,
				Details: map[string]string{
					"component":   "sct_signature",
					"log_id":      sct.LogID,
					"hash_algo":   sct.HashAlgo,
					"description": sct.Reason,
				},
			})
		}
	}

	// Convert secure renegotiation status to compliance finding (audit fix: issue #4)
	// Insecure renegotiation (RFC 5746 not supported) enables MitM injection attacks.
	// This is a protocol-level behavior, not a crypto algorithm.
	if deep.SecureRenegotiation != nil && deep.SecureRenegotiation.Zone == models.ZoneRed {
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:          fmt.Sprintf("%s:renegotiation", deep.Target),
			Type:        models.AssetConfig,
			Algorithm:   "TLS-Renegotiation-Insecure",
			KeySize:     0,
			Zone:        models.ZoneRed,
			Location:    fmt.Sprintf("%s (RFC 5746 secure renegotiation NOT supported)", deep.Target),
			Criticality: models.CriticalityHVA,
			Details: map[string]string{
				"component":   "secure_renegotiation",
				"method":      deep.SecureRenegotiation.Method,
				"description": deep.SecureRenegotiation.Reason,
				"critical":    "true",
			},
		})
	}

	// Convert TLS compression status to compliance finding (audit fix: issue #5)
	// TLS compression enables the CRIME attack (CVE-2012-4929) — session cookie extraction
	// via compressed ciphertext oracle. Any server accepting DEFLATE is critically vulnerable.
	if deep.TLSCompression != nil && deep.TLSCompression.Supported {
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:          fmt.Sprintf("%s:compression", deep.Target),
			Type:        models.AssetConfig,
			Algorithm:   "TLS-Compression-CRIME",
			KeySize:     0,
			Zone:        models.ZoneRed,
			Location:    fmt.Sprintf("%s (CRITICAL: TLS compression enabled — CRIME attack CVE-2012-4929)", deep.Target),
			Criticality: models.CriticalityHVA,
			Details: map[string]string{
				"component":   "tls_compression",
				"method":      deep.TLSCompression.Method,
				"description": deep.TLSCompression.Reason,
				"critical":    "true",
			},
		})
	}

	return result
}

// countSupportedProtocols returns a comma-separated list of supported protocols.
func countSupportedProtocols(deep *DeepTLSResult) string {
	var supported []string
	order := []string{"tls_1_3", "tls_1_2", "tls_1_1", "tls_1_0", "ssl_3_0", "ssl_2_0"}
	for _, name := range order {
		if p, ok := deep.Protocols[name]; ok && p.Supported {
			supported = append(supported, strings.ReplaceAll(strings.ToUpper(name), "_", " "))
		}
	}
	return strings.Join(supported, ", ")
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase 11: HNDL Risk Quantification Engine Bridge
// ──────────────────────────────────────────────────────────────────────────────

// computeHNDLFromDeepScan extracts all discovered cryptographic assets from the
// deep scan results and feeds them into the HNDL Risk Quantification Engine.
//
// This is the "connector" between the scan pipeline (which discovers assets)
// and the HNDL engine (which scores risk). Assets are collected from:
//   - Cipher suites: key exchange, bulk cipher, MAC algorithms
//   - Certificate chain: signature algorithms, public key algorithms
//   - Key exchange groups: named curves and PQ hybrid groups
//   - OCSP staple: signature algorithm
//   - SCT signatures: CT log signature algorithms
//
// Patent: PQCAT-P002 — Integration of multi-layer cryptographic asset discovery
// with time-domain risk scoring.
func computeHNDLFromDeepScan(result *DeepTLSResult, opts DeepTLSScanOptions) *HNDLEngineResult {
	var assets []HNDLAsset

	// ── Collect from cipher suites ──
	seen := make(map[string]bool) // Dedup by "source:algorithm"
	for _, cs := range result.CipherSuites {
		// Key exchange
		key := "cipher-kex:" + cs.KeyExchange
		if !seen[key] && cs.KeyExchange != "" {
			seen[key] = true
			assets = append(assets, HNDLAsset{
				Name:       fmt.Sprintf("Key Exchange: %s", cs.KeyExchange),
				Algorithm:  cs.KeyExchange,
				Zone:       cs.KeyExchangeZone,
				ExpiryDays: -1, // Key exchange is session-based, no expiry
				Source:     "tls",
			})
		}

		// Bulk cipher
		key = "cipher-bulk:" + cs.BulkCipher
		if !seen[key] && cs.BulkCipher != "" {
			seen[key] = true
			assets = append(assets, HNDLAsset{
				Name:       fmt.Sprintf("Bulk Cipher: %s", cs.BulkCipher),
				Algorithm:  cs.BulkCipher,
				Zone:       cs.BulkCipherZone,
				KeyBits:    cs.KeySize,
				ExpiryDays: -1,
				Source:     "tls",
			})
		}

		// Authentication
		key = "cipher-auth:" + cs.Authentication
		if !seen[key] && cs.Authentication != "" {
			seen[key] = true
			assets = append(assets, HNDLAsset{
				Name:       fmt.Sprintf("Authentication: %s", cs.Authentication),
				Algorithm:  cs.Authentication,
				Zone:       cs.AuthZone,
				ExpiryDays: -1,
				Source:     "tls",
			})
		}
	}

	// ── Collect from certificate chain ──
	for _, cert := range result.CertificateChain {
		// Signature algorithm
		assets = append(assets, HNDLAsset{
			Name:       fmt.Sprintf("Cert Signature: %s (%s)", cert.SignatureAlgorithm, cert.SubjectCN),
			Algorithm:  cert.SignatureAlgorithm,
			Zone:       cert.SignatureZone,
			ExpiryDays: cert.DaysRemaining,
			Source:     "pki",
		})

		// Public key algorithm
		assets = append(assets, HNDLAsset{
			Name:       fmt.Sprintf("Cert Public Key: %s (%s)", cert.PublicKeyAlgorithm, cert.SubjectCN),
			Algorithm:  cert.PublicKeyAlgorithm,
			Zone:       cert.PublicKeyZone,
			KeyBits:    cert.KeySize,
			ExpiryDays: cert.DaysRemaining,
			Source:     "pki",
		})
	}

	// ── Collect from key exchange groups ──
	if result.KeyExchangeGroups != nil {
		for _, g := range result.KeyExchangeGroups.Groups {
			if g.Supported {
				assets = append(assets, HNDLAsset{
					Name:       fmt.Sprintf("Key Exchange Group: %s", g.Name),
					Algorithm:  g.Name,
					Zone:       g.Zone,
					KeyBits:    g.KeyBits,
					ExpiryDays: -1,
					Source:     "tls",
				})
			}
		}
	}

	// ── Collect from OCSP analysis ──
	if result.OCSPAnalysis != nil && result.OCSPAnalysis.Stapled {
		assets = append(assets, HNDLAsset{
			Name:       fmt.Sprintf("OCSP Staple: %s", result.OCSPAnalysis.SignatureAlgorithm),
			Algorithm:  result.OCSPAnalysis.SignatureAlgorithm,
			Zone:       result.OCSPAnalysis.Zone,
			ExpiryDays: -1,
			Source:     "tls",
		})
	}

	// ── Collect from SCT analysis ──
	if result.SCTAnalysis != nil {
		for _, sct := range result.SCTAnalysis.SCTs {
			assets = append(assets, HNDLAsset{
				Name:       fmt.Sprintf("SCT Signature: %s (Log: %s)", sct.SignatureAlgo, sct.LogID),
				Algorithm:  sct.SignatureAlgo,
				Zone:       sct.Zone,
				ExpiryDays: -1,
				Source:     "tls",
			})
		}
	}

	// ── Build HNDL engine input ──
	profile := GetHNDLProfile(opts.HNDLFramework)

	input := HNDLEngineInput{
		Sensitivity:         ParseHNDLSensitivity(opts.HNDLSensitivity),
		Framework:           opts.HNDLFramework,
		Profile:             profile,
		Assets:              assets,
		CustomRetentionDays: opts.HNDLRetention,
		CustomQuantumYear:   opts.HNDLQuantumYear,
	}

	return CalculateHNDLRisk(input)
}
