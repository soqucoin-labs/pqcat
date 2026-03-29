// sbom_enhanced.go — SBOM Scanner Sprint: resolves SBOM-1 through SBOM-4
//
// SBOM-1: Version-specific vulnerability mapping (OpenSSL, Java, .NET, etc.)
// SBOM-2: Transitive dependency detection from CycloneDX dependency graph
// SBOM-3: SBOM completeness scoring and quality assessment
// SBOM-4: SPDX PURL parsing for ecosystem detection
//
// Architecture: Post-processing enrichment, same pattern as code_enhanced.go
package scanner

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SBOM-1: Version-Specific Vulnerability Mapping
// ═══════════════════════════════════════════════════════════════════════════════

// versionVulnEntry represents a known vulnerable version range for a library.
type versionVulnEntry struct {
	library     string // key in cryptoLibraries
	minVersion  string // inclusive start of vulnerable range ("" = any)
	maxVersion  string // exclusive end of vulnerable range ("" = any above min)
	severity    string // CRITICAL, HIGH, MEDIUM
	vulnID      string // CVE or advisory ID
	description string
	algorithms  []string // specific algorithms affected (empty = all)
}

// knownVulnerableVersions is the curated list of version-specific crypto vulnerabilities.
// Focus: top libraries that federal/enterprise systems depend on.
var knownVulnerableVersions = []versionVulnEntry{
	// ── OpenSSL ──
	{library: "openssl", maxVersion: "1.0.2", severity: "CRITICAL",
		vulnID: "CVE-2014-0160", description: "Heartbleed — memory disclosure via TLS heartbeat",
		algorithms: []string{"RSA-2048", "ECDSA-P256"}},
	{library: "openssl", minVersion: "1.0.0", maxVersion: "1.0.2u", severity: "CRITICAL",
		vulnID: "EOL", description: "OpenSSL 1.0.x is end-of-life — no security patches since 2019"},
	{library: "openssl", minVersion: "1.1.0", maxVersion: "1.1.1", severity: "HIGH",
		vulnID: "CVE-2020-1967", description: "Segmentation fault in SSL_check_chain via DoS"},
	{library: "openssl", minVersion: "1.1.1", maxVersion: "1.1.1w", severity: "HIGH",
		vulnID: "EOL-2023", description: "OpenSSL 1.1.1 is end-of-life since September 2023"},
	{library: "openssl", minVersion: "3.0.0", maxVersion: "3.0.7", severity: "HIGH",
		vulnID: "CVE-2022-3602", description: "X.509 email address buffer overflow (Punycode)"},

	// ── GnuTLS ──
	{library: "gnutls", maxVersion: "3.6.0", severity: "HIGH",
		vulnID: "CVE-2020-13777", description: "TLS 1.3 session ticket key reuse — session hijacking"},

	// ── NSS ──
	{library: "nss", maxVersion: "3.73", severity: "HIGH",
		vulnID: "CVE-2021-43527", description: "BigSig — heap overflow in DER-encoded DSA/RSA-PSS sigs"},

	// ── wolfSSL ──
	{library: "wolfssl", maxVersion: "5.5.0", severity: "HIGH",
		vulnID: "CVE-2022-42905", description: "Buffer overflow in wolfSSL TLS 1.3 ClientHello"},

	// ── Bouncy Castle ──
	{library: "org.bouncycastle", maxVersion: "1.68", severity: "HIGH",
		vulnID: "CVE-2020-26939", description: "LDAP injection via X.509 certificate DN parsing"},
	{library: "org.bouncycastle", minVersion: "1.56", maxVersion: "1.65", severity: "MEDIUM",
		vulnID: "CVE-2020-28052", description: "OpenBSDBCrypt password check bypass"},

	// ── Python cryptography ──
	{library: "cryptography", maxVersion: "39.0.1", severity: "HIGH",
		vulnID: "CVE-2023-23931", description: "Memory corruption in Cipher.update_into()"},

	// ── Node.js node-forge ──
	{library: "node-forge", maxVersion: "1.3.0", severity: "HIGH",
		vulnID: "CVE-2022-24771", description: "Signature verification bypass via PKCS#1 v1.5"},

	// ── PyCryptodome ──
	{library: "pycryptodome", maxVersion: "3.19.1", severity: "MEDIUM",
		vulnID: "CVE-2023-52323", description: "Bleichenbacher timing oracle in PKCS#1 v1.5 RSA"},

	// ── jsonwebtoken (Node.js) ──
	{library: "jsonwebtoken", maxVersion: "9.0.0", severity: "HIGH",
		vulnID: "CVE-2022-23529", description: "Insecure key retrieval — arbitrary code execution"},

	// ── libssh ──
	{library: "libssh", minVersion: "0.6.0", maxVersion: "0.7.6", severity: "CRITICAL",
		vulnID: "CVE-2018-10933", description: "Authentication bypass — server accepts MSG_USERAUTH_SUCCESS from client"},

	// ── libssh2 ──
	{library: "libssh2", maxVersion: "1.9.0", severity: "HIGH",
		vulnID: "CVE-2019-3855", description: "Integer overflow in SSH_MSG_CHANNEL_REQUEST"},

	// ── cURL / libcurl ──
	{library: "curl", maxVersion: "8.4.0", severity: "HIGH",
		vulnID: "CVE-2023-38545", description: "SOCKS5 heap buffer overflow (worst curl vuln ever)"},
	{library: "libcurl", maxVersion: "8.4.0", severity: "HIGH",
		vulnID: "CVE-2023-38545", description: "SOCKS5 heap buffer overflow"},

	// ── Apache Shiro ──
	{library: "org.apache.shiro", maxVersion: "1.11.0", severity: "CRITICAL",
		vulnID: "CVE-2023-22602", description: "Authentication bypass via path traversal"},

	// ── crypto-js (browser) ──
	{library: "crypto-js", maxVersion: "4.2.0", severity: "CRITICAL",
		vulnID: "CVE-2023-46233", description: "Default PBKDF2 uses 1 iteration — trivially brute-forced"},
}

// VersionSeverity returns the worst vulnerability for a given library+version.
// Returns empty strings if no known vulnerability.
func VersionSeverity(library, version string) (severity, vulnID, description string) {
	if version == "" || version == "unknown" {
		return "", "", ""
	}
	libLower := strings.ToLower(library)

	worstSeverity := ""
	worstVulnID := ""
	worstDesc := ""

	for _, v := range knownVulnerableVersions {
		if libLower != strings.ToLower(v.library) {
			continue
		}

		if versionInRange(version, v.minVersion, v.maxVersion) {
			if severityRank(v.severity) > severityRank(worstSeverity) {
				worstSeverity = v.severity
				worstVulnID = v.vulnID
				worstDesc = v.description
			}
		}
	}

	return worstSeverity, worstVulnID, worstDesc
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// versionInRange checks if version falls within [minVersion, maxVersion).
// Uses simplified semantic version comparison (major.minor.patch).
func versionInRange(version, minVer, maxVer string) bool {
	v := parseVersion(version)
	if v == nil {
		return false // Can't parse — skip
	}

	if minVer != "" {
		min := parseVersion(minVer)
		if min != nil && compareVersions(v, min) < 0 {
			return false // version < minVersion
		}
	}

	if maxVer != "" {
		max := parseVersion(maxVer)
		if max != nil && compareVersions(v, max) > 0 {
			return false // version > maxVersion
		}
	}

	return true
}

// semver holds parsed semantic version components.
type semver struct {
	major, minor, patch int
	suffix              string // e.g., "u" in "1.0.2u"
}

var versionRegex = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$`)

// parseVersion extracts major.minor.patch from a version string.
func parseVersion(s string) *semver {
	m := versionRegex.FindStringSubmatch(s)
	if m == nil {
		return nil
	}

	major, _ := strconv.Atoi(m[1])
	minor := 0
	if m[2] != "" {
		minor, _ = strconv.Atoi(m[2])
	}
	patch := 0
	if m[3] != "" {
		patch, _ = strconv.Atoi(m[3])
	}

	return &semver{major: major, minor: minor, patch: patch, suffix: m[4]}
}

// compareVersions returns -1, 0, or 1.
func compareVersions(a, b *semver) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	// Compare suffixes alphabetically (e.g., "u" < "w")
	if a.suffix != b.suffix {
		if a.suffix < b.suffix {
			return -1
		}
		return 1
	}
	return 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// SBOM-2: Transitive Dependency Detection
// ═══════════════════════════════════════════════════════════════════════════════

// TransitiveDep tracks a transitive crypto dependency chain.
type TransitiveDep struct {
	Component string   // the component that indirectly uses crypto
	Chain     []string // dependency chain: [component → dep1 → dep2 → cryptoLib]
	CryptoLib string   // the resolved crypto library
}

// FindTransitiveCryptoDeps walks the CycloneDX dependency graph and finds
// components that transitively depend on crypto libraries.
func FindTransitiveCryptoDeps(components []componentInfo, deps []cycloneDXDep) []TransitiveDep {
	var results []TransitiveDep

	// Build adjacency list: ref → list of dependencies
	graph := make(map[string][]string)
	for _, d := range deps {
		graph[d.Ref] = d.DependsOn
	}

	// Build name→ref lookup from components
	nameToRef := make(map[string]string)
	refToName := make(map[string]string)
	for _, c := range components {
		ref := c.purl
		if ref == "" {
			ref = c.name
		}
		nameToRef[c.name] = ref
		refToName[ref] = c.name
	}

	// Identify direct crypto libraries
	directCrypto := make(map[string]bool)
	for _, c := range components {
		nameLower := strings.ToLower(c.name)
		for pattern := range cryptoLibraries {
			if strings.Contains(nameLower, strings.ToLower(pattern)) {
				ref := nameToRef[c.name]
				if ref != "" {
					directCrypto[ref] = true
				}
				directCrypto[c.name] = true
				break
			}
		}
	}

	// BFS from each non-crypto component to find transitive crypto paths
	for _, c := range components {
		cRef := nameToRef[c.name]
		if cRef == "" {
			cRef = c.name
		}

		// Skip if this is already a direct crypto library
		if directCrypto[cRef] || directCrypto[c.name] {
			continue
		}

		// BFS to find reachable crypto libraries
		visited := make(map[string]bool)
		type bfsNode struct {
			ref  string
			path []string
		}
		queue := []bfsNode{{ref: cRef, path: []string{c.name}}}
		visited[cRef] = true

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]

			for _, depRef := range graph[cur.ref] {
				if visited[depRef] {
					continue
				}
				visited[depRef] = true

				depName := refToName[depRef]
				if depName == "" {
					depName = depRef
				}

				newPath := make([]string, len(cur.path)+1)
				copy(newPath, cur.path)
				newPath[len(cur.path)] = depName

				if directCrypto[depRef] || directCrypto[depName] {
					// Found a transitive crypto dependency!
					results = append(results, TransitiveDep{
						Component: c.name,
						Chain:     newPath,
						CryptoLib: depName,
					})
				} else {
					queue = append(queue, bfsNode{ref: depRef, path: newPath})
				}
			}
		}
	}

	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// SBOM-3: Completeness Scoring
// ═══════════════════════════════════════════════════════════════════════════════

// SBOMQuality represents the quality assessment of an SBOM document.
type SBOMQuality struct {
	ComponentCount    int
	WithVersions      int
	WithPURLs         int
	WithLicenses      int
	CryptoLibsFound   int
	CompletenessScore float64 // 0.0 - 1.0
	Grade             string  // A, B, C, D, F
	Warnings          []string
}

// AssessSBOMQuality evaluates the quality and completeness of an SBOM.
func AssessSBOMQuality(components []componentInfo, cryptoAssetCount int) SBOMQuality {
	q := SBOMQuality{
		ComponentCount:  len(components),
		CryptoLibsFound: cryptoAssetCount,
	}

	for _, c := range components {
		if c.version != "" && c.version != "unknown" {
			q.WithVersions++
		}
		if c.purl != "" {
			q.WithPURLs++
		}
	}

	// Warnings
	if q.ComponentCount == 0 {
		q.Warnings = append(q.Warnings, "SBOM contains zero components — likely empty or incorrectly generated")
		q.CompletenessScore = 0.0
		q.Grade = "F"
		return q
	}

	if q.ComponentCount < 5 {
		q.Warnings = append(q.Warnings, fmt.Sprintf("SBOM has only %d components — suspiciously low, likely incomplete", q.ComponentCount))
	}

	if q.ComponentCount < 20 {
		q.Warnings = append(q.Warnings, "SBOM has fewer than 20 components — may be missing transitive dependencies")
	}

	versionRatio := float64(q.WithVersions) / float64(q.ComponentCount)
	if versionRatio < 0.5 {
		q.Warnings = append(q.Warnings, fmt.Sprintf("Only %.0f%% of components have version info — poor for vulnerability tracking", versionRatio*100))
	}

	purlRatio := float64(q.WithPURLs) / float64(q.ComponentCount)
	if purlRatio < 0.3 {
		q.Warnings = append(q.Warnings, "Less than 30% of components have PURL identifiers — limits ecosystem identification")
	}

	if q.CryptoLibsFound == 0 && q.ComponentCount > 20 {
		q.Warnings = append(q.Warnings, "No crypto libraries detected in SBOM — either the application uses no crypto (unlikely) or the SBOM generator missed crypto dependencies")
	}

	// Score: weighted average of coverage factors
	score := 0.0
	score += 0.15 * clampFloat(float64(q.ComponentCount)/50.0, 0.0, 1.0) // Component count (50+ = full marks)
	score += 0.35 * versionRatio                                         // Version coverage
	score += 0.25 * purlRatio                                            // PURL coverage
	score += 0.25 * clampFloat(float64(q.CryptoLibsFound)/5.0, 0.0, 1.0) // Crypto libs found (5+ = full)

	q.CompletenessScore = score

	// Grade assignment
	switch {
	case score >= 0.9:
		q.Grade = "A"
	case score >= 0.75:
		q.Grade = "B"
	case score >= 0.6:
		q.Grade = "C"
	case score >= 0.4:
		q.Grade = "D"
	default:
		q.Grade = "F"
	}

	return q
}

func clampFloat(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// ═══════════════════════════════════════════════════════════════════════════════
// SBOM-4: SPDX PURL Parsing
// ═══════════════════════════════════════════════════════════════════════════════

// ParsedPURL holds the decomposed elements of a Package URL.
type ParsedPURL struct {
	Scheme     string // always "pkg"
	Type       string // npm, pypi, maven, golang, nuget, cargo, etc.
	Namespace  string // org/group (e.g., "org.bouncycastle")
	Name       string // package name
	Version    string // package version
	Qualifiers string // everything after ?
	Subpath    string // everything after #
}

// purlRegex matches PURL format: pkg:type/namespace/name@version?qualifiers#subpath
var purlRegex = regexp.MustCompile(`^pkg:([a-zA-Z][a-zA-Z0-9._-]*)(?:/([^@#?]+?))?/([^@#?]+)(?:@([^?#]+))?(?:\?([^#]+))?(?:#(.+))?$`)

// ParsePURL decomposes a Package URL into its components.
func ParsePURL(purl string) *ParsedPURL {
	if purl == "" {
		return nil
	}

	m := purlRegex.FindStringSubmatch(purl)
	if m == nil {
		return nil
	}

	return &ParsedPURL{
		Scheme:     "pkg",
		Type:       m[1],
		Namespace:  m[2],
		Name:       m[3],
		Version:    m[4],
		Qualifiers: m[5],
		Subpath:    m[6],
	}
}

// EcosystemFromPURL extracts the ecosystem type from a PURL.
func EcosystemFromPURL(purl string) string {
	p := ParsePURL(purl)
	if p == nil {
		return ""
	}
	return p.Type
}

// EcosystemFromDownloadLocation infers ecosystem from SPDX download URLs.
func EcosystemFromDownloadLocation(dl string) string {
	dl = strings.ToLower(dl)

	switch {
	case strings.Contains(dl, "npmjs.org") || strings.Contains(dl, "npmjs.com"):
		return "npm"
	case strings.Contains(dl, "pypi.org") || strings.Contains(dl, "pypi.python.org") || strings.Contains(dl, "pythonhosted.org"):
		return "pypi"
	case strings.Contains(dl, "repo1.maven.org") || strings.Contains(dl, "maven.org"):
		return "maven"
	case strings.Contains(dl, "nuget.org"):
		return "nuget"
	case strings.Contains(dl, "crates.io"):
		return "cargo"
	case strings.Contains(dl, "rubygems.org"):
		return "gem"
	case strings.Contains(dl, "pkg.go.dev") || strings.Contains(dl, "proxy.golang.org"):
		return "golang"
	case strings.Contains(dl, "packagist.org"):
		return "composer"
	case strings.Contains(dl, "github.com"):
		return "github"
	case strings.Contains(dl, "gitlab.com"):
		return "gitlab"
	default:
		return ""
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EnrichSBOMAssets — Wires SBOM-1 through SBOM-4 into the scan pipeline
// ═══════════════════════════════════════════════════════════════════════════════

// EnrichSBOMAssets enriches SBOM scan results with vulnerability data,
// transitive deps, and ecosystem info.
func EnrichSBOMAssets(assets []models.CryptoAsset, components []componentInfo, deps []cycloneDXDep) []models.CryptoAsset {
	enriched := make([]models.CryptoAsset, len(assets))
	copy(enriched, assets)

	// SBOM-1: Version vulnerability mapping
	for i := range enriched {
		a := &enriched[i]
		lib := a.Details["library"]
		ver := a.Details["version"]

		sev, vulnID, desc := VersionSeverity(lib, ver)
		if sev != "" {
			a.Details["vuln_severity"] = sev
			a.Details["vuln_id"] = vulnID
			a.Details["vuln_description"] = desc

			// Escalate zone for CRITICAL/HIGH vulnerabilities
			if sev == "CRITICAL" {
				a.Zone = models.ZoneRed
				a.Criticality = models.CriticalityNSS
			} else if sev == "HIGH" && a.Zone != models.ZoneRed {
				a.Zone = models.ZoneRed
			}
		}

		// SBOM-4: PURL ecosystem tagging
		purl := a.Details["purl"]
		if purl != "" {
			eco := EcosystemFromPURL(purl)
			if eco != "" {
				a.Details["ecosystem"] = eco
			}
			parsed := ParsePURL(purl)
			if parsed != nil && parsed.Version != "" && (ver == "" || ver == "unknown") {
				a.Details["version"] = parsed.Version
			}
		}
	}

	// SBOM-2: Transitive dependency detection
	transitiveDeps := FindTransitiveCryptoDeps(components, deps)
	for _, td := range transitiveDeps {
		// Find the matching crypto library to get algorithms
		cryptoNameLower := strings.ToLower(td.CryptoLib)
		for pattern, info := range cryptoLibraries {
			if strings.Contains(cryptoNameLower, strings.ToLower(pattern)) {
				// Create a transitive dependency asset for the FIRST algorithm only
				// (to avoid flooding the report)
				chainStr := strings.Join(td.Chain, " → ")
				enriched = append(enriched, models.CryptoAsset{
					ID:        fmt.Sprintf("sbom:transitive:%s:%s", td.Component, td.CryptoLib),
					Type:      models.AssetSBOMDep,
					Algorithm: info.algorithms[0],
					Zone:      models.ZoneYellow, // Transitive = moderate risk (hidden dependency)
					Location:  fmt.Sprintf("TRANSITIVE: %s (via %s)", td.CryptoLib, td.Component),
					Details: map[string]string{
						"package":          td.Component,
						"transitive_to":    td.CryptoLib,
						"dependency_chain": chainStr,
						"depth":            fmt.Sprintf("%d", len(td.Chain)-1),
						"risk_type":        "transitive_crypto_dependency",
						"description":      info.desc,
						"library":          pattern,
					},
					Criticality: models.CriticalityStandard,
				})
				break
			}
		}
	}

	return enriched
}
