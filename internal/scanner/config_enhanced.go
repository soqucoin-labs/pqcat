// config_enhanced.go — Config Scanner Sprint: resolves CONFIG-1, CONFIG-3, CONFIG-4, CONFIG-5
//
// CONFIG-1: HAProxy TLS configuration parsing
// CONFIG-3: RHEL/Fedora crypto-policies level detection
// CONFIG-4: Java keystore.type and securerandom.source detection
// CONFIG-5: Hyperledger Fabric crypto-config.yaml parsing
//
// Architecture: Adds new parsers and wires them into the existing dispatch.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// Config file registration is now handled by the package-level
// additionalConfigFilesExact and additionalConfigFilesContains slices.

// additionalConfigFilesExact are matched by exact basename only.
// Short/generic names that would false-positive on substring matching.
var additionalConfigFilesExact = []string{
	"config", "state", "msp",
}

// additionalConfigFilesContains are distinctive enough for substring matching.
var additionalConfigFilesContains = []string{
	"haproxy.cfg",
	"crypto-policies",
	"crypto-config.yaml",
}

// isAdditionalConfigFile checks against the extended config file list.
// Short/generic names use exact basename match; distinctive names use substring.
func isAdditionalConfigFile(name string) bool {
	lower := strings.ToLower(filepath.Base(name))
	for _, f := range additionalConfigFilesExact {
		if lower == f {
			return true
		}
	}
	for _, f := range additionalConfigFilesContains {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG-1: HAProxy TLS Configuration Parser
// ═══════════════════════════════════════════════════════════════════════════════

// HAProxy TLS directives:
//   global section:    ssl-default-bind-ciphers, ssl-default-bind-ciphersuites,
//                      ssl-default-bind-options, ssl-default-server-ciphers,
//                      ssl-default-server-ciphersuites, ssl-default-server-options
//   bind/server line:  ssl, ciphers, ciphersuites, ssl-min-ver, ssl-max-ver
//   fronted/backend:   similar to bind/server

var (
	// Global defaults
	haproxyBindCiphersRe   = regexp.MustCompile(`(?i)ssl-default-bind-ciphers\s+(.+)`)
	haproxyBindSuitesRe    = regexp.MustCompile(`(?i)ssl-default-bind-ciphersuites\s+(.+)`)
	haproxyBindOptionsRe   = regexp.MustCompile(`(?i)ssl-default-bind-options\s+(.+)`)
	haproxyServerCiphersRe = regexp.MustCompile(`(?i)ssl-default-server-ciphers\s+(.+)`)
	haproxyServerSuitesRe  = regexp.MustCompile(`(?i)ssl-default-server-ciphersuites\s+(.+)`)
	haproxyServerOptionsRe = regexp.MustCompile(`(?i)ssl-default-server-options\s+(.+)`)

	// Per-line bind/server directives
	haproxySSLMinVerRe = regexp.MustCompile(`(?i)ssl-min-ver\s+(TLSv[\d.]+|SSLv[\d.]+)`)
	haproxySSLMaxVerRe = regexp.MustCompile(`(?i)ssl-max-ver\s+(TLSv[\d.]+|SSLv[\d.]+)`)
	haproxyCiphersRe   = regexp.MustCompile(`(?i)\bciphers\s+([^\s]+)`)
	haproxySuitesRe    = regexp.MustCompile(`(?i)\bciphersuites\s+([^\s]+)`)
)

// ParseHAProxyConfig parses an HAProxy configuration file for TLS settings.
func ParseHAProxyConfig(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	sc := bufio.NewScanner(file)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		loc := fmt.Sprintf("%s:%d", path, lineNum)

		// Parse cipher lists (TLS 1.2 and below)
		for _, re := range []*regexp.Regexp{haproxyBindCiphersRe, haproxyServerCiphersRe, haproxyCiphersRe} {
			if m := re.FindStringSubmatch(line); m != nil {
				for _, cipher := range strings.Split(m[1], ":") {
					cipher = strings.TrimSpace(cipher)
					if cipher == "" {
						continue
					}
					assets = append(assets, models.CryptoAsset{
						ID:        fmt.Sprintf("config:haproxy:%s:%d", cipher, lineNum),
						Algorithm: cipher,
						Location:  loc,
						Type:      models.AssetConfig,
						Zone:      classifyOpenSSLCipher(cipher),
						Details: map[string]string{
							"config_type": "haproxy",
							"directive":   "cipher",
							"source":      "HAProxy TLS configuration",
						},
					})
				}
			}
		}

		// Parse TLS 1.3 ciphersuites
		for _, re := range []*regexp.Regexp{haproxyBindSuitesRe, haproxyServerSuitesRe, haproxySuitesRe} {
			if m := re.FindStringSubmatch(line); m != nil {
				for _, suite := range strings.Split(m[1], ":") {
					suite = strings.TrimSpace(suite)
					if suite == "" {
						continue
					}
					assets = append(assets, models.CryptoAsset{
						ID:        fmt.Sprintf("config:haproxy:tls13:%s:%d", suite, lineNum),
						Algorithm: "TLS1.3:" + suite,
						Location:  loc,
						Type:      models.AssetConfig,
						Zone:      classifyTLS13Suite(suite),
						Details: map[string]string{
							"config_type": "haproxy",
							"directive":   "ciphersuite",
							"tls_version": "1.3",
							"source":      "HAProxy TLS 1.3 configuration",
						},
					})
				}
			}
		}

		// Parse ssl-default-bind-options / ssl-default-server-options
		for _, re := range []*regexp.Regexp{haproxyBindOptionsRe, haproxyServerOptionsRe} {
			if m := re.FindStringSubmatch(line); m != nil {
				options := strings.Fields(m[1])
				for _, opt := range options {
					opt = strings.TrimSpace(opt)
					zone, detail := classifyHAProxyOption(opt)
					if detail != "" {
						assets = append(assets, models.CryptoAsset{
							ID:        fmt.Sprintf("config:haproxy:option:%s:%d", opt, lineNum),
							Algorithm: "HAProxy-Option:" + opt,
							Location:  loc,
							Type:      models.AssetConfig,
							Zone:      zone,
							Details: map[string]string{
								"config_type": "haproxy",
								"directive":   "ssl-option",
								"detail":      detail,
								"source":      "HAProxy SSL options",
							},
						})
					}
				}
			}
		}

		// Parse ssl-min-ver / ssl-max-ver
		if m := haproxySSLMinVerRe.FindStringSubmatch(line); m != nil {
			proto := strings.TrimSpace(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:haproxy:minver:%s:%d", proto, lineNum),
				Algorithm: "MinProtocol:" + proto,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
				Details: map[string]string{
					"config_type": "haproxy",
					"directive":   "ssl-min-ver",
					"source":      "HAProxy minimum TLS version",
				},
			})
		}

		if m := haproxySSLMaxVerRe.FindStringSubmatch(line); m != nil {
			proto := strings.TrimSpace(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:haproxy:maxver:%s:%d", proto, lineNum),
				Algorithm: "MaxProtocol:" + proto,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
				Details: map[string]string{
					"config_type": "haproxy",
					"directive":   "ssl-max-ver",
					"source":      "HAProxy maximum TLS version",
				},
			})
		}
	}

	return assets, sc.Err()
}

// classifyTLS13Suite classifies TLS 1.3 ciphersuites.
func classifyTLS13Suite(suite string) models.Zone {
	upper := strings.ToUpper(suite)
	// All standard TLS 1.3 suites are strong (AES-GCM, ChaCha20)
	// But they're still classical (not PQ)
	if strings.Contains(upper, "AES_256_GCM") || strings.Contains(upper, "CHACHA20") {
		return models.ZoneYellow // Strong but not PQ
	}
	if strings.Contains(upper, "AES_128_GCM") {
		return models.ZoneYellow // Acceptable but 128-bit
	}
	return models.ZoneYellow
}

// classifyHAProxyOption classifies HAProxy SSL options.
func classifyHAProxyOption(opt string) (models.Zone, string) {
	lower := strings.ToLower(opt)
	switch {
	case lower == "no-sslv3":
		return models.ZoneGreen, "SSLv3 disabled (good)"
	case lower == "no-tlsv10":
		return models.ZoneGreen, "TLS 1.0 disabled (good)"
	case lower == "no-tlsv11":
		return models.ZoneGreen, "TLS 1.1 disabled (good)"
	case lower == "no-tlsv12":
		return models.ZoneRed, "TLS 1.2 disabled — may break compatibility"
	case lower == "no-tls-tickets":
		return models.ZoneGreen, "TLS session tickets disabled (forward secrecy)"
	case lower == "force-sslv3":
		return models.ZoneRed, "CRITICAL: Forces SSLv3 — severely insecure"
	case lower == "force-tlsv10":
		return models.ZoneRed, "Forces TLS 1.0 — insecure"
	case lower == "force-tlsv11":
		return models.ZoneRed, "Forces TLS 1.1 — insecure"
	case lower == "force-tlsv12":
		return models.ZoneYellow, "Forces TLS 1.2 — prevents TLS 1.3 upgrade"
	case lower == "prefer-client-ciphers":
		return models.ZoneGreen, "Server defers to client cipher preference"
	default:
		return models.ZoneYellow, ""
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG-3: RHEL/Fedora Crypto-Policies Parser
// ═══════════════════════════════════════════════════════════════════════════════
//
// RHEL 8+ uses /etc/crypto-policies/ for system-wide crypto settings.
// The key files:
//   /etc/crypto-policies/config         — active policy name
//   /etc/crypto-policies/state/current  — symlink to policy definitions
//   /etc/crypto-policies/back-ends/     — per-application configs
//
// Policy levels: LEGACY < DEFAULT < FUTURE < FIPS
// FIPS = FIPS 140-2/140-3 compliant subset
// FUTURE = Only algorithms expected to survive PQ era (but not PQ itself)
// DEFAULT = Reasonable balance of security and compatibility
// LEGACY = Maximum compatibility, allows weak crypto

// CryptoPolicyLevel represents a RHEL crypto-policy setting.
type CryptoPolicyLevel struct {
	Name        string
	Zone        models.Zone
	Description string
	Allows      []string // algorithms this policy allows
	Blocks      []string // algorithms this policy blocks
}

// knownCryptoPolicies maps RHEL crypto-policy names to their security assessment.
var knownCryptoPolicies = map[string]CryptoPolicyLevel{
	"LEGACY": {
		Name:        "LEGACY",
		Zone:        models.ZoneRed,
		Description: "Maximum compatibility — allows TLS 1.0, SHA-1, RSA-1024, RC4, 3DES. NOT acceptable for federal systems.",
		Allows:      []string{"TLS1.0", "TLS1.1", "SHA-1", "RSA-1024", "RC4", "3DES-CBC", "DH-1024"},
		Blocks:      []string{},
	},
	"DEFAULT": {
		Name:        "DEFAULT",
		Zone:        models.ZoneYellow,
		Description: "Reasonable security — TLS 1.2+, RSA-2048+, SHA-256+. Classical but adequate for most uses.",
		Allows:      []string{"TLS1.2", "TLS1.3", "RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"},
		Blocks:      []string{"TLS1.0", "TLS1.1", "RC4", "3DES", "RSA-1024", "DH-1024"},
	},
	"FUTURE": {
		Name:        "FUTURE",
		Zone:        models.ZoneYellow,
		Description: "Forward-looking — TLS 1.3 only, RSA-3072+, SHA-384+. Best classical policy, but still NOT post-quantum.",
		Allows:      []string{"TLS1.3", "RSA-3072", "RSA-4096", "ECDSA-P384", "AES-256-GCM", "SHA-384"},
		Blocks:      []string{"TLS1.0", "TLS1.1", "TLS1.2", "RSA-2048", "SHA-256", "ECDSA-P256"},
	},
	"FIPS": {
		Name:        "FIPS",
		Zone:        models.ZoneYellow,
		Description: "FIPS 140-2/3 compliant — TLS 1.2+, only FIPS-approved algorithms. Required for federal systems but NOT post-quantum.",
		Allows:      []string{"TLS1.2", "TLS1.3", "RSA-2048", "RSA-3072", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "SHA-256", "SHA-384"},
		Blocks:      []string{"TLS1.0", "TLS1.1", "RC4", "3DES", "ChaCha20-Poly1305", "Ed25519"},
	},
	"DEFAULT:NO-SHA1": {
		Name:        "DEFAULT:NO-SHA1",
		Zone:        models.ZoneYellow,
		Description: "DEFAULT with SHA-1 disabled — extra hardening.",
		Allows:      []string{"TLS1.2", "TLS1.3", "RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"},
		Blocks:      []string{"TLS1.0", "TLS1.1", "RC4", "3DES", "SHA-1"},
	},
	"FIPS:NO-SHA1": {
		Name:        "FIPS:NO-SHA1",
		Zone:        models.ZoneYellow,
		Description: "FIPS with SHA-1 disabled — stronger FIPS variant.",
		Allows:      []string{"TLS1.2", "TLS1.3", "RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"},
		Blocks:      []string{"TLS1.0", "TLS1.1", "RC4", "3DES", "SHA-1"},
	},
}

// ParseCryptoPolicy parses a RHEL crypto-policies configuration file.
// The file typically contains just the policy name (e.g., "DEFAULT\n").
func ParseCryptoPolicy(path string) ([]models.CryptoAsset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, nil
	}

	var assets []models.CryptoAsset

	// Check if this looks like a policy name
	policyName := strings.ToUpper(content)

	// Handle subpolicies (e.g., "DEFAULT:NO-SHA1")
	policy, known := knownCryptoPolicies[policyName]
	if !known {
		// Try base policy without modifier
		baseName := policyName
		if idx := strings.Index(policyName, ":"); idx > 0 {
			baseName = policyName[:idx]
		}
		policy, known = knownCryptoPolicies[baseName]
		if !known {
			// Unknown policy — report as-is
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:crypto-policy:%s", policyName),
				Algorithm: "CryptoPolicy:" + policyName,
				Location:  path,
				Type:      models.AssetConfig,
				Zone:      models.ZoneYellow,
				Details: map[string]string{
					"config_type": "rhel-crypto-policy",
					"policy":      policyName,
					"description": "Unknown crypto-policy level — manual review required",
					"risk_type":   "unknown_policy",
				},
			})
			return assets, nil
		}
	}

	// Add the policy assessment
	assets = append(assets, models.CryptoAsset{
		ID:        fmt.Sprintf("config:crypto-policy:%s", policyName),
		Algorithm: "CryptoPolicy:" + policyName,
		Location:  path,
		Type:      models.AssetConfig,
		Zone:      policy.Zone,
		Details: map[string]string{
			"config_type": "rhel-crypto-policy",
			"policy":      policyName,
			"description": policy.Description,
			"pq_ready":    "false",
			"risk_type":   "system_wide_crypto_policy",
		},
	})

	// Add individual algorithm assessments for allowed algorithms
	for _, algo := range policy.Allows {
		zone := models.ZoneYellow
		// Mark weak algorithms in LEGACY policy
		if isWeakAlgorithm(algo) {
			zone = models.ZoneRed
		}
		assets = append(assets, models.CryptoAsset{
			ID:        fmt.Sprintf("config:crypto-policy:%s:allows:%s", policyName, algo),
			Algorithm: algo,
			Location:  path,
			Type:      models.AssetConfig,
			Zone:      zone,
			Details: map[string]string{
				"config_type": "rhel-crypto-policy",
				"policy":      policyName,
				"status":      "ALLOWED",
				"source":      "RHEL system-wide crypto-policy",
			},
		})
	}

	// Add blocked algorithms (these are good — they're blocked)
	for _, algo := range policy.Blocks {
		assets = append(assets, models.CryptoAsset{
			ID:        fmt.Sprintf("config:crypto-policy:%s:blocks:%s", policyName, algo),
			Algorithm: algo,
			Location:  path,
			Type:      models.AssetConfig,
			Zone:      models.ZoneGreen,
			Details: map[string]string{
				"config_type": "rhel-crypto-policy",
				"policy":      policyName,
				"status":      "BLOCKED",
				"source":      "RHEL system-wide crypto-policy (blocked = good)",
			},
		})
	}

	return assets, nil
}

// isWeakAlgorithm returns true for algorithms that are known to be weak.
func isWeakAlgorithm(algo string) bool {
	weak := []string{"TLS1.0", "TLS1.1", "SHA-1", "RSA-1024", "RC4", "3DES", "DH-1024", "MD5"}
	upper := strings.ToUpper(algo)
	for _, w := range weak {
		if upper == w || strings.Contains(upper, w) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG-4: Java Keystore Type & SecureRandom Source Detection
// ═══════════════════════════════════════════════════════════════════════════════

var (
	javaKeystoreTypeRe       = regexp.MustCompile(`(?i)keystore\.type\s*=\s*(.+)`)
	javaSecureRandomRe       = regexp.MustCompile(`(?i)securerandom\.source\s*=\s*(.+)`)
	javaSecureRandomStrongRe = regexp.MustCompile(`(?i)securerandom\.strongAlgorithms\s*=\s*(.+)`)
)

// ParseJavaKeystoreAndRNG extracts keystore type and RNG configuration from java.security.
// Called as post-processing on java.security files after the base parser runs.
func ParseJavaKeystoreAndRNG(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	sc := bufio.NewScanner(file)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		loc := fmt.Sprintf("%s:%d", path, lineNum)

		// Keystore type
		if m := javaKeystoreTypeRe.FindStringSubmatch(line); m != nil {
			ksType := strings.TrimSpace(m[1])
			zone, desc := classifyKeystoreType(ksType)
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:java:keystore-type:%d", lineNum),
				Algorithm: "KeystoreType:" + ksType,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      zone,
				Details: map[string]string{
					"config_type":   "java-security",
					"directive":     "keystore.type",
					"keystore_type": ksType,
					"description":   desc,
				},
			})
		}

		// SecureRandom source
		if m := javaSecureRandomRe.FindStringSubmatch(line); m != nil {
			source := strings.TrimSpace(m[1])
			zone, desc := classifySecureRandomSource(source)
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:java:securerandom:%d", lineNum),
				Algorithm: "SecureRandom:" + source,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      zone,
				Details: map[string]string{
					"config_type": "java-security",
					"directive":   "securerandom.source",
					"rng_source":  source,
					"description": desc,
				},
			})
		}

		// SecureRandom strong algorithms
		if m := javaSecureRandomStrongRe.FindStringSubmatch(line); m != nil {
			algos := strings.TrimSpace(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:java:securerandom-strong:%d", lineNum),
				Algorithm: "SecureRandomStrong:" + algos,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      models.ZoneYellow,
				Details: map[string]string{
					"config_type": "java-security",
					"directive":   "securerandom.strongAlgorithms",
					"description": "Strong RNG algorithm configuration",
				},
			})
		}
	}

	return assets, sc.Err()
}

// classifyKeystoreType assesses the security of a Java keystore type.
func classifyKeystoreType(ksType string) (models.Zone, string) {
	upper := strings.ToUpper(strings.TrimSpace(ksType))
	switch upper {
	case "PKCS12":
		return models.ZoneYellow, "PKCS#12 — industry standard, supports strong encryption"
	case "JKS":
		return models.ZoneRed, "JKS — Java KeyStore uses weak PBE (MD5+3DES), migrate to PKCS12"
	case "JCEKS":
		return models.ZoneRed, "JCEKS — uses 3DES-based PBE, migrate to PKCS12"
	case "BKS":
		return models.ZoneYellow, "BKS — Bouncy Castle KeyStore, acceptable"
	case "UBER":
		return models.ZoneYellow, "UBER — Bouncy Castle UBER store, acceptable"
	case "BCFKS":
		return models.ZoneGreen, "BCFKS — Bouncy Castle FIPS KeyStore, FIPS 140-2 approved"
	default:
		return models.ZoneYellow, "Unknown keystore type — manual review required"
	}
}

// classifySecureRandomSource assesses the quality of a SecureRandom source.
func classifySecureRandomSource(source string) (models.Zone, string) {
	lower := strings.ToLower(source)
	switch {
	case strings.Contains(lower, "/dev/urandom"):
		return models.ZoneYellow, "/dev/urandom — non-blocking kernel CSPRNG, acceptable for most uses"
	case strings.Contains(lower, "/dev/random"):
		return models.ZoneYellow, "/dev/random — blocking kernel CSPRNG, high quality but may stall"
	case strings.Contains(lower, "nativeprng"):
		return models.ZoneYellow, "NativePRNG — OS-backed CSPRNG, acceptable"
	case strings.Contains(lower, "sha1prng"):
		return models.ZoneRed, "SHA1PRNG — uses SHA-1, potentially predictable seed, NOT recommended"
	case strings.Contains(lower, "drbg"):
		return models.ZoneYellow, "DRBG — NIST SP 800-90A compliant, good"
	default:
		return models.ZoneYellow, "Custom SecureRandom source — verify entropy quality"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG-5: Hyperledger Fabric crypto-config.yaml Parser
// ═══════════════════════════════════════════════════════════════════════════════

// Hyperledger Fabric uses YAML configuration for cryptographic material:
//   crypto-config.yaml — defines org structure, key algorithms, certificate params
//   configtx.yaml — channel crypto policies
//   core.yaml — peer BCCSP (Blockchain Crypto Service Provider) config

var (
	fabricKeyAlgoRe  = regexp.MustCompile(`(?i)(?:key|algorithm)\s*:\s*["']?(\w+)["']?`)
	fabricBCCSPRe    = regexp.MustCompile(`(?i)BCCSP\s*:`)
	fabricHashRe     = regexp.MustCompile(`(?i)hash\s*:\s*["']?(\w+)["']?`)
	fabricSecLevelRe = regexp.MustCompile(`(?i)security\s*:\s*(\d+)`)
	fabricDefaultRe  = regexp.MustCompile(`(?i)default\s*:\s*["']?(\w+)["']?`)
)

// ParseFabricCryptoConfig parses Hyperledger Fabric crypto configuration.
func ParseFabricCryptoConfig(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	sc := bufio.NewScanner(file)
	lineNum := 0
	inBCCSP := false

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		loc := fmt.Sprintf("%s:%d", path, lineNum)

		// Track BCCSP section
		if fabricBCCSPRe.MatchString(trimmed) {
			inBCCSP = true
		}

		// Key algorithm in BCCSP
		if inBCCSP {
			if m := fabricDefaultRe.FindStringSubmatch(trimmed); m != nil {
				provider := strings.TrimSpace(m[1])
				zone, desc := classifyBCCSPProvider(provider)
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:fabric:bccsp:%s:%d", provider, lineNum),
					Algorithm: "BCCSP:" + provider,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      zone,
					Details: map[string]string{
						"config_type": "hyperledger-fabric",
						"directive":   "BCCSP.Default",
						"provider":    provider,
						"description": desc,
					},
				})
			}

			if m := fabricHashRe.FindStringSubmatch(trimmed); m != nil {
				hash := strings.TrimSpace(m[1])
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:fabric:hash:%s:%d", hash, lineNum),
					Algorithm: hash,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      classifyFabricHash(hash),
					Details: map[string]string{
						"config_type": "hyperledger-fabric",
						"directive":   "BCCSP.Hash",
						"source":      "Hyperledger Fabric hash configuration",
					},
				})
			}

			if m := fabricSecLevelRe.FindStringSubmatch(trimmed); m != nil {
				level := strings.TrimSpace(m[1])
				zone := models.ZoneYellow
				desc := "Security level " + level
				if level == "256" {
					zone = models.ZoneYellow
					desc = "ECDSA P-256 (classical, not PQ)"
				} else if level == "384" {
					zone = models.ZoneYellow
					desc = "ECDSA P-384 (classical, stronger curve)"
				}
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:fabric:security:%s:%d", level, lineNum),
					Algorithm: "SecurityLevel:" + level,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      zone,
					Details: map[string]string{
						"config_type":    "hyperledger-fabric",
						"directive":      "BCCSP.Security",
						"security_level": level,
						"description":    desc,
					},
				})
			}
		}

		// Generic key algorithm detection
		if m := fabricKeyAlgoRe.FindStringSubmatch(trimmed); m != nil {
			algo := strings.TrimSpace(m[1])
			// Filter out non-algorithm YAML values
			if isFabricAlgorithm(algo) {
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:fabric:algo:%s:%d", algo, lineNum),
					Algorithm: algo,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      classifyFabricAlgorithm(algo),
					Details: map[string]string{
						"config_type": "hyperledger-fabric",
						"source":      "Hyperledger Fabric crypto configuration",
					},
				})
			}
		}
	}

	return assets, sc.Err()
}

// classifyBCCSPProvider assesses the crypto provider type.
func classifyBCCSPProvider(provider string) (models.Zone, string) {
	upper := strings.ToUpper(provider)
	switch upper {
	case "SW":
		return models.ZoneYellow, "Software-based crypto — ECDSA P-256, not PQ-safe"
	case "PKCS11":
		return models.ZoneYellow, "PKCS#11 HSM-backed crypto — hardware security, not PQ-safe"
	case "GM":
		return models.ZoneRed, "GM (Chinese national standard) — limited algorithm set"
	default:
		return models.ZoneYellow, "Unknown BCCSP provider"
	}
}

// classifyFabricHash classifies a hash algorithm in Fabric context.
func classifyFabricHash(hash string) models.Zone {
	upper := strings.ToUpper(hash)
	switch {
	case strings.Contains(upper, "SHA2"), strings.Contains(upper, "SHA256"),
		strings.Contains(upper, "SHA-256"):
		return models.ZoneYellow
	case strings.Contains(upper, "SHA3"):
		return models.ZoneYellow // SHA-3 is PQ-safe for hashing
	case strings.Contains(upper, "SHA384"), strings.Contains(upper, "SHA-384"):
		return models.ZoneYellow
	case strings.Contains(upper, "MD5"), strings.Contains(upper, "SHA1"):
		return models.ZoneRed
	default:
		return models.ZoneYellow
	}
}

// isFabricAlgorithm filters out non-algorithm YAML values.
func isFabricAlgorithm(s string) bool {
	algos := []string{"ecdsa", "rsa", "ed25519", "aes", "sha", "dilithium", "kyber", "mlkem", "mldsa", "ecdsawithsha256"}
	lower := strings.ToLower(s)
	for _, a := range algos {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
}

// classifyFabricAlgorithm classifies a Fabric algorithm for PQ readiness.
func classifyFabricAlgorithm(algo string) models.Zone {
	upper := strings.ToUpper(algo)
	if strings.Contains(upper, "DILITHIUM") || strings.Contains(upper, "KYBER") ||
		strings.Contains(upper, "MLKEM") || strings.Contains(upper, "MLDSA") {
		return models.ZoneGreen
	}
	return models.ZoneYellow // Classical ECDSA/RSA
}
