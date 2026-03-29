// config_envoy.go — CONFIG-2: Envoy / Istio proxy TLS configuration parser
//
// Envoy proxy uses YAML-based configuration for TLS contexts:
//   - Listener filter_chains → transport_socket → tls_context
//   - Cluster transport_socket → upstream_tls_context
//   - tls_params: tls_minimum_protocol_version, tls_maximum_protocol_version, cipher_suites
//   - SDS (Secret Discovery Service) certificate references
//
// Istio service mesh layered on Envoy:
//   - DestinationRule → trafficPolicy → tls → mode (DISABLE|SIMPLE|MUTUAL|ISTIO_MUTUAL)
//   - PeerAuthentication → mtls → mode (DISABLE|PERMISSIVE|STRICT|UNSET)
//   - Gateway → servers → tls → mode, cipherSuites, minProtocolVersion
//
// This parser handles both raw Envoy YAML and Istio CRD YAML, extracting all
// cryptographic configuration for PQ readiness assessment.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

func init() {
	// Wire Envoy/Istio config file names into the scanner
	additionalConfigFiles = append(additionalConfigFiles,
		"envoy.yaml", "envoy.yml", "envoy.json",
		"bootstrap.yaml", "bootstrap.yml",
		"front-envoy.yaml",
		// Istio CRDs (often in k8s manifests)
		"destinationrule", "peerauthentication", "gateway",
	)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG-2: Envoy / Istio TLS Configuration Parser
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// Envoy TLS parameters
	envoyMinProtoRe      = regexp.MustCompile(`(?i)tls_minimum_protocol_version\s*:\s*["]?(\w+)["]?`)
	envoyMaxProtoRe      = regexp.MustCompile(`(?i)tls_maximum_protocol_version\s*:\s*["]?(\w+)["]?`)
	envoyCipherRe        = regexp.MustCompile(`(?i)cipher_suites\s*:\s*["\[]?([^"\]]+)["\]]?`)
	envoyECDHRe          = regexp.MustCompile(`(?i)ecdh_curves\s*:\s*["\[]?([^"\]]+)["\]]?`)
	envoyALPNRe          = regexp.MustCompile(`(?i)alpn_protocols\s*:\s*["\[]?([^"\]]+)["\]]?`)
	envoyRequireClientRe = regexp.MustCompile(`(?i)require_client_certificate\s*:\s*(true|false)`)
	envoySDS             = regexp.MustCompile(`(?i)sds_config\s*:`)
	envoySecretName      = regexp.MustCompile(`(?i)name\s*:\s*["]?([^"\s]+)["]?`)

	// Envoy transport socket detection
	envoyTransportSocket = regexp.MustCompile(`(?i)transport_socket\s*:`)
	envoyTLSContext      = regexp.MustCompile(`(?i)(downstream_tls_context|upstream_tls_context|common_tls_context)\s*:`)
	envoyTLSParams       = regexp.MustCompile(`(?i)tls_params\s*:`)

	// Istio-specific
	istioTLSModeRe  = regexp.MustCompile(`(?i)\bmode\s*:\s*(DISABLE|SIMPLE|MUTUAL|ISTIO_MUTUAL|PERMISSIVE|STRICT|UNSET)`)
	istioCipherRe   = regexp.MustCompile(`(?i)cipherSuites\s*:`)
	istioMinProtoRe = regexp.MustCompile(`(?i)minProtocolVersion\s*:\s*["]?(\w+)["]?`)
	istioMaxProtoRe = regexp.MustCompile(`(?i)maxProtocolVersion\s*:\s*["]?(\w+)["]?`)
	istioKindRe     = regexp.MustCompile(`(?i)kind\s*:\s*(DestinationRule|PeerAuthentication|Gateway)`)
)

// ParseEnvoyConfig parses an Envoy or Istio YAML configuration file for TLS settings.
func ParseEnvoyConfig(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	sc := bufio.NewScanner(file)
	lineNum := 0

	// State tracking
	inTLSContext := false
	inTLSParams := false
	inTransportSocket := false
	isIstio := false
	contextType := "envoy" // "envoy" or "istio"
	istioKind := ""

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		loc := fmt.Sprintf("%s:%d", path, lineNum)

		// Detect Istio CRD kind
		if m := istioKindRe.FindStringSubmatch(trimmed); m != nil {
			isIstio = true
			contextType = "istio"
			istioKind = m[1]
		}

		// Track context nesting
		if envoyTransportSocket.MatchString(trimmed) {
			inTransportSocket = true
		}
		if envoyTLSContext.MatchString(trimmed) {
			inTLSContext = true
			if m := envoyTLSContext.FindStringSubmatch(trimmed); m != nil {
				if strings.Contains(m[1], "upstream") {
					contextType = "envoy-upstream"
				} else if strings.Contains(m[1], "downstream") {
					contextType = "envoy-downstream"
				}
			}
		}
		if envoyTLSParams.MatchString(trimmed) {
			inTLSParams = true
		}

		// ── Envoy TLS minimum protocol version ──
		if m := envoyMinProtoRe.FindStringSubmatch(trimmed); m != nil {
			proto := normalizeEnvoyProtocol(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:envoy:min-proto:%d", lineNum),
				Algorithm: "MinProtocol:" + proto,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
				Details: map[string]string{
					"config_type": contextType,
					"directive":   "tls_minimum_protocol_version",
					"protocol":    proto,
					"source":      "Envoy TLS parameters",
				},
			})
		}

		// ── Envoy TLS maximum protocol version ──
		if m := envoyMaxProtoRe.FindStringSubmatch(trimmed); m != nil {
			proto := normalizeEnvoyProtocol(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:envoy:max-proto:%d", lineNum),
				Algorithm: "MaxProtocol:" + proto,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
				Details: map[string]string{
					"config_type": contextType,
					"directive":   "tls_maximum_protocol_version",
					"protocol":    proto,
					"source":      "Envoy TLS parameters",
				},
			})
		}

		// ── Cipher suites (Envoy format: colon-delimited BoringSSL cipher string) ──
		if m := envoyCipherRe.FindStringSubmatch(trimmed); m != nil {
			cipherStr := strings.TrimSpace(m[1])
			// Envoy uses BoringSSL cipher strings (colon-delimited)
			for _, cipher := range splitCipherList(cipherStr) {
				if cipher == "" {
					continue
				}
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:envoy:cipher:%s:%d", cipher, lineNum),
					Algorithm: cipher,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      classifyOpenSSLCipher(cipher),
					Details: map[string]string{
						"config_type": contextType,
						"directive":   "cipher_suites",
						"source":      "Envoy/BoringSSL cipher configuration",
					},
				})
			}
		}

		// ── ECDH curves ──
		if m := envoyECDHRe.FindStringSubmatch(trimmed); m != nil {
			curves := strings.TrimSpace(m[1])
			for _, curve := range splitCipherList(curves) {
				if curve == "" {
					continue
				}
				zone, desc := classifyECDHCurve(curve)
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:envoy:ecdh:%s:%d", curve, lineNum),
					Algorithm: "ECDH:" + curve,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      zone,
					Details: map[string]string{
						"config_type": contextType,
						"directive":   "ecdh_curves",
						"curve":       curve,
						"description": desc,
						"source":      "Envoy ECDH curve configuration",
					},
				})
			}
		}

		// ── ALPN protocols ──
		if m := envoyALPNRe.FindStringSubmatch(trimmed); m != nil {
			alpn := strings.TrimSpace(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:envoy:alpn:%d", lineNum),
				Algorithm: "ALPN:" + alpn,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      models.ZoneYellow, // ALPN is informational
				Details: map[string]string{
					"config_type": contextType,
					"directive":   "alpn_protocols",
					"alpn":        alpn,
					"source":      "Envoy application-layer protocol negotiation",
				},
			})
		}

		// ── mTLS requirement ──
		if m := envoyRequireClientRe.FindStringSubmatch(trimmed); m != nil {
			required := m[1] == "true"
			zone := models.ZoneYellow
			desc := "Client certificate NOT required — one-way TLS only"
			if required {
				zone = models.ZoneGreen
				desc = "Mutual TLS enforced — client certificate required"
			}
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:envoy:mtls:%d", lineNum),
				Algorithm: fmt.Sprintf("mTLS:require_client_cert=%s", m[1]),
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      zone,
				Details: map[string]string{
					"config_type": contextType,
					"directive":   "require_client_certificate",
					"mtls":        m[1],
					"description": desc,
					"source":      "Envoy client certificate requirement",
				},
			})
		}

		// ── Istio TLS mode ──
		if isIstio || strings.Contains(strings.ToLower(trimmed), "mode") {
			if m := istioTLSModeRe.FindStringSubmatch(trimmed); m != nil {
				mode := strings.ToUpper(m[1])
				zone, desc := classifyIstioTLSMode(mode)
				label := contextType
				if istioKind != "" {
					label = "istio:" + istioKind
				}
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("config:istio:tls-mode:%s:%d", mode, lineNum),
					Algorithm: "IstioTLS:" + mode,
					Location:  loc,
					Type:      models.AssetConfig,
					Zone:      zone,
					Details: map[string]string{
						"config_type": label,
						"directive":   "tls.mode",
						"mode":        mode,
						"description": desc,
						"source":      "Istio service mesh TLS policy",
					},
				})
			}
		}

		// ── Istio minProtocolVersion / maxProtocolVersion ──
		if m := istioMinProtoRe.FindStringSubmatch(trimmed); m != nil {
			proto := normalizeIstioProtocol(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:istio:min-proto:%d", lineNum),
				Algorithm: "MinProtocol:" + proto,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
				Details: map[string]string{
					"config_type": "istio",
					"directive":   "minProtocolVersion",
					"protocol":    proto,
					"source":      "Istio TLS protocol version",
				},
			})
		}
		if m := istioMaxProtoRe.FindStringSubmatch(trimmed); m != nil {
			proto := normalizeIstioProtocol(m[1])
			assets = append(assets, models.CryptoAsset{
				ID:        fmt.Sprintf("config:istio:max-proto:%d", lineNum),
				Algorithm: "MaxProtocol:" + proto,
				Location:  loc,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
				Details: map[string]string{
					"config_type": "istio",
					"directive":   "maxProtocolVersion",
					"protocol":    proto,
					"source":      "Istio TLS protocol version",
				},
			})
		}
	}

	// If we found TLS context markers but no explicit settings, flag default config
	if (inTLSContext || inTransportSocket || inTLSParams) && len(assets) == 0 {
		assets = append(assets, models.CryptoAsset{
			ID:        fmt.Sprintf("config:envoy:defaults:%s", path),
			Algorithm: "Envoy-ImplicitDefaults",
			Location:  path,
			Type:      models.AssetConfig,
			Zone:      models.ZoneYellow,
			Details: map[string]string{
				"config_type": contextType,
				"directive":   "implicit",
				"description": "TLS context detected but no explicit cipher/protocol settings — using Envoy/BoringSSL defaults",
				"risk_type":   "implicit_defaults",
				"source":      "Envoy implicit TLS configuration",
			},
		})
	}

	_ = inTLSParams // suppress unused warning in minimal configs

	return assets, sc.Err()
}

// ── Classification Helpers ──

// normalizeEnvoyProtocol converts Envoy protocol enum names to standard names.
// Envoy uses: TLS_AUTO, TLSv1_0, TLSv1_1, TLSv1_2, TLSv1_3
func normalizeEnvoyProtocol(proto string) string {
	upper := strings.ToUpper(strings.TrimSpace(proto))
	switch upper {
	case "TLSV1_0", "TLSV1.0":
		return "TLSv1.0"
	case "TLSV1_1", "TLSV1.1":
		return "TLSv1.1"
	case "TLSV1_2", "TLSV1.2":
		return "TLSv1.2"
	case "TLSV1_3", "TLSV1.3":
		return "TLSv1.3"
	case "TLS_AUTO":
		return "TLS-Auto"
	default:
		return proto
	}
}

// normalizeIstioProtocol converts Istio protocol names.
// Istio uses: TLSV1_0, TLSV1_1, TLSV1_2, TLSV1_3
func normalizeIstioProtocol(proto string) string {
	return normalizeEnvoyProtocol(proto) // Same enum values
}

// classifyIstioTLSMode assesses the security of an Istio TLS mode.
func classifyIstioTLSMode(mode string) (models.Zone, string) {
	switch mode {
	case "DISABLE":
		return models.ZoneRed, "CRITICAL: TLS disabled — all traffic is plaintext"
	case "SIMPLE":
		return models.ZoneYellow, "One-way TLS — server authenticated, client NOT authenticated"
	case "MUTUAL":
		return models.ZoneGreen, "Mutual TLS — both client and server authenticated (explicit certs)"
	case "ISTIO_MUTUAL":
		return models.ZoneGreen, "Istio-managed mTLS — auto-provisioned certificates via Citadel/istiod"
	case "PERMISSIVE":
		return models.ZoneRed, "PERMISSIVE: Accepts both plaintext AND mTLS — downgrade attack possible"
	case "STRICT":
		return models.ZoneGreen, "STRICT: Only mTLS connections accepted — no plaintext allowed"
	case "UNSET":
		return models.ZoneYellow, "TLS mode not set — inherits from parent namespace/mesh policy"
	default:
		return models.ZoneYellow, "Unknown Istio TLS mode"
	}
}

// classifyECDHCurve assesses an ECDH curve for PQ readiness.
func classifyECDHCurve(curve string) (models.Zone, string) {
	upper := strings.ToUpper(strings.TrimSpace(curve))
	switch {
	case upper == "X25519" || upper == "CURVE25519":
		return models.ZoneYellow, "X25519 — fast, secure, but classical (vulnerable to quantum)"
	case upper == "P-256" || upper == "PRIME256V1" || upper == "SECP256R1":
		return models.ZoneYellow, "P-256 — NIST standard curve, classical (vulnerable to quantum)"
	case upper == "P-384" || upper == "SECP384R1":
		return models.ZoneYellow, "P-384 — NIST curve, classical but higher security margin"
	case upper == "P-521" || upper == "SECP521R1":
		return models.ZoneYellow, "P-521 — NIST curve, classical but highest security margin"
	case strings.Contains(upper, "X25519KYBER") || strings.Contains(upper, "X25519MLKEM"):
		return models.ZoneGreen, "X25519+ML-KEM hybrid — post-quantum key exchange!"
	case strings.Contains(upper, "KYBER") || strings.Contains(upper, "MLKEM"):
		return models.ZoneGreen, "ML-KEM (Kyber) — post-quantum key encapsulation"
	default:
		return models.ZoneYellow, "Unknown ECDH curve — manual review required"
	}
}

// splitCipherList splits a cipher string by common delimiters.
// Handles colon-separated (OpenSSL/BoringSSL), comma-separated (Istio), and YAML list items.
func splitCipherList(s string) []string {
	s = strings.TrimSpace(s)
	// Remove YAML list markers
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	// Remove quotes
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "'", "")

	// Split by colon first (BoringSSL style), then by comma
	var result []string
	if strings.Contains(s, ":") {
		result = strings.Split(s, ":")
	} else if strings.Contains(s, ",") {
		result = strings.Split(s, ",")
	} else if strings.Contains(s, " ") {
		result = strings.Fields(s)
	} else {
		result = []string{s}
	}

	// Clean up
	var cleaned []string
	for _, c := range result {
		c = strings.TrimSpace(c)
		c = strings.TrimPrefix(c, "- ") // YAML list items
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}
	return cleaned
}

// isEnvoyConfigFile checks if a filename matches Envoy or Istio configuration patterns.
func isEnvoyConfigFile(name string) bool {
	lower := strings.ToLower(name)
	envoyPatterns := []string{
		"envoy.yaml", "envoy.yml", "envoy.json",
		"bootstrap.yaml", "bootstrap.yml",
		"front-envoy.yaml", "front-envoy.yml",
	}
	for _, p := range envoyPatterns {
		if lower == p || strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
