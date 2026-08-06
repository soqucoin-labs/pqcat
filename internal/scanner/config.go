// Package scanner — Config file analysis module (CBOM Gap #3).
//
// Scans cryptographic configuration files for runtime-effective algorithm
// settings. Detects misconfigurations, insecure defaults, and PQC readiness
// in:
//   - java.security — JDK TLS/cipher configuration
//   - openssl.cnf — OpenSSL cipher strings and protocol versions
//   - nginx.conf — TLS cipher suites and protocols
//   - apache ssl.conf — mod_ssl configuration
//   - ssh_config / sshd_config — SSH algorithm preferences
//
// These configurations determine which algorithms are ACTUALLY used at runtime,
// regardless of what the code or library supports. A system may have PQ-capable
// libraries but be configured to use only classical algorithms.
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ScanConfig analyzes cryptographic configuration files.
func ScanConfig(ctx context.Context, target string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		Target:    target,
		ScanType:  "config",
		Timestamp: time.Now().UTC(),
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", target, err)
	}

	if info.IsDir() {
		// Walk directory looking for known config files
		err = filepath.Walk(target, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil || fi.IsDir() {
				return walkErr
			}
			if isConfigFile(fi.Name()) {
				assets, parseErr := parseConfigFile(path)
				if parseErr == nil {
					result.Assets = append(result.Assets, assets...)
				}
			}
			return nil
		})
		if err != nil {
			return result, fmt.Errorf("directory walk error: %w", err)
		}
	} else {
		assets, parseErr := parseConfigFile(target)
		if parseErr != nil {
			return nil, parseErr
		}
		result.Assets = append(result.Assets, assets...)
	}

	return result, nil
}

// isConfigFile checks if a filename is a known cryptographic config file.
func isConfigFile(name string) bool {
	lower := strings.ToLower(name)
	knownConfigs := []string{
		"java.security",
		"openssl.cnf", "openssl.conf",
		"nginx.conf",
		"ssl.conf", "httpd-ssl.conf",
		"sshd_config", "ssh_config",
		"crypto-policies",
		"krb5.conf",
		"nssdb",
		"haproxy.cfg",
		"crypto-config.yaml", "core.yaml", "configtx.yaml",
	}
	for _, known := range knownConfigs {
		if lower == known || strings.Contains(lower, known) {
			return true
		}
	}
	// Check dynamically registered config files from enhanced parsers
	if isAdditionalConfigFile(lower) {
		return true
	}
	return false
}

// parseConfigFile dispatches to the appropriate parser based on filename.
func parseConfigFile(path string) ([]models.CryptoAsset, error) {
	name := strings.ToLower(filepath.Base(path))

	switch {
	case name == "java.security":
		// Parse both standard java.security AND keystore/RNG settings (CONFIG-4)
		assets, err := parseJavaSecurity(path)
		if err != nil {
			return assets, err
		}
		extraAssets, _ := ParseJavaKeystoreAndRNG(path)
		assets = append(assets, extraAssets...)
		return assets, nil
	case name == "openssl.cnf" || name == "openssl.conf":
		return parseOpenSSLConf(path)
	case strings.Contains(name, "nginx"):
		return parseNginxConf(path)
	case name == "ssl.conf" || name == "httpd-ssl.conf":
		return parseApacheSSL(path)
	case name == "sshd_config" || name == "ssh_config":
		return parseSSHConfig(path)
	case name == "haproxy.cfg" || strings.Contains(name, "haproxy"):
		return ParseHAProxyConfig(path)
	case name == "config" && isCryptoPolicyPath(path):
		return ParseCryptoPolicy(path)
	case name == "crypto-config.yaml" || name == "core.yaml" || name == "configtx.yaml":
		return ParseFabricCryptoConfig(path)
	case isEnvoyConfigFile(name):
		return ParseEnvoyConfig(path)
	default:
		return parseGenericConfig(path)
	}
}

// isCryptoPolicyPath checks if a "config" file is in a crypto-policies directory.
func isCryptoPolicyPath(path string) bool {
	return strings.Contains(path, "crypto-policies") || strings.Contains(path, "crypto_policies")
}

// ── java.security Parser ──

var javaDisabledRe = regexp.MustCompile(`(?i)jdk\.tls\.disabledAlgorithms\s*=\s*(.+)`)
var javaLegacyRe = regexp.MustCompile(`(?i)jdk\.tls\.legacyAlgorithms\s*=\s*(.+)`)
var javaProviderRe = regexp.MustCompile(`(?i)security\.provider\.(\d+)\s*=\s*(.+)`)

func parseJavaSecurity(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	sc := bufio.NewScanner(file)
	lineNum := 0

	// Accumulate multi-line values (java.security uses \ continuation)
	var currentKey string
	var currentValue string

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle continuation lines
		if currentKey != "" {
			cleanLine := strings.TrimSuffix(line, "\\")
			currentValue += " " + strings.TrimSpace(cleanLine)
			if !strings.HasSuffix(line, "\\") {
				// Process accumulated value
				assets = append(assets, processJavaProperty(path, lineNum, currentKey, currentValue)...)
				currentKey = ""
				currentValue = ""
			}
			continue
		}

		// Check for known properties
		if m := javaDisabledRe.FindStringSubmatch(line); m != nil {
			currentKey = "jdk.tls.disabledAlgorithms"
			currentValue = strings.TrimSuffix(strings.TrimSpace(m[1]), "\\")
			if !strings.HasSuffix(line, "\\") {
				assets = append(assets, processJavaProperty(path, lineNum, currentKey, currentValue)...)
				currentKey = ""
			}
		} else if m := javaLegacyRe.FindStringSubmatch(line); m != nil {
			currentKey = "jdk.tls.legacyAlgorithms"
			currentValue = strings.TrimSuffix(strings.TrimSpace(m[1]), "\\")
			if !strings.HasSuffix(line, "\\") {
				assets = append(assets, processJavaProperty(path, lineNum, currentKey, currentValue)...)
				currentKey = ""
			}
		} else if m := javaProviderRe.FindStringSubmatch(line); m != nil {
			provider := strings.TrimSpace(m[2])
			assets = append(assets, models.CryptoAsset{
				Algorithm: "SecurityProvider:" + provider,
				Location:  fmt.Sprintf("%s:%d", path, lineNum),
				Type:      models.AssetConfig,
				Zone:      classifyJavaProvider(provider),
			})
		}
	}

	return assets, sc.Err()
}

func processJavaProperty(path string, line int, key, value string) []models.CryptoAsset {
	value = strings.TrimSuffix(strings.TrimSpace(value), "\\")
	parts := strings.Split(value, ",")

	var assets []models.CryptoAsset
	for _, part := range parts {
		algo := strings.TrimSpace(part)
		if algo == "" {
			continue
		}
		// Remove constraints like "keySize < 1024"
		if idx := strings.Index(algo, " "); idx > 0 {
			algo = algo[:idx]
		}

		zone := models.ZoneGreen // Disabled algorithms are good (they're blocked)
		if key == "jdk.tls.legacyAlgorithms" {
			zone = models.ZoneYellow // Legacy means deprecated but still allowed
		}

		assets = append(assets, models.CryptoAsset{
			Algorithm: algo,
			Location:  fmt.Sprintf("%s:%d", path, line),
			Type:      models.AssetConfig,
			Zone:      zone,
		})
	}
	return assets
}

func classifyJavaProvider(provider string) models.Zone {
	lower := strings.ToLower(provider)
	if strings.Contains(lower, "bouncycastle") || strings.Contains(lower, "bcpqjceprovider") {
		return models.ZoneGreen // PQ-capable provider
	}
	if strings.Contains(lower, "sunjce") || strings.Contains(lower, "sunpkcs11") {
		return models.ZoneYellow // Classical but maintained
	}
	return models.ZoneYellow
}

// ── OpenSSL Config Parser ──

var opensslCipherRe = regexp.MustCompile(`(?i)CipherString\s*=\s*(.+)`)
var opensslMinProtRe = regexp.MustCompile(`(?i)MinProtocol\s*=\s*(.+)`)
var opensslMaxProtRe = regexp.MustCompile(`(?i)MaxProtocol\s*=\s*(.+)`)
var opensslGroupsRe = regexp.MustCompile(`(?i)Groups\s*=\s*(.+)`)

func parseOpenSSLConf(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	s := bufio.NewScanner(file)
	lineNum := 0

	for s.Scan() {
		lineNum++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if m := opensslCipherRe.FindStringSubmatch(line); m != nil {
			for _, cipher := range strings.Split(m[1], ":") {
				cipher = strings.TrimSpace(cipher)
				if cipher == "" {
					continue
				}
				assets = append(assets, models.CryptoAsset{
					Algorithm: cipher,
					Location:  fmt.Sprintf("%s:%d", path, lineNum),
					Type:      models.AssetConfig,
					Zone:      classifyOpenSSLCipher(cipher),
				})
			}
		}

		if m := opensslMinProtRe.FindStringSubmatch(line); m != nil {
			proto := strings.TrimSpace(m[1])
			assets = append(assets, models.CryptoAsset{
				Algorithm: "MinProtocol:" + proto,
				Location:  fmt.Sprintf("%s:%d", path, lineNum),
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
			})
		}

		if m := opensslMaxProtRe.FindStringSubmatch(line); m != nil {
			proto := strings.TrimSpace(m[1])
			assets = append(assets, models.CryptoAsset{
				Algorithm: "MaxProtocol:" + proto,
				Location:  fmt.Sprintf("%s:%d", path, lineNum),
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
			})
		}

		if m := opensslGroupsRe.FindStringSubmatch(line); m != nil {
			for _, group := range strings.Split(m[1], ":") {
				group = strings.TrimSpace(group)
				if group == "" {
					continue
				}
				assets = append(assets, models.CryptoAsset{
					Algorithm: "KEX:" + group,
					Location:  fmt.Sprintf("%s:%d", path, lineNum),
					Type:      models.AssetConfig,
					Zone:      classifyKEXGroup(group),
				})
			}
		}
	}

	return assets, s.Err()
}

func classifyOpenSSLCipher(cipher string) models.Zone {
	upper := strings.ToUpper(cipher)
	// PQ-safe ciphers
	if strings.Contains(upper, "KYBER") || strings.Contains(upper, "MLKEM") ||
		strings.Contains(upper, "DILITHIUM") || strings.Contains(upper, "MLDSA") {
		return models.ZoneGreen
	}
	// Explicitly weak
	if strings.Contains(upper, "DES") || strings.Contains(upper, "RC4") ||
		strings.Contains(upper, "MD5") || strings.Contains(upper, "NULL") ||
		strings.Contains(upper, "EXPORT") || strings.Contains(upper, "ANON") {
		return models.ZoneRed
	}
	return models.ZoneYellow // Classical but not deprecated
}

func classifyProtocol(proto string) models.Zone {
	upper := strings.ToUpper(strings.TrimSpace(proto))
	switch {
	case upper == "TLSV1.3", upper == "TLS1.3":
		return models.ZoneYellow // Good but not PQ
	case upper == "TLSV1.2", upper == "TLS1.2":
		return models.ZoneYellow
	case upper == "TLSV1.1", upper == "TLS1.1",
		upper == "TLSV1", upper == "TLS1",
		upper == "TLSV1.0", upper == "TLS1.0",
		upper == "SSLV3", upper == "SSL3":
		return models.ZoneRed // Insecure
	default:
		return models.ZoneYellow
	}
}

func classifyKEXGroup(group string) models.Zone {
	upper := strings.ToUpper(group)
	if strings.Contains(upper, "KYBER") || strings.Contains(upper, "MLKEM") ||
		strings.Contains(upper, "X25519MLKEM768") {
		return models.ZoneGreen
	}
	if strings.Contains(upper, "X25519") || strings.Contains(upper, "X448") ||
		strings.Contains(upper, "P-256") || strings.Contains(upper, "P-384") {
		return models.ZoneYellow
	}
	return models.ZoneRed
}

// ── Nginx Config Parser ──

var nginxProtocolsRe = regexp.MustCompile(`(?i)ssl_protocols\s+(.+?);`)
var nginxCiphersRe = regexp.MustCompile(`(?i)ssl_ciphers\s+['"]?(.+?)['"]?\s*;`)

func parseNginxConf(path string) ([]models.CryptoAsset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	var assets []models.CryptoAsset

	// Protocols
	if m := nginxProtocolsRe.FindStringSubmatch(content); m != nil {
		for _, proto := range strings.Fields(m[1]) {
			assets = append(assets, models.CryptoAsset{
				Algorithm: proto,
				Location:  path,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
			})
		}
	}

	// Ciphers
	if m := nginxCiphersRe.FindStringSubmatch(content); m != nil {
		for _, cipher := range strings.Split(m[1], ":") {
			cipher = strings.TrimSpace(cipher)
			if cipher == "" || cipher == "!" {
				continue
			}
			assets = append(assets, models.CryptoAsset{
				Algorithm: cipher,
				Location:  path,
				Type:      models.AssetConfig,
				Zone:      classifyOpenSSLCipher(cipher),
			})
		}
	}

	return assets, nil
}

// ── Apache SSL Config Parser ──

var apacheProtocolRe = regexp.MustCompile(`(?i)SSLProtocol\s+(.+)`)
var apacheCipherRe = regexp.MustCompile(`(?i)SSLCipherSuite\s+(.+)`)

func parseApacheSSL(path string) ([]models.CryptoAsset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	var assets []models.CryptoAsset

	// Parse ALL SSLProtocol directives (not just the first)
	for _, m := range apacheProtocolRe.FindAllStringSubmatch(content, -1) {
		for _, proto := range strings.Fields(m[1]) {
			// In Apache, "-" means disabled — skip it entirely
			if strings.HasPrefix(proto, "-") {
				continue
			}
			proto = strings.TrimPrefix(proto, "+")

			// Expand "all" per Apache semantics
			if strings.EqualFold(proto, "all") {
				// "all" = all protocols; typically combined with -SSLv3 etc.
				// Don't emit a generic "all" asset — the individual disabled
				// tokens are already skipped above
				continue
			}

			assets = append(assets, models.CryptoAsset{
				Algorithm: proto,
				Location:  path,
				Type:      models.AssetConfig,
				Zone:      classifyProtocol(proto),
			})
		}
	}

	if m := apacheCipherRe.FindStringSubmatch(content); m != nil {
		for _, cipher := range strings.Split(m[1], ":") {
			cipher = strings.TrimSpace(cipher)
			if cipher == "" {
				continue
			}
			assets = append(assets, models.CryptoAsset{
				Algorithm: cipher,
				Location:  path,
				Type:      models.AssetConfig,
				Zone:      classifyOpenSSLCipher(cipher),
			})
		}
	}

	return assets, nil
}

// ── SSH Config Parser ──

var sshCiphersRe = regexp.MustCompile(`(?i)^Ciphers\s+(.+)`)
var sshKexRe = regexp.MustCompile(`(?i)^KexAlgorithms\s+(.+)`)
var sshMacsRe = regexp.MustCompile(`(?i)^MACs\s+(.+)`)
var sshHostKeyRe = regexp.MustCompile(`(?i)^HostKeyAlgorithms\s+(.+)`)

func parseSSHConfig(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	s := bufio.NewScanner(file)
	lineNum := 0

	for s.Scan() {
		lineNum++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parseSSHDirective := func(re *regexp.Regexp, dtype string) {
			if m := re.FindStringSubmatch(line); m != nil {
				for _, algo := range strings.Split(m[1], ",") {
					algo = strings.TrimSpace(algo)
					if algo == "" {
						continue
					}
					assets = append(assets, models.CryptoAsset{
						Algorithm: algo,
						Location:  fmt.Sprintf("%s:%d", path, lineNum),
						Type:      models.AssetConfig,
						Zone:      classifySSHAlgo(algo),
					})
				}
			}
		}

		parseSSHDirective(sshCiphersRe, "config-ssh-cipher")
		parseSSHDirective(sshKexRe, "config-ssh-kex")
		parseSSHDirective(sshMacsRe, "config-ssh-mac")
		parseSSHDirective(sshHostKeyRe, "config-ssh-hostkey")
	}

	return assets, s.Err()
}

func classifySSHAlgo(algo string) models.Zone {
	lower := strings.ToLower(algo)
	// PQ algorithms
	if strings.Contains(lower, "mlkem") || strings.Contains(lower, "sntrup") ||
		strings.Contains(lower, "kyber") || strings.Contains(lower, "ntru") {
		return models.ZoneGreen
	}
	// Weak classical
	if strings.Contains(lower, "des") || strings.Contains(lower, "arcfour") ||
		strings.Contains(lower, "blowfish") || strings.Contains(lower, "cast") ||
		strings.Contains(lower, "md5") || strings.Contains(lower, "sha1") ||
		strings.Contains(lower, "diffie-hellman-group1") ||
		strings.Contains(lower, "diffie-hellman-group14-sha1") {
		return models.ZoneRed
	}
	return models.ZoneYellow
}

// ── Generic Config Parser (fallback) ──

func parseGenericConfig(path string) ([]models.CryptoAsset, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var assets []models.CryptoAsset
	s := bufio.NewScanner(file)
	lineNum := 0

	// Generic patterns for crypto config keywords
	cryptoRe := regexp.MustCompile(`(?i)(cipher|algorithm|protocol|kex|mac|hash|encrypt|tls|ssl|digest)\s*[:=]\s*(.+)`)

	for s.Scan() {
		lineNum++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		if m := cryptoRe.FindStringSubmatch(line); m != nil {
			value := strings.TrimSpace(m[2])
			assets = append(assets, models.CryptoAsset{
				Algorithm: value,
				Location:  fmt.Sprintf("%s:%d", path, lineNum),
				Type:      models.AssetConfig,
				Zone:      models.ZoneYellow,
			})
		}
	}

	return assets, s.Err()
}
