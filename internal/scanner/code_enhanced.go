// Package scanner provides enhanced code analysis for cryptographic API calls.
//
// This file resolves 4 blindspots identified in the first-principles audit:
//   - CODE-1: Key size extraction from API arguments
//   - CODE-3: Cipher mode detection (ECB vs GCM vs CBC)
//   - CODE-4: Scala/Groovy/R language coverage
//   - CODE-5: .env / .properties / .cfg secret scanning
//
// Architecture: Post-processing enrichment layer that runs AFTER the base
// pattern matcher (`scanFileForCrypto`) to extract deeper semantics from
// matched lines without duplicating the core scanning loop.
package scanner

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CODE-1: Key Size Extraction
//
// PROBLEM: When we detect `rsa.GenerateKey(rand.Reader, 2048)`, we always
// classify it as "RSA-2048" regardless of the actual argument. A 4096-bit RSA
// key has ~140-bit security vs 112-bit for 2048-bit — this matters for CNSA 2.0
// transition timelines.
//
// APPROACH: Regex-extract numeric key size arguments from the matched source
// line and refine the algorithm label. This is a second-pass enrichment that
// runs on lines already matched by the base scanner.
// ═══════════════════════════════════════════════════════════════════════════════

// keySizePattern pairs a regex that captures a key size with information about
// which algorithm family the extraction applies to.
type keySizePattern struct {
	name       string
	regex      *regexp.Regexp
	algoFamily string // e.g., "RSA", "ECDSA", "AES", "DH"
}

var keySizePatterns = []keySizePattern{
	// ── Go ──
	{name: "Go rsa.GenerateKey", regex: regexp.MustCompile(`rsa\.GenerateKey\s*\(\s*[\w.]+\s*,\s*(\d+)\s*\)`), algoFamily: "RSA"},
	{name: "Go ecdsa.GenerateKey P-curve", regex: regexp.MustCompile(`ecdsa\.GenerateKey\s*\(\s*elliptic\.(P256|P384|P521)\s*\(`), algoFamily: "ECDSA"},

	// ── Python ──
	{name: "Python RSA.generate", regex: regexp.MustCompile(`RSA\.generate\s*\(\s*(\d+)`), algoFamily: "RSA"},
	{name: "Python rsa.generate_private_key", regex: regexp.MustCompile(`generate_private_key\s*\(\s*public_exponent\s*=\s*\d+\s*,\s*key_size\s*=\s*(\d+)`), algoFamily: "RSA"},
	{name: "Python rsa.generate_private_key positional", regex: regexp.MustCompile(`generate_private_key\s*\(\s*\d+\s*,\s*(\d+)`), algoFamily: "RSA"},
	{name: "Python ec.SECP curve", regex: regexp.MustCompile(`ec\.(SECP256R1|SECP384R1|SECP521R1)\s*\(`), algoFamily: "ECDSA"},

	// ── Java / Kotlin ──
	{name: "Java KeyPairGenerator initialize", regex: regexp.MustCompile(`\.initialize\s*\(\s*(\d+)`), algoFamily: "RSA"},
	{name: "Java KeyGenerator init", regex: regexp.MustCompile(`\.init\s*\(\s*(\d+)\s*[,)]`), algoFamily: "AES"},

	// ── C / C++ (OpenSSL) ──
	{name: "C RSA_generate_key bits", regex: regexp.MustCompile(`RSA_generate_key(_ex)?\s*\(\s*(\d+)`), algoFamily: "RSA"},
	{name: "C EVP_PKEY keygen bits", regex: regexp.MustCompile(`EVP_PKEY_CTX_set_rsa_keygen_bits\s*\(\s*\w+\s*,\s*(\d+)`), algoFamily: "RSA"},
	{name: "C DH_generate_parameters bits", regex: regexp.MustCompile(`DH_generate_parameters(_ex)?\s*\(\s*(\d+)`), algoFamily: "DH"},

	// ── C# ──
	{name: "C# RSA.Create keySizeInBits", regex: regexp.MustCompile(`RSA\.Create\s*\(\s*(\d+)\s*\)`), algoFamily: "RSA"},
	{name: "C# ECDsa.Create curve", regex: regexp.MustCompile(`ECDsa\.Create\s*\(\s*ECCurve\.NamedCurves\.(nistP256|nistP384|nistP521)`), algoFamily: "ECDSA"},

	// ── Rust ──
	{name: "Rust RsaPrivateKey::new bits", regex: regexp.MustCompile(`RsaPrivateKey::new\s*\(\s*&mut\s+\w+\s*,\s*(\d+)\s*\)`), algoFamily: "RSA"},

	// ── Ruby ──
	{name: "Ruby OpenSSL RSA.generate bits", regex: regexp.MustCompile(`RSA\.(new|generate)\s*\(\s*(\d+)`), algoFamily: "RSA"},

	// ── Shell / CLI ──
	{name: "Shell openssl genrsa bits", regex: regexp.MustCompile(`openssl\s+genrsa\s+.*?(\d{3,5})\s*$`), algoFamily: "RSA"},
	{name: "Shell ssh-keygen -b bits", regex: regexp.MustCompile(`ssh-keygen\s+.*-b\s+(\d+)`), algoFamily: "RSA"},

	// ── Terraform ──
	{name: "Terraform rsa_bits", regex: regexp.MustCompile(`rsa_bits\s*=\s*(\d+)`), algoFamily: "RSA"},
}

// ExtractKeySize attempts to extract an explicit key size from a matched code line.
// Returns a refined algorithm string (e.g., "RSA-4096" instead of "RSA-2048")
// and the extracted key size in bits. Returns "", 0 if no key size found.
func ExtractKeySize(line, currentAlgo string) (refinedAlgo string, keySizeBits int) {
	for _, ksp := range keySizePatterns {
		matches := ksp.regex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		// Find the numeric capture group
		for i := 1; i < len(matches); i++ {
			match := matches[i]

			// Handle curve names → key sizes
			switch strings.ToUpper(match) {
			case "P256", "SECP256R1", "NISTP256":
				return ksp.algoFamily + "-P256", 256
			case "P384", "SECP384R1", "NISTP384":
				return ksp.algoFamily + "-P384", 384
			case "P521", "SECP521R1", "NISTP521":
				return ksp.algoFamily + "-P521", 521
			}

			// Parse numeric key size
			size := 0
			for _, c := range match {
				if c >= '0' && c <= '9' {
					size = size*10 + int(c-'0')
				}
			}
			if size >= 128 && size <= 16384 {
				return ksp.algoFamily + "-" + match, size
			}
		}
	}
	return "", 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// CODE-3: Cipher Mode Detection
//
// PROBLEM: The base scanner detects `AES.new(key, AES.MODE_ECB)` and classifies
// it as "AES-256" — but ECB mode is catastrophically insecure (leaks patterns).
// GCM provides authenticated encryption. CBC is legacy but acceptable. We need
// to distinguish these because ECB is RED regardless of key size.
//
// APPROACH: Pattern-match cipher mode indicators on already-matched lines to
// upgrade algorithm labels (e.g., "AES-256" → "AES-256-ECB" or "AES-256-GCM").
// ═══════════════════════════════════════════════════════════════════════════════

// cipherModePattern detects specific cipher modes in matched code lines.
type cipherModePattern struct {
	name  string
	regex *regexp.Regexp
	mode  string // "ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "CCM", "XTS"
}

var cipherModePatterns = []cipherModePattern{
	// ── Python ──
	{name: "Python AES MODE_ECB", regex: regexp.MustCompile(`MODE_ECB|\.ECB\b`), mode: "ECB"},
	{name: "Python AES MODE_CBC", regex: regexp.MustCompile(`MODE_CBC|\.CBC\b`), mode: "CBC"},
	{name: "Python AES MODE_GCM", regex: regexp.MustCompile(`MODE_GCM|\.GCM\b`), mode: "GCM"},
	{name: "Python AES MODE_CTR", regex: regexp.MustCompile(`MODE_CTR|\.CTR\b`), mode: "CTR"},
	{name: "Python AES MODE_CFB", regex: regexp.MustCompile(`MODE_CFB|\.CFB\b`), mode: "CFB"},
	{name: "Python AES MODE_OFB", regex: regexp.MustCompile(`MODE_OFB|\.OFB\b`), mode: "OFB"},
	{name: "Python AES MODE_CCM", regex: regexp.MustCompile(`MODE_CCM|\.CCM\b`), mode: "CCM"},

	// ── Java / Kotlin (Cipher.getInstance) ──
	{name: "Java AES/ECB", regex: regexp.MustCompile(`"AES/ECB/`), mode: "ECB"},
	{name: "Java AES/CBC", regex: regexp.MustCompile(`"AES/CBC/`), mode: "CBC"},
	{name: "Java AES/GCM", regex: regexp.MustCompile(`"AES/GCM/`), mode: "GCM"},
	{name: "Java AES/CTR", regex: regexp.MustCompile(`"AES/CTR/`), mode: "CTR"},
	{name: "Java AES/CFB", regex: regexp.MustCompile(`"AES/CFB/`), mode: "CFB"},
	{name: "Java DES/ECB", regex: regexp.MustCompile(`"DES(ede)?/ECB/`), mode: "ECB"},
	{name: "Java DES/CBC", regex: regexp.MustCompile(`"DES(ede)?/CBC/`), mode: "CBC"},
	{name: "Java Blowfish/ECB", regex: regexp.MustCompile(`"Blowfish/ECB/`), mode: "ECB"},

	// ── C / C++ (OpenSSL) ──
	{name: "C EVP_aes_ecb", regex: regexp.MustCompile(`EVP_aes_\d+_ecb`), mode: "ECB"},
	{name: "C EVP_aes_cbc", regex: regexp.MustCompile(`EVP_aes_\d+_cbc`), mode: "CBC"},
	{name: "C EVP_aes_gcm", regex: regexp.MustCompile(`EVP_aes_\d+_gcm`), mode: "GCM"},
	{name: "C EVP_aes_ctr", regex: regexp.MustCompile(`EVP_aes_\d+_ctr`), mode: "CTR"},
	{name: "C EVP_aes_xts", regex: regexp.MustCompile(`EVP_aes_\d+_xts`), mode: "XTS"},
	{name: "C AES_ecb_encrypt", regex: regexp.MustCompile(`AES_ecb_encrypt`), mode: "ECB"},
	{name: "C AES_cbc_encrypt", regex: regexp.MustCompile(`AES_cbc_encrypt`), mode: "CBC"},
	{name: "C DES_ecb_encrypt", regex: regexp.MustCompile(`DES_ecb_encrypt`), mode: "ECB"},
	{name: "C DES_cbc_encrypt", regex: regexp.MustCompile(`DES_cbc_encrypt`), mode: "CBC"},

	// ── C++ (mbedTLS) ──
	{name: "C mbedtls_aes_crypt_ecb", regex: regexp.MustCompile(`mbedtls_aes_crypt_ecb`), mode: "ECB"},
	{name: "C mbedtls_aes_crypt_cbc", regex: regexp.MustCompile(`mbedtls_aes_crypt_cbc`), mode: "CBC"},

	// ── C# / .NET ──
	{name: "C# CipherMode.ECB", regex: regexp.MustCompile(`CipherMode\.ECB`), mode: "ECB"},
	{name: "C# CipherMode.CBC", regex: regexp.MustCompile(`CipherMode\.CBC`), mode: "CBC"},
	{name: "C# CipherMode.CFB", regex: regexp.MustCompile(`CipherMode\.CFB`), mode: "CFB"},
	{name: "C# AesGcm", regex: regexp.MustCompile(`\bAesGcm\b`), mode: "GCM"},

	// ── Ruby ──
	{name: "Ruby AES-ECB", regex: regexp.MustCompile(`AES-\d+-ECB|aes-\d+-ecb`), mode: "ECB"},
	{name: "Ruby AES-CBC", regex: regexp.MustCompile(`AES-\d+-CBC|aes-\d+-cbc`), mode: "CBC"},
	{name: "Ruby AES-GCM", regex: regexp.MustCompile(`AES-\d+-GCM|aes-\d+-gcm`), mode: "GCM"},

	// ── PHP ──
	{name: "PHP aes-ecb", regex: regexp.MustCompile(`aes-\d+-ecb|AES-\d+-ECB`), mode: "ECB"},
	{name: "PHP aes-cbc", regex: regexp.MustCompile(`aes-\d+-cbc|AES-\d+-CBC`), mode: "CBC"},
	{name: "PHP aes-gcm", regex: regexp.MustCompile(`aes-\d+-gcm|AES-\d+-GCM`), mode: "GCM"},

	// ── Shell (openssl enc) ──
	{name: "Shell openssl aes-ecb", regex: regexp.MustCompile(`-aes-\d+-ecb`), mode: "ECB"},
	{name: "Shell openssl aes-cbc", regex: regexp.MustCompile(`-aes-\d+-cbc`), mode: "CBC"},
	{name: "Shell openssl aes-gcm", regex: regexp.MustCompile(`-aes-\d+-gcm`), mode: "GCM"},

	// ── Generic (catches string constants in any language) ──
	{name: "Generic ECB string", regex: regexp.MustCompile(`["\'].*ECB["\']`), mode: "ECB"},
}

// DetectCipherMode checks a matched code line for cipher mode indicators.
// Returns the detected mode (e.g., "ECB", "GCM") or "" if none found.
// ECB mode is always RED — it leaks data patterns regardless of key size.
func DetectCipherMode(line string) string {
	for _, cmp := range cipherModePatterns {
		if cmp.regex.MatchString(line) {
			return cmp.mode
		}
	}
	return ""
}

// CipherModeIsInsecure returns true for modes that are cryptographically broken.
func CipherModeIsInsecure(mode string) bool {
	return mode == "ECB"
}

// CipherModeIsLegacy returns true for modes that are functional but not recommended.
func CipherModeIsLegacy(mode string) bool {
	return mode == "CBC" || mode == "CFB" || mode == "OFB"
}

// CipherModeIsModern returns true for authenticated encryption modes.
func CipherModeIsModern(mode string) bool {
	return mode == "GCM" || mode == "CCM" || mode == "XTS"
}

// ═══════════════════════════════════════════════════════════════════════════════
// CODE-5: Secrets / Key Material Detection in Config Files
//
// PROBLEM: Hardcoded secrets in .env, .properties, and .cfg files are a
// critical security issue that also reveals cryptographic configurations.
// A line like `DB_ENCRYPTION_KEY=AES256` tells us an AES key exists *and*
// that the key might be embedded in plaintext.
//
// APPROACH: New pattern set for configuration file formats that are commonly
// excluded from the crypto pattern matching because they aren't "source code."
// ═══════════════════════════════════════════════════════════════════════════════

// secretPattern detects potential cryptographic secrets in configuration files.
type secretPattern struct {
	name      string
	regex     *regexp.Regexp
	riskType  string // "hardcoded_key", "api_secret", "private_key", "encryption_config"
	algorithm string
}

var secretPatterns = []secretPattern{
	// ── .env files ──
	{name: "ENV encryption key", regex: regexp.MustCompile(`(?i)(ENCRYPTION_KEY|ENCRYPT_KEY|AES_KEY|SECRET_KEY|SIGNING_KEY|PRIVATE_KEY|API_SECRET|JWT_SECRET|HMAC_SECRET|MASTER_KEY)\s*=\s*.+`), riskType: "hardcoded_key", algorithm: "AES-256"},
	{name: "ENV database password", regex: regexp.MustCompile(`(?i)(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD)\s*=\s*.+`), riskType: "hardcoded_key", algorithm: "AES-256"},
	{name: "ENV AWS secret", regex: regexp.MustCompile(`(?i)(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*.+`), riskType: "api_secret", algorithm: "HMAC-SHA256"},
	{name: "ENV GCP/Azure secret", regex: regexp.MustCompile(`(?i)(GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET|AZURE_TENANT_ID)\s*=\s*.+`), riskType: "api_secret", algorithm: "RSA-2048"},
	{name: "ENV TLS cert path", regex: regexp.MustCompile(`(?i)(TLS_CERT|SSL_CERT|CA_CERT|TLS_KEY|SSL_KEY)\s*=\s*.+`), riskType: "encryption_config", algorithm: "RSA-2048"},
	{name: "ENV token/apikey", regex: regexp.MustCompile(`(?i)(AUTH_TOKEN|API_KEY|ACCESS_TOKEN|BEARER_TOKEN|SERVICE_TOKEN)\s*=\s*.+`), riskType: "api_secret", algorithm: "HMAC-SHA256"},

	// ── .properties files (Java) ──
	{name: "Properties keystore password", regex: regexp.MustCompile(`(?i)(keystore\.password|truststore\.password|key\.password|ssl\.key\.password)\s*=\s*.+`), riskType: "hardcoded_key", algorithm: "RSA-2048"},
	{name: "Properties keystore path", regex: regexp.MustCompile(`(?i)(keystore\.path|truststore\.path|keystore\.location|ssl\.keystore)\s*=\s*.+`), riskType: "encryption_config", algorithm: "RSA-2048"},
	{name: "Properties crypto algorithm", regex: regexp.MustCompile(`(?i)(algorithm|cipher|crypto\.provider|security\.provider)\s*=\s*(AES|RSA|DES|3DES|Blowfish|RC4|SHA)`), riskType: "encryption_config", algorithm: "AES-256"},
	{name: "Properties JDBC with SSL", regex: regexp.MustCompile(`jdbc:.*ssl(Mode)?=(true|require|verify)`), riskType: "encryption_config", algorithm: "RSA-2048"},

	// ── Generic config patterns ──
	{name: "Config private key inline", regex: regexp.MustCompile(`(?i)(private.key|secret.key|signing.key)\s*[=:]\s*[A-Za-z0-9+/=]{20,}`), riskType: "hardcoded_key", algorithm: "RSA-2048"},
	{name: "Config base64 secret", regex: regexp.MustCompile(`(?i)(secret|password|credential|token)\s*[=:]\s*[A-Za-z0-9+/]{40,}={0,2}\s*$`), riskType: "hardcoded_key", algorithm: "AES-256"},
}

// ConfigSecretExtensions lists file extensions for secret scanning.
var ConfigSecretExtensions = map[string]bool{
	".env":        true,
	".properties": true,
	".cfg":        true,
	".ini":        true,
	".conf":       true,
	".toml":       true,
}

// ScanLineForSecrets checks a single line from a config file for hardcoded secrets.
// Returns matching assets if secrets are detected.
func ScanLineForSecrets(line, path string, lineNum int) []models.CryptoAsset {
	var assets []models.CryptoAsset
	trimmed := strings.TrimSpace(line)

	// Skip comments
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "//") {
		return nil
	}

	for _, sp := range secretPatterns {
		if sp.regex.MatchString(trimmed) {
			zone := classifier.Classify(sp.algorithm)

			// Hardcoded keys are always RED regardless of algorithm strength
			if sp.riskType == "hardcoded_key" {
				zone = models.ZoneRed
			}

			assets = append(assets, models.CryptoAsset{
				ID:        "secret-" + strings.ReplaceAll(sp.name, " ", "-"),
				Type:      models.AssetCodeCrypto,
				Algorithm: sp.algorithm,
				Zone:      zone,
				Location:  path + ":" + strconv.Itoa(lineNum),
				Details: map[string]string{
					"pattern":   sp.name,
					"risk_type": sp.riskType,
					"line":      strconv.Itoa(lineNum),
					"language":  strings.ToLower(strings.TrimPrefix(path[strings.LastIndex(path, "."):], ".")),
				},
			})
		}
	}

	return assets
}

// ═══════════════════════════════════════════════════════════════════════════════
// CODE-4: Scala / Groovy / R Language Coverage
//
// These languages use Java (Scala/Groovy) or R-specific crypto APIs.
// Added as additional cryptoPatterns to the base scanner's pattern set.
// ═══════════════════════════════════════════════════════════════════════════════

// ScalaGroovyRPatterns returns additional patterns for Scala, Groovy, and R.
// These are designed to be appended to the main cryptoPatterns slice.
var ScalaGroovyRPatterns = []cryptoPattern{
	// ── Scala (JVM — uses Java crypto APIs with Scala syntax) ──
	{name: "Scala KeyPairGenerator RSA", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"RSA"`), algorithms: []string{"RSA-2048"}, languages: []string{".scala"}},
	{name: "Scala KeyPairGenerator EC", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"EC"`), algorithms: []string{"ECDSA-P256"}, languages: []string{".scala"}},
	{name: "Scala Cipher getInstance", regex: regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"(AES|RSA|DES|DESede|Blowfish)[/"]`), algorithms: []string{"AES-256"}, languages: []string{".scala"}},
	{name: "Scala Signature getInstance", regex: regexp.MustCompile(`Signature\.getInstance\s*\(\s*"SHA\d+with(RSA|ECDSA)"`), algorithms: []string{"RSA-2048"}, languages: []string{".scala"}},
	{name: "Scala MessageDigest", regex: regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"(SHA-256|SHA-384|SHA-512|SHA-1|MD5)"`), algorithms: []string{"SHA-256"}, languages: []string{".scala"}},
	{name: "Scala Mac getInstance", regex: regexp.MustCompile(`Mac\.getInstance\s*\(\s*"Hmac`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".scala"}},
	{name: "Scala SSLContext", regex: regexp.MustCompile(`SSLContext\.getInstance\s*\(`), algorithms: []string{"TLS"}, languages: []string{".scala"}},
	{name: "Scala BouncyCastle import", regex: regexp.MustCompile(`import\s+org\.bouncycastle\.\w+`), algorithms: []string{"RSA-2048"}, languages: []string{".scala"}},
	{name: "Scala Akka TLS", regex: regexp.MustCompile(`SSLConfig|HttpsConnectionContext|TLS\.apply`), algorithms: []string{"RSA-2048"}, languages: []string{".scala"}},
	{name: "Scala javax.crypto import", regex: regexp.MustCompile(`import\s+javax\.crypto\.`), algorithms: []string{"AES-256"}, languages: []string{".scala"}},
	{name: "Scala java.security import", regex: regexp.MustCompile(`import\s+java\.security\.`), algorithms: []string{"RSA-2048"}, languages: []string{".scala"}},

	// ── Groovy (JVM — Java crypto APIs with Groovy dynamic syntax) ──
	{name: "Groovy KeyPairGenerator", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*['"]`), algorithms: []string{"RSA-2048"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy Cipher", regex: regexp.MustCompile(`Cipher\.getInstance\s*\(\s*['"]`), algorithms: []string{"AES-256"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy MessageDigest", regex: regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*['"]`), algorithms: []string{"SHA-256"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy Mac", regex: regexp.MustCompile(`Mac\.getInstance\s*\(\s*['"]Hmac`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy SecretKeySpec", regex: regexp.MustCompile(`SecretKeySpec\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy SSLContext", regex: regexp.MustCompile(`SSLContext\.getInstance\s*\(`), algorithms: []string{"TLS"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy digest", regex: regexp.MustCompile(`\.digest\s*\(\s*['"]`), algorithms: []string{"SHA-256"}, languages: []string{".groovy", ".gradle"}},
	{name: "Groovy Jenkins credentials", regex: regexp.MustCompile(`credentials\s*\(\s*['"]`), algorithms: []string{"RSA-2048"}, languages: []string{".groovy", ".gradle"}},

	// ── R (statistical computing — crypto/TLS usage in data pipelines) ──
	{name: "R openssl gen_rsa", regex: regexp.MustCompile(`(rsa_keygen|ec_keygen|dsa_keygen)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".r", ".R"}},
	{name: "R openssl encrypt", regex: regexp.MustCompile(`(aes_cbc_encrypt|aes_ctr_encrypt|aes_gcm_encrypt)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".r", ".R"}},
	{name: "R openssl decrypt", regex: regexp.MustCompile(`(aes_cbc_decrypt|aes_ctr_decrypt|aes_gcm_decrypt)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".r", ".R"}},
	{name: "R digest package", regex: regexp.MustCompile(`digest\s*\(\s*.*,\s*algo\s*=\s*['"]`), algorithms: []string{"SHA-256"}, languages: []string{".r", ".R"}},
	{name: "R digest sha256", regex: regexp.MustCompile(`digest\s*\(.*['"]sha(256|384|512|1|md5)['"]`), algorithms: []string{"SHA-256"}, languages: []string{".r", ".R"}},
	{name: "R httr ssl", regex: regexp.MustCompile(`httr::(GET|POST|PUT)\s*\(.*ssl`), algorithms: []string{"RSA-2048"}, languages: []string{".r", ".R"}},
	{name: "R openssl sign/verify", regex: regexp.MustCompile(`(signature_create|signature_verify)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".r", ".R"}},
	{name: "R openssl cert", regex: regexp.MustCompile(`(read_cert|download_ssl_cert|x509_info)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".r", ".R"}},
	{name: "R library openssl", regex: regexp.MustCompile(`library\s*\(\s*openssl\s*\)`), algorithms: []string{"RSA-2048"}, languages: []string{".r", ".R"}},
	{name: "R library digest", regex: regexp.MustCompile(`library\s*\(\s*digest\s*\)`), algorithms: []string{"SHA-256"}, languages: []string{".r", ".R"}},
	{name: "R sodium", regex: regexp.MustCompile(`(data_encrypt|data_decrypt|sig_sign|sig_verify|keygen)\s*\(`), algorithms: []string{"XSalsa20-Poly1305"}, languages: []string{".r", ".R"}},
	{name: "R library sodium", regex: regexp.MustCompile(`library\s*\(\s*sodium\s*\)`), algorithms: []string{"Ed25519"}, languages: []string{".r", ".R"}},
}

// AdditionalCodeExtensions lists file extensions added for Scala/Groovy/R support.
var AdditionalCodeExtensions = map[string]bool{
	".scala":  true,
	".groovy": true,
	".gradle": true,
	".r":      true,
	".R":      true,
}

// ═══════════════════════════════════════════════════════════════════════════════
// EnrichAssets applies post-processing to base scanner results:
//  1. Extracts key sizes from code context
//  2. Detects cipher modes (ECB = RED escalation)
//  3. Reclassifies zones based on enriched information
// ═══════════════════════════════════════════════════════════════════════════════

// EnrichAssets takes the raw asset list from the base scanner and enriches
// each asset with key size and cipher mode information.
func EnrichAssets(assets []models.CryptoAsset) []models.CryptoAsset {
	enriched := make([]models.CryptoAsset, len(assets))
	copy(enriched, assets)

	for i := range enriched {
		codeLine := enriched[i].Details["code"]
		if codeLine == "" {
			continue
		}

		// CODE-1: Key size extraction
		if refinedAlgo, keyBits := ExtractKeySize(codeLine, enriched[i].Algorithm); refinedAlgo != "" {
			enriched[i].Algorithm = refinedAlgo
			enriched[i].Zone = classifier.Classify(refinedAlgo)
			if enriched[i].Details == nil {
				enriched[i].Details = make(map[string]string)
			}
			enriched[i].Details["key_size_bits"] = strconv.Itoa(keyBits)
			enriched[i].Details["key_size_source"] = "extracted"
		}

		// CODE-3: Cipher mode detection
		mode := DetectCipherMode(codeLine)
		if mode != "" {
			if enriched[i].Details == nil {
				enriched[i].Details = make(map[string]string)
			}
			enriched[i].Details["cipher_mode"] = mode

			// Append mode to algorithm name if not already present
			if !strings.Contains(enriched[i].Algorithm, mode) {
				baseAlgo := enriched[i].Algorithm
				// Strip existing generic mode suffix
				for _, suffix := range []string{"-CBC", "-GCM", "-CTR", "-ECB", "-CFB", "-OFB"} {
					baseAlgo = strings.TrimSuffix(baseAlgo, suffix)
				}
				enriched[i].Algorithm = baseAlgo + "-" + mode
			}

			// ECB is always RED — catastrophically insecure
			if CipherModeIsInsecure(mode) {
				enriched[i].Zone = models.ZoneRed
				enriched[i].Details["cipher_mode_risk"] = "CRITICAL — ECB leaks plaintext patterns, prohibited by all standards"
			} else if CipherModeIsLegacy(mode) {
				enriched[i].Details["cipher_mode_risk"] = "LEGACY — use GCM/CCM for authenticated encryption"
			} else if CipherModeIsModern(mode) {
				enriched[i].Details["cipher_mode_risk"] = "MODERN — authenticated encryption mode"
			}
		}
	}

	return enriched
}

// scanFileForSecrets scans a config file for hardcoded secrets line by line.
func scanFileForSecrets(path string) []models.CryptoAsset {
	var assets []models.CryptoAsset

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		found := ScanLineForSecrets(line, path, lineNum)
		assets = append(assets, found...)
	}

	return assets
}

func init() {
	// Wire in CODE-4: Register Scala/Groovy/R patterns with the base scanner
	cryptoPatterns = append(cryptoPatterns, ScalaGroovyRPatterns...)

	// Wire in CODE-4/5: Register additional file extensions
	for ext := range AdditionalCodeExtensions {
		codeExtensions[ext] = true
	}
	for ext := range ConfigSecretExtensions {
		codeExtensions[ext] = true
	}
}
