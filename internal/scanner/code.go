// Package scanner provides source code cryptographic API detection.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// cryptoPattern represents a crypto API usage pattern to scan for.
type cryptoPattern struct {
	name       string         // Human-readable name
	regex      *regexp.Regexp // Compiled pattern
	algorithms []string       // Algorithms this pattern implies
	languages  []string       // Languages this pattern applies to
}

// cryptoPatterns is the knowledge base of crypto API calls to detect.
var cryptoPatterns = []cryptoPattern{
	// ═══════════════════════════════════════════════════════════════════
	// Go Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "Go RSA Generate", regex: regexp.MustCompile(`rsa\.GenerateKey\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".go"}},
	{name: "Go RSA Sign", regex: regexp.MustCompile(`rsa\.Sign(PSS|PKCS1v15)?\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".go"}},
	{name: "Go ECDSA Sign", regex: regexp.MustCompile(`ecdsa\.Sign\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".go"}},
	{name: "Go ECDSA Generate", regex: regexp.MustCompile(`ecdsa\.GenerateKey\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".go"}},
	{name: "Go Ed25519 Sign", regex: regexp.MustCompile(`ed25519\.(Sign|GenerateKey)\s*\(`), algorithms: []string{"Ed25519"}, languages: []string{".go"}},
	{name: "Go X25519", regex: regexp.MustCompile(`curve25519\.X25519\s*\(`), algorithms: []string{"X25519"}, languages: []string{".go"}},
	{name: "Go AES", regex: regexp.MustCompile(`aes\.NewCipher\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".go"}},
	{name: "Go AES-GCM", regex: regexp.MustCompile(`cipher\.NewGCM\s*\(`), algorithms: []string{"AES-256-GCM"}, languages: []string{".go"}},
	{name: "Go SHA-256", regex: regexp.MustCompile(`sha256\.(New|Sum256)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".go"}},
	{name: "Go SHA-512", regex: regexp.MustCompile(`sha512\.(New|Sum512)\s*\(`), algorithms: []string{"SHA-512"}, languages: []string{".go"}},
	{name: "Go TLS Config", regex: regexp.MustCompile(`tls\.(Config|Dial|Listen)`), algorithms: []string{"TLS"}, languages: []string{".go"}},
	{name: "Go HMAC", regex: regexp.MustCompile(`hmac\.New\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".go"}},

	// ═══════════════════════════════════════════════════════════════════
	// Python Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "Python RSA Generate", regex: regexp.MustCompile(`RSA\.generate\s*\(|rsa\.generate_private_key\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python ECDSA", regex: regexp.MustCompile(`ec\.(SECP256R1|SECP384R1|generate_private_key)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".py"}},
	{name: "Python Ed25519", regex: regexp.MustCompile(`Ed25519PrivateKey\.generate\s*\(`), algorithms: []string{"Ed25519"}, languages: []string{".py"}},
	{name: "Python AES", regex: regexp.MustCompile(`AES\.(new|MODE_GCM|MODE_CBC)`), algorithms: []string{"AES-256"}, languages: []string{".py"}},
	{name: "Python Fernet", regex: regexp.MustCompile(`Fernet\s*\(`), algorithms: []string{"AES-128-CBC"}, languages: []string{".py"}},
	{name: "Python hashlib", regex: regexp.MustCompile(`hashlib\.(sha256|sha384|sha512|md5)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".py"}},
	{name: "Python PBKDF2", regex: regexp.MustCompile(`PBKDF2HMAC\s*\(`), algorithms: []string{"PBKDF2"}, languages: []string{".py"}},
	{name: "Python PyNaCl", regex: regexp.MustCompile(`nacl\.(signing|public|secret)\b`), algorithms: []string{"Ed25519"}, languages: []string{".py"}},

	// ═══════════════════════════════════════════════════════════════════
	// Java Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "Java KeyPairGenerator RSA", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"RSA"`), algorithms: []string{"RSA-2048"}, languages: []string{".java"}},
	{name: "Java KeyPairGenerator EC", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"EC"`), algorithms: []string{"ECDSA-P256"}, languages: []string{".java"}},
	{name: "Java Signature RSA", regex: regexp.MustCompile(`Signature\.getInstance\s*\(\s*"SHA\d+withRSA"`), algorithms: []string{"RSA-2048"}, languages: []string{".java"}},
	{name: "Java Signature ECDSA", regex: regexp.MustCompile(`Signature\.getInstance\s*\(\s*"SHA\d+withECDSA"`), algorithms: []string{"ECDSA-P256"}, languages: []string{".java"}},
	{name: "Java Cipher AES", regex: regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"AES`), algorithms: []string{"AES-256"}, languages: []string{".java"}},
	{name: "Java KeyGenerator AES", regex: regexp.MustCompile(`KeyGenerator\.getInstance\s*\(\s*"AES"`), algorithms: []string{"AES-256"}, languages: []string{".java"}},
	{name: "Java MessageDigest", regex: regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"SHA-(256|384|512)"`), algorithms: []string{"SHA-256"}, languages: []string{".java"}},
	{name: "Java SSLContext", regex: regexp.MustCompile(`SSLContext\.getInstance\s*\(`), algorithms: []string{"TLS"}, languages: []string{".java"}},
	{name: "Java Mac HMAC", regex: regexp.MustCompile(`Mac\.getInstance\s*\(\s*"Hmac`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".java"}},

	// ═══════════════════════════════════════════════════════════════════
	// JavaScript / TypeScript Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "JS SubtleCrypto", regex: regexp.MustCompile(`crypto\.subtle\.(generateKey|sign|encrypt|decrypt)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "JS createSign RSA", regex: regexp.MustCompile(`crypto\.createSign\s*\(\s*['"]RSA`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts"}},
	{name: "JS createCipheriv", regex: regexp.MustCompile(`crypto\.createCipheriv\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".js", ".ts"}},
	{name: "JS createHash", regex: regexp.MustCompile(`crypto\.createHash\s*\(\s*['"]sha(256|384|512)`), algorithms: []string{"SHA-256"}, languages: []string{".js", ".ts"}},
	{name: "JS createHmac", regex: regexp.MustCompile(`crypto\.createHmac\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".js", ".ts"}},
	{name: "JS JWT sign", regex: regexp.MustCompile(`jwt\.sign\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts"}},
	{name: "JS bcrypt", regex: regexp.MustCompile(`bcrypt\.(hash|compare)\s*\(`), algorithms: []string{"bcrypt"}, languages: []string{".js", ".ts"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ Crypto APIs (OpenSSL, libsodium)
	// ═══════════════════════════════════════════════════════════════════
	{name: "C OpenSSL RSA", regex: regexp.MustCompile(`RSA_generate_key(_ex)?\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP Sign", regex: regexp.MustCompile(`EVP_DigestSign(Init|Update|Final)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EC Key", regex: regexp.MustCompile(`EC_KEY_(new_by_curve_name|generate_key)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL AES", regex: regexp.MustCompile(`EVP_aes_(128|256)_(gcm|cbc|ctr)\s*\(`), algorithms: []string{"AES-256-GCM"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL SHA", regex: regexp.MustCompile(`EVP_sha(256|384|512)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL TLS", regex: regexp.MustCompile(`SSL_CTX_new\s*\(`), algorithms: []string{"TLS"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium sign", regex: regexp.MustCompile(`crypto_sign(_ed25519)?\s*\(`), algorithms: []string{"Ed25519"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium box", regex: regexp.MustCompile(`crypto_box(_curve25519)?\s*\(`), algorithms: []string{"X25519"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium aead", regex: regexp.MustCompile(`crypto_aead_chacha20poly1305\s*\(`), algorithms: []string{"ChaCha20-Poly1305"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// Rust Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "Rust RSA", regex: regexp.MustCompile(`RsaPrivateKey::(new|generate)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".rs"}},
	{name: "Rust ring sign", regex: regexp.MustCompile(`ring::signature::(Ed25519|ECDSA|RSA)`), algorithms: []string{"Ed25519"}, languages: []string{".rs"}},
	{name: "Rust AES-GCM", regex: regexp.MustCompile(`Aes256Gcm::(new|encrypt)\s*\(`), algorithms: []string{"AES-256-GCM"}, languages: []string{".rs"}},
	{name: "Rust ChaCha20", regex: regexp.MustCompile(`ChaCha20Poly1305::(new|encrypt)\s*\(`), algorithms: []string{"ChaCha20-Poly1305"}, languages: []string{".rs"}},
	{name: "Rust SHA-256", regex: regexp.MustCompile(`Sha256::digest\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".rs"}},

	// ═══════════════════════════════════════════════════════════════════
	// C# / .NET Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "C# RSA Create", regex: regexp.MustCompile(`RSA\.Create\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".cs"}},
	{name: "C# ECDsa Create", regex: regexp.MustCompile(`ECDsa\.Create\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".cs"}},
	{name: "C# Aes Create", regex: regexp.MustCompile(`Aes\.Create\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".cs"}},
	{name: "C# SHA256", regex: regexp.MustCompile(`SHA256\.(Create|HashData)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".cs"}},
	{name: "C# HMAC", regex: regexp.MustCompile(`HMACSHA256\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".cs"}},

	// ═══════════════════════════════════════════════════════════════════
	// Ruby Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "Ruby OpenSSL RSA", regex: regexp.MustCompile(`OpenSSL::PKey::RSA\.(new|generate)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".rb"}},
	{name: "Ruby OpenSSL EC", regex: regexp.MustCompile(`OpenSSL::PKey::EC\.generate\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".rb"}},
	{name: "Ruby Digest SHA", regex: regexp.MustCompile(`Digest::SHA(256|384|512)\.(new|hexdigest)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".rb"}},

	// ═══════════════════════════════════════════════════════════════════
	// PHP Crypto APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "PHP openssl_sign", regex: regexp.MustCompile(`openssl_sign\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP openssl_encrypt", regex: regexp.MustCompile(`openssl_encrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".php"}},
	{name: "PHP openssl_pkey", regex: regexp.MustCompile(`openssl_pkey_new\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP hash", regex: regexp.MustCompile(`hash\s*\(\s*['"]sha(256|384|512)`), algorithms: []string{"SHA-256"}, languages: []string{".php"}},
}

// File extensions to scan.
var codeExtensions = map[string]bool{
	".go": true, ".py": true, ".java": true, ".js": true, ".ts": true,
	".mjs": true, ".c": true, ".cpp": true, ".h": true, ".hpp": true,
	".rs": true, ".cs": true, ".rb": true, ".php": true,
}

// Directories to skip.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "__pycache__": true,
	"target": true, "build": true, "dist": true, ".idea": true, ".vscode": true,
	"bin": true, "obj": true, "pkg": true,
}

// ScanCode scans source code files for cryptographic API usage.
func ScanCode(target string) (*models.ScanResult, error) {
	start := time.Now()

	result := &models.ScanResult{
		Target:    target,
		ScanType:  "code",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", target, err)
	}

	var files []string
	if info.IsDir() {
		files, err = findCodeFiles(target)
		if err != nil {
			return nil, fmt.Errorf("failed to scan directory: %w", err)
		}
	} else {
		files = []string{target}
	}

	totalFindings := 0
	filesWithCrypto := 0

	for _, file := range files {
		findings := scanFileForCrypto(file)
		if len(findings) > 0 {
			filesWithCrypto++
			totalFindings += len(findings)
			result.Assets = append(result.Assets, findings...)
		}
	}

	result.Duration = time.Since(start)
	result.Details = map[string]string{
		"files_scanned":     fmt.Sprintf("%d", len(files)),
		"files_with_crypto": fmt.Sprintf("%d", filesWithCrypto),
		"total_findings":    fmt.Sprintf("%d", totalFindings),
	}

	return result, nil
}

// findCodeFiles recursively finds source code files, skipping common non-source dirs.
func findCodeFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			base := filepath.Base(path)
			if skipDirs[base] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if codeExtensions[ext] {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// scanFileForCrypto scans a single source file for crypto API patterns.
func scanFileForCrypto(path string) []models.CryptoAsset {
	var assets []models.CryptoAsset

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	ext := strings.ToLower(filepath.Ext(path))
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments (simple heuristic)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "*") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		for _, pattern := range cryptoPatterns {
			// Check if pattern applies to this file type
			applicable := false
			for _, lang := range pattern.languages {
				if lang == ext {
					applicable = true
					break
				}
			}
			if !applicable {
				continue
			}

			if pattern.regex.MatchString(line) {
				for _, algo := range pattern.algorithms {
					zone := classifier.Classify(algo)

					assets = append(assets, models.CryptoAsset{
						ID:        fmt.Sprintf("code-%s-%d", filepath.Base(path), lineNum),
						Type:      models.AssetCodeCrypto,
						Algorithm: algo,
						Zone:      zone,
						Location:  fmt.Sprintf("%s:%d (%s)", path, lineNum, pattern.name),
						Details: map[string]string{
							"pattern":  pattern.name,
							"line":     fmt.Sprintf("%d", lineNum),
							"code":     strings.TrimSpace(line),
							"language": ext,
						},
					})
				}
			}
		}
	}

	return assets
}
