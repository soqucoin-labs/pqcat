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
	"github.com/soqucoin-labs/pqcat/internal/tui"
)

// cryptoPattern represents a crypto API usage pattern to scan for.
type cryptoPattern struct {
	name       string                                     // Human-readable name
	regex      *regexp.Regexp                             // Compiled pattern
	algorithms []string                                   // Default algorithms (fallback)
	languages  []string                                   // Languages this pattern applies to
	resolver   func(match []string, line string) []string // Dynamic algorithm from capture groups + line context
}

// resolveGoAESKeySize inspects the line containing aes.NewCipher() to infer key size.
// Go's aes.NewCipher accepts 16 (AES-128), 24 (AES-192), or 32 (AES-256) byte keys.
// This function checks for common patterns like key[:16], key[:24], key[:32],
// make([]byte, N), or literal byte slices to determine the actual key size.
func resolveGoAESKeySize(_ []string, line string) []string {
	// Check for explicit slice length: key[:16], key[:24], key[:32]
	if strings.Contains(line, "[:16]") || strings.Contains(line, "[0:16]") {
		return []string{"AES-128"}
	}
	if strings.Contains(line, "[:24]") || strings.Contains(line, "[0:24]") {
		return []string{"AES-192"}
	}
	if strings.Contains(line, "[:32]") || strings.Contains(line, "[0:32]") {
		return []string{"AES-256"}
	}

	// Check for make([]byte, N) on the same line
	makePat := regexp.MustCompile(`make\(\[\]byte,\s*(16|24|32)\)`)
	if m := makePat.FindStringSubmatch(line); m != nil {
		switch m[1] {
		case "16":
			return []string{"AES-128"}
		case "24":
			return []string{"AES-192"}
		case "32":
			return []string{"AES-256"}
		}
	}

	// Default: can't determine key size, return nil to use fallback (AES-256)
	return nil
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
	{name: "Go AES", regex: regexp.MustCompile(`aes\.NewCipher\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".go"},
		resolver: resolveGoAESKeySize,
	},
	{name: "Go AES-GCM", regex: regexp.MustCompile(`cipher\.NewGCM\s*\(`), algorithms: []string{"AES-256-GCM"}, languages: []string{".go"}},
	{name: "Go SHA-256", regex: regexp.MustCompile(`sha256\.(New|Sum256)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".go"}},
	{name: "Go SHA-512", regex: regexp.MustCompile(`sha512\.(New|Sum512)\s*\(`), algorithms: []string{"SHA-512"}, languages: []string{".go"}},
	{name: "Go SHA-1", regex: regexp.MustCompile(`sha1\.(New|Sum)\s*\(`), algorithms: []string{"SHA-1"}, languages: []string{".go"}},
	{name: "Go MD5", regex: regexp.MustCompile(`md5\.(New|Sum)\s*\(`), algorithms: []string{"MD5"}, languages: []string{".go"}},
	{name: "Go SHA3", regex: regexp.MustCompile(`sha3\.(New256|New384|New512|Sum256|Sum384|Sum512|NewShake128|NewShake256)\s*\(`), algorithms: []string{"SHA3-256"}, languages: []string{".go"}},
	{name: "Go DES", regex: regexp.MustCompile(`des\.(NewCipher|NewTripleDESCipher)\s*\(`), algorithms: []string{"DES"}, languages: []string{".go"}},
	{name: "Go crypto/sha1 import", regex: regexp.MustCompile(`"crypto/sha1"`), algorithms: []string{"SHA-1"}, languages: []string{".go"}},
	{name: "Go crypto/md5 import", regex: regexp.MustCompile(`"crypto/md5"`), algorithms: []string{"MD5"}, languages: []string{".go"}},
	{name: "Go crypto/des import", regex: regexp.MustCompile(`"crypto/des"`), algorithms: []string{"DES"}, languages: []string{".go"}},
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
	{name: "Python hashlib", regex: regexp.MustCompile(`hashlib\.(sha256|sha384|sha512|sha1|md5)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".py"}},
	{name: "Python hashlib SHA1 explicit", regex: regexp.MustCompile(`hashlib\.sha1\s*\(`), algorithms: []string{"SHA-1"}, languages: []string{".py"}},
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
	// JS createCipheriv, createHash, createHmac — covered by Tier 3 Node.js patterns (lines 687-690)
	// which include .mjs support. Removed from here to avoid double-counting.
	{name: "JS JWT sign", regex: regexp.MustCompile(`jwt\.sign\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts"}},
	{name: "JS bcrypt", regex: regexp.MustCompile(`bcrypt\.(hash|compare)\s*\(`), algorithms: []string{"bcrypt"}, languages: []string{".js", ".ts"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ Crypto APIs — OpenSSL High-Level (EVP)
	// ═══════════════════════════════════════════════════════════════════
	{name: "C OpenSSL RSA", regex: regexp.MustCompile(`RSA_generate_key(_ex)?\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP Sign", regex: regexp.MustCompile(`EVP_DigestSign(Init|Update|Final)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP Verify", regex: regexp.MustCompile(`EVP_DigestVerify(Init|Update|Final)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EC Key", regex: regexp.MustCompile(`EC_KEY_(new_by_curve_name|generate_key)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL ECDSA Sign", regex: regexp.MustCompile(`ECDSA_(sign|verify|do_sign|do_verify)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP AES", regex: regexp.MustCompile(`EVP_aes_(128|192|256)_(gcm|cbc|ctr|ecb)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"},
		resolver: func(m []string, _ string) []string {
			if len(m) >= 3 {
				return []string{"AES-" + m[1] + "-" + strings.ToUpper(m[2])}
			}
			return nil
		},
	},
	{name: "C OpenSSL EVP SHA", regex: regexp.MustCompile(`EVP_sha(1|256|384|512)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"},
		resolver: func(m []string, _ string) []string {
			if len(m) >= 2 {
				if m[1] == "1" {
					return []string{"SHA-1"}
				}
				return []string{"SHA-" + m[1]}
			}
			return nil
		},
	},
	{name: "C OpenSSL EVP MD5", regex: regexp.MustCompile(`EVP_md5\s*\(`), algorithms: []string{"MD5"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL TLS", regex: regexp.MustCompile(`SSL_CTX_new\s*\(`), algorithms: []string{"TLS"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP PKEY", regex: regexp.MustCompile(`EVP_PKEY_(new|keygen|derive)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL DH", regex: regexp.MustCompile(`DH_(generate_parameters|generate_key|compute_key)\s*\(`), algorithms: []string{"DH-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ — OpenSSL Low-Level / Raw APIs
	// ═══════════════════════════════════════════════════════════════════
	{name: "C Raw SHA256", regex: regexp.MustCompile(`SHA256_(Init|Update|Final)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw SHA512", regex: regexp.MustCompile(`SHA512_(Init|Update|Final)\s*\(`), algorithms: []string{"SHA-512"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw SHA1", regex: regexp.MustCompile(`SHA1_(Init|Update|Final)\s*\(`), algorithms: []string{"SHA-1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw MD5", regex: regexp.MustCompile(`MD5_(Init|Update|Final)\s*\(`), algorithms: []string{"MD5"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw SHA256 oneshot", regex: regexp.MustCompile(`SHA256\s*\([^)]*,[^)]*,[^)]*\)`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw SHA512 oneshot", regex: regexp.MustCompile(`SHA512\s*\([^)]*,[^)]*,[^)]*\)`), algorithms: []string{"SHA-512"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw AES encrypt", regex: regexp.MustCompile(`AES_(set_encrypt_key|set_decrypt_key|encrypt|cbc_encrypt)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw HMAC", regex: regexp.MustCompile(`HMAC\s*\(\s*EVP_`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw HMAC CTX", regex: regexp.MustCompile(`HMAC_CTX_(new|init|update|final)\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C Raw RIPEMD160", regex: regexp.MustCompile(`RIPEMD160_(Init|Update|Final)\s*\(`), algorithms: []string{"RIPEMD-160"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ — Bitcoin Core / libsecp256k1 Custom Crypto
	// ═══════════════════════════════════════════════════════════════════
	{name: "C++ Bitcoin CSHA256", regex: regexp.MustCompile(`CSHA256\b`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CSHA512", regex: regexp.MustCompile(`CSHA512\b`), algorithms: []string{"SHA-512"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CHash256", regex: regexp.MustCompile(`CHash256\b`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CHash160", regex: regexp.MustCompile(`CHash160\b`), algorithms: []string{"RIPEMD-160"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CRIPEMD160", regex: regexp.MustCompile(`CRIPEMD160\b`), algorithms: []string{"RIPEMD-160"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CHMAC SHA256", regex: regexp.MustCompile(`CHMAC_SHA256\b`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CHMAC SHA512", regex: regexp.MustCompile(`CHMAC_SHA512\b`), algorithms: []string{"HMAC-SHA512"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin AES256Encrypt", regex: regexp.MustCompile(`AES256(Encrypt|Decrypt|CBCEncrypt|CBCDecrypt)\b`), algorithms: []string{"AES-256-CBC"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin AES128Encrypt", regex: regexp.MustCompile(`AES128(Encrypt|Decrypt|CBCEncrypt|CBCDecrypt)\b`), algorithms: []string{"AES-128-CBC"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin CKey", regex: regexp.MustCompile(`\bCKey\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".cpp", ".h"}},
	{name: "C++ Bitcoin CPubKey", regex: regexp.MustCompile(`\bCPubKey\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".cpp", ".h"}},
	{name: "C++ Bitcoin CExtKey", regex: regexp.MustCompile(`\bCExtKey\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".cpp", ".h"}},
	{name: "C++ Bitcoin CExtPubKey", regex: regexp.MustCompile(`\bCExtPubKey\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".cpp", ".h"}},
	{name: "C secp256k1 ECDSA sign", regex: regexp.MustCompile(`secp256k1_ecdsa_sign\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 ECDSA verify", regex: regexp.MustCompile(`secp256k1_ecdsa_verify\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 Schnorr sign", regex: regexp.MustCompile(`secp256k1_schnorrsig_sign`), algorithms: []string{"Schnorr-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 Schnorr verify", regex: regexp.MustCompile(`secp256k1_schnorrsig_verify\b`), algorithms: []string{"Schnorr-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 ECDH", regex: regexp.MustCompile(`secp256k1_ecdh\b`), algorithms: []string{"ECDH-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 keypair", regex: regexp.MustCompile(`secp256k1_(ec_pubkey_create|keypair_create|ec_seckey_verify)\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 context", regex: regexp.MustCompile(`secp256k1_context_(create|destroy)\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C secp256k1 recovery", regex: regexp.MustCompile(`secp256k1_ecdsa_recover(able_signature_parse|_pubkey)?\b`), algorithms: []string{"ECDSA-secp256k1"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin ChaCha20", regex: regexp.MustCompile(`\bChaCha20\b`), algorithms: []string{"ChaCha20"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin Poly1305", regex: regexp.MustCompile(`\bPoly1305\b`), algorithms: []string{"Poly1305"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin ChaCha20Poly1305", regex: regexp.MustCompile(`ChaCha20Poly1305\b`), algorithms: []string{"ChaCha20-Poly1305"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin SipHash", regex: regexp.MustCompile(`\bCSipHasher\b`), algorithms: []string{"SipHash"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin MuHash", regex: regexp.MustCompile(`\bMuHash3072\b`), algorithms: []string{"MuHash-3072"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C++ Bitcoin PBKDF2", regex: regexp.MustCompile(`PBKDF2_SHA256\b`), algorithms: []string{"PBKDF2-SHA256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ — Crypto Header Includes (broad detection)
	// ═══════════════════════════════════════════════════════════════════
	{name: "C include openssl/sha", regex: regexp.MustCompile(`#include\s*[<"]openssl/sha\.h[>"]`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/rsa", regex: regexp.MustCompile(`#include\s*[<"]openssl/rsa\.h[>"]`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/ec", regex: regexp.MustCompile(`#include\s*[<"]openssl/ec\.h[>"]`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/ecdsa", regex: regexp.MustCompile(`#include\s*[<"]openssl/ecdsa\.h[>"]`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/aes", regex: regexp.MustCompile(`#include\s*[<"]openssl/aes\.h[>"]`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/hmac", regex: regexp.MustCompile(`#include\s*[<"]openssl/hmac\.h[>"]`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/ripemd", regex: regexp.MustCompile(`#include\s*[<"]openssl/ripemd\.h[>"]`), algorithms: []string{"RIPEMD-160"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/dh", regex: regexp.MustCompile(`#include\s*[<"]openssl/dh\.h[>"]`), algorithms: []string{"DH-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/evp", regex: regexp.MustCompile(`#include\s*[<"]openssl/evp\.h[>"]`), algorithms: []string{"EVP-Crypto"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/ssl", regex: regexp.MustCompile(`#include\s*[<"]openssl/ssl\.h[>"]`), algorithms: []string{"TLS"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/des", regex: regexp.MustCompile(`#include\s*[<"]openssl/des\.h[>"]`), algorithms: []string{"DES"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C include openssl/md5", regex: regexp.MustCompile(`#include\s*[<"]openssl/md5\.h[>"]`), algorithms: []string{"MD5"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ — Generic Crypto (mbedTLS, wolfSSL, Botan, BoringSSL)
	// ═══════════════════════════════════════════════════════════════════
	{name: "C mbedTLS RSA", regex: regexp.MustCompile(`mbedtls_rsa_(init|gen_key|pkcs1_sign)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C mbedTLS ECDSA", regex: regexp.MustCompile(`mbedtls_ecdsa_(write_signature|read_signature|sign|verify)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C mbedTLS SHA256", regex: regexp.MustCompile(`mbedtls_sha256\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C mbedTLS AES", regex: regexp.MustCompile(`mbedtls_aes_(setkey_enc|crypt_cbc|crypt_ecb)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C wolfSSL SHA256", regex: regexp.MustCompile(`wc_Sha256(Update|Final|Hash)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C wolfSSL RSA", regex: regexp.MustCompile(`wc_Rsa(PublicEncrypt|PrivateDecrypt|SSL_Sign)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C wolfSSL ECC", regex: regexp.MustCompile(`wc_ecc_(sign_hash|verify_hash|make_key)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ — libsodium
	// ═══════════════════════════════════════════════════════════════════
	{name: "C libsodium sign", regex: regexp.MustCompile(`crypto_sign(_ed25519)?(_detached|_open|_verify_detached)?\s*\(`), algorithms: []string{"Ed25519"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium box", regex: regexp.MustCompile(`crypto_box(_curve25519xsalsa20poly1305)?(_open|_seal|_seal_open)?\s*\(`), algorithms: []string{"X25519"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium aead", regex: regexp.MustCompile(`crypto_aead_(chacha20poly1305|xchacha20poly1305|aes256gcm)_`), algorithms: []string{"ChaCha20-Poly1305"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium secretbox", regex: regexp.MustCompile(`crypto_secretbox(_open|_detached)?\s*\(`), algorithms: []string{"XSalsa20-Poly1305"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium hash", regex: regexp.MustCompile(`crypto_hash_sha(256|512)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libsodium kx", regex: regexp.MustCompile(`crypto_kx_(client_session_keys|server_session_keys)\s*\(`), algorithms: []string{"X25519"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ — Generic Patterns (catch-all for custom implementations)
	// ═══════════════════════════════════════════════════════════════════
	{name: "C/C++ DES usage", regex: regexp.MustCompile(`\bDES_(ecb_encrypt|cbc_encrypt|set_key)\s*\(`), algorithms: []string{"DES"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C/C++ 3DES usage", regex: regexp.MustCompile(`\bDES_ede3_(cbc_encrypt|ecb_encrypt)\s*\(`), algorithms: []string{"3DES"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C/C++ Blowfish", regex: regexp.MustCompile(`\bBF_(set_key|ecb_encrypt|cbc_encrypt)\s*\(`), algorithms: []string{"Blowfish"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C/C++ RC4", regex: regexp.MustCompile(`\bRC4\s*\(`), algorithms: []string{"RC4"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

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
	// PHP openssl_sign — covered by Tier 3 PHP extended pattern (line 745) with broader regex.
	// Removed to avoid double-counting.
	{name: "PHP openssl_encrypt", regex: regexp.MustCompile(`openssl_encrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".php"}},
	{name: "PHP openssl_pkey", regex: regexp.MustCompile(`openssl_pkey_new\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP hash", regex: regexp.MustCompile(`hash\s*\(\s*['"]sha(256|384|512)`), algorithms: []string{"SHA-256"}, languages: []string{".php"}},

	// ═══════════════════════════════════════════════════════════════════
	// Windows CNG (Cryptography Next Generation) — BCrypt* / NCrypt*
	// Used by virtually all Windows government & enterprise applications
	// ═══════════════════════════════════════════════════════════════════
	// Symmetric key operations
	{name: "Win CNG BCryptGenerateSymmetricKey", regex: regexp.MustCompile(`\bBCryptGenerateSymmetricKey\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptEncrypt", regex: regexp.MustCompile(`\bBCryptEncrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptDecrypt", regex: regexp.MustCompile(`\bBCryptDecrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	// Hash operations
	{name: "Win CNG BCryptCreateHash", regex: regexp.MustCompile(`\bBCryptCreateHash\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptHashData", regex: regexp.MustCompile(`\bBCryptHashData\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptFinishHash", regex: regexp.MustCompile(`\bBCryptFinishHash\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	// Asymmetric key operations (quantum-vulnerable)
	{name: "Win CNG BCryptGenerateKeyPair", regex: regexp.MustCompile(`\bBCryptGenerateKeyPair\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptSignHash", regex: regexp.MustCompile(`\bBCryptSignHash\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptVerifySignature", regex: regexp.MustCompile(`\bBCryptVerifySignature\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptDeriveKey", regex: regexp.MustCompile(`\bBCryptDeriveKey\s*\(`), algorithms: []string{"ECDH-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptSecretAgreement", regex: regexp.MustCompile(`\bBCryptSecretAgreement\s*\(`), algorithms: []string{"ECDH-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCryptImportKeyPair", regex: regexp.MustCompile(`\bBCryptImportKeyPair\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	// NCrypt (key storage provider — TPM / smart card)
	{name: "Win CNG NCryptCreatePersistedKey", regex: regexp.MustCompile(`\bNCryptCreatePersistedKey\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG NCryptSignHash", regex: regexp.MustCompile(`\bNCryptSignHash\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG NCryptVerifySignature", regex: regexp.MustCompile(`\bNCryptVerifySignature\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG NCryptDecrypt", regex: regexp.MustCompile(`\bNCryptDecrypt\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	// Legacy CAPI (CryptoAPI v1 — still in legacy gov apps)
	{name: "Win CAPI CryptAcquireContext", regex: regexp.MustCompile(`\bCryptAcquireContext\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CAPI CryptGenKey", regex: regexp.MustCompile(`\bCryptGenKey\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CAPI CryptEncrypt", regex: regexp.MustCompile(`\bCryptEncrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CAPI CryptDecrypt", regex: regexp.MustCompile(`\bCryptDecrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CAPI CryptSignHash", regex: regexp.MustCompile(`\bCryptSignHash\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CAPI CryptVerifySignature", regex: regexp.MustCompile(`\bCryptVerifySignature\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	// Algorithm identifiers (string constants in CNG)
	{name: "Win CNG BCRYPT_RSA_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_RSA_ALGORITHM`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_ECDSA_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_ECD(SA|H)_ALGORITHM`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_DSA_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_DSA_ALGORITHM`), algorithms: []string{"DSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_DH_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_DH_ALGORITHM`), algorithms: []string{"DH-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_AES_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_AES_ALGORITHM`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_3DES_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_3?DES_ALGORITHM`), algorithms: []string{"3DES"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_MD5_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_MD5_ALGORITHM`), algorithms: []string{"MD5"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_SHA1_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_SHA1_ALGORITHM`), algorithms: []string{"SHA-1"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	{name: "Win CNG BCRYPT_SHA256_ALGORITHM", regex: regexp.MustCompile(`BCRYPT_SHA(256|384|512)_ALGORITHM`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".cs"}},
	// .NET / C# P/Invoke and managed CNG wrappers
	{name: "C# CngKey Create", regex: regexp.MustCompile(`CngKey\.Create\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".cs"}},
	{name: "C# ECDsaCng", regex: regexp.MustCompile(`\bECDsaCng\b`), algorithms: []string{"ECDSA-P256"}, languages: []string{".cs"}},
	{name: "C# RSACng", regex: regexp.MustCompile(`\bRSACng\b`), algorithms: []string{"RSA-2048"}, languages: []string{".cs"}},
	{name: "C# ECDiffieHellmanCng", regex: regexp.MustCompile(`\bECDiffieHellmanCng\b`), algorithms: []string{"ECDH-P256"}, languages: []string{".cs"}},
	{name: "C# DSACng", regex: regexp.MustCompile(`\bDSACng\b`), algorithms: []string{"DSA-2048"}, languages: []string{".cs"}},
	{name: "C# TripleDES Create", regex: regexp.MustCompile(`TripleDES\.Create\s*\(`), algorithms: []string{"3DES"}, languages: []string{".cs"}},
	{name: "C# DES Create", regex: regexp.MustCompile(`DES\.Create\s*\(`), algorithms: []string{"DES"}, languages: []string{".cs"}},
	{name: "C# MD5 Create", regex: regexp.MustCompile(`MD5\.(Create|HashData)\s*\(`), algorithms: []string{"MD5"}, languages: []string{".cs"}},
	{name: "C# SHA1 Create", regex: regexp.MustCompile(`SHA1\.(Create|HashData)\s*\(`), algorithms: []string{"SHA-1"}, languages: []string{".cs"}},

	// ═══════════════════════════════════════════════════════════════════
	// Apple CryptoKit (Swift) / CommonCrypto (C) / Security.framework
	// iOS/macOS federal apps — DISA STIG-hardened Apple devices
	// ═══════════════════════════════════════════════════════════════════
	// CryptoKit (Swift — modern Apple crypto)
	{name: "Swift CryptoKit P256 Signing", regex: regexp.MustCompile(`P256\.Signing\.(PrivateKey|PublicKey)`), algorithms: []string{"ECDSA-P256"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit P384 Signing", regex: regexp.MustCompile(`P384\.Signing\.(PrivateKey|PublicKey)`), algorithms: []string{"ECDSA-P384"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit P521 Signing", regex: regexp.MustCompile(`P521\.Signing\.(PrivateKey|PublicKey)`), algorithms: []string{"ECDSA-P521"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit P256 KeyAgreement", regex: regexp.MustCompile(`P256\.KeyAgreement\.(PrivateKey|PublicKey)`), algorithms: []string{"ECDH-P256"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit Curve25519 Signing", regex: regexp.MustCompile(`Curve25519\.Signing\.(PrivateKey|PublicKey)`), algorithms: []string{"Ed25519"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit Curve25519 KeyAgreement", regex: regexp.MustCompile(`Curve25519\.KeyAgreement\.(PrivateKey|PublicKey)`), algorithms: []string{"X25519"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit AES GCM", regex: regexp.MustCompile(`AES\.GCM\.(seal|open|SealedBox)`), algorithms: []string{"AES-256-GCM"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit ChaChaPoly", regex: regexp.MustCompile(`ChaChaPoly\.(seal|open|SealedBox)`), algorithms: []string{"ChaCha20-Poly1305"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit SHA256", regex: regexp.MustCompile(`SHA256\.(hash|Digest)`), algorithms: []string{"SHA-256"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit SHA384", regex: regexp.MustCompile(`SHA384\.(hash|Digest)`), algorithms: []string{"SHA-384"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit SHA512", regex: regexp.MustCompile(`SHA512\.(hash|Digest)`), algorithms: []string{"SHA-512"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit HMAC", regex: regexp.MustCompile(`HMAC<SHA(256|384|512)>`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".swift"}},
	{name: "Swift CryptoKit import", regex: regexp.MustCompile(`import\s+CryptoKit`), algorithms: []string{"ECDSA-P256"}, languages: []string{".swift"}},
	// CommonCrypto (C-level Apple crypto — older but prevalent)
	{name: "Apple CC_SHA256", regex: regexp.MustCompile(`\bCC_SHA(1|256|384|512)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".m", ".mm", ".swift"},
		resolver: func(m []string, _ string) []string {
			if len(m) >= 2 {
				if m[1] == "1" {
					return []string{"SHA-1"}
				}
				return []string{"SHA-" + m[1]}
			}
			return nil
		},
	},
	{name: "Apple CC_SHA256_Init", regex: regexp.MustCompile(`\bCC_SHA(1|256|384|512)_Init\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".m", ".mm"}},
	{name: "Apple CC_SHA256_Update", regex: regexp.MustCompile(`\bCC_SHA(1|256|384|512)_(Update|Final)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".m", ".mm"}},
	{name: "Apple CCCrypt", regex: regexp.MustCompile(`\bCCCrypt\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".m", ".mm", ".swift"}},
	{name: "Apple CCCryptorCreate", regex: regexp.MustCompile(`\bCCCryptorCreate\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".m", ".mm"}},
	{name: "Apple CCHmac", regex: regexp.MustCompile(`\bCCHmac\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".c", ".cpp", ".m", ".mm"}},
	{name: "Apple CCKeyDerivationPBKDF", regex: regexp.MustCompile(`\bCCKeyDerivationPBKDF\s*\(`), algorithms: []string{"PBKDF2-SHA256"}, languages: []string{".c", ".cpp", ".m", ".mm"}},
	{name: "Apple CC_MD5", regex: regexp.MustCompile(`\bCC_MD5\s*\(`), algorithms: []string{"MD5"}, languages: []string{".c", ".cpp", ".m", ".mm"}},
	{name: "Apple kCCAlgorithmDES", regex: regexp.MustCompile(`kCCAlgorithm(DES|3DES|AES|RC4|Blowfish)`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".m", ".mm", ".swift"}},
	{name: "Apple CommonCrypto include", regex: regexp.MustCompile(`#import\s+<CommonCrypto/`), algorithms: []string{"AES-256"}, languages: []string{".m", ".mm"}},
	// Security.framework (Keychain & certificate operations)
	{name: "Apple SecKeyCreateRandomKey", regex: regexp.MustCompile(`\bSecKeyCreateRandomKey\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},
	{name: "Apple SecKeyCreateSignature", regex: regexp.MustCompile(`\bSecKeyCreateSignature\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},
	{name: "Apple SecKeyCreateEncryptedData", regex: regexp.MustCompile(`\bSecKeyCreate(Encrypted|Decrypted)Data\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},
	{name: "Apple SecKeyVerifySignature", regex: regexp.MustCompile(`\bSecKeyVerifySignature\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},
	{name: "Apple SecCertificate", regex: regexp.MustCompile(`\bSecCertificateCreateWith`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},
	{name: "Apple SecTrust", regex: regexp.MustCompile(`\bSecTrustEvaluate`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},
	{name: "Apple kSecAttrKeyTypeRSA", regex: regexp.MustCompile(`kSecAttrKeyType(RSA|EC)`), algorithms: []string{"RSA-2048"}, languages: []string{".swift", ".m", ".mm"}},

	// ═══════════════════════════════════════════════════════════════════
	// Java Bouncy Castle — #1 FIPS crypto provider in enterprise Java
	// ═══════════════════════════════════════════════════════════════════
	// Provider registration
	{name: "Java BC Provider", regex: regexp.MustCompile(`BouncyCastleProvider\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC FIPS Provider", regex: regexp.MustCompile(`BouncyCastleFipsProvider\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".java", ".kt", ".kts"}},
	// Key generators
	{name: "Java BC RSA KeyPairGenerator", regex: regexp.MustCompile(`\bRSAKeyPairGenerator\b`), algorithms: []string{"RSA-2048"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC EC KeyPairGenerator", regex: regexp.MustCompile(`\bECKeyPairGenerator\b`), algorithms: []string{"ECDSA-P256"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC DSA KeyPairGenerator", regex: regexp.MustCompile(`\bDSAKeyPairGenerator\b`), algorithms: []string{"DSA-2048"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC Ed25519 KeyPairGenerator", regex: regexp.MustCompile(`\bEd25519KeyPairGenerator\b`), algorithms: []string{"Ed25519"}, languages: []string{".java", ".kt", ".kts"}},
	// Engines
	{name: "Java BC AESEngine", regex: regexp.MustCompile(`\bAESEngine\b`), algorithms: []string{"AES-256"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC GCMBlockCipher", regex: regexp.MustCompile(`\bGCMBlockCipher\b`), algorithms: []string{"AES-256-GCM"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC CBCBlockCipher", regex: regexp.MustCompile(`\bCBCBlockCipher\b`), algorithms: []string{"AES-256-CBC"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC RSAEngine", regex: regexp.MustCompile(`\bRSAEngine\b`), algorithms: []string{"RSA-2048"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC DESEngine", regex: regexp.MustCompile(`\bDES(ede)?Engine\b`), algorithms: []string{"DES"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC BlowfishEngine", regex: regexp.MustCompile(`\bBlowfishEngine\b`), algorithms: []string{"Blowfish"}, languages: []string{".java", ".kt", ".kts"}},
	// Digests
	{name: "Java BC SHA256Digest", regex: regexp.MustCompile(`\bSHA256Digest\b`), algorithms: []string{"SHA-256"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC SHA1Digest", regex: regexp.MustCompile(`\bSHA1Digest\b`), algorithms: []string{"SHA-1"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC MD5Digest", regex: regexp.MustCompile(`\bMD5Digest\b`), algorithms: []string{"MD5"}, languages: []string{".java", ".kt", ".kts"}},
	// Signers
	{name: "Java BC Ed25519Signer", regex: regexp.MustCompile(`\bEd25519(ph)?Signer\b`), algorithms: []string{"Ed25519"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC RSADigestSigner", regex: regexp.MustCompile(`\bRSADigestSigner\b`), algorithms: []string{"RSA-2048"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC ECDSASigner", regex: regexp.MustCompile(`\bECDSASigner\b`), algorithms: []string{"ECDSA-P256"}, languages: []string{".java", ".kt", ".kts"}},
	// Key agreement
	{name: "Java BC X25519Agreement", regex: regexp.MustCompile(`\bX25519Agreement\b`), algorithms: []string{"X25519"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC ECDHBasicAgreement", regex: regexp.MustCompile(`\bECDH(C)?BasicAgreement\b`), algorithms: []string{"ECDH-P256"}, languages: []string{".java", ".kt", ".kts"}},
	// BC PQC implementations (detect migration progress)
	{name: "Java BC Dilithium", regex: regexp.MustCompile(`\bDilithium(KeyPairGenerator|Signer|Parameters)\b`), algorithms: []string{"ML-DSA"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC Kyber", regex: regexp.MustCompile(`\bKyber(KEMGenerator|KeyPairGenerator|Parameters)\b`), algorithms: []string{"ML-KEM"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "Java BC SPHINCS+", regex: regexp.MustCompile(`\bSPHINCSPlus(KeyPairGenerator|Signer|Parameters)\b`), algorithms: []string{"SLH-DSA"}, languages: []string{".java", ".kt", ".kts"}},
	// BC imports (detect BC dependency)
	{name: "Java BC import org.bouncycastle", regex: regexp.MustCompile(`import\s+org\.bouncycastle\.(crypto|jce|pqc)`), algorithms: []string{"RSA-2048"}, languages: []string{".java", ".kt", ".kts"}},

	// ═══════════════════════════════════════════════════════════════════
	// Shell / CLI Cryptographic Commands
	// DevOps scripts, CI/CD pipelines, certificate management
	// ═══════════════════════════════════════════════════════════════════
	// OpenSSL CLI
	{name: "Shell openssl genrsa", regex: regexp.MustCompile(`openssl\s+genrsa\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl genpkey", regex: regexp.MustCompile(`openssl\s+genpkey\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl req", regex: regexp.MustCompile(`openssl\s+req\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl x509", regex: regexp.MustCompile(`openssl\s+x509\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl s_client", regex: regexp.MustCompile(`openssl\s+s_client\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl dgst", regex: regexp.MustCompile(`openssl\s+dgst\b`), algorithms: []string{"SHA-256"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl enc", regex: regexp.MustCompile(`openssl\s+enc\b`), algorithms: []string{"AES-256"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl pkcs12", regex: regexp.MustCompile(`openssl\s+pkcs12\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl ecparam", regex: regexp.MustCompile(`openssl\s+ecparam\b`), algorithms: []string{"ECDSA-P256"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl ec", regex: regexp.MustCompile(`openssl\s+ec\b`), algorithms: []string{"ECDSA-P256"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell openssl verify", regex: regexp.MustCompile(`openssl\s+verify\b`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	// ssh-keygen
	{name: "Shell ssh-keygen RSA", regex: regexp.MustCompile(`ssh-keygen\s+.*-t\s+rsa`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell ssh-keygen ECDSA", regex: regexp.MustCompile(`ssh-keygen\s+.*-t\s+ecdsa`), algorithms: []string{"ECDSA-P256"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell ssh-keygen Ed25519", regex: regexp.MustCompile(`ssh-keygen\s+.*-t\s+ed25519`), algorithms: []string{"Ed25519"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	// GPG
	{name: "Shell gpg gen-key", regex: regexp.MustCompile(`gpg\s+.*--(gen-key|generate-key|full-generate-key)`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	{name: "Shell gpg encrypt", regex: regexp.MustCompile(`gpg\s+.*--(encrypt|symmetric|sign)`), algorithms: []string{"RSA-2048"}, languages: []string{".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"}},
	// certutil (Windows)
	{name: "Shell certutil", regex: regexp.MustCompile(`certutil\s+.*(-encode|-decode|-hashfile|-verify)`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1", ".bat", ".cmd"}},
	// Makefile/Dockerfile openssl usage
	{name: "Makefile openssl", regex: regexp.MustCompile(`openssl\s+(genrsa|genpkey|req|x509|dgst|enc)`), algorithms: []string{"RSA-2048"}, languages: []string{".mk"}},

	// ═══════════════════════════════════════════════════════════════════
	// C++ Crypto Libraries: Crypto++, Botan, GnuTLS, Mozilla NSS
	// ═══════════════════════════════════════════════════════════════════
	// Crypto++ (CryptoPP namespace)
	{name: "C++ CryptoPP RSA PrivateKey", regex: regexp.MustCompile(`CryptoPP::RSA::(PrivateKey|PublicKey)`), algorithms: []string{"RSA-2048"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP ECDSA", regex: regexp.MustCompile(`CryptoPP::ECDSA<`), algorithms: []string{"ECDSA-P256"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP AES", regex: regexp.MustCompile(`CryptoPP::AES::(Encryption|Decryption)`), algorithms: []string{"AES-256"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP GCM", regex: regexp.MustCompile(`CryptoPP::GCM<`), algorithms: []string{"AES-256-GCM"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP CBC", regex: regexp.MustCompile(`CryptoPP::CBC_Mode<`), algorithms: []string{"AES-256-CBC"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP SHA256", regex: regexp.MustCompile(`CryptoPP::SHA(1|256|384|512)\b`), algorithms: []string{"SHA-256"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP MD5", regex: regexp.MustCompile(`CryptoPP::MD5\b`), algorithms: []string{"MD5"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP DES", regex: regexp.MustCompile(`CryptoPP::(DES|DES_EDE3)\b`), algorithms: []string{"DES"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP Ed25519", regex: regexp.MustCompile(`CryptoPP::ed25519(PrivateKey|PublicKey|Signer|Verifier)`), algorithms: []string{"Ed25519"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ CryptoPP include", regex: regexp.MustCompile(`#include\s+[<"]cryptopp/`), algorithms: []string{"RSA-2048"}, languages: []string{".cpp", ".h", ".hpp"}},
	// Botan
	{name: "C++ Botan RSA PrivateKey", regex: regexp.MustCompile(`Botan::RSA_PrivateKey\b`), algorithms: []string{"RSA-2048"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan ECDSA PrivateKey", regex: regexp.MustCompile(`Botan::ECDSA_PrivateKey\b`), algorithms: []string{"ECDSA-P256"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan Ed25519 PrivateKey", regex: regexp.MustCompile(`Botan::Ed25519_PrivateKey\b`), algorithms: []string{"Ed25519"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan SHA256", regex: regexp.MustCompile(`Botan::SHA_(1|256|384|512)\b`), algorithms: []string{"SHA-256"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan AES", regex: regexp.MustCompile(`Botan::AES_(128|256)\b`), algorithms: []string{"AES-256"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan DES", regex: regexp.MustCompile(`Botan::(DES|TripleDES)\b`), algorithms: []string{"DES"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan TLS Client", regex: regexp.MustCompile(`Botan::TLS::(Client|Server)\b`), algorithms: []string{"RSA-2048"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan X509 Certificate", regex: regexp.MustCompile(`Botan::X509_Certificate\b`), algorithms: []string{"RSA-2048"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan Dilithium", regex: regexp.MustCompile(`Botan::Dilithium_PrivateKey\b`), algorithms: []string{"ML-DSA"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan Kyber", regex: regexp.MustCompile(`Botan::Kyber_PrivateKey\b`), algorithms: []string{"ML-KEM"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "C++ Botan include", regex: regexp.MustCompile(`#include\s+[<"]botan/`), algorithms: []string{"RSA-2048"}, languages: []string{".cpp", ".h", ".hpp"}},
	// GnuTLS
	{name: "C GnuTLS init", regex: regexp.MustCompile(`\bgnutls_(init|global_init)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C GnuTLS handshake", regex: regexp.MustCompile(`\bgnutls_handshake\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C GnuTLS certificate", regex: regexp.MustCompile(`\bgnutls_certificate_set_x509`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C GnuTLS priority set", regex: regexp.MustCompile(`\bgnutls_priority_set\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C GnuTLS include", regex: regexp.MustCompile(`#include\s+[<"]gnutls/gnutls\.h[>"]`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	// Mozilla NSS
	{name: "C NSS PK11 GenerateKeyPair", regex: regexp.MustCompile(`\bPK11_GenerateKeyPair\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS PK11 Sign", regex: regexp.MustCompile(`\bPK11_Sign\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS PK11 Verify", regex: regexp.MustCompile(`\bPK11_Verify\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS PK11 CipherOp", regex: regexp.MustCompile(`\bPK11_CipherOp\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS HASH Create", regex: regexp.MustCompile(`\bHASH_(Create|Begin|Update|End)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS PK11 ImportSymKey", regex: regexp.MustCompile(`\bPK11_ImportSymKey\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS CERT GetDefaultCertDB", regex: regexp.MustCompile(`\bCERT_GetDefaultCertDB\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C NSS include nss.h", regex: regexp.MustCompile(`#include\s+[<"](nss|pk11pub|secmodt)\.h[>"]`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	// libtomcrypt
	{name: "C libtomcrypt rsa_make_key", regex: regexp.MustCompile(`\brsa_make_key\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libtomcrypt ecc_make_key", regex: regexp.MustCompile(`\becc_make_key\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libtomcrypt hash", regex: regexp.MustCompile(`\b(sha256|sha512|md5)_init\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C libtomcrypt include", regex: regexp.MustCompile(`#include\s+[<"]tomcrypt\.h[>"]`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 2: Configuration File Crypto Detection
	// Web servers, SSH daemons, TLS proxy configs
	// ═══════════════════════════════════════════════════════════════════
	// nginx
	{name: "Config nginx ssl_protocols", regex: regexp.MustCompile(`ssl_protocols?\s+.*\b(TLSv1\b|TLSv1\.1|SSLv3|SSLv2)`), algorithms: []string{"TLS-1.0"}, languages: []string{".conf", ".cfg"}},
	{name: "Config nginx ssl_ciphers", regex: regexp.MustCompile(`ssl_ciphers\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg"}},
	{name: "Config nginx ssl_certificate", regex: regexp.MustCompile(`ssl_certificate(_key)?\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg"}},
	// Apache
	{name: "Config Apache SSLProtocol", regex: regexp.MustCompile(`SSLProtocol\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg"}},
	{name: "Config Apache SSLCipherSuite", regex: regexp.MustCompile(`SSLCipherSuite\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg"}},
	{name: "Config Apache SSLCertificateFile", regex: regexp.MustCompile(`SSLCertificate(Key)?File\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg"}},
	// sshd_config
	{name: "Config sshd Ciphers", regex: regexp.MustCompile(`^Ciphers\s+`), algorithms: []string{"AES-256"}, languages: []string{".conf", ".cfg", ".ini"}},
	{name: "Config sshd MACs", regex: regexp.MustCompile(`^MACs\s+`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".conf", ".cfg", ".ini"}},
	{name: "Config sshd KexAlgorithms", regex: regexp.MustCompile(`^KexAlgorithms\s+`), algorithms: []string{"ECDH-P256"}, languages: []string{".conf", ".cfg", ".ini"}},
	{name: "Config sshd HostKeyAlgorithms", regex: regexp.MustCompile(`^HostKeyAlgorithms\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg", ".ini"}},
	{name: "Config sshd PubkeyAcceptedAlgorithms", regex: regexp.MustCompile(`^PubkeyAccepted(Algorithms|KeyTypes)\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg", ".ini"}},
	// Generic TLS config patterns (HAProxy, Envoy, Traefik, etc.)
	{name: "Config TLS min version", regex: regexp.MustCompile(`(tls_?min_?version|min_tls_version|ssl_min_ver)\s*[=:]\s*["']?(TLS1\.0|TLSv1\b|1\.0|TLS1\.1|TLSv1\.1|1\.1)`), algorithms: []string{"TLS-1.0"}, languages: []string{".conf", ".cfg", ".ini", ".yml", ".yaml"}},
	{name: "Config TLS cipher list", regex: regexp.MustCompile(`(cipher_?list|cipher_?suites?|ssl_?ciphers)\s*[=:]`), algorithms: []string{"RSA-2048"}, languages: []string{".conf", ".cfg", ".ini", ".yml", ".yaml"}},
	// Deprecated protocols
	{name: "Config TLSv1.0 reference", regex: regexp.MustCompile(`\b(TLSv1\b|TLS1\.0|ssl_protocols?.*\bTLSv1\b)`), algorithms: []string{"TLS-1.0"}, languages: []string{".yml", ".yaml", ".ini"}},
	{name: "Config SSLv3 reference", regex: regexp.MustCompile(`\b(SSLv3|SSLv2)\b`), algorithms: []string{"SSL-3.0"}, languages: []string{".conf", ".cfg", ".yml", ".yaml", ".ini"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 2: Key Material / Secrets Detection
	// PEM-encoded private keys, cloud provider API keys in source
	// ═══════════════════════════════════════════════════════════════════
	// PEM headers (any language)
	{name: "Secret RSA Private Key PEM", regex: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), algorithms: []string{"RSA-2048"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	{name: "Secret EC Private Key PEM", regex: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), algorithms: []string{"ECDSA-P256"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	{name: "Secret Private Key PEM generic", regex: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`), algorithms: []string{"RSA-2048"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	{name: "Secret OpenSSH Private Key PEM", regex: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), algorithms: []string{"Ed25519"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	{name: "Secret Certificate PEM", regex: regexp.MustCompile(`-----BEGIN CERTIFICATE-----`), algorithms: []string{"RSA-2048"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	{name: "Secret DSA Private Key PEM", regex: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), algorithms: []string{"DSA-2048"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	{name: "Secret Encrypted Private Key PEM", regex: regexp.MustCompile(`-----BEGIN ENCRYPTED PRIVATE KEY-----`), algorithms: []string{"RSA-2048"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},
	// PKCS and DH
	{name: "Secret DH Parameters PEM", regex: regexp.MustCompile(`-----BEGIN DH PARAMETERS-----`), algorithms: []string{"DH-2048"}, languages: []string{".go", ".py", ".java", ".js", ".ts", ".mjs", ".c", ".cpp", ".h", ".hpp", ".rs", ".cs", ".rb", ".php", ".swift", ".m", ".mm", ".kt", ".kts", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".tf"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 2: Python Extended Libraries
	// paramiko, ssl, bcrypt, argon2, x25519, DH
	// ═══════════════════════════════════════════════════════════════════
	// paramiko (SSH library — huge in federal automation)
	{name: "Python paramiko RSAKey", regex: regexp.MustCompile(`paramiko\.(RSAKey|DSSKey|ECDSAKey|Ed25519Key)`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python paramiko Transport", regex: regexp.MustCompile(`paramiko\.Transport\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python paramiko SSHClient", regex: regexp.MustCompile(`paramiko\.SSHClient\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python paramiko import", regex: regexp.MustCompile(`import\s+paramiko`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	// ssl module
	{name: "Python ssl create_default_context", regex: regexp.MustCompile(`ssl\.create_default_context\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python ssl wrap_socket", regex: regexp.MustCompile(`ssl\.wrap_socket\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python ssl SSLContext", regex: regexp.MustCompile(`ssl\.SSLContext\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python ssl PROTOCOL_TLS", regex: regexp.MustCompile(`ssl\.(PROTOCOL_TLSv1|PROTOCOL_SSLv23|PROTOCOL_SSLv3|PROTOCOL_TLS\b)`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	// bcrypt
	{name: "Python bcrypt hashpw", regex: regexp.MustCompile(`bcrypt\.(hashpw|checkpw|gensalt)\s*\(`), algorithms: []string{"Bcrypt"}, languages: []string{".py"}},
	{name: "Python bcrypt import", regex: regexp.MustCompile(`import\s+bcrypt`), algorithms: []string{"Bcrypt"}, languages: []string{".py"}},
	// argon2
	{name: "Python argon2 PasswordHasher", regex: regexp.MustCompile(`argon2\.PasswordHasher\s*\(`), algorithms: []string{"Argon2"}, languages: []string{".py"}},
	{name: "Python argon2 hash", regex: regexp.MustCompile(`argon2\.(hash|verify)\s*\(`), algorithms: []string{"Argon2"}, languages: []string{".py"}},
	// cryptography library extended
	{name: "Python X25519 PrivateKey", regex: regexp.MustCompile(`x25519\.X25519PrivateKey\.generate\s*\(`), algorithms: []string{"X25519"}, languages: []string{".py"}},
	{name: "Python X448 PrivateKey", regex: regexp.MustCompile(`x448\.X448PrivateKey\.generate\s*\(`), algorithms: []string{"X448"}, languages: []string{".py"}},
	{name: "Python Ed448 PrivateKey", regex: regexp.MustCompile(`ed448\.Ed448PrivateKey\.generate\s*\(`), algorithms: []string{"Ed448"}, languages: []string{".py"}},
	{name: "Python DH generate_parameters", regex: regexp.MustCompile(`dh\.generate_parameters\s*\(`), algorithms: []string{"DH-2048"}, languages: []string{".py"}},
	{name: "Python DH generate_private_key", regex: regexp.MustCompile(`dh\.DHParameterNumbers.*generate_private_key`), algorithms: []string{"DH-2048"}, languages: []string{".py"}},
	{name: "Python serialization PEM", regex: regexp.MustCompile(`serialization\.(Encoding\.PEM|BestAvailableEncryption|NoEncryption)`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python load_pem_private_key", regex: regexp.MustCompile(`load_(pem|der)_private_key\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	// PyCryptodome
	{name: "Python PyCryptodome RSA", regex: regexp.MustCompile(`Crypto\.PublicKey\.RSA\.(generate|import_key)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python PyCryptodome ECC", regex: regexp.MustCompile(`Crypto\.PublicKey\.ECC\.generate\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".py"}},
	{name: "Python PyCryptodome DSA", regex: regexp.MustCompile(`Crypto\.PublicKey\.DSA\.generate\s*\(`), algorithms: []string{"DSA-2048"}, languages: []string{".py"}},
	{name: "Python PyCryptodome AES", regex: regexp.MustCompile(`Crypto\.Cipher\.AES\.new\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".py"}},
	{name: "Python PyCryptodome DES3", regex: regexp.MustCompile(`Crypto\.Cipher\.(DES3|DES)\.new\s*\(`), algorithms: []string{"3DES"}, languages: []string{".py"}},
	{name: "Python PyCryptodome SHA256", regex: regexp.MustCompile(`Crypto\.Hash\.SHA(256|384|512)\.new\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".py"}},
	{name: "Python PyCryptodome MD5", regex: regexp.MustCompile(`Crypto\.Hash\.MD5\.new\s*\(`), algorithms: []string{"MD5"}, languages: []string{".py"}},
	{name: "Python PyCryptodome PKCS1_OAEP", regex: regexp.MustCompile(`Crypto\.Cipher\.PKCS1_OAEP\.new\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	{name: "Python PyCryptodome import", regex: regexp.MustCompile(`from\s+Crypto\.(PublicKey|Cipher|Hash|Signature)\s+import`), algorithms: []string{"RSA-2048"}, languages: []string{".py"}},
	// scrypt
	{name: "Python scrypt", regex: regexp.MustCompile(`Scrypt\s*\(|hashlib\.scrypt\s*\(`), algorithms: []string{"Scrypt"}, languages: []string{".py"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 2: Kotlin / Android Keystore
	// Android app crypto — widely deployed in gov mobile apps
	// ═══════════════════════════════════════════════════════════════════
	{name: "Kotlin AndroidKeyStore", regex: regexp.MustCompile(`KeyStore\.getInstance\s*\(\s*"AndroidKeyStore"\s*\)`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin KeyPairGenerator AndroidKeyStore", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"(RSA|EC)"\s*,\s*"AndroidKeyStore"\s*\)`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin KeyGenerator AndroidKeyStore", regex: regexp.MustCompile(`KeyGenerator\.getInstance\s*\(\s*"AES"\s*,\s*"AndroidKeyStore"\s*\)`), algorithms: []string{"AES-256"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin KeyGenParameterSpec", regex: regexp.MustCompile(`KeyGenParameterSpec\.Builder\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin KeyProperties PURPOSE", regex: regexp.MustCompile(`KeyProperties\.(PURPOSE_ENCRYPT|PURPOSE_DECRYPT|PURPOSE_SIGN|PURPOSE_VERIFY)`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin Cipher getInstance", regex: regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"(RSA|AES|DES|DESede|Blowfish)[/"]`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin Mac getInstance", regex: regexp.MustCompile(`Mac\.getInstance\s*\(\s*"Hmac(SHA256|SHA384|SHA512|SHA1|MD5)"\s*\)`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin MessageDigest getInstance", regex: regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"(SHA-256|SHA-384|SHA-512|SHA-1|MD5)"\s*\)`), algorithms: []string{"SHA-256"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin KeyPairGenerator getInstance", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"(RSA|EC|DSA|DH)"\s*\)`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin KeyAgreement getInstance", regex: regexp.MustCompile(`KeyAgreement\.getInstance\s*\(\s*"(ECDH|DH|X25519)"\s*\)`), algorithms: []string{"ECDH-P256"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin Signature getInstance", regex: regexp.MustCompile(`Signature\.getInstance\s*\(\s*"(SHA256withRSA|SHA256withECDSA|SHA384withRSA|SHA512withRSA|SHA1withRSA|MD5withRSA|Ed25519)"\s*\)`), algorithms: []string{"RSA-2048"}, languages: []string{".kt", ".kts", ".java"}},
	{name: "Kotlin SecretKeySpec", regex: regexp.MustCompile(`SecretKeySpec\s*\([^,]+,\s*"(AES|DES|DESede|Blowfish|HmacSHA256)"\s*\)`), algorithms: []string{"AES-256"}, languages: []string{".kt", ".kts", ".java"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 2: Infrastructure as Code
	// Terraform, CloudFormation, Ansible, Docker
	// ═══════════════════════════════════════════════════════════════════
	// Terraform
	{name: "IaC Terraform tls_private_key", regex: regexp.MustCompile(`resource\s+"tls_private_key"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform tls_cert_request", regex: regexp.MustCompile(`resource\s+"tls_cert_request"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform tls_self_signed_cert", regex: regexp.MustCompile(`resource\s+"tls_self_signed_cert"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform tls_locally_signed_cert", regex: regexp.MustCompile(`resource\s+"tls_locally_signed_cert"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform algorithm RSA", regex: regexp.MustCompile(`algorithm\s*=\s*"(RSA|ECDSA)"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform rsa_bits", regex: regexp.MustCompile(`rsa_bits\s*=\s*`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform ecdsa_curve", regex: regexp.MustCompile(`ecdsa_curve\s*=\s*"(P256|P384|P521)"`), algorithms: []string{"ECDSA-P256"}, languages: []string{".tf"}},
	{name: "IaC Terraform aws_acm_certificate", regex: regexp.MustCompile(`resource\s+"aws_acm_certificate"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform aws_kms_key", regex: regexp.MustCompile(`resource\s+"aws_kms_key"`), algorithms: []string{"AES-256"}, languages: []string{".tf"}},
	{name: "IaC Terraform aws_kms KeySpec", regex: regexp.MustCompile(`key_spec\s*=\s*"(RSA_2048|RSA_4096|ECC_NIST_P256|ECC_NIST_P384|SYMMETRIC_DEFAULT)"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform azurerm_key_vault_key", regex: regexp.MustCompile(`resource\s+"azurerm_key_vault_(key|certificate)"`), algorithms: []string{"RSA-2048"}, languages: []string{".tf"}},
	{name: "IaC Terraform google_kms_crypto_key", regex: regexp.MustCompile(`resource\s+"google_kms_crypto_key"`), algorithms: []string{"AES-256"}, languages: []string{".tf"}},
	// CloudFormation / YAML infrastructure
	{name: "IaC CF ACM Certificate", regex: regexp.MustCompile(`AWS::CertificateManager::Certificate`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC CF KMS Key", regex: regexp.MustCompile(`AWS::KMS::Key`), algorithms: []string{"AES-256"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC CF KMS KeySpec", regex: regexp.MustCompile(`KeySpec:\s*(RSA_2048|RSA_4096|ECC_NIST_P256|ECC_NIST_P384|SYMMETRIC_DEFAULT)`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC CF Secrets Manager", regex: regexp.MustCompile(`AWS::SecretsManager::Secret`), algorithms: []string{"AES-256"}, languages: []string{".yml", ".yaml"}},
	// Ansible
	{name: "IaC Ansible openssl_privatekey", regex: regexp.MustCompile(`openssl_privatekey:`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC Ansible openssl_certificate", regex: regexp.MustCompile(`openssl_certificate:`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC Ansible openssl_csr", regex: regexp.MustCompile(`openssl_csr:`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC Ansible crypto_info", regex: regexp.MustCompile(`community\.crypto\.(openssl_privatekey|x509_certificate|openssl_csr)`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC Ansible type RSA", regex: regexp.MustCompile(`type:\s*(RSA|ECC|DSA)\b`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC Ansible size/bits", regex: regexp.MustCompile(`(size|bits):\s*(1024|2048|4096)\b`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	// Docker / Kubernetes TLS
	{name: "IaC K8s tls.crt/tls.key", regex: regexp.MustCompile(`\btls\.(crt|key):\s*`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC K8s Secret type TLS", regex: regexp.MustCompile(`type:\s*kubernetes\.io/tls`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC K8s cert-manager", regex: regexp.MustCompile(`cert-manager\.io/`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "IaC Helm tls enabled", regex: regexp.MustCompile(`tls:\s*\n\s+enabled:\s*true`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Dart / Flutter
	// pointycastle, crypto, encrypt packages
	// ═══════════════════════════════════════════════════════════════════
	{name: "Dart pointycastle RSA", regex: regexp.MustCompile(`RSAEngine\(\)|RSAKeyGenerator(Parameters)?\(`), algorithms: []string{"RSA-2048"}, languages: []string{".dart"}},
	{name: "Dart pointycastle AES", regex: regexp.MustCompile(`AESFastEngine\(\)|AESEngine\(\)`), algorithms: []string{"AES-256"}, languages: []string{".dart"}},
	{name: "Dart pointycastle SHA", regex: regexp.MustCompile(`SHA256Digest\(\)|SHA384Digest\(\)|SHA512Digest\(\)|MD5Digest\(\)`), algorithms: []string{"SHA-256"}, languages: []string{".dart"}},
	{name: "Dart pointycastle EC", regex: regexp.MustCompile(`ECDSASigner\(\)|ECDHBasicAgreement\(\)|ECKeyGenerator(Parameters)?\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".dart"}},
	{name: "Dart pointycastle GCM", regex: regexp.MustCompile(`GCMBlockCipher\(|CBCBlockCipher\(|CTRBlockCipher\(`), algorithms: []string{"AES-256"}, languages: []string{".dart"}},
	{name: "Dart pointycastle HMAC", regex: regexp.MustCompile(`HMac\(|PBKDF2KeyDerivator\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".dart"}},
	{name: "Dart pointycastle import", regex: regexp.MustCompile(`import\s+['"]package:pointycastle/`), algorithms: []string{"RSA-2048"}, languages: []string{".dart"}},
	{name: "Dart crypto package", regex: regexp.MustCompile(`import\s+['"]package:crypto/`), algorithms: []string{"SHA-256"}, languages: []string{".dart"}},
	{name: "Dart encrypt package", regex: regexp.MustCompile(`import\s+['"]package:encrypt/`), algorithms: []string{"AES-256"}, languages: []string{".dart"}},
	{name: "Dart crypto sha256", regex: regexp.MustCompile(`\b(sha256|sha384|sha512|md5|sha1)\.(convert|newInstance)\b`), algorithms: []string{"SHA-256"}, languages: []string{".dart"}},
	{name: "Dart Encrypter AES", regex: regexp.MustCompile(`Encrypter\(AES\(`), algorithms: []string{"AES-256"}, languages: []string{".dart"}},
	{name: "Dart RSA KeyPair", regex: regexp.MustCompile(`RSAKeyPair|RSAPublicKey|RSAPrivateKey`), algorithms: []string{"RSA-2048"}, languages: []string{".dart"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Perl
	// Crypt::OpenSSL, Digest, Net::SSLeay — legacy federal systems
	// ═══════════════════════════════════════════════════════════════════
	{name: "Perl Crypt::OpenSSL::RSA", regex: regexp.MustCompile(`Crypt::OpenSSL::RSA`), algorithms: []string{"RSA-2048"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Crypt::OpenSSL::AES", regex: regexp.MustCompile(`Crypt::OpenSSL::(AES|DSA|EC|X509|Random)`), algorithms: []string{"AES-256"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Crypt::RSA", regex: regexp.MustCompile(`Crypt::(RSA|DSA|DES|Blowfish|Rijndael|Twofish|RC4|CAST5)`), algorithms: []string{"RSA-2048"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Crypt::CBC", regex: regexp.MustCompile(`Crypt::(CBC|ECB|GCM|Mode::\w+)`), algorithms: []string{"AES-256"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Digest::SHA", regex: regexp.MustCompile(`Digest::(SHA|SHA256|SHA384|SHA512|MD5|SHA1|HMAC)`), algorithms: []string{"SHA-256"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Net::SSLeay", regex: regexp.MustCompile(`Net::SSLeay`), algorithms: []string{"RSA-2048"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Crypt::PK::RSA", regex: regexp.MustCompile(`Crypt::PK::(RSA|ECC|DSA|DH|Ed25519|X25519)`), algorithms: []string{"RSA-2048"}, languages: []string{".pl", ".pm"}},
	{name: "Perl Crypt::JWT", regex: regexp.MustCompile(`Crypt::(JWT|Misc|AuthEnc|KeyWrap)`), algorithms: []string{"RSA-2048"}, languages: []string{".pl", ".pm"}},
	{name: "Perl use Crypt import", regex: regexp.MustCompile(`use\s+Crypt::`), algorithms: []string{"RSA-2048"}, languages: []string{".pl", ".pm"}},
	{name: "Perl use Digest import", regex: regexp.MustCompile(`use\s+Digest::`), algorithms: []string{"SHA-256"}, languages: []string{".pl", ".pm"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: PowerShell (.NET crypto via PowerShell)
	// System.Security.Cryptography classes invoked from PS scripts
	// ═══════════════════════════════════════════════════════════════════
	{name: "PS RSA Create", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.(RSA|RSACryptoServiceProvider)\]::Create`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1"}},
	{name: "PS ECDSA Create", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.(ECDsa|ECDiffieHellman)\]::Create`), algorithms: []string{"ECDSA-P256"}, languages: []string{".ps1"}},
	{name: "PS AES Create", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.(Aes|AesCryptoServiceProvider|AesManaged)\]::Create`), algorithms: []string{"AES-256"}, languages: []string{".ps1"}},
	{name: "PS TripleDES Create", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.(TripleDES|DES|DESCryptoServiceProvider)\]::Create`), algorithms: []string{"3DES"}, languages: []string{".ps1"}},
	{name: "PS SHA Create", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.(SHA256|SHA384|SHA512|MD5|SHA1)(Managed|CryptoServiceProvider|Cng)?\]::Create`), algorithms: []string{"SHA-256"}, languages: []string{".ps1"}},
	{name: "PS HMAC", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.HMAC(SHA256|SHA384|SHA512|SHA1|MD5)\]`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".ps1"}},
	{name: "PS X509Certificate2", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.X509Certificates\.X509Certificate2\]`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1"}},
	{name: "PS RSACng", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.(RSACng|DSACng|ECDsaCng|ECDiffieHellmanCng)\]`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1"}},
	{name: "PS ConvertTo-SecureString", regex: regexp.MustCompile(`ConvertTo-SecureString`), algorithms: []string{"AES-256"}, languages: []string{".ps1"}},
	{name: "PS Get-PfxCertificate", regex: regexp.MustCompile(`Get-PfxCertificate`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1"}},
	{name: "PS New-SelfSignedCertificate", regex: regexp.MustCompile(`New-SelfSignedCertificate`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1"}},
	{name: "PS Invoke-WebRequest TLS", regex: regexp.MustCompile(`\[Net\.ServicePointManager\]::SecurityProtocol`), algorithms: []string{"RSA-2048"}, languages: []string{".ps1"}},
	{name: "PS Rfc2898DeriveBytes", regex: regexp.MustCompile(`\[System\.Security\.Cryptography\.Rfc2898DeriveBytes\]`), algorithms: []string{"PBKDF2"}, languages: []string{".ps1"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Weak / Insecure RNG Detection
	// Non-cryptographic PRNGs used where CSPRNG is required
	// ═══════════════════════════════════════════════════════════════════
	// JavaScript
	{name: "WeakRNG JS Math.random", regex: regexp.MustCompile(`Math\.random\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".js", ".ts", ".mjs"}},
	// Python
	{name: "WeakRNG Python random", regex: regexp.MustCompile(`\brandom\.(random|randint|choice|shuffle|sample|randrange)\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".py"}},
	// C/C++
	{name: "WeakRNG C rand", regex: regexp.MustCompile(`\b(rand|srand)\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	// Java
	{name: "WeakRNG Java Random", regex: regexp.MustCompile(`new\s+Random\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "WeakRNG Java Math.random", regex: regexp.MustCompile(`Math\.random\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".java", ".kt", ".kts"}},
	// Go
	{name: "WeakRNG Go math/rand", regex: regexp.MustCompile(`math/rand"|(rand\.Intn|rand\.Int63|rand\.Float64|rand\.New\(rand\.NewSource)\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".go"}},
	// Ruby
	{name: "WeakRNG Ruby rand", regex: regexp.MustCompile(`\brand\s*\(|Random\.new\b`), algorithms: []string{"WEAK-RNG"}, languages: []string{".rb"}},
	// PHP
	{name: "WeakRNG PHP rand", regex: regexp.MustCompile(`\b(rand|mt_rand|array_rand|shuffle)\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".php"}},
	// C#
	{name: "WeakRNG CS Random", regex: regexp.MustCompile(`new\s+Random\s*\(`), algorithms: []string{"WEAK-RNG"}, languages: []string{".cs"}},
	// Rust
	{name: "WeakRNG Rust thread_rng", regex: regexp.MustCompile(`thread_rng\(\)|SmallRng::seed_from_u64`), algorithms: []string{"WEAK-RNG"}, languages: []string{".rs"}},
	// Dart
	{name: "WeakRNG Dart Random", regex: regexp.MustCompile(`Random\(\)|Random\(\d+\)`), algorithms: []string{"WEAK-RNG"}, languages: []string{".dart"}},
	{name: "Dart Random.secure CSPRNG", regex: regexp.MustCompile(`Random\.secure\(\)`), algorithms: []string{"CSPRNG"}, languages: []string{".dart"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: XML Crypto — SAML, XML-DSig, WS-Security, XKMS
	// Huge in legacy federal systems (identity federation, SOAP services)
	// ═══════════════════════════════════════════════════════════════════
	// XML-DSig
	{name: "XML DSig SignedInfo", regex: regexp.MustCompile(`<(ds:)?SignedInfo\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig SignatureMethod", regex: regexp.MustCompile(`<(ds:)?SignatureMethod\s+Algorithm=`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig DigestMethod", regex: regexp.MustCompile(`<(ds:)?DigestMethod\s+Algorithm=`), algorithms: []string{"SHA-256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig RSA-SHA256", regex: regexp.MustCompile(`rsa-sha(1|256|384|512)`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig ECDSA-SHA256", regex: regexp.MustCompile(`ecdsa-sha(256|384|512)`), algorithms: []string{"ECDSA-P256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig hmac-sha", regex: regexp.MustCompile(`hmac-sha(1|256|384|512)`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig xmldsig namespace", regex: regexp.MustCompile(`xmlns.*xmldsig|www\.w3\.org/2000/09/xmldsig`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig X509Certificate element", regex: regexp.MustCompile(`<(ds:)?X509Certificate\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML DSig KeyInfo", regex: regexp.MustCompile(`<(ds:)?KeyInfo\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	// SAML
	{name: "XML SAML Assertion", regex: regexp.MustCompile(`<saml[p2]?:Assertion\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".saml"}},
	{name: "XML SAML AuthnRequest", regex: regexp.MustCompile(`<samlp:AuthnRequest\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".saml"}},
	{name: "XML SAML EncryptedAssertion", regex: regexp.MustCompile(`<saml:EncryptedAssertion\b`), algorithms: []string{"AES-256"}, languages: []string{".xml", ".saml"}},
	{name: "XML SAML namespace", regex: regexp.MustCompile(`urn:oasis:names:tc:SAML`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".saml", ".yml", ".yaml", ".conf"}},
	// WS-Security
	{name: "XML WS-Security header", regex: regexp.MustCompile(`<wsse:Security\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl"}},
	{name: "XML WS-Security BinarySecurityToken", regex: regexp.MustCompile(`<wsse:BinarySecurityToken\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl"}},
	{name: "XML WS-Security UsernameToken", regex: regexp.MustCompile(`<wsse:UsernameToken\b`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl"}},
	{name: "XML WS-Security namespace", regex: regexp.MustCompile(`wsse.*oasis.*wss|oasis-wss-wssecurity`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl"}},
	// XML Encryption
	{name: "XML EncryptedData", regex: regexp.MustCompile(`<(xenc:)?EncryptedData\b`), algorithms: []string{"AES-256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML EncryptionMethod", regex: regexp.MustCompile(`<(xenc:)?EncryptionMethod\s+Algorithm=`), algorithms: []string{"AES-256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML xmlenc namespace", regex: regexp.MustCompile(`xmlns.*xmlenc|www\.w3\.org/2001/04/xmlenc`), algorithms: []string{"AES-256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	// XML encryption algorithm URIs
	{name: "XML aes128-cbc URI", regex: regexp.MustCompile(`aes128-cbc|aes256-cbc|aes192-cbc`), algorithms: []string{"AES-256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML aes128-gcm URI", regex: regexp.MustCompile(`aes128-gcm|aes256-gcm`), algorithms: []string{"AES-256"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML rsa-oaep URI", regex: regexp.MustCompile(`rsa-oaep(-mgf1p)?`), algorithms: []string{"RSA-2048"}, languages: []string{".xml", ".wsdl", ".saml"}},
	{name: "XML tripledes-cbc URI", regex: regexp.MustCompile(`tripledes-cbc`), algorithms: []string{"3DES"}, languages: []string{".xml", ".wsdl", ".saml"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Docker / Container Extended
	// Dockerfile TLS, compose crypto, registry trust
	// ═══════════════════════════════════════════════════════════════════
	{name: "Docker FROM with TLS", regex: regexp.MustCompile(`COPY\s+.*\.(crt|key|pem)\s+`), algorithms: []string{"RSA-2048"}, languages: []string{".dockerfile"}},
	{name: "Docker ENV SSL_CERT", regex: regexp.MustCompile(`ENV\s+(SSL_CERT|TLS_CERT|SSL_KEY|TLS_KEY|CA_CERT)`), algorithms: []string{"RSA-2048"}, languages: []string{".dockerfile"}},
	{name: "Docker openssl in RUN", regex: regexp.MustCompile(`RUN\s+.*openssl\s+(genrsa|req|x509|s_client|genpkey)`), algorithms: []string{"RSA-2048"}, languages: []string{".dockerfile"}},
	{name: "Docker EXPOSE 443", regex: regexp.MustCompile(`EXPOSE\s+443`), algorithms: []string{"RSA-2048"}, languages: []string{".dockerfile"}},
	{name: "Docker update-ca-certificates", regex: regexp.MustCompile(`update-ca-certificates`), algorithms: []string{"RSA-2048"}, languages: []string{".dockerfile"}},
	// docker-compose
	{name: "Docker compose secrets", regex: regexp.MustCompile(`secrets:\s*\n`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},
	{name: "Docker compose HTTPS_PORT", regex: regexp.MustCompile(`HTTPS_PORT|SSL_PORT|TLS_PORT`), algorithms: []string{"RSA-2048"}, languages: []string{".yml", ".yaml"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Protocol Buffers (.proto crypto fields)
	// gRPC services with crypto-related field names
	// ═══════════════════════════════════════════════════════════════════
	{name: "Proto crypto field", regex: regexp.MustCompile(`\b(bytes|string)\s+(public_key|private_key|secret_key|signature|certificate|encrypted|cipher_text|hmac|digest|hash|nonce|salt|iv|token|api_key)\s*=`), algorithms: []string{"RSA-2048"}, languages: []string{".proto"}},
	{name: "Proto TLS config", regex: regexp.MustCompile(`\b(tls_cert|tls_key|ca_cert|ssl_cert|ssl_key|client_cert|server_cert)\s*=`), algorithms: []string{"RSA-2048"}, languages: []string{".proto"}},
	{name: "Proto crypto message", regex: regexp.MustCompile(`message\s+(Certificate|Signature|EncryptedData|KeyPair|CryptoKey|SignedMessage|AuthToken)\s*\{`), algorithms: []string{"RSA-2048"}, languages: []string{".proto"}},
	{name: "Proto crypto service", regex: regexp.MustCompile(`rpc\s+(Sign|Verify|Encrypt|Decrypt|GenerateKey|DeriveKey|Hash|Seal|Open)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".proto"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Node.js crypto / tls / forge
	// Extended JS/TS crypto beyond the basics already covered
	// ═══════════════════════════════════════════════════════════════════
	{name: "Node crypto createCipher", regex: regexp.MustCompile(`crypto\.create(Cipher|Decipher)(iv)?\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto createSign", regex: regexp.MustCompile(`crypto\.create(Sign|Verify)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto createHash", regex: regexp.MustCompile(`crypto\.createHash\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto createHmac", regex: regexp.MustCompile(`crypto\.createHmac\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto generateKeyPair", regex: regexp.MustCompile(`crypto\.generateKeyPair(Sync)?\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto createDiffieHellman", regex: regexp.MustCompile(`crypto\.createDiffieHellman(Group)?\s*\(`), algorithms: []string{"DH-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto createECDH", regex: regexp.MustCompile(`crypto\.createECDH\s*\(`), algorithms: []string{"ECDH-P256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto pbkdf2", regex: regexp.MustCompile(`crypto\.pbkdf2(Sync)?\s*\(`), algorithms: []string{"PBKDF2"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto scrypt", regex: regexp.MustCompile(`crypto\.scrypt(Sync)?\s*\(`), algorithms: []string{"Scrypt"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto randomBytes", regex: regexp.MustCompile(`crypto\.randomBytes\s*\(`), algorithms: []string{"CSPRNG"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node crypto X509Certificate", regex: regexp.MustCompile(`crypto\.X509Certificate|new X509Certificate\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node tls createServer", regex: regexp.MustCompile(`tls\.create(Server|SecureContext)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node tls connect", regex: regexp.MustCompile(`tls\.connect\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node tls minVersion", regex: regexp.MustCompile(`minVersion:\s*['"]TLS`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	// node-forge
	{name: "Node forge RSA", regex: regexp.MustCompile(`forge\.(pki|rsa)\.(generateKeyPair|setPublicKey|certificationRequest|createCertificate)`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node forge AES", regex: regexp.MustCompile(`forge\.cipher\.(createCipher|createDecipher)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node forge SHA", regex: regexp.MustCompile(`forge\.md\.(sha256|sha384|sha512|sha1|md5)\.create\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node forge HMAC", regex: regexp.MustCompile(`forge\.hmac\.create\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node forge import", regex: regexp.MustCompile(`require\s*\(\s*['"]node-forge['"]\s*\)|from\s+['"]node-forge['"]`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	// jose (JWT library)
	{name: "Node jose JWT", regex: regexp.MustCompile(`(jose|jsonwebtoken)\.(sign|verify|encrypt|decrypt)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	{name: "Node jose import", regex: regexp.MustCompile(`require\s*\(\s*['"]jose['"]\s*\)|from\s+['"]jose['"]`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},
	// SubtleCrypto (Web Crypto API / Node 16+)
	{name: "Node SubtleCrypto", regex: regexp.MustCompile(`(crypto\.)?subtle\.(encrypt|decrypt|sign|verify|generateKey|importKey|deriveKey|deriveBits|digest|wrapKey|unwrapKey|exportKey)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".js", ".ts", ".mjs"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Rust Crypto Libraries (Extended)
	// ring, RustCrypto, rustls
	// ═══════════════════════════════════════════════════════════════════
	{name: "Rust ring RSA", regex: regexp.MustCompile(`ring::(signature|agreement|aead|digest|hmac|pbkdf2|rand)`), algorithms: []string{"RSA-2048"}, languages: []string{".rs"}},
	{name: "Rust ring import", regex: regexp.MustCompile(`use\s+ring::`), algorithms: []string{"RSA-2048"}, languages: []string{".rs"}},
	{name: "Rust RustCrypto sha2", regex: regexp.MustCompile(`(sha2|sha3|md5|aes|des|rsa|ed25519_dalek|x25519_dalek|chacha20poly1305)::`), algorithms: []string{"SHA-256"}, languages: []string{".rs"}},
	{name: "Rust rustls", regex: regexp.MustCompile(`rustls::(ServerConfig|ClientConfig|Certificate|PrivateKey)`), algorithms: []string{"RSA-2048"}, languages: []string{".rs"}},
	{name: "Rust native-tls", regex: regexp.MustCompile(`native_tls::(TlsConnector|TlsAcceptor|Identity)`), algorithms: []string{"RSA-2048"}, languages: []string{".rs"}},
	{name: "Rust openssl crate", regex: regexp.MustCompile(`openssl::(ssl|pkey|rsa|ec|x509|hash|sign|symm)::`), algorithms: []string{"RSA-2048"}, languages: []string{".rs"}},
	{name: "Rust pqcrypto", regex: regexp.MustCompile(`pqcrypto::(kem|sign)::(dilithium|kyber|sphincs)`), algorithms: []string{"ML-DSA-65"}, languages: []string{".rs"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: Ruby Crypto Libraries (Extended)
	// OpenSSL, bcrypt, rbnacl, jwt
	// ═══════════════════════════════════════════════════════════════════
	{name: "Ruby OpenSSL PKey RSA", regex: regexp.MustCompile(`OpenSSL::PKey::(RSA|EC|DSA|DH)\.new`), algorithms: []string{"RSA-2048"}, languages: []string{".rb"}},
	{name: "Ruby OpenSSL Cipher", regex: regexp.MustCompile(`OpenSSL::Cipher(\.new)?\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".rb"}},
	{name: "Ruby OpenSSL Digest", regex: regexp.MustCompile(`OpenSSL::Digest(\.new)?\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".rb"}},
	{name: "Ruby OpenSSL HMAC", regex: regexp.MustCompile(`OpenSSL::HMAC\.(digest|hexdigest|new)\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".rb"}},
	{name: "Ruby OpenSSL X509", regex: regexp.MustCompile(`OpenSSL::X509::(Certificate|Request|CRL|Store)\.new`), algorithms: []string{"RSA-2048"}, languages: []string{".rb"}},
	{name: "Ruby OpenSSL SSL", regex: regexp.MustCompile(`OpenSSL::SSL::(SSLContext|SSLSocket|SSLServer)\.new`), algorithms: []string{"RSA-2048"}, languages: []string{".rb"}},
	{name: "Ruby bcrypt", regex: regexp.MustCompile(`BCrypt::Password\.(new|create)\s*\(`), algorithms: []string{"Bcrypt"}, languages: []string{".rb"}},
	{name: "Ruby rbnacl", regex: regexp.MustCompile(`RbNaCl::(SigningKey|VerifyKey|PrivateKey|PublicKey|SecretBox|SimpleBox)`), algorithms: []string{"Ed25519"}, languages: []string{".rb"}},
	{name: "Ruby JWT", regex: regexp.MustCompile(`JWT\.(encode|decode)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".rb"}},
	{name: "Ruby Digest SHA", regex: regexp.MustCompile(`Digest::(SHA256|SHA384|SHA512|SHA1|MD5)\.(hexdigest|digest|new)`), algorithms: []string{"SHA-256"}, languages: []string{".rb"}},

	// ═══════════════════════════════════════════════════════════════════
	// TIER 3: PHP Crypto Libraries (Extended)
	// OpenSSL ext, Sodium, mcrypt, password_hash
	// ═══════════════════════════════════════════════════════════════════
	{name: "PHP openssl_pkey_new", regex: regexp.MustCompile(`openssl_pkey_(new|get_public|get_private|export)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP openssl_sign", regex: regexp.MustCompile(`openssl_(sign|verify|encrypt|decrypt|seal|open)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP openssl_cipher", regex: regexp.MustCompile(`openssl_(cipher_iv_length|encrypt|decrypt)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".php"}},
	{name: "PHP openssl_digest", regex: regexp.MustCompile(`openssl_digest\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".php"}},
	{name: "PHP openssl_x509", regex: regexp.MustCompile(`openssl_x509_(parse|checkpurpose|verify|export|read)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP openssl_csr", regex: regexp.MustCompile(`openssl_csr_(new|sign|export)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".php"}},
	{name: "PHP sodium", regex: regexp.MustCompile(`sodium_(crypto_sign|crypto_box|crypto_secretbox|crypto_aead|crypto_pwhash|crypto_kx)\s*\(`), algorithms: []string{"Ed25519"}, languages: []string{".php"}},
	{name: "PHP password_hash", regex: regexp.MustCompile(`password_(hash|verify|needs_rehash)\s*\(`), algorithms: []string{"Bcrypt"}, languages: []string{".php"}},
	{name: "PHP hash function", regex: regexp.MustCompile(`\bhash\s*\(\s*['"]`), algorithms: []string{"SHA-256"}, languages: []string{".php"}},
	{name: "PHP hash_hmac", regex: regexp.MustCompile(`hash_hmac\s*\(`), algorithms: []string{"HMAC-SHA256"}, languages: []string{".php"}},
	{name: "PHP hash_pbkdf2", regex: regexp.MustCompile(`hash_pbkdf2\s*\(`), algorithms: []string{"PBKDF2"}, languages: []string{".php"}},
	{name: "PHP mcrypt deprecated", regex: regexp.MustCompile(`mcrypt_(encrypt|decrypt|create_iv|module_open)\s*\(`), algorithms: []string{"3DES"}, languages: []string{".php"}},

	// ═══════════════════════════════════════════════════════════════════
	// POST-QUANTUM CRYPTOGRAPHY (PQC) — FIPS 203/204/205 Algorithms
	// Detects implementations AND library usage of ML-DSA, ML-KEM, SLH-DSA
	// ═══════════════════════════════════════════════════════════════════

	// ─── CRYSTALS-Dilithium / ML-DSA (FIPS 204) — Digital Signatures ───
	// Reference implementation function names (pqcrystals project)
	{name: "PQC CRYSTALS-Dilithium keypair", regex: regexp.MustCompile(`(pqcrystals_dilithium\d?_?(ref|avx2)?_?(keypair|signature|verify|open))\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium crypto_sign", regex: regexp.MustCompile(`\bcrypto_sign_(keypair|signature|verify)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium NAMESPACE macro", regex: regexp.MustCompile(`DILITHIUM_NAMESPACE\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium MODE define", regex: regexp.MustCompile(`DILITHIUM_MODE\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium params header", regex: regexp.MustCompile(`#include\s*[<"].*dilithium.*(params|sign|api|poly|ntt|config)\.h[>"]`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium directory include", regex: regexp.MustCompile(`#include\s*[<"].*dilithium/`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium polyvec operations", regex: regexp.MustCompile(`\b(polyveck_|polyvecl_)(ntt|reduce|add|sub|chknorm|uniform_eta|uniform_gamma1|pointwise)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Dilithium core functions", regex: regexp.MustCompile(`\b(dilithium_sign|dilithium_verify|dilithium_keygen|DilithiumKey|DilithiumPubKey|CDilithiumKey|CDilithiumPubKey)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC FIPS202 (SHA-3 for Dilithium)", regex: regexp.MustCompile(`FIPS202_NAMESPACE\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	// Consensus/blockchain Dilithium integration
	{name: "PQC Dilithium consensus", regex: regexp.MustCompile(`\b(dilithiumOnlyHeight|DILITHIUM_VERIFY_COST|dilithium_only|isDilithium|IsDilithium)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ─── CRYSTALS-Kyber / ML-KEM (FIPS 203) — Key Encapsulation ───
	{name: "PQC CRYSTALS-Kyber functions", regex: regexp.MustCompile(`(pqcrystals_kyber\d*_?(ref|avx2)?_?(keypair|enc|dec))\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Kyber crypto_kem", regex: regexp.MustCompile(`\bcrypto_kem_(keypair|enc|dec)\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Kyber NAMESPACE macro", regex: regexp.MustCompile(`KYBER_NAMESPACE\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Kyber params header", regex: regexp.MustCompile(`#include\s*[<"].*kyber.*(params|kem|api|poly|ntt|indcpa)\.h[>"]`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Kyber directory include", regex: regexp.MustCompile(`#include\s*[<"].*kyber/`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ─── SPHINCS+ / SLH-DSA (FIPS 205) — Hash-Based Signatures ───
	{name: "PQC SPHINCS+ functions", regex: regexp.MustCompile(`(crypto_sign_sphincs|sphincs_sign|sphincs_verify|SPX_)`), algorithms: []string{"SLH-DSA"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC SPHINCS+ include", regex: regexp.MustCompile(`#include\s*[<"].*sphincs`), algorithms: []string{"SLH-DSA"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC SPHINCS+ namespace", regex: regexp.MustCompile(`SPHINCS_NAMESPACE\b`), algorithms: []string{"SLH-DSA"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ─── Falcon — Lattice-Based Signatures ───
	{name: "PQC Falcon functions", regex: regexp.MustCompile(`(falcon_sign|falcon_verify|falcon_keygen|falcon_make_public|falcon\d+_)`), algorithms: []string{"Falcon-512"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC Falcon include", regex: regexp.MustCompile(`#include\s*[<"].*falcon`), algorithms: []string{"Falcon-512"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ─── liboqs (Open Quantum Safe) — C Library ───
	{name: "PQC liboqs SIG", regex: regexp.MustCompile(`\bOQS_SIG_(new|sign|verify|keypair|free)\s*\(`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC liboqs KEM", regex: regexp.MustCompile(`\bOQS_KEM_(new|keypair|encaps|decaps|free)\s*\(`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC liboqs algorithm name", regex: regexp.MustCompile(`OQS_SIG_alg_(dilithium|ml_dsa|falcon|sphincs|slh_dsa)`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC liboqs KEM algorithm name", regex: regexp.MustCompile(`OQS_KEM_alg_(kyber|ml_kem|hqc|bike|frodokem)`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC liboqs include", regex: regexp.MustCompile(`#include\s*[<"](oqs/oqs|oqs/sig|oqs/kem)\.h[>"]`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},

	// ─── Go PQC Libraries ───
	// Cloudflare circl (widely used in Go PQC)
	{name: "PQC Go circl dilithium", regex: regexp.MustCompile(`circl/sign/(dilithium|ed448)`), algorithms: []string{"ML-DSA-65"}, languages: []string{".go"}},
	{name: "PQC Go circl kyber", regex: regexp.MustCompile(`circl/kem/kyber`), algorithms: []string{"ML-KEM-768"}, languages: []string{".go"}},
	{name: "PQC Go circl schemes", regex: regexp.MustCompile(`circl/sign/schemes`), algorithms: []string{"ML-DSA-65"}, languages: []string{".go"}},
	{name: "PQC Go circl import", regex: regexp.MustCompile(`"github\.com/cloudflare/circl`), algorithms: []string{"ML-DSA-65"}, languages: []string{".go"}},
	// Go pqcrypto
	{name: "PQC Go pqcrypto sign", regex: regexp.MustCompile(`pqcrypto\.(sign|kem)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".go"}},
	// Go standard library (post-Go 1.23 PQC experiment)
	{name: "PQC Go crypto/mlkem", regex: regexp.MustCompile(`crypto/ml(kem|dsa)`), algorithms: []string{"ML-KEM-768"}, languages: []string{".go"}},

	// ─── Python PQC Libraries ───
	{name: "PQC Python pqcrypto", regex: regexp.MustCompile(`pqcrypto\.(sign|kem)\.(dilithium|kyber|sphincs|falcon)`), algorithms: []string{"ML-DSA-65"}, languages: []string{".py"}},
	{name: "PQC Python pqcrypto import", regex: regexp.MustCompile(`from\s+pqcrypto\.(sign|kem)\s+import`), algorithms: []string{"ML-DSA-65"}, languages: []string{".py"}},
	{name: "PQC Python oqs", regex: regexp.MustCompile(`oqs\.(Signature|KeyEncapsulation)\s*\(`), algorithms: []string{"ML-DSA-65"}, languages: []string{".py"}},
	{name: "PQC Python oqs import", regex: regexp.MustCompile(`import\s+oqs`), algorithms: []string{"ML-DSA-65"}, languages: []string{".py"}},
	{name: "PQC Python pyspx", regex: regexp.MustCompile(`pyspx\.(sign|verify|keygen)`), algorithms: []string{"SLH-DSA"}, languages: []string{".py"}},

	// ─── Java PQC Libraries ───
	// Bouncy Castle PQC (extends the existing BC section above)
	{name: "PQC Java BC ML-DSA", regex: regexp.MustCompile(`\b(MLDSAParameterSpec|MLDSAKeyPairGenerator|MLDSASigner)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "PQC Java BC ML-KEM", regex: regexp.MustCompile(`\b(MLKEMParameterSpec|MLKEMKeyPairGenerator|MLKEMExtractor|MLKEMGenerator)\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "PQC Java BC SLH-DSA", regex: regexp.MustCompile(`\b(SLHDSAParameterSpec|SLHDSAKeyPairGenerator|SLHDSASigner)\b`), algorithms: []string{"SLH-DSA"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "PQC Java BC Falcon", regex: regexp.MustCompile(`\b(FalconKeyPairGenerator|FalconSigner|FalconParameters)\b`), algorithms: []string{"Falcon-512"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "PQC Java BC pqc import", regex: regexp.MustCompile(`import\s+org\.bouncycastle\.pqc\.(crypto|jcajce)\.(dilithium|kyber|sphincsplus|falcon|mlkem|mldsa|slhdsa)`), algorithms: []string{"ML-DSA-65"}, languages: []string{".java", ".kt", ".kts"}},
	{name: "PQC Java JCA PQC providers", regex: regexp.MustCompile(`KeyPairGenerator\.getInstance\s*\(\s*"(Dilithium|ML-DSA|ML-KEM|SPHINCS\+|SLH-DSA|Falcon)"`), algorithms: []string{"ML-DSA-65"}, languages: []string{".java", ".kt", ".kts"}},

	// ─── .NET / C# PQC ───
	{name: "PQC C# BCrypt PQC", regex: regexp.MustCompile(`\b(MLDsa|MLKem|SlhDsa)(44|65|87|512|768|1024)?\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".cs"}},
	{name: "PQC C# BouncyCastle PQC", regex: regexp.MustCompile(`Org\.BouncyCastle\.Pqc\.(Crypto|Asn1)\.(Dilithium|Kyber|SphincsPlus|Falcon)`), algorithms: []string{"ML-DSA-65"}, languages: []string{".cs"}},

	// ─── Rust PQC Libraries (extends existing Rust section) ───
	{name: "PQC Rust pqcrypto crate", regex: regexp.MustCompile(`pqcrypto_(dilithium|kyber|sphincsplus|falcon)::`), algorithms: []string{"ML-DSA-65"}, languages: []string{".rs"}},
	{name: "PQC Rust oqs crate", regex: regexp.MustCompile(`oqs::(Sig|Kem)\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".rs"}},

	// ─── C++ PQC Libraries ───
	// Botan PQC (extends existing Botan section)
	{name: "PQC C++ Botan ML-DSA", regex: regexp.MustCompile(`Botan::(Dilithium|ML_DSA)_(Private|Public)Key\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "PQC C++ Botan ML-KEM", regex: regexp.MustCompile(`Botan::(Kyber|ML_KEM)_(Private|Public)Key\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".cpp", ".h", ".hpp"}},
	{name: "PQC C++ Botan SLH-DSA", regex: regexp.MustCompile(`Botan::(SphincsPlus|SLH_DSA)_(Private|Public)Key\b`), algorithms: []string{"SLH-DSA"}, languages: []string{".cpp", ".h", ".hpp"}},

	// ─── Generic / Cross-Language PQC Detection ───
	// FIPS 203/204/205 standard names (any language)
	{name: "PQC ML-DSA reference", regex: regexp.MustCompile(`\b(ML.DSA.(44|65|87))\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".go", ".py", ".java", ".kt", ".rs", ".cs", ".js", ".ts"}},
	{name: "PQC ML-KEM reference", regex: regexp.MustCompile(`\b(ML.KEM.(512|768|1024))\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".go", ".py", ".java", ".kt", ".rs", ".cs", ".js", ".ts"}},
	{name: "PQC SLH-DSA reference", regex: regexp.MustCompile(`\bSLH.DSA.(SHA2|SHAKE).(128|192|256)(s|f)\b`), algorithms: []string{"SLH-DSA"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".go", ".py", ".java", ".kt", ".rs", ".cs", ".js", ".ts"}},
	// Algorithm name mentions (comments, constants, config)
	{name: "PQC Dilithium mention", regex: regexp.MustCompile(`\b[Dd]ilithium[_-]?(2|3|5|44|65|87|ref|avx2)?\b`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".go", ".py", ".java", ".kt", ".rs", ".cs", ".js", ".ts", ".yml", ".yaml", ".conf", ".cfg"}},
	{name: "PQC Kyber mention", regex: regexp.MustCompile(`\b[Kk]yber[_-]?(512|768|1024|ref|avx2)?\b`), algorithms: []string{"ML-KEM-768"}, languages: []string{".c", ".cpp", ".h", ".hpp", ".go", ".py", ".java", ".kt", ".rs", ".cs", ".js", ".ts", ".yml", ".yaml", ".conf", ".cfg"}},
	// Lattice-based crypto primitives common to Dilithium/Kyber
	{name: "PQC lattice NTT operations", regex: regexp.MustCompile(`\b(ntt|invntt_tomont|ntt_init|basemul|poly_ntt|poly_invntt)\s*\(`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC lattice polynomial ops", regex: regexp.MustCompile(`\b(poly_uniform|poly_challenge|poly_decompose|poly_make_hint|poly_use_hint|polyeta_pack|polyeta_unpack)\s*\(`), algorithms: []string{"ML-DSA-65"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "PQC SHAKE/Keccak for PQC", regex: regexp.MustCompile(`\b(shake128|shake256|keccak_absorb|keccak_squeeze|SHAKE128|SHAKE256)\s*\(`), algorithms: []string{"SHAKE"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
}

// File extensions to scan.
var codeExtensions = map[string]bool{
	// Core languages
	".go": true, ".py": true, ".java": true, ".js": true, ".ts": true, ".mjs": true,
	// C / C++
	".c": true, ".cpp": true, ".h": true, ".hpp": true,
	// Rust, C#, Ruby, PHP
	".rs": true, ".cs": true, ".rb": true, ".php": true,
	// Apple (Swift, Objective-C)
	".swift": true, ".m": true, ".mm": true,
	// Kotlin / Android
	".kt": true, ".kts": true,
	// Shell / DevOps
	".sh": true, ".bash": true, ".zsh": true, ".ps1": true, ".bat": true, ".cmd": true,
	// Build files
	".mk": true,
	// Config files (server/daemon crypto settings)
	".conf": true, ".cfg": true, ".ini": true,
	// Infrastructure as Code
	".tf": true, ".tfvars": true,
	// YAML (CloudFormation, Ansible, K8s, Docker)
	".yml": true, ".yaml": true,
	// Dart / Flutter
	".dart": true,
	// Perl (legacy federal)
	".pl": true, ".pm": true,
	// Protocol Buffers
	".proto": true,
	// XML / SOAP / SAML
	".xml": true, ".wsdl": true, ".saml": true,
	// Dockerfile (matched by basename, but extension helps)
	".dockerfile": true,
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

	// GAP-08: Progress indicator for code scans
	quiet := os.Getenv("PQCAT_QUIET") == "1"
	progress := tui.NewProgress("Scanning source code", len(files), quiet)

	totalFindings := 0
	filesWithCrypto := 0

	for i, file := range files {
		findings := scanFileForCrypto(file)

		// CODE-5: Secret scanning for config files (.env, .properties, etc.)
		ext := strings.ToLower(filepath.Ext(file))
		if ConfigSecretExtensions[ext] {
			secrets := scanFileForSecrets(file)
			findings = append(findings, secrets...)
		}

		if len(findings) > 0 {
			filesWithCrypto++
			totalFindings += len(findings)
			result.Assets = append(result.Assets, findings...)
		}
		// Update progress every 10 files or on the last file
		if (i+1)%10 == 0 || i == len(files)-1 {
			progress.Update(i+1, filepath.Base(file))
		}
	}

	// CODE-1 + CODE-3: Post-process enrichment (key sizes + cipher modes)
	result.Assets = EnrichAssets(result.Assets)

	progress.Done(fmt.Sprintf("Scanned %d files, %d findings in %d files",
		len(files), totalFindings, filesWithCrypto))

	result.Duration = time.Since(start)
	result.Details = map[string]string{
		"files_scanned":     fmt.Sprintf("%d", len(files)),
		"files_with_crypto": fmt.Sprintf("%d", filesWithCrypto),
		"total_findings":    fmt.Sprintf("%d", totalFindings),
	}

	return result, nil
}

// findCodeFiles recursively finds source code files, skipping common non-source dirs.
// Supports .pqcatignore for custom exclusion patterns (POL-09).
func findCodeFiles(dir string) ([]string, error) {
	var files []string

	// POL-09: Load .pqcatignore patterns
	ignorePatterns := loadPqcatIgnore(dir)

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

		// POL-09: Check .pqcatignore patterns
		relPath, _ := filepath.Rel(dir, path)
		if matchesIgnorePattern(relPath, ignorePatterns) {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if codeExtensions[ext] {
			files = append(files, path)
		} else if ext == "" {
			// Handle extensionless files by basename (Dockerfile, Makefile, etc.)
			base := strings.ToLower(filepath.Base(path))
			if base == "dockerfile" || base == "makefile" || base == "gemfile" || base == "rakefile" {
				files = append(files, path)
			}
		}
		return nil
	})

	return files, err
}

// loadPqcatIgnore reads .pqcatignore patterns from the target directory and parents.
// Patterns use gitignore-style glob syntax (one pattern per line, # for comments).
func loadPqcatIgnore(dir string) []string {
	var patterns []string

	// Check target dir first, then walk up to root
	current := dir
	for {
		ignorePath := filepath.Join(current, ".pqcatignore")
		if data, err := os.ReadFile(ignorePath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					patterns = append(patterns, line)
				}
			}
			break // Use the closest .pqcatignore only
		}
		parent := filepath.Dir(current)
		if parent == current {
			break // Reached filesystem root
		}
		current = parent
	}

	return patterns
}

// matchesIgnorePattern checks if a relative path matches any .pqcatignore pattern.
func matchesIgnorePattern(relPath string, patterns []string) bool {
	for _, pattern := range patterns {
		// Try matching the full relative path
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}
		// Try matching just the filename (for simple patterns like "*.min.js")
		if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
			return true
		}
		// Support directory patterns (e.g., "vendor/" matches "vendor/foo/bar.go")
		if strings.HasSuffix(pattern, "/") {
			dirPattern := strings.TrimSuffix(pattern, "/")
			if strings.HasPrefix(relPath, dirPattern+"/") || relPath == dirPattern {
				return true
			}
		}
		// Support ** glob (match any depth)
		if strings.Contains(pattern, "**") {
			// Convert ** to a simple prefix/suffix check
			parts := strings.SplitN(pattern, "**", 2)
			if len(parts) == 2 {
				prefix := parts[0]
				suffix := parts[1]
				if strings.HasPrefix(relPath, prefix) && strings.HasSuffix(relPath, suffix) {
					return true
				}
			}
		}
	}
	return false
}

// mapExtensionlessFile maps extensionless filenames to logical extensions so that
// language-specific patterns fire correctly. Without this, Dockerfile/Makefile files
// would be discovered but produce zero findings (GAP-1).
func mapExtensionlessFile(path, ext string) string {
	if ext != "" {
		return ext
	}
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "dockerfile":
		return ".dockerfile"
	case "makefile", "gnumakefile":
		return ".mk"
	case "gemfile", "rakefile":
		return ".rb"
	case "vagrantfile":
		return ".rb"
	}
	return ext
}

// blockCommentState tracks whether the scanner is inside a multi-line comment block.
// This is the standard approach used by enterprise-grade static analysis tools
// (SonarQube, Semgrep, CodeQL) during lexical analysis.
type blockCommentState struct {
	inBlock   bool
	delimiter string // "*/", `"""`, "'''", "-->"
}

// processLine checks if the current line enters, exits, or is within a block comment.
// Returns true if the line should be skipped (it's inside a comment block).
func (s *blockCommentState) processLine(trimmed, ext string) bool {
	// If we're inside a block comment, look for the closing delimiter
	if s.inBlock {
		if strings.Contains(trimmed, s.delimiter) {
			s.inBlock = false
			s.delimiter = ""
		}
		return true // Skip this line regardless (closing line is still comment)
	}

	// Check for block comment openers
	// C-style /* ... */ (most languages)
	if strings.Contains(trimmed, "/*") {
		if !strings.Contains(trimmed, "*/") {
			// Multi-line block comment starts here
			s.inBlock = true
			s.delimiter = "*/"
		}
		return true // Skip the opening line too
	}

	// Python/Ruby triple-quoted strings (often used as docstrings/comments)
	if ext == ".py" || ext == ".rb" {
		if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, `'''`) {
			delim := trimmed[:3]
			// Check if it closes on the same line (count occurrences)
			if strings.Count(trimmed, delim) == 1 {
				s.inBlock = true
				s.delimiter = delim
			}
			return true
		}
	}

	// HTML/XML <!-- ... -->
	if ext == ".xml" || ext == ".wsdl" || ext == ".saml" {
		if strings.Contains(trimmed, "<!--") {
			if !strings.Contains(trimmed, "-->") {
				s.inBlock = true
				s.delimiter = "-->"
			}
			return true
		}
	}

	return false
}

// scanFileForCrypto scans a single source file for crypto API patterns.
// Uses an enterprise-grade lexer state machine for block comment tracking.
func scanFileForCrypto(path string) []models.CryptoAsset {
	var assets []models.CryptoAsset

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	ext := mapExtensionlessFile(path, strings.ToLower(filepath.Ext(path)))
	scanner := bufio.NewScanner(f)
	lineNum := 0
	findingIdx := 0 // Per-file counter for unique asset IDs (GAP-9)
	commentState := &blockCommentState{}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Block comment state machine (GAP-4)
		if commentState.processLine(trimmed, ext) {
			continue
		}

		// Single-line comment filters
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		// '#' is a comment in Python/Ruby/Shell/Perl/PHP — but NOT in C/C++/ObjC
		cOrObjC := ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp" || ext == ".m" || ext == ".mm"
		if strings.HasPrefix(trimmed, "#") && !cOrObjC {
			continue
		}
		// In C/C++/ObjC, skip preprocessor lines that are clearly NOT crypto-relevant
		// (but keep #include and #import which our patterns match)
		if cOrObjC && strings.HasPrefix(trimmed, "#") {
			if !strings.HasPrefix(trimmed, "#include") && !strings.HasPrefix(trimmed, "#import") {
				continue
			}
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

			if matches := pattern.regex.FindStringSubmatch(line); matches != nil {
				// Determine algorithms: use resolver if available, otherwise defaults
				algos := pattern.algorithms
				if pattern.resolver != nil {
					if resolved := pattern.resolver(matches, line); len(resolved) > 0 {
						algos = resolved
					}
				}
				for _, algo := range algos {
					zone := classifier.Classify(algo)
					findingIdx++

					assets = append(assets, models.CryptoAsset{
						ID:        fmt.Sprintf("code-%s-%d-%d", filepath.Base(path), lineNum, findingIdx),
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
