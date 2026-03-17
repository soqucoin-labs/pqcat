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
	// C/C++ Crypto APIs — OpenSSL High-Level (EVP)
	// ═══════════════════════════════════════════════════════════════════
	{name: "C OpenSSL RSA", regex: regexp.MustCompile(`RSA_generate_key(_ex)?\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP Sign", regex: regexp.MustCompile(`EVP_DigestSign(Init|Update|Final)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP Verify", regex: regexp.MustCompile(`EVP_DigestVerify(Init|Update|Final)\s*\(`), algorithms: []string{"RSA-2048"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EC Key", regex: regexp.MustCompile(`EC_KEY_(new_by_curve_name|generate_key)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL ECDSA Sign", regex: regexp.MustCompile(`ECDSA_(sign|verify|do_sign|do_verify)\s*\(`), algorithms: []string{"ECDSA-P256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP AES", regex: regexp.MustCompile(`EVP_aes_(128|256)_(gcm|cbc|ctr|ecb)\s*\(`), algorithms: []string{"AES-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
	{name: "C OpenSSL EVP SHA", regex: regexp.MustCompile(`EVP_sha(1|256|384|512)\s*\(`), algorithms: []string{"SHA-256"}, languages: []string{".c", ".cpp", ".h", ".hpp"}},
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

		// Skip comments (language-aware heuristic)
		trimmed := strings.TrimSpace(line)
		// C-style single and multi-line comment openers (all languages)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}
		// '#' is a comment in Python/Ruby/Shell/PHP — but NOT in C/C++ (it's #include/#define)
		if strings.HasPrefix(trimmed, "#") && ext != ".c" && ext != ".cpp" && ext != ".h" && ext != ".hpp" {
			continue
		}
		// In C/C++, skip preprocessor lines that are clearly NOT crypto-relevant
		// (but keep #include which our patterns match)
		if (ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp") && strings.HasPrefix(trimmed, "#") {
			if !strings.HasPrefix(trimmed, "#include") {
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
