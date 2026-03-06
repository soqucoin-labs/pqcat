package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// SBOMFormat identifies the SBOM format.
type SBOMFormat string

const (
	FormatCycloneDX SBOMFormat = "cyclonedx"
	FormatSPDX      SBOMFormat = "spdx"
	FormatAuto      SBOMFormat = "auto"
)

// cryptoLibraries maps known package names/patterns to their cryptographic algorithms.
// This is the core intelligence of the SBOM scanner — it knows which libraries
// ship which crypto implementations.
//
// Coverage: 120+ libraries across all federal technology stacks.
// Categories: TLS/SSL, PKI, HSM, KMS, VPN/IPSec, SSH, JWT/JOSE, XML Security,
// FIDO/WebAuthn, Database Encryption, Container Signing, PQC, and language-native.
var cryptoLibraries = map[string]cryptoLibInfo{

	// ═══════════════════════════════════════════════════════════════════
	// TLS/SSL Libraries (core dependency for nearly every federal system)
	// ═══════════════════════════════════════════════════════════════════
	"openssl":   {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "Ed25519", "AES-256-GCM", "AES-128-GCM", "SHA-256", "SHA-384", "ChaCha20-Poly1305"}, desc: "OpenSSL cryptographic library"},
	"libressl":  {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "ChaCha20-Poly1305"}, desc: "LibreSSL (OpenBSD fork)"},
	"boringssl": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "ML-KEM-768", "ChaCha20-Poly1305"}, desc: "BoringSSL (Google fork, partial PQC)"},
	"gnutls":    {algorithms: []string{"RSA-2048", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "ChaCha20-Poly1305"}, desc: "GnuTLS"},
	"mbedtls":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "AES-128-GCM"}, desc: "Mbed TLS (ARM/embedded)"},
	"wolfssl":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "ML-KEM-768", "ML-DSA-65"}, desc: "wolfSSL (partial PQC, FIPS validated)"},
	"s2n-tls":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "ML-KEM-768"}, desc: "AWS s2n-tls (PQC hybrid support)"},
	"aws-lc":    {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "ML-KEM-768", "ML-DSA-65"}, desc: "AWS LibCrypto (BoringSSL fork, PQC)"},
	"rustls":    {algorithms: []string{"ECDSA-P256", "Ed25519", "AES-256-GCM", "ML-KEM-768"}, desc: "Rust TLS (PQC via rustls-post-quantum)"},

	// ═══════════════════════════════════════════════════════════════════
	// Government/DoD Specific Crypto
	// ═══════════════════════════════════════════════════════════════════
	"nss":         {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "SHA-256", "SHA-384"}, desc: "Mozilla NSS (used in Firefox, RHEL, DoD)"},
	"libnss":      {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "NSS shared libraries"},
	"nss-softokn": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "NSS FIPS 140-2 validated soft token"},
	"nss-util":    {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "NSS utility library"},
	"gnupg":       {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "Ed25519", "AES-256-CBC"}, desc: "GNU Privacy Guard"},
	"gpg":         {algorithms: []string{"RSA-2048", "RSA-4096", "Ed25519", "AES-256-CBC"}, desc: "GnuPG command-line"},
	"gpgme":       {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256"}, desc: "GPGME (GnuPG Made Easy)"},
	"libgcrypt":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"}, desc: "GnuTLS/GPG low-level crypto"},

	// ═══════════════════════════════════════════════════════════════════
	// HSM / Hardware Security Module SDKs & PKCS#11
	// ═══════════════════════════════════════════════════════════════════
	"pkcs11":     {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM"}, desc: "PKCS#11 (Cryptoki) — HSM interface standard"},
	"softhsm":    {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "SoftHSMv2 (PKCS#11 software HSM)"},
	"luna":       {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM"}, desc: "Thales Luna HSM SDK"},
	"safenet":    {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "AES-256-GCM"}, desc: "SafeNet/Thales HSM client"},
	"ncipher":    {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "AES-256-GCM"}, desc: "Entrust nShield/nCipher HSM"},
	"entrust":    {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256"}, desc: "Entrust PKI/HSM products"},
	"yubihsm":    {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519", "AES-256-GCM"}, desc: "YubiHSM 2 SDK"},
	"tpm2-tss":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-128-GCM", "SHA-256"}, desc: "TPM 2.0 Software Stack"},
	"tpm2-tools": {algorithms: []string{"RSA-2048", "ECDSA-P256", "SHA-256"}, desc: "TPM 2.0 command-line tools"},

	// ═══════════════════════════════════════════════════════════════════
	// Cloud KMS / Key Management SDKs
	// ═══════════════════════════════════════════════════════════════════
	"aws-encryption-sdk":      {algorithms: []string{"RSA-2048", "AES-256-GCM", "ECDSA-P256"}, desc: "AWS Encryption SDK"},
	"aws-kms":                 {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "HMAC"}, desc: "AWS KMS SDK"},
	"@aws-crypto":             {algorithms: []string{"AES-256-GCM", "SHA-256"}, desc: "AWS Crypto Tools (JS/Node)"},
	"com.amazonaws.kms":       {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "AWS KMS Java SDK"},
	"azure-keyvault":          {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "AES-256-GCM"}, desc: "Azure Key Vault SDK"},
	"azure-security-keyvault": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Azure Key Vault (new SDK)"},
	"google-cloud-kms":        {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM"}, desc: "Google Cloud KMS SDK"},
	"hashicorp-vault":         {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "Ed25519", "AES-256-GCM"}, desc: "HashiCorp Vault"},
	"vault":                   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "Ed25519"}, desc: "HashiCorp Vault client"},

	// ═══════════════════════════════════════════════════════════════════
	// VPN / IPSec / Network Encryption
	// ═══════════════════════════════════════════════════════════════════
	"strongswan": {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "SHA-256", "SHA-384"}, desc: "strongSwan IPSec VPN"},
	"libreswan":  {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "AES-256-GCM", "SHA-256"}, desc: "Libreswan IPSec (RHEL/Fedora default)"},
	"openswan":   {algorithms: []string{"RSA-2048", "AES-256-CBC", "SHA-256"}, desc: "OpenSwan IPSec (legacy)"},
	"wireguard":  {algorithms: []string{"X25519", "ChaCha20-Poly1305"}, desc: "WireGuard VPN"},
	"openvpn":    {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"}, desc: "OpenVPN"},
	"libipsec":   {algorithms: []string{"RSA-2048", "AES-256-GCM", "SHA-256"}, desc: "IPSec user-space library"},

	// ═══════════════════════════════════════════════════════════════════
	// SSH Implementations (across all languages)
	// ═══════════════════════════════════════════════════════════════════
	"openssh":                 {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519", "AES-256-GCM", "ChaCha20-Poly1305"}, desc: "OpenSSH"},
	"paramiko":                {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519", "AES-256-GCM"}, desc: "Python Paramiko SSH"},
	"asyncssh":                {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, desc: "Python AsyncSSH"},
	"jsch":                    {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Java JSch SSH2"},
	"sshj":                    {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519", "AES-256-GCM"}, desc: "Java sshj SSH library"},
	"apache-mina-sshd":        {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519", "AES-256-GCM"}, desc: "Apache MINA SSHD (Java)"},
	"golang.org/x/crypto/ssh": {algorithms: []string{"RSA-2048", "Ed25519", "ECDSA-P256", "AES-256-GCM"}, desc: "Go SSH library"},
	"ssh2":                    {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Node.js ssh2"},
	"phpseclib":               {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "PHP Secure Communications"},
	"libssh":                  {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519", "AES-256-GCM"}, desc: "C libssh"},
	"libssh2":                 {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "C libssh2"},

	// ═══════════════════════════════════════════════════════════════════
	// Go Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"golang.org/x/crypto":     {algorithms: []string{"Ed25519", "ChaCha20-Poly1305", "AES-256-GCM", "SHA-256"}, desc: "Go extended cryptography"},
	"crypto/tls":              {algorithms: []string{"ECDSA-P256", "RSA-2048", "AES-128-GCM", "AES-256-GCM"}, desc: "Go standard TLS library"},
	"crypto/ecdsa":            {algorithms: []string{"ECDSA-P256"}, desc: "Go ECDSA implementation"},
	"crypto/rsa":              {algorithms: []string{"RSA-2048"}, desc: "Go RSA implementation"},
	"crypto/ed25519":          {algorithms: []string{"Ed25519"}, desc: "Go Ed25519 implementation"},
	"filippo.io/age":          {algorithms: []string{"X25519", "ChaCha20-Poly1305"}, desc: "Go age file encryption"},
	"filippo.io/edwards25519": {algorithms: []string{"Ed25519"}, desc: "Go Edwards25519 implementation"},

	// ═══════════════════════════════════════════════════════════════════
	// Python Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"cryptography":  {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "Ed25519", "AES-256-GCM", "SHA-256"}, desc: "Python pyca/cryptography"},
	"pycryptodome":  {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-CBC", "AES-256-GCM", "SHA-256"}, desc: "Python PyCryptodome"},
	"pycryptodomex": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Python PyCryptodomeX"},
	"pynacl":        {algorithms: []string{"Ed25519", "X25519", "ChaCha20-Poly1305"}, desc: "Python NaCl bindings"},
	"pyopenssl":     {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Python OpenSSL wrapper"},
	"python-gnupg":  {algorithms: []string{"RSA-2048", "RSA-4096", "Ed25519"}, desc: "Python GnuPG wrapper"},

	// ═══════════════════════════════════════════════════════════════════
	// Java / JVM Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"org.bouncycastle":       {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "Ed25519", "AES-256-GCM", "ML-DSA-65", "ML-KEM-768"}, desc: "Bouncy Castle (Java, PQC support)"},
	"javax.crypto":           {algorithms: []string{"RSA-2048", "AES-256-GCM", "SHA-256"}, desc: "Java Cryptography Architecture (JCA)"},
	"java.security":          {algorithms: []string{"RSA-2048", "ECDSA-P256", "SHA-256"}, desc: "Java Security (JCE)"},
	"io.netty":               {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Netty (Java async TLS)"},
	"com.google.crypto.tink": {algorithms: []string{"ECDSA-P256", "AES-256-GCM", "Ed25519", "ChaCha20-Poly1305"}, desc: "Google Tink (Java/Android)"},
	"org.apache.shiro":       {algorithms: []string{"RSA-2048", "AES-256-CBC", "SHA-256"}, desc: "Apache Shiro security"},
	"org.jasypt":             {algorithms: []string{"RSA-2048", "AES-256-CBC"}, desc: "Jasypt (Java Simplified Encryption)"},
	"org.keycloak":           {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Keycloak (auth server)"},
	"com.nimbusds":           {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, desc: "Nimbus JOSE/JWT (Java)"},

	// ═══════════════════════════════════════════════════════════════════
	// .NET / C# Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"system.security.cryptography":      {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "SHA-256", "SHA-384"}, desc: ".NET System.Security.Cryptography"},
	"bouncycastle.cryptography":         {algorithms: []string{"RSA-2048", "ECDSA-P256", "ML-DSA-65", "ML-KEM-768", "AES-256-GCM"}, desc: "Bouncy Castle .NET (PQC support)"},
	"portable.bouncycastle":             {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Bouncy Castle .NET Portable"},
	"microsoft.aspnetcore.cryptography": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "ASP.NET Core Data Protection"},
	"nsec":                              {algorithms: []string{"Ed25519", "X25519", "AES-256-GCM"}, desc: ".NET NSec modern crypto"},
	"microsoft.identitymodel":           {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: ".NET Identity Model (JWT/OAuth)"},

	// ═══════════════════════════════════════════════════════════════════
	// Rust Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"ring":               {algorithms: []string{"ECDSA-P256", "ECDSA-P384", "Ed25519", "AES-256-GCM", "SHA-256", "SHA-384"}, desc: "Rust ring cryptography"},
	"dalek-cryptography": {algorithms: []string{"Ed25519", "X25519"}, desc: "Rust Dalek curve operations"},
	"curve25519-dalek":   {algorithms: []string{"Ed25519", "X25519"}, desc: "Rust Curve25519 impl"},
	"ed25519-dalek":      {algorithms: []string{"Ed25519"}, desc: "Rust Ed25519 signatures"},
	"x25519-dalek":       {algorithms: []string{"X25519"}, desc: "Rust X25519 key exchange"},
	"rust-openssl":       {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Rust OpenSSL bindings"},
	"aes-gcm":            {algorithms: []string{"AES-256-GCM"}, desc: "Rust AES-GCM (RustCrypto)"},
	"chacha20poly1305":   {algorithms: []string{"ChaCha20-Poly1305"}, desc: "Rust ChaCha20-Poly1305"},
	"rsa":                {algorithms: []string{"RSA-2048"}, desc: "Rust RSA (RustCrypto)"},
	"pqcrypto":           {algorithms: []string{"ML-KEM-768", "ML-DSA-65"}, desc: "Rust PQC implementations"},

	// ═══════════════════════════════════════════════════════════════════
	// Node.js / JavaScript Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"node-forge":          {algorithms: []string{"RSA-2048", "AES-256-CBC", "AES-256-GCM", "SHA-256"}, desc: "Node.js Forge"},
	"jose":                {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, desc: "JavaScript JOSE/JWT"},
	"jsonwebtoken":        {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Node.js JWT library"},
	"crypto-js":           {algorithms: []string{"AES-256-CBC", "SHA-256"}, desc: "CryptoJS (browser crypto)"},
	"tweetnacl":           {algorithms: []string{"Ed25519", "X25519", "ChaCha20-Poly1305"}, desc: "TweetNaCl.js"},
	"noble-ed25519":       {algorithms: []string{"Ed25519"}, desc: "noble-ed25519 (pure JS)"},
	"@noble/curves":       {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "noble curves (pure JS)"},
	"@noble/hashes":       {algorithms: []string{"SHA-256", "SHA-384", "SHA-512"}, desc: "noble hashes (pure JS)"},
	"webcrypto":           {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Web Crypto API polyfill"},
	"@peculiar/webcrypto": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Peculiar WebCrypto (Node.js)"},

	// ═══════════════════════════════════════════════════════════════════
	// Ruby Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"openssl-ruby": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Ruby OpenSSL bindings"},
	"rbnacl":       {algorithms: []string{"Ed25519", "X25519", "ChaCha20-Poly1305"}, desc: "Ruby NaCl bindings"},
	"bcrypt-ruby":  {algorithms: []string{"AES-128-GCM"}, desc: "Ruby bcrypt password hashing"},
	"jwt":          {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Ruby JWT gem"},

	// ═══════════════════════════════════════════════════════════════════
	// PHP Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	// Note: phpseclib is already listed under SSH Implementations
	"php-encryption":   {algorithms: []string{"AES-256-GCM", "SHA-256"}, desc: "PHP defuse/php-encryption"},
	"sodium_compat":    {algorithms: []string{"Ed25519", "X25519", "ChaCha20-Poly1305"}, desc: "PHP sodium compatibility"},
	"firebase/php-jwt": {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "PHP Firebase JWT"},

	// ═══════════════════════════════════════════════════════════════════
	// Erlang/Elixir Crypto (federal telecom / messaging systems)
	// ═══════════════════════════════════════════════════════════════════
	"crypto-erlang": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"}, desc: "Erlang :crypto module"},

	// ═══════════════════════════════════════════════════════════════════
	// C/C++ Crypto Libraries
	// ═══════════════════════════════════════════════════════════════════
	"libsodium":   {algorithms: []string{"Ed25519", "X25519", "ChaCha20-Poly1305", "AES-256-GCM"}, desc: "NaCl/libsodium"},
	"nacl":        {algorithms: []string{"Ed25519", "X25519", "ChaCha20-Poly1305"}, desc: "Networking and Cryptography library"},
	"nettle":      {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"}, desc: "Nettle (GnuTLS backend)"},
	"libtomcrypt": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM", "SHA-256"}, desc: "LibTomCrypt"},
	"tinycrypt":   {algorithms: []string{"AES-128-GCM", "SHA-256", "ECDSA-P256"}, desc: "TinyCrypt (embedded/IoT)"},
	"libcrypto":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "OpenSSL libcrypto"},

	// ═══════════════════════════════════════════════════════════════════
	// Certificate / PKI Management
	// ═══════════════════════════════════════════════════════════════════
	"certbot":      {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Let's Encrypt Certbot"},
	"cfssl":        {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}, desc: "Cloudflare PKI toolkit"},
	"step-ca":      {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Smallstep CA"},
	"step-cli":     {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Smallstep CLI"},
	"ejbca":        {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384"}, desc: "EJBCA Enterprise PKI"},
	"dogtag":       {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256"}, desc: "Dogtag PKI (Red Hat/RHEL CA)"},
	"cert-manager": {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, desc: "Kubernetes cert-manager"},
	"openxpki":     {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256"}, desc: "OpenXPKI PKI management"},
	"boulder":      {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Let's Encrypt ACME CA (Boulder)"},

	// ═══════════════════════════════════════════════════════════════════
	// JWT / JOSE / OAuth / Identity
	// ═══════════════════════════════════════════════════════════════════
	"com.auth0":    {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Auth0 Java JWT"},
	"passport-jwt": {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Passport.js JWT strategy"},
	"oauth2-proxy": {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "OAuth2 Proxy"},
	"dex":          {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "CoreOS Dex OIDC provider"},

	// ═══════════════════════════════════════════════════════════════════
	// XML / SOAP Security (common in federal/DoD legacy systems)
	// ═══════════════════════════════════════════════════════════════════
	"xml-crypto":       {algorithms: []string{"RSA-2048", "ECDSA-P256", "SHA-256"}, desc: "Node.js XML digital signatures"},
	"xmlsec":           {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-CBC"}, desc: "XML Security (C library)"},
	"xmlsec1":          {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-CBC"}, desc: "xmlsec1 CLI"},
	"apache-santuario": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Apache Santuario XML Security (Java)"},
	"signxml":          {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Python XML signature/encryption"},
	"xml-enc":          {algorithms: []string{"RSA-2048", "AES-256-CBC"}, desc: "XML Encryption"},

	// ═══════════════════════════════════════════════════════════════════
	// FIDO / WebAuthn / Passkeys
	// ═══════════════════════════════════════════════════════════════════
	"fido2":       {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "FIDO2 library"},
	"webauthn":    {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "WebAuthn server library"},
	"go-webauthn": {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Go WebAuthn implementation"},
	"py_webauthn": {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Python WebAuthn"},
	"yubico-piv":  {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Yubico PIV (smartcard)"},

	// ═══════════════════════════════════════════════════════════════════
	// Database Encryption
	// ═══════════════════════════════════════════════════════════════════
	"pgcrypto":                    {algorithms: []string{"RSA-2048", "AES-256-CBC", "SHA-256"}, desc: "PostgreSQL pgcrypto"},
	"oracle-tde":                  {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "Oracle Transparent Data Encryption"},
	"sqlcipher":                   {algorithms: []string{"AES-256-CBC", "SHA-256"}, desc: "SQLCipher (encrypted SQLite)"},
	"mongodb-csfle":               {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "MongoDB Client-Side Field Level Encryption"},
	"mongodb-encryption":          {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "MongoDB Enterprise encryption"},
	"mysql-enterprise-encryption": {algorithms: []string{"RSA-2048", "AES-256-CBC"}, desc: "MySQL Enterprise Encryption"},

	// ═══════════════════════════════════════════════════════════════════
	// Container / Supply Chain Signing
	// ═══════════════════════════════════════════════════════════════════
	"cosign":               {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Sigstore cosign (container signing)"},
	"notary":               {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, desc: "Notary v2 / TUF signing"},
	"rekor":                {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Sigstore Rekor transparency log"},
	"fulcio":               {algorithms: []string{"ECDSA-P256", "Ed25519"}, desc: "Sigstore Fulcio CA"},
	"in-toto":              {algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, desc: "in-toto supply chain attestation"},
	"docker-content-trust": {algorithms: []string{"RSA-2048", "ECDSA-P256"}, desc: "Docker Content Trust (Notary v1)"},

	// ═══════════════════════════════════════════════════════════════════
	// Kerberos / Directory / Enterprise Auth
	// ═══════════════════════════════════════════════════════════════════
	"krb5":       {algorithms: []string{"RSA-2048", "AES-256-GCM", "SHA-256"}, desc: "MIT Kerberos 5"},
	"heimdal":    {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "Heimdal Kerberos"},
	"cyrus-sasl": {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "Cyrus SASL (auth framework)"},
	"openldap":   {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "OpenLDAP (TLS-enabled directory)"},
	"389-ds":     {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "389 Directory Server (Red Hat/RHEL)"},
	"sssd":       {algorithms: []string{"RSA-2048", "AES-256-GCM"}, desc: "System Security Services Daemon"},

	// ═══════════════════════════════════════════════════════════════════
	// Email / S/MIME / Messaging
	// ═══════════════════════════════════════════════════════════════════
	"openpgp":         {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "Ed25519"}, desc: "OpenPGP implementation"},
	"gopenpgp":        {algorithms: []string{"RSA-2048", "RSA-4096", "Ed25519"}, desc: "Go OpenPGP (ProtonMail)"},
	"smime":           {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-CBC"}, desc: "S/MIME email encryption"},
	"signal-protocol": {algorithms: []string{"X25519", "Ed25519", "AES-256-GCM"}, desc: "Signal Protocol"},

	// ═══════════════════════════════════════════════════════════════════
	// Protocol Libraries (HTTP, cURL, etc.)
	// ═══════════════════════════════════════════════════════════════════
	"curl":           {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "cURL / libcurl (TLS client)"},
	"libcurl":        {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "libcurl C library"},
	"httpcomponents": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Apache HttpComponents (Java)"},
	"okhttp":         {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "OkHttp (Android/Java)"},
	"requests":       {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Python requests (uses urllib3 TLS)"},

	// ═══════════════════════════════════════════════════════════════════
	// Key Derivation / Password Hashing (not quantum-vulnerable but tracked)
	// ═══════════════════════════════════════════════════════════════════
	"bcrypt": {algorithms: []string{"AES-128-GCM"}, desc: "bcrypt password hashing"},
	"argon2": {algorithms: []string{"AES-256-GCM"}, desc: "Argon2 key derivation (winner of PHC)"},
	"scrypt": {algorithms: []string{"AES-256-GCM"}, desc: "scrypt key derivation"},

	// ═══════════════════════════════════════════════════════════════════
	// PQC-Specific Libraries (GREEN zone)
	// ═══════════════════════════════════════════════════════════════════
	"liboqs":           {algorithms: []string{"ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-128F", "SLH-DSA-256F"}, desc: "Open Quantum Safe (PQC reference)"},
	"oqs-provider":     {algorithms: []string{"ML-KEM-768", "ML-DSA-65", "SLH-DSA-128F"}, desc: "OQS OpenSSL 3 provider"},
	"circl":            {algorithms: []string{"ML-KEM-768", "ML-DSA-65", "X25519"}, desc: "Cloudflare CIRCL (PQC support)"},
	"pqclean":          {algorithms: []string{"ML-KEM-768", "ML-DSA-65", "SLH-DSA-128F"}, desc: "PQClean (clean PQC implementations)"},
	"pq-crystals":      {algorithms: []string{"ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87"}, desc: "PQ-CRYSTALS (Kyber/Dilithium reference)"},
	"ntru":             {algorithms: []string{"ML-KEM-768"}, desc: "NTRU lattice-based crypto"},
	"classic-mceliece": {algorithms: []string{"ML-KEM-768"}, desc: "Classic McEliece code-based KEM"},
	"bc-pqc":           {algorithms: []string{"ML-DSA-65", "ML-KEM-768", "SLH-DSA-128F"}, desc: "Bouncy Castle PQC provider (Java)"},
	"pqcrypto-go":      {algorithms: []string{"ML-KEM-768", "ML-DSA-65"}, desc: "Go PQC implementations"},
	"dilithium":        {algorithms: []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}, desc: "CRYSTALS-Dilithium standalone"},
	"kyber":            {algorithms: []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}, desc: "CRYSTALS-Kyber standalone"},

	// ═══════════════════════════════════════════════════════════════════
	// FIPS Validated Modules (federal compliance critical)
	// ═══════════════════════════════════════════════════════════════════
	"fips-openssl":          {algorithms: []string{"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "SHA-256", "SHA-384"}, desc: "OpenSSL FIPS module"},
	"openssl-fips-provider": {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "OpenSSL 3 FIPS provider"},
	"bc-fips":               {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "Bouncy Castle FIPS (Java)"},
	"wolfcrypt-fips":        {algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256-GCM"}, desc: "wolfCrypt FIPS module"},
}

type cryptoLibInfo struct {
	algorithms []string
	desc       string
}

// CycloneDX JSON structures (simplified for the fields we need)
type cycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	Components   []cycloneDXComponent `json:"components"`
	Dependencies []cycloneDXDep       `json:"dependencies,omitempty"`
}

type cycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl,omitempty"`
	Group   string `json:"group,omitempty"`
}

type cycloneDXDep struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// SPDX JSON structures (simplified)
type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	SPDXID           string `json:"SPDXID"`
}

// ScanSBOM reads an SBOM file and extracts cryptographic dependencies.
func ScanSBOM(path string, format SBOMFormat) (*models.ScanResult, error) {
	start := time.Now()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM: %w", err)
	}

	result := &models.ScanResult{
		Target:    path,
		ScanType:  "sbom",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	// Auto-detect format
	if format == FormatAuto {
		format = detectFormat(data)
	}

	var components []componentInfo

	switch format {
	case FormatCycloneDX:
		components, err = parseCycloneDX(data)
	case FormatSPDX:
		components, err = parseSPDX(data)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}

	if err != nil {
		result.Duration = time.Since(start)
		result.Error = err.Error()
		return result, err
	}

	// Match components against crypto library database
	for _, comp := range components {
		matchCryptoAssets(comp, result)
	}

	result.Duration = time.Since(start)
	return result, nil
}

// componentInfo is a normalized representation of an SBOM component.
type componentInfo struct {
	name    string
	version string
	purl    string
	group   string
}

// detectFormat auto-detects the SBOM format from JSON content.
func detectFormat(data []byte) SBOMFormat {
	// Quick heuristic: check for known format markers
	s := string(data[:min(500, len(data))])
	if strings.Contains(s, "bomFormat") || strings.Contains(s, "CycloneDX") {
		return FormatCycloneDX
	}
	if strings.Contains(s, "spdxVersion") || strings.Contains(s, "SPDX") {
		return FormatSPDX
	}
	return FormatCycloneDX // Default fallback
}

// parseCycloneDX parses a CycloneDX JSON SBOM.
func parseCycloneDX(data []byte) ([]componentInfo, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX: %w", err)
	}

	var components []componentInfo
	for _, c := range bom.Components {
		components = append(components, componentInfo{
			name:    c.Name,
			version: c.Version,
			purl:    c.Purl,
			group:   c.Group,
		})
	}
	return components, nil
}

// parseSPDX parses an SPDX JSON SBOM.
func parseSPDX(data []byte) ([]componentInfo, error) {
	var doc spdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX: %w", err)
	}

	var components []componentInfo
	for _, p := range doc.Packages {
		components = append(components, componentInfo{
			name:    p.Name,
			version: p.VersionInfo,
		})
	}
	return components, nil
}

// matchCryptoAssets checks a component against the crypto library database
// and adds classified assets to the result.
func matchCryptoAssets(comp componentInfo, result *models.ScanResult) {
	// Normalize name for matching
	nameLower := strings.ToLower(comp.name)
	fullName := nameLower
	if comp.group != "" {
		fullName = strings.ToLower(comp.group) + "/" + nameLower
	}

	for pattern, info := range cryptoLibraries {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(fullName, patternLower) || strings.Contains(nameLower, patternLower) {
			// Found a crypto library — create an asset for each algorithm it provides
			for i, algo := range info.algorithms {
				zone := classifier.Classify(algo)
				versionStr := comp.version
				if versionStr == "" {
					versionStr = "unknown"
				}

				result.Assets = append(result.Assets, models.CryptoAsset{
					ID:        fmt.Sprintf("sbom:%s:%s:%d", comp.name, versionStr, i),
					Type:      models.AssetSBOMDep,
					Algorithm: algo,
					Zone:      zone,
					Location:  fmt.Sprintf("%s@%s (%s)", comp.name, versionStr, info.desc),
					Details: map[string]string{
						"package":     comp.name,
						"version":     versionStr,
						"purl":        comp.purl,
						"description": info.desc,
						"library":     pattern,
					},
					Criticality: models.CriticalityStandard,
				})
			}
			break // Only match the first pattern hit per component
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
