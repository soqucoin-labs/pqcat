# Changelog

All notable changes to PQCAT will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

## [2.4.0] — 2026-03-29

### Added — TLS Deep Scan (Headline Feature)

SSL Labs-grade TLS assessment with proprietary quantum-risk classification — **90× faster** than Qualys SSL Labs.

#### 8-Phase Deep Scan Pipeline
- **Protocol Probing** — Tests TLS 1.0, 1.1, 1.2, 1.3 support via real handshakes
- **Legacy Detection** — Raw TCP probes for SSLv3 and SSLv2 (distinct record formats)
- **Cipher Suite Enumeration** — Tests 20+ cipher suites per protocol version with preference analysis
- **Certificate Enrichment** — Full chain analysis with SHA-1/SHA-256 fingerprints, SCT status, OCSP stapling
- **HTTP Security Headers** — HSTS, max-age, includeSubDomains, preload detection
- **Quantum Risk Classification** — Per-component zone classification (RED/YELLOW/GREEN) with aggregated quantum summary

#### Two-Mode Architecture
- `--deep` — Full 8-phase deep scan (single targets, ~15-20s). Default for single-host TLS scans
- `--fast` — Quick certificate-only scan (original behavior, ~1s). Default for CIDR ranges
- Auto-detection: single targets get deep scan, CIDR ranges get fast scan unless overridden

#### Deep Scan Output
- `supported_protocols` — Array of all supported TLS/SSL versions
- `cipher_suites` — Full enumeration with strength, zone, and forward-secrecy classification
- `server_preference` — Whether server enforces cipher order
- `http_headers` — HSTS configuration and security header analysis
- `quantum_summary` — Aggregated risk: `quantum_zone`, `quantum_score`, `pq_ready`, `issues`

### Added — Container Image Scanner

- New `pqcat scan image <name:tag>` command for Docker/OCI container scanning
- Extracts and analyzes crypto assets from container filesystem layers
- Supports local images and remote registries

### Added — CLI Enterprise Polish

- **`.pqcatignore`** — Exclude files and directories from code scans (gitignore syntax)
- **`--quiet`** — Suppress non-essential output for CI/CD pipelines
- **`--machine`** — Machine-readable output format (JSON lines)
- **`--all-reports`** — Generate PDF, HTML, JSON, CBOM, Executive, and ATO reports in one pass
- **`pqcat history`** — List, show, and diff past scan results from SQLite history
- **`pqcat config validate`** — Validate YAML configuration without running a scan
- **`pqcat config show`** — Display resolved configuration with precedence chain
- **`pqcat alert test`** — Test webhook/email alert channels
- **`pqcat self-update`** — Check for and install latest PQCAT version
- **Progress bars** — Animated progress indicators for long-running scans
- **`--help` interception** — Context-aware help for all subcommands

### Added — Dashboard Enhancements (Pro)

- **Persona Modes** — Role-tailored views for CISO, Auditor, CIO, and Executive personas (FIX-11)
- **Section 508 Accessibility** — WCAG 2.1 AA compliance: focus indicators, ARIA labels, keyboard nav (FIX-14)
- **HTML Table of Contents** — Clickable TOC in HTML report output (FIX-15)
- **License Expiry Banner** — Dashboard shows days remaining and renewal link
- **Progressive Disclosure** — Collapsible sidebar groups: Essentials, Discovery, Analysis, Compliance (FIX-18)
- **First-Login Wizard** — 3-step guided onboarding for new Pro installations (FIX-19)
- **Password Recovery** — Admin password reset flow via CLI
- **Config Scan Wiring** — Configuration file scanner integrated into dashboard

### Added — Reports

- **PDF Bookmarks** — Clickable Table of Contents sidebar in PDF reports
- **Branded Reports** — Custom logo, accent color, organization name, and classification marking

### Added — Windows Installer

- **NSIS Installer** — Full GUI installer with Start Menu shortcuts and uninstaller
- **PowerShell Install Script** — `irm https://install.pqcat.io/windows | iex`
- **CI Integration** — Automated Windows installer build in GitHub Actions release pipeline

### Added — Infrastructure

- **install.pqcat.io** — Cloudflare Worker serving platform-detect install scripts
- **First-Run Onboarding** — Interactive `pqcat quickstart` guided setup

### Changed
- Scanner module count: 7 → **9** (added Container Image, Auto-Detect)
- TLS scan default behavior: single targets now use deep scan automatically
- Dashboard tabs: 18 → **21** (added Persona, Config Scan, Wizard)

### Fixed
- `gofmt` formatting on 14 source files (CI lint now passes)
- Dashboard persona mode switch cases for Users and Audit Log tabs
- CBOM Kit gap closure (UX/DX designer feedback)

---

## [2.0.1] — 2026-03-18

### Added — PQC Detection Patterns (80 patterns)

PQCAT can now detect post-quantum cryptographic implementations and classify them as **GREEN** (PQ Compliant), enabling organizations to track their PQC migration progress — not just their vulnerabilities.

#### CRYSTALS-Dilithium / ML-DSA (FIPS 204)
- Reference implementation functions: `pqcrystals_dilithium*_ref`, `crypto_sign_keypair`, `crypto_sign_signature`, `crypto_sign_verify`
- NAMESPACE macros (`DILITHIUM_NAMESPACE`), polyvec operations, Dilithium header includes
- Consensus integration patterns: `CDilithiumPubKey`, `CDilithiumSignature`

#### CRYSTALS-Kyber / ML-KEM (FIPS 203)
- `crypto_kem_keypair`, `crypto_kem_enc`, `crypto_kem_dec`, Kyber header includes

#### SPHINCS+ / SLH-DSA (FIPS 205), Falcon
- SPHINCS+ reference implementation functions, Falcon sign/verify

#### Library Implementations
- **liboqs** — `OQS_SIG_*`, `OQS_KEM_*`, `OQS_SIG_alg_*`
- **Go** — Cloudflare `circl/sign/dilithium`, `crypto/mlkem`
- **Python** — `pqcrypto.sign.dilithium*`, `oqs.Signature`
- **Java** — Bouncy Castle PQC (`MLDSAParameterSpec`, `MLKEMParameterSpec`)
- **Rust** — `pqcrypto::sign`, `pqcrypto::kem`
- **.NET** — `MLDsa`, `MLKem` System.Security.Cryptography
- **Botan** — `Botan::Dilithium_PrivateKey`, `Botan::Kyber_PrivateKey`

#### Generic Lattice Primitives
- NTT (`ntt()`, `invntt_tomont()`), polyvec operations, SHAKE/Keccak usage

### Changed
- **Classifier**: Added `Falcon` and `SHAKE` to GREEN (quantum-safe) classification
- **Total pattern count**: 499 → **579** (16% increase)

### Impact
- Soqucoin codebase scan: **0 → 619 PQC detections** (571 ML-DSA-65 + 48 SHAKE)
- Zone classification: 76% RED → **52.5% GREEN** (organizations with PQC migrations now see their progress reflected in scores)

## [2.0.0] — 2026-03-17

### Added — Tier 1 Scanner Expansion (Federal-Critical)

#### Windows CNG / CAPI (31 patterns)
- **BCrypt* APIs** — `BCryptGenerateSymmetricKey`, `BCryptEncrypt/Decrypt`, `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`, `BCryptGenerateKeyPair`, `BCryptSignHash`, `BCryptVerifySignature`, `BCryptDeriveKey`, `BCryptSecretAgreement`, `BCryptImportKeyPair`
- **NCrypt* APIs** — `NCryptCreatePersistedKey`, `NCryptSignHash`, `NCryptVerifySignature`, `NCryptDecrypt`
- **CAPI (legacy)** — `CryptAcquireContext`, `CryptGenKey`, `CryptEncrypt/Decrypt`, `CryptSignHash`, `CryptVerifySignature`, `CryptCreateHash`, `CryptHashData`, `CryptDeriveKey`, `CryptImportKey/CryptExportKey`
- **CNG algorithm IDs** — `BCRYPT_RSA_ALGORITHM`, `BCRYPT_ECDSA_P256/P384_ALGORITHM`, `BCRYPT_AES/3DES_ALGORITHM`, `BCRYPT_SHA256/384/512_ALGORITHM`

#### Apple CryptoKit / CommonCrypto / Security.framework (30 patterns)
- **CryptoKit** — `P256/P384/P521.Signing/KeyAgreement`, `Curve25519.Signing/KeyAgreement`, `AES.GCM`, `ChaChaPoly`, `SHA256/384/512`, `HMAC`, `SymmetricKey`, `SecureEnclave`
- **CommonCrypto** — `CCCrypt`, `CC_SHA256/384/512`, `CC_MD5`, `CCHmac`, `CCKeyDerivationPBKDF`
- **Security.framework** — `SecKeyCreateRandomKey`, `SecKeyCreateEncryptedData/DecryptedData`, `SecKeyCreateSignature/VerifySignature`, `SecCertificate*`, `SecTrust*`

#### Java Bouncy Castle (24 patterns)
- **Core** — `BouncyCastleProvider`, `KeyPairGenerator.getInstance`, `KeyAgreement.getInstance`
- **PQC** — `KyberKeyPairGenerator`, `DilithiumSigner`, `SPHINCSPlusSigner`, `NTRUEncapsulation`, `FrodoKeyPairGenerator`, `BIKEKeyPairGenerator`, `CMCEKeyPairGenerator`
- **Classic** — `RSAKeyPairGenerator`, `Ed25519Signer`, `X25519Agreement`
- **Symmetric** — `AESEngine`, `CBCBlockCipher`, `GCMBlockCipher`, `ChaCha20Poly1305`
- **Hash/KDF** — `SHA256Digest`, `HKDFBytesGenerator`, `Argon2BytesGenerator`

#### Shell / CLI (18 patterns)
- **openssl** — `genrsa`, `genpkey`, `req`, `x509`, `s_client`, `s_server`, `enc`, `dgst`, `pkcs12`, `verify`
- **SSH** — `ssh-keygen`, `ssh-agent`, `ssh-add`
- **GPG** — `gpg --gen-key`, `--encrypt`, `--sign`
- **Windows** — `certutil`, `signtool sign`

#### C++ Crypto Libraries (35 patterns)
- **Crypto++** — `RSA::*`, `ECDSA::*`, `AES::Encryption`, `SHA256`, `AutoSeededRandomPool`, `ECIES`
- **Botan** — `Botan::RSA_PrivateKey`, `ECDSA_PrivateKey`, `X25519_PrivateKey`, `TLS::Client/Server`, `AutoSeeded_RNG`, `PBKDF`
- **GnuTLS** — `gnutls_x509_*`, `gnutls_privkey_*`, `gnutls_certificate_*`
- **NSS** — `PK11_*`, `CERT_*`, `SEC_*`
- **libtomcrypt** — `rsa_make_key`, `ecc_make_key`, `sha256/sha512/md5_init`

### Changed
- **File extension support**: 14 → 40 types
- **Comment filter**: Now handles Objective-C `#import` directives
- **Classifier**: Added `X25519`, `X448`, `CURVE25519`, `Ed448` as quantum-vulnerable asymmetric
- **Classifier**: Added `Bcrypt`, `Argon2`, `Scrypt`, `PBKDF2`, `CSPRNG` as quantum-safe symmetric
- **Classifier**: Added `TLS-1.0`, `TLS-1.1`, `SSL-3.0`, `SSL-2.0` as deprecated protocol RED
- **Classifier**: Added `WEAK-RNG` as RED with specific reason ("must use CSPRNG")

### Added — Tier 2 Scanner Expansion (Enterprise-Critical)

#### Configuration File Crypto Detection (16 patterns)
- **nginx** — `ssl_protocols`, `ssl_ciphers`, `ssl_certificate(_key)`
- **Apache** — `SSLProtocol`, `SSLCipherSuite`, `SSLCertificate(Key)File`
- **sshd_config** — `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`
- **Generic TLS** — `tls_min_version`, `cipher_list/suites`, deprecated protocol references

#### Key Material / Secrets Detection (8 patterns)
- PEM headers: RSA/EC/DSA/OPENSSH/ENCRYPTED PRIVATE KEY, CERTIFICATE, DH PARAMETERS

#### Python Extended Libraries (27 patterns)
- **paramiko** — SSHClient, Transport, RSAKey/DSSKey/ECDSAKey
- **ssl** — create_default_context, wrap_socket, SSLContext, PROTOCOL_TLS*
- **bcrypt/argon2** — hashpw, checkpw, PasswordHasher
- **cryptography extended** — X25519/X448/Ed448/DH, serialization, load_pem/der_private_key
- **PyCryptodome** — Crypto.PublicKey.RSA/ECC/DSA, Crypto.Cipher.AES/DES3/PKCS1_OAEP, Crypto.Hash.*

#### Kotlin / Android Keystore (12 patterns)
- AndroidKeyStore, KeyPairGenerator, KeyGenerator, Cipher/Mac/MessageDigest/Signature.getInstance, SecretKeySpec

#### Infrastructure as Code (25 patterns)
- **Terraform** — tls_private_key, aws_acm_certificate, aws_kms_key, azurerm_key_vault_*, google_kms_crypto_key
- **CloudFormation** — AWS::CertificateManager, AWS::KMS::Key, AWS::SecretsManager::Secret
- **Ansible** — openssl_privatekey/certificate/csr, community.crypto.*
- **Kubernetes** — tls.crt/key, kubernetes.io/tls, cert-manager.io, Helm TLS

### Added — Tier 3 Scanner Expansion (Differentiators)

#### Dart / Flutter (12 patterns)
- **pointycastle** — RSAEngine, AESFastEngine, SHA256Digest, ECDSASigner, GCMBlockCipher, HMac, PBKDF2KeyDerivator
- **crypto/encrypt packages** — sha256.convert, Encrypter(AES), RSAKeyPair/RSAPublicKey/RSAPrivateKey

#### Perl Legacy Federal (10 patterns)
- **Crypt::OpenSSL** — RSA, AES, DSA, EC, X509
- **Crypt::** — RSA, DES, Blowfish, Rijndael, CBC, GCM
- **Digest::** — SHA, SHA256, MD5, HMAC
- **Net::SSLeay**, Crypt::PK::*, Crypt::JWT

#### PowerShell .NET Crypto (13 patterns)
- **[System.Security.Cryptography]** — RSA, ECDsa, Aes, TripleDES, SHA256, HMACSHA256, RSACng, Rfc2898DeriveBytes
- **Cmdlets** — ConvertTo-SecureString, Get-PfxCertificate, New-SelfSignedCertificate
- **X509Certificate2**, SecurityProtocol

#### Weak RNG Detection (11 patterns, cross-language)
- JS `Math.random()`, Python `random.*`, C/C++ `rand()/srand()`, Java/Kotlin `new Random()`, Go `math/rand`
- Ruby `rand()`, PHP `rand()/mt_rand()`, C# `new Random()`, Rust `thread_rng()/SmallRng`, Dart `Random()`

#### XML Crypto — SAML, XML-DSig, WS-Security (24 patterns)
- **XML-DSig** — SignedInfo, SignatureMethod, DigestMethod, KeyInfo, X509Certificate, xmldsig namespace
- **Algorithm URIs** — rsa-sha256, ecdsa-sha256, hmac-sha256, aes256-cbc/gcm, rsa-oaep, tripledes-cbc
- **SAML** — Assertion, AuthnRequest, EncryptedAssertion, SAML namespace
- **WS-Security** — Security header, BinarySecurityToken, UsernameToken, wsse namespace
- **XML Encryption** — EncryptedData, EncryptionMethod, xmlenc namespace

#### Docker / Container Extended (7 patterns)
- **Dockerfile** — COPY .crt/.key/.pem, ENV SSL_CERT/TLS_KEY, RUN openssl, EXPOSE 443, update-ca-certificates
- **docker-compose** — secrets, HTTPS_PORT/SSL_PORT

#### Protocol Buffers (4 patterns)
- Crypto fields (public_key, private_key, signature, certificate, cipher_text, hmac, nonce, salt, iv)
- TLS config fields, crypto message types, crypto RPC services

### Added — Bonus: Extended Language Support

#### Node.js crypto / tls / forge / jose (22 patterns)
- **crypto** — createCipher/Decipher, createSign/Verify, createHash, createHmac, generateKeyPair, createDiffieHellman, createECDH, pbkdf2, scrypt, randomBytes, X509Certificate
- **tls** — createServer, createSecureContext, connect, minVersion
- **node-forge** — pki.generateKeyPair, cipher.createCipher, md.sha256.create, hmac.create
- **jose/jsonwebtoken** — sign, verify, encrypt, decrypt
- **SubtleCrypto** — Web Crypto API (encrypt, decrypt, sign, verify, generateKey, importKey, deriveKey, digest)

#### Rust Extended — ring, RustCrypto, rustls (7 patterns)
- **ring** — signature, agreement, aead, digest, hmac, pbkdf2
- **rustls/native-tls** — ServerConfig, ClientConfig, TlsConnector, TlsAcceptor
- **RustCrypto** — sha2, aes, rsa, ed25519_dalek, x25519_dalek, chacha20poly1305
- **pqcrypto** — dilithium, kyber, sphincs (classified GREEN!)

#### Ruby Extended — OpenSSL, bcrypt, rbnacl, JWT (10 patterns)
- OpenSSL::PKey::RSA/EC/DSA/DH, Cipher, Digest, HMAC, X509, SSL
- BCrypt::Password, RbNaCl, JWT.encode/decode, Digest::SHA256

#### PHP Extended — OpenSSL, Sodium, mcrypt (12 patterns)
- openssl_pkey_*, openssl_sign/verify/encrypt/decrypt, openssl_x509_*, openssl_csr_*
- sodium_crypto_sign/box/secretbox/aead/pwhash
- password_hash/verify, hash/hash_hmac/hash_pbkdf2
- mcrypt_* (deprecated, classified as 3DES/RED)

### Impact — v2.0.0 Summary
- **Total pattern count**: ~80 → ~450+ (**463% increase**)
- **File extensions**: 14 → 40 types
- **Languages covered**: 20+ (Go, Python, Java, JS/TS, C, C++, C#, Rust, Swift, ObjC, Kotlin, Dart, Perl, Ruby, PHP, PowerShell, Bash, YAML, XML, Proto, Terraform)
- **Tier 1 validation**: 127 findings across 6 files
- **Tier 2 validation**: 118 findings across 7 files
- **Tier 3 validation**: 203 findings across 9 files
- **Combined**: **448 findings across 22 test files, 100% file detection rate**

## [1.1.1] — 2026-03-17

### Fixed
- **Code Scanner: C/C++ pattern coverage** — Expanded from 10 to 80+ patterns. Previously only matched OpenSSL EVP APIs and libsodium; now detects:
  - Bitcoin Core / libsecp256k1 classes (`CSHA256`, `secp256k1_ecdsa_sign`, `CKey`, `CPubKey`, `CRIPEMD160`, `AES256CBCEncrypt`, `CHMAC_SHA256`)
  - Raw OpenSSL APIs (`SHA256_Init/Update/Final`, `AES_set_encrypt_key`, `RIPEMD160_*`)
  - OpenSSL header includes (`#include <openssl/sha.h>`, etc.)
  - mbedTLS and wolfSSL APIs
  - Legacy/broken algorithms (DES, 3DES, RC4, Blowfish)
  - Schnorr signatures (`secp256k1_schnorrsig_sign*`)
- **Code Scanner: Comment filter killed C/C++ #include detection** — The `#` prefix was treated as a comment for all languages, silently filtering all C/C++ preprocessor directives including `#include <openssl/*.h>`. Now language-aware: `#` is only a comment in Python/Ruby/PHP
- **Code Scanner: Asterisk filter removed** — Lines starting with `*` (C block comment continuation) were incorrectly filtering legitimate C++ pointer operations
- **Classifier: New algorithm support** — Added proper classification for `ECDSA-secp256k1`, `Schnorr-secp256k1`, `ECDH-secp256k1`, `RIPEMD-160`, `MD5`, `SHA-1`, `DES`, `3DES`, `RC4`, `Blowfish`, `SipHash`, `MuHash-3072`, `PBKDF2-SHA256`, `DH-2048`

### Impact
- Bitcoin Core C++ scan: **0 findings → 22+ findings** across `src/` directory
- NASA CryptoLib C scan: Expected significant finding increase for C source files

## [1.1.0] — 2026-03-14

### Added
- **Dashboard: Migration Simulator** — Model PQC migration timelines with configurable org size, budget, risk tolerance, team size, target score, and compliance framework parameters
- **Dashboard: Scheduled Scans & Alerts** — Configure recurring scans (6h/12h/daily/weekly), manage alert channels (webhooks, email), view next-run countdowns
- **Dashboard: CCE Evidence** — Dedicated tab for Confidential Compliance Engine management: sealed report history, 3-layer privacy architecture reference, HNDL risk methodology documentation
- **Dashboard: Audit Log Integrity** — "Verify Chain Integrity" button validates HMAC-SHA256 chain and reports entry count or first broken row
- **Score Trends: Sparse Data Guidance** — Empty-state messaging now explains `--save-db` flag and 3+ data point requirement for meaningful trends
- **TLS Scanner: KeySize Population** — All TLS assets (cipher suites, certificate signatures, public keys) now populate the `key_size` field for accurate reporting
- **TLS Scanner: Issuer Organization** — Certificate assets now include `issuer_org` in details for proper vendor attribution in supply chain reports
- **POA&M: Auto Due Dates** — RED-zone POA&M entries auto-populate `due_date` based on priority: HIGH=30 days, MEDIUM=90 days, LOW=180 days
- **18-Tab Dashboard** — Up from 15 tabs with addition of Scheduled Scans, Migration Simulator, and CCE Evidence

### Changed
- Version strings updated from `1.0.0-alpha` to `1.1.0` across health, stats, and API docs endpoints
- Sidebar footer updated to `PQCAT™ Pro v1.1.0`

### Fixed
- Supply chain report vendor attribution now uses certificate issuer organization instead of scan target hostname
- POA&M entries no longer created without scheduled completion dates (OMB compliance gap)
- TLS assets no longer report `key_size: 0` for certificates and cipher suites

## [1.0.0] — 2026-03-12

### Added
- **9 Scanner Modules**: TLS, SSH, SBOM (180+ libraries), PKI, Code (60+ regex), HSM, CIDR Range, OpenSCAP, Aggregate
- **Compliance Frameworks**: FISMA, FedRAMP, DoD, NIST, CNSA 2.0, PCI DSS, SOX, HIPAA, NYDFS, SWIFT CSP, CMMC with STANDARD/HVA/NSS criticality levels
- **Smart Scan**: "Run All" auto-detects target type (hostname, file, CIDR) and runs applicable scanners
- **Two Editions**: Enclave (air-gapped, zero network code) and Pro (REST API, live threat intel, web dashboard)
- **Dashboard**: 15-tab enterprise Command Center with global scan context selector
- **Report Formats**: HTML, PDF, JSON, Executive Briefing, ATO Package
- **ML-DSA-44 Report Seal**: FIPS 204 post-quantum signatures on assessment reports via Cloudflare CIRCL
- **Role-Based Access Control (RBAC)**: Three roles — admin, analyst, viewer — with route-level enforcement
- **User Management**: CRUD via `/api/users` (admin-only), bcrypt password hashing, 12-character minimum
- **First-Run Admin Setup**: Cryptographically random 32-character admin password with force-change flag
- **Audit Logging**: HMAC-SHA256 chained tamper-proof audit trail with chain integrity verification
- **Session Authentication**: 256-bit random tokens, HttpOnly/Secure/SameSite cookies, 8h TTL
- **Prometheus Metrics**: Admin-only `/metrics` endpoint — 12 operational metrics
- **SIEM Integration**: Splunk HEC, ELK Bulk JSON, CEF Syslog with one-click export
- **Federal Compliance**: NIST 800-53 control mapping, ATO package generator, POA&M tracker
- **Vendor Supply Chain**: Per-vendor PQC readiness scoring and risk matrix
- **Scan History**: Full audit trail with per-scan analysis, comparison, and report generation
- **Threat Intelligence**: Embedded quantum timeline base + live feed (Pro), sidecar JSON (Enclave)
- **Score Trending**: Historical score tracking with visual trend analysis
- **Baselines & Drift**: Save baseline scans and detect cryptographic drift between assessments
- **Configuration**: YAML-based with 6-level precedence chain, org/environment/framework settings
- **SBOM Generation**: CycloneDX SBOM auto-generated in CI via `syft`
- **Environment-Based Secrets**: Sensitive configuration via env vars only
- **Server Test Suite**: 26 httptest-based tests covering auth, RBAC, rate limiting, audit log
- **CI/CD**: Dual test runs (Enclave + Pro), dual `go vet`, `govulncheck`, dual coverage reporting
- **Cross-platform**: macOS (ARM64, x86_64), Linux (AMD64, ARM64), Windows
- **Zero-dependency**: Single static binary, no CGO, no runtime dependencies

### Security
- Air-gap edition contains zero outbound network code — guaranteed by Go compiler build tags
- Timing-attack resistant authentication: constant-time API key comparison, dummy bcrypt for unknown usernames
- RBAC enforced at route level with audit trail on access denials
- HMAC-SHA256 chained audit log — tampering with any entry breaks the verifiable chain
- Secrets via env vars only — never stored in plaintext config files
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- ML-DSA-44 digital signatures on all assessment reports
