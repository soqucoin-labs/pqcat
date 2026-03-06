// Package scanner provides HSM and hardware security module discovery.
// Probes PKCS#11 slot information, KMIP endpoints, and cloud KMS APIs
// to identify hardware-backed cryptographic operations and their quantum readiness.
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// Known PKCS#11 library paths by platform.
var pkcs11Paths = map[string][]string{
	"linux": {
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/pkcs11/opensc-pkcs11.so",
		"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
		"/opt/safenet/lunaclient/lib/libCryptoki2_64.so",
		"/opt/nfast/toolkits/pkcs11/libcknfast.so",
		"/usr/lib/libeToken.so",
		"/usr/lib/libykcs11.so",
		"/usr/local/lib/libykcs11.so",
	},
	"darwin": {
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
		"/Library/OpenSC/lib/opensc-pkcs11.so",
		"/usr/local/lib/libykcs11.dylib",
		"/opt/homebrew/lib/libykcs11.dylib",
	},
}

// HSM vendor identification patterns.
type hsmVendor struct {
	name       string
	patterns   []string
	algorithms []string
	pqcReady   bool
}

var knownHSMVendors = []hsmVendor{
	{name: "Thales Luna", patterns: []string{"luna", "safenet", "chrysalis"}, algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256"}, pqcReady: false},
	{name: "nCipher/Entrust nShield", patterns: []string{"nfast", "ncipher", "nshield"}, algorithms: []string{"RSA-4096", "ECDSA-P384", "AES-256"}, pqcReady: false},
	{name: "SoftHSM", patterns: []string{"softhsm"}, algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256"}, pqcReady: false},
	{name: "OpenSC (Smart Card)", patterns: []string{"opensc", "smart"}, algorithms: []string{"RSA-2048", "ECDSA-P256"}, pqcReady: false},
	{name: "YubiKey (PIV)", patterns: []string{"ykcs11", "yubi"}, algorithms: []string{"RSA-2048", "ECDSA-P256", "Ed25519"}, pqcReady: false},
	{name: "AWS CloudHSM", patterns: []string{"cloudhsm", "cavium"}, algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256"}, pqcReady: false},
	{name: "Azure Managed HSM", patterns: []string{"azure", "managed.hsm"}, algorithms: []string{"RSA-2048", "ECDSA-P256", "AES-256"}, pqcReady: false},
	{name: "Google Cloud HSM", patterns: []string{"cloudkms", "google.hsm"}, algorithms: []string{"RSA-4096", "ECDSA-P384", "AES-256"}, pqcReady: false},
}

// ScanHSM discovers hardware security modules and their cryptographic capabilities.
func ScanHSM(target string) (*models.ScanResult, error) {
	start := time.Now()

	result := &models.ScanResult{
		Target:    target,
		ScanType:  "hsm",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	hsmCount := 0
	pkcs11Count := 0

	// Phase 1: Scan for PKCS#11 libraries
	platform := runtime.GOOS
	paths := pkcs11Paths[platform]
	if target != "" && target != "auto" {
		// If target is a specific path, scan just that
		paths = []string{target}
	}

	for _, libPath := range paths {
		if _, err := os.Stat(libPath); err == nil {
			pkcs11Count++
			vendor := identifyVendor(libPath)

			for _, algo := range vendor.algorithms {
				zone := classifier.Classify(algo)
				hsmCount++

				result.Assets = append(result.Assets, models.CryptoAsset{
					ID:        fmt.Sprintf("hsm-%s-%d", vendor.name, hsmCount),
					Type:      models.AssetHSMModule,
					Algorithm: algo,
					Zone:      zone,
					Location:  fmt.Sprintf("PKCS#11: %s (%s)", libPath, vendor.name),
					Details: map[string]string{
						"vendor":    vendor.name,
						"library":   libPath,
						"type":      "PKCS#11",
						"pqc_ready": fmt.Sprintf("%v", vendor.pqcReady),
					},
					Criticality: models.CriticalityHVA,
				})
			}
		}
	}

	// Phase 2: Scan for environment-configured KMS
	kmsAssets := discoverKMSFromEnv()
	result.Assets = append(result.Assets, kmsAssets...)

	// Phase 3: Scan for local keystore files
	keystoreAssets := discoverKeystores()
	result.Assets = append(result.Assets, keystoreAssets...)

	result.Duration = time.Since(start)
	result.Details = map[string]string{
		"pkcs11_libraries": fmt.Sprintf("%d", pkcs11Count),
		"hsm_modules":      fmt.Sprintf("%d", hsmCount),
		"kms_endpoints":    fmt.Sprintf("%d", len(kmsAssets)),
		"keystores":        fmt.Sprintf("%d", len(keystoreAssets)),
	}

	return result, nil
}

// identifyVendor matches a PKCS#11 library path to a known HSM vendor.
func identifyVendor(path string) hsmVendor {
	lower := strings.ToLower(path)
	for _, v := range knownHSMVendors {
		for _, pattern := range v.patterns {
			if strings.Contains(lower, pattern) {
				return v
			}
		}
	}
	return hsmVendor{
		name:       "Unknown HSM",
		patterns:   nil,
		algorithms: []string{"RSA-2048"},
		pqcReady:   false,
	}
}

// discoverKMSFromEnv checks environment variables for cloud KMS configuration.
func discoverKMSFromEnv() []models.CryptoAsset {
	var assets []models.CryptoAsset

	kmsEnvVars := []struct {
		envVar     string
		vendor     string
		algorithms []string
	}{
		{"AWS_KMS_KEY_ID", "AWS KMS", []string{"AES-256", "RSA-2048", "ECDSA-P256"}},
		{"AWS_DEFAULT_REGION", "AWS KMS (Region)", []string{"AES-256"}},
		{"AZURE_KEYVAULT_URL", "Azure Key Vault", []string{"RSA-2048", "ECDSA-P256", "AES-256"}},
		{"GOOGLE_KMS_KEY", "Google Cloud KMS", []string{"RSA-4096", "ECDSA-P384", "AES-256"}},
		{"VAULT_ADDR", "HashiCorp Vault", []string{"AES-256", "RSA-2048", "Ed25519"}},
		{"KMIP_HOST", "KMIP Server", []string{"AES-256", "RSA-2048"}},
	}

	for _, kms := range kmsEnvVars {
		if val, ok := os.LookupEnv(kms.envVar); ok && val != "" {
			for _, algo := range kms.algorithms {
				zone := classifier.Classify(algo)
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("kms-%s-%s", kms.vendor, algo),
					Type:      models.AssetHSMModule,
					Algorithm: algo,
					Zone:      zone,
					Location:  fmt.Sprintf("Cloud KMS: %s (env: %s)", kms.vendor, kms.envVar),
					Details: map[string]string{
						"vendor":  kms.vendor,
						"type":    "Cloud KMS",
						"env_var": kms.envVar,
					},
					Criticality: models.CriticalityHVA,
				})
			}
		}
	}

	return assets
}

// discoverKeystores finds Java keystores and PKCS#12 files.
func discoverKeystores() []models.CryptoAsset {
	var assets []models.CryptoAsset

	keystorePaths := []string{
		filepath.Join(os.Getenv("HOME"), ".keystore"),
		filepath.Join(os.Getenv("HOME"), ".ssh"),
		"/etc/ssl/private",
		"/etc/pki/tls/private",
	}

	// Check JAVA_HOME cacerts
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		keystorePaths = append(keystorePaths,
			filepath.Join(javaHome, "lib/security/cacerts"),
			filepath.Join(javaHome, "jre/lib/security/cacerts"),
		)
	}

	keystoreExts := map[string]bool{
		".jks": true, ".p12": true, ".pfx": true, ".keystore": true,
	}

	for _, dir := range keystorePaths {
		info, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			// Single file check
			ext := strings.ToLower(filepath.Ext(dir))
			if keystoreExts[ext] || strings.Contains(dir, "cacerts") {
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("keystore-%s", filepath.Base(dir)),
					Type:      models.AssetHSMModule,
					Algorithm: "RSA-2048",
					Zone:      models.ZoneRed,
					Location:  fmt.Sprintf("Keystore: %s", dir),
					Details: map[string]string{
						"type": "Java Keystore / PKCS#12",
						"path": dir,
					},
					Criticality: models.CriticalityHVA,
				})
			}
			continue
		}

		// Scan directory
		filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if keystoreExts[ext] {
				assets = append(assets, models.CryptoAsset{
					ID:        fmt.Sprintf("keystore-%s", filepath.Base(path)),
					Type:      models.AssetHSMModule,
					Algorithm: "RSA-2048",
					Zone:      models.ZoneRed,
					Location:  fmt.Sprintf("Keystore: %s", path),
					Details: map[string]string{
						"type": "Keystore File",
						"path": path,
					},
					Criticality: models.CriticalityHVA,
				})
			}
			return nil
		})
	}

	return assets
}
