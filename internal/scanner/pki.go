// Package scanner provides PKI certificate chain analysis.
package scanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ScanPKI analyzes certificate files or directories for quantum-vulnerable algorithms.
// Supports PEM and DER-encoded certificates (.pem, .crt, .cer, .der).
// If target is a directory, recursively scans all certificate files.
func ScanPKI(target string) (*models.ScanResult, error) {
	start := time.Now()

	result := &models.ScanResult{
		Target:    target,
		ScanType:  "pki",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", target, err)
	}

	var certFiles []string
	if info.IsDir() {
		certFiles, err = findCertFiles(target)
		if err != nil {
			return nil, fmt.Errorf("failed to scan directory: %w", err)
		}
	} else {
		certFiles = []string{target}
	}

	totalCerts := 0
	for _, file := range certFiles {
		certs, parseErr := parseCertFile(file)
		if parseErr != nil {
			continue // Skip unparseable files
		}

		for i, cert := range certs {
			totalCerts++
			assets := classifyCert(cert, file, i, len(certs))
			result.Assets = append(result.Assets, assets...)
		}
	}

	result.Duration = time.Since(start)
	result.Details = map[string]string{
		"files_scanned":      fmt.Sprintf("%d", len(certFiles)),
		"certificates_found": fmt.Sprintf("%d", totalCerts),
	}

	return result, nil
}

// findCertFiles recursively finds certificate files in a directory.
func findCertFiles(dir string) ([]string, error) {
	var files []string
	certExts := map[string]bool{
		".pem": true, ".crt": true, ".cer": true, ".der": true,
		".cert": true, ".key": true, ".pub": true, ".p12": true,
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if certExts[ext] {
				files = append(files, path)
			}
		}
		return nil
	})

	return files, err
}

// parseCertFile reads and parses certificates from a PEM or DER file.
func parseCertFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	// Try PEM decode first
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" || block.Type == "X509 CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
	}

	// If no PEM certs found, try DER
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}

	return certs, nil
}

// classifyCert analyzes a single certificate and returns crypto assets.
func classifyCert(cert *x509.Certificate, file string, index, chainLen int) []models.CryptoAsset {
	var assets []models.CryptoAsset

	// Determine chain position
	position := "leaf"
	if cert.IsCA {
		if cert.Issuer.CommonName == cert.Subject.CommonName {
			position = "root"
		} else {
			position = "intermediate"
		}
	}

	label := fmt.Sprintf("%s (cert %d/%d, %s)", cert.Subject.CommonName, index+1, chainLen, position)
	location := fmt.Sprintf("%s (%s)", file, label)

	// Signature algorithm
	sigAlgo := cert.SignatureAlgorithm.String()
	sigZone := classifier.Classify(sigAlgo)

	assets = append(assets, models.CryptoAsset{
		ID:        fmt.Sprintf("pki-%s-%d-sig", filepath.Base(file), index),
		Type:      models.AssetPKICert,
		Algorithm: sigAlgo,
		Zone:      sigZone,
		Location:  location,
		Details: map[string]string{
			"subject":    cert.Subject.CommonName,
			"issuer":     cert.Issuer.CommonName,
			"serial":     cert.SerialNumber.String(),
			"not_before": cert.NotBefore.Format("2006-01-02"),
			"not_after":  cert.NotAfter.Format("2006-01-02"),
			"is_ca":      fmt.Sprintf("%v", cert.IsCA),
			"position":   position,
		},
		Expiry:      &cert.NotAfter,
		Criticality: certCriticality(cert),
	})

	// Public key algorithm + key size
	pubKeyAlgo, keySize := extractPubKeyInfo(cert)
	pubKeyZone := classifier.Classify(pubKeyAlgo)

	assets = append(assets, models.CryptoAsset{
		ID:          fmt.Sprintf("pki-%s-%d-key", filepath.Base(file), index),
		Type:        models.AssetPKICert,
		Algorithm:   pubKeyAlgo,
		KeySize:     keySize,
		Zone:        pubKeyZone,
		Location:    location,
		Criticality: certCriticality(cert),
	})

	return assets
}

// extractPubKeyInfo returns the public key algorithm name and key size.
func extractPubKeyInfo(cert *x509.Certificate) (string, int) {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		return fmt.Sprintf("RSA-%d", bits), bits
	case *ecdsa.PublicKey:
		bits := key.Curve.Params().BitSize
		name := key.Curve.Params().Name
		return fmt.Sprintf("ECDSA-%s", name), bits
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}

// certCriticality assigns criticality based on certificate properties.
func certCriticality(cert *x509.Certificate) models.Criticality {
	// Root CAs are HVA, government-issued certs are NSS
	cn := strings.ToLower(cert.Subject.CommonName)
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = strings.ToLower(cert.Subject.Organization[0])
	}

	if strings.Contains(org, "government") || strings.Contains(org, "federal") ||
		strings.Contains(cn, ".gov") || strings.Contains(cn, ".mil") {
		return models.CriticalityNSS
	}

	if cert.IsCA {
		return models.CriticalityHVA
	}

	return models.CriticalityStandard
}
