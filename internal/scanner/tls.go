// Package scanner provides cryptographic asset discovery modules.
package scanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// TLSScanOptions configures TLS scanning behavior.
type TLSScanOptions struct {
	Timeout    time.Duration
	Port       string
	SkipVerify bool
}

// DefaultTLSOptions returns sensible defaults.
func DefaultTLSOptions() TLSScanOptions {
	return TLSScanOptions{
		Timeout:    10 * time.Second,
		Port:       "443",
		SkipVerify: true, // We're scanning, not validating trust
	}
}

// ScanTLS connects to a target host, extracts the TLS certificate chain
// and negotiated cipher suite, and classifies each cryptographic asset.
func ScanTLS(target string, opts TLSScanOptions) (*models.ScanResult, error) {
	start := time.Now()

	host, port := parseTarget(target, opts.Port)
	addr := net.JoinHostPort(host, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: opts.Timeout},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: opts.SkipVerify,
			ServerName:         host,
		},
	)
	if err != nil {
		return &models.ScanResult{
			Target:    target,
			ScanType:  "tls",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Sprintf("connection failed: %v", err),
		}, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &models.ScanResult{
		Target:    target,
		ScanType:  "tls",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	// Extract negotiated cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	cipherAlgos := parseCipherSuite(cipherName)
	for i, algo := range cipherAlgos {
		zone := classifier.Classify(algo)
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:cipher:%d", addr, i),
			Type:      models.AssetTLSCipher,
			Algorithm: algo,
			Zone:      zone,
			Location:  fmt.Sprintf("%s (cipher suite: %s)", addr, cipherName),
			Details: map[string]string{
				"cipher_suite": cipherName,
				"tls_version":  tlsVersionName(state.Version),
				"component":    cipherComponent(i),
			},
			Criticality: models.CriticalityStandard,
		})
	}

	// Extract certificate chain
	for i, cert := range state.PeerCertificates {
		sigAlgo := cert.SignatureAlgorithm.String()
		pubKeyAlgo := describePublicKey(cert)

		// Classify the signature algorithm
		sigZone := classifier.Classify(sigAlgo)
		expiry := cert.NotAfter
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:cert:%d:sig", addr, i),
			Type:      models.AssetTLSCert,
			Algorithm: sigAlgo,
			Zone:      sigZone,
			Location:  fmt.Sprintf("%s (cert %d: %s)", addr, i, cert.Subject.CommonName),
			Details: map[string]string{
				"subject":     cert.Subject.CommonName,
				"issuer":      cert.Issuer.CommonName,
				"serial":      cert.SerialNumber.String(),
				"not_before":  cert.NotBefore.Format(time.RFC3339),
				"not_after":   cert.NotAfter.Format(time.RFC3339),
				"chain_depth": fmt.Sprintf("%d", i),
				"is_ca":       fmt.Sprintf("%v", cert.IsCA),
				"component":   "signature",
			},
			Expiry:      &expiry,
			Criticality: models.CriticalityStandard,
		})

		// Classify the public key algorithm
		pubZone := classifier.Classify(pubKeyAlgo)
		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:cert:%d:pubkey", addr, i),
			Type:      models.AssetTLSCert,
			Algorithm: pubKeyAlgo,
			Zone:      pubZone,
			Location:  fmt.Sprintf("%s (cert %d: %s)", addr, i, cert.Subject.CommonName),
			Details: map[string]string{
				"subject":   cert.Subject.CommonName,
				"component": "public_key",
			},
			Criticality: models.CriticalityStandard,
		})
	}

	result.Duration = time.Since(start)
	return result, nil
}

// parseTarget splits "host:port" or returns host with default port.
func parseTarget(target, defaultPort string) (string, string) {
	// Strip protocol prefix if present
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, defaultPort
	}
	return host, port
}

// describePublicKey returns a human-readable algorithm + key size string.
func describePublicKey(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA-P%d", pub.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// parseCipherSuite breaks a cipher suite name into its component algorithms.
func parseCipherSuite(name string) []string {
	var algos []string

	// Extract key exchange
	switch {
	case strings.Contains(name, "ECDHE"):
		algos = append(algos, "ECDHE")
	case strings.Contains(name, "DHE") && !strings.Contains(name, "ECDHE"):
		algos = append(algos, "DHE")
	case strings.Contains(name, "RSA") && !strings.Contains(name, "ECDHE"):
		algos = append(algos, "RSA-KEX")
	}

	// Extract bulk cipher
	switch {
	case strings.Contains(name, "AES_256_GCM"):
		algos = append(algos, "AES-256-GCM")
	case strings.Contains(name, "AES_128_GCM"):
		algos = append(algos, "AES-128-GCM")
	case strings.Contains(name, "CHACHA20_POLY1305"):
		algos = append(algos, "ChaCha20-Poly1305")
	case strings.Contains(name, "AES_256_CBC"):
		algos = append(algos, "AES-256-CBC")
	case strings.Contains(name, "AES_128_CBC"):
		algos = append(algos, "AES-128-CBC")
	}

	if len(algos) == 0 {
		algos = append(algos, name) // Fallback: whole name
	}

	return algos
}

// cipherComponent returns a label for the cipher suite component by index.
func cipherComponent(index int) string {
	labels := []string{"key_exchange", "bulk_cipher", "mac"}
	if index < len(labels) {
		return labels[index]
	}
	return fmt.Sprintf("component_%d", index)
}

// tlsVersionName returns a human-readable TLS version string.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
