package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
	"golang.org/x/crypto/ssh"

	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// SSHScanOptions configures SSH scanning.
type SSHScanOptions struct {
	Timeout time.Duration
	Port    string
}

// DefaultSSHOptions returns sensible defaults for SSH scanning.
func DefaultSSHOptions() SSHScanOptions {
	return SSHScanOptions{
		Timeout: 10 * time.Second,
		Port:    "22",
	}
}

// ScanSSH connects to a target host and extracts SSH host key and key exchange
// algorithm information for classification.
func ScanSSH(ctx context.Context, target string, opts SSHScanOptions) (*models.ScanResult, error) {
	start := time.Now()

	host, port := parseTarget(target, opts.Port)
	addr := net.JoinHostPort(host, port)

	result := &models.ScanResult{
		Target:    target,
		ScanType:  "ssh",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	// We use a HostKeyCallback that captures the host key but rejects connection.
	// We only need the handshake data, not a full authenticated session.
	var hostKeyAlgo string
	var hostKeyBits int

	config := &ssh.ClientConfig{
		User:    "pqcat-scanner",
		Auth:    []ssh.AuthMethod{}, // No real auth
		Timeout: opts.Timeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKeyAlgo = key.Type()
			hostKeyBits = keyBitSize(key)
			return nil
		},
	}

	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		// Even on auth failure we may have captured the host key
		if hostKeyAlgo == "" {
			result.Duration = time.Since(start)
			result.Error = fmt.Sprintf("SSH handshake failed: %v", err)
			return result, err
		}
		// Auth failed but we got the host key — that's fine
	} else {
		conn.Close()
	}

	if hostKeyAlgo != "" {
		algoName := normalizeSSHAlgo(hostKeyAlgo)
		zone := classifier.Classify(algoName)

		result.Assets = append(result.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:ssh:hostkey", addr),
			Type:      models.AssetSSHHostKey,
			Algorithm: algoName,
			KeySize:   hostKeyBits,
			Zone:      zone,
			Location:  addr,
			Details: map[string]string{
				"ssh_key_type": hostKeyAlgo,
				"raw_type":     hostKeyAlgo,
			},
			Criticality: models.CriticalityStandard,
		})
	}

	result.Duration = time.Since(start)

	// SSH-5: Enrich with banner capture (product, version, PQ readiness)
	if len(result.Assets) > 0 {
		// Grab the raw SSH banner from a TCP connection
		banner := grabSSHBanner(ctx, addr, opts.Timeout)
		if banner != "" {
			result.Assets = EnrichSSHWithBanner(result.Assets, banner)
		}
	}

	return result, nil
}

// normalizeSSHAlgo maps SSH key type strings to classifier-compatible names.
func normalizeSSHAlgo(sshType string) string {
	normalized := map[string]string{
		"ssh-rsa":                            "RSA-2048",
		"rsa-sha2-256":                       "RSA-2048",
		"rsa-sha2-512":                       "RSA-2048",
		"ssh-ed25519":                        "Ed25519",
		"ecdsa-sha2-nistp256":                "ECDSA-P256",
		"ecdsa-sha2-nistp384":                "ECDSA-P384",
		"ecdsa-sha2-nistp521":                "ECDSA-P521",
		"ssh-dss":                            "DSA-1024",
		"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-P256",
		"sk-ssh-ed25519@openssh.com":         "Ed25519",
	}

	if name, ok := normalized[strings.ToLower(sshType)]; ok {
		return name
	}
	return sshType
}

// keyBitSize determines the key size from an SSH public key.
func keyBitSize(key ssh.PublicKey) int {
	// CryptoPublicKey interface exposes the underlying crypto key
	if cpk, ok := key.(ssh.CryptoPublicKey); ok {
		switch k := cpk.CryptoPublicKey().(type) {
		case *rsa.PublicKey:
			return k.N.BitLen()
		case *ecdsa.PublicKey:
			return k.Curve.Params().BitSize
		case ed25519.PublicKey:
			return 256
		case *dsa.PublicKey:
			return k.P.BitLen()
		}
	}

	// Fallback based on type (only for non-standard key types)
	switch key.Type() {
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		return 2048 // Conservative default when CryptoPublicKey unavailable
	case "ssh-ed25519":
		return 256
	case "ecdsa-sha2-nistp256":
		return 256
	case "ecdsa-sha2-nistp384":
		return 384
	case "ecdsa-sha2-nistp521":
		return 521
	default:
		return 0
	}
}

// grabSSHBanner connects via raw TCP and reads the SSH identification string.
// The banner is the first line sent by the server (e.g. "SSH-2.0-OpenSSH_9.6").
func grabSSHBanner(ctx context.Context, addr string, timeout time.Duration) string {
	conn, err := dialContext(ctx, "tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	banner := strings.TrimSpace(string(buf[:n]))
	// SSH banners start with "SSH-"
	if strings.HasPrefix(banner, "SSH-") {
		return banner
	}
	return ""
}
