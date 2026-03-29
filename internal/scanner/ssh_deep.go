package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/models"
)

// DeepSSHResult contains full SSH handshake analysis.
type DeepSSHResult struct {
	Target      string         `json:"target"`
	Banner      string         `json:"banner"`         // e.g. "SSH-2.0-OpenSSH_9.6"
	ServerSW    string         `json:"server_sw"`      // Parsed software name
	HostKeys    []SSHAlgorithm `json:"host_keys"`      // All supported host key types
	KEX         []SSHAlgorithm `json:"kex_algorithms"` // Key exchange algorithms
	Ciphers     []SSHAlgorithm `json:"ciphers"`        // Encryption algorithms
	MACs        []SSHAlgorithm `json:"macs"`           // MAC algorithms
	Compression []string       `json:"compression"`    // Compression methods
	PQReady     bool           `json:"pq_ready"`       // True if sntrup761 or ML-KEM present
	PQAlgos     []string       `json:"pq_algos"`       // Names of PQ-capable algorithms
	Duration    time.Duration  `json:"duration_ns"`
	Error       string         `json:"error,omitempty"`
}

// SSHAlgorithm represents a classified SSH algorithm.
type SSHAlgorithm struct {
	Name     string      `json:"name"`
	Zone     models.Zone `json:"zone"`
	Reason   string      `json:"reason"`
	Category string      `json:"category"` // "kex", "host_key", "cipher", "mac"
}

// sshKEXINIT represents the parsed SSH_MSG_KEXINIT packet.
type sshKEXINIT struct {
	KexAlgorithms         string
	ServerHostKeyAlgos    string
	CiphersClientToServer string
	CiphersServerToClient string
	MACsClientToServer    string
	MACsServerToClient    string
	CompressionC2S        string
	CompressionS2C        string
}

// ScanSSHDeep performs a comprehensive SSH security assessment by directly
// parsing the SSH_MSG_KEXINIT packet from the server. This captures ALL
// algorithms the server supports — not just the one Go's SSH library negotiates.
func ScanSSHDeep(target string, opts SSHScanOptions) (*DeepSSHResult, *models.ScanResult, error) {
	start := time.Now()

	host, port := parseTarget(target, opts.Port)
	addr := net.JoinHostPort(host, port)

	result := &DeepSSHResult{
		Target: addr,
	}

	scanResult := &models.ScanResult{
		Target:    target,
		ScanType:  "ssh",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	// Phase 1: Raw TCP connection to capture banner and KEXINIT
	conn, err := net.DialTimeout("tcp", addr, opts.Timeout)
	if err != nil {
		result.Duration = time.Since(start)
		result.Error = fmt.Sprintf("connection failed: %v", err)
		scanResult.Duration = time.Since(start)
		scanResult.Error = result.Error
		return result, scanResult, err
	}
	defer conn.Close()

	// Set deadline for the entire exchange
	conn.SetDeadline(time.Now().Add(opts.Timeout))

	// Phase 2: Read server banner (SSH-2.0-OpenSSH_9.6)
	reader := bufio.NewReader(conn)
	bannerLine, err := reader.ReadString('\n')
	if err != nil {
		result.Duration = time.Since(start)
		result.Error = fmt.Sprintf("failed to read banner: %v", err)
		scanResult.Duration = time.Since(start)
		scanResult.Error = result.Error
		return result, scanResult, err
	}
	result.Banner = strings.TrimSpace(bannerLine)
	result.ServerSW = parseSSHBanner(result.Banner)

	// Send our banner to continue the handshake
	_, err = fmt.Fprintf(conn, "SSH-2.0-PQCAT_Scanner_2.4\r\n")
	if err != nil {
		result.Duration = time.Since(start)
		result.Error = fmt.Sprintf("failed to send banner: %v", err)
		scanResult.Duration = time.Since(start)
		scanResult.Error = result.Error
		return result, scanResult, err
	}

	// Phase 3: Read SSH_MSG_KEXINIT (message type 20)
	kexInit, err := readKEXINIT(reader)
	if err != nil {
		result.Duration = time.Since(start)
		result.Error = fmt.Sprintf("failed to read KEXINIT: %v", err)
		scanResult.Duration = time.Since(start)
		scanResult.Error = result.Error
		// Even on KEXINIT failure, return the banner info
		return result, scanResult, err
	}

	// Phase 4: Classify all algorithms
	result.KEX = classifySSHAlgorithms(splitNameList(kexInit.KexAlgorithms), "kex")
	result.HostKeys = classifySSHAlgorithms(splitNameList(kexInit.ServerHostKeyAlgos), "host_key")
	// Use server-to-client as the authoritative list (what the server sends us)
	result.Ciphers = classifySSHAlgorithms(splitNameList(kexInit.CiphersServerToClient), "cipher")
	result.MACs = classifySSHAlgorithms(splitNameList(kexInit.MACsServerToClient), "mac")
	result.Compression = splitNameList(kexInit.CompressionS2C)

	// Phase 5: Check for PQ readiness
	for _, kex := range result.KEX {
		if kex.Zone == models.ZoneGreen && isPQSSHAlgo(kex.Name) {
			result.PQReady = true
			result.PQAlgos = append(result.PQAlgos, kex.Name)
		}
	}

	// Phase 6: Emit crypto assets for the unified report
	for _, hk := range result.HostKeys {
		scanResult.Assets = append(scanResult.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:ssh:hostkey:%s", addr, hk.Name),
			Type:      models.AssetSSHHostKey,
			Algorithm: normalizeSSHDeepAlgo(hk.Name),
			KeySize:   sshAlgoKeySize(hk.Name),
			Zone:      hk.Zone,
			Location:  fmt.Sprintf("%s (host key)", addr),
			Details: map[string]string{
				"ssh_key_type": hk.Name,
				"category":     "host_key",
				"banner":       result.Banner,
			},
			Criticality: models.CriticalityStandard,
		})
	}

	for _, kex := range result.KEX {
		// Skip the ext-info pseudo-algorithms
		if strings.HasPrefix(kex.Name, "ext-info-") || kex.Name == "kex-strict-s-v00@openssh.com" || kex.Name == "kex-strict-c-v00@openssh.com" {
			continue
		}
		scanResult.Assets = append(scanResult.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:ssh:kex:%s", addr, kex.Name),
			Type:      models.AssetSSHKEX,
			Algorithm: normalizeSSHDeepAlgo(kex.Name),
			KeySize:   sshKEXKeySize(kex.Name),
			Zone:      kex.Zone,
			Location:  fmt.Sprintf("%s (key exchange)", addr),
			Details: map[string]string{
				"kex_algorithm": kex.Name,
				"category":      "kex",
				"pq_ready":      fmt.Sprintf("%v", isPQSSHAlgo(kex.Name)),
			},
			Criticality: models.CriticalityHVA, // KEX is the critical quantum-vulnerable layer
		})
	}

	for _, c := range result.Ciphers {
		scanResult.Assets = append(scanResult.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:ssh:cipher:%s", addr, c.Name),
			Type:      models.AssetSSHCipher,
			Algorithm: normalizeSSHCipherAlgo(c.Name),
			KeySize:   sshCipherKeySize(c.Name),
			Zone:      c.Zone,
			Location:  fmt.Sprintf("%s (encryption)", addr),
			Details: map[string]string{
				"cipher":   c.Name,
				"category": "cipher",
			},
			Criticality: models.CriticalityStandard,
		})
	}

	for _, m := range result.MACs {
		scanResult.Assets = append(scanResult.Assets, models.CryptoAsset{
			ID:        fmt.Sprintf("%s:ssh:mac:%s", addr, m.Name),
			Type:      models.AssetSSHMAC,
			Algorithm: normalizeSSHMACAlgo(m.Name),
			Zone:      m.Zone,
			Location:  fmt.Sprintf("%s (integrity)", addr),
			Details: map[string]string{
				"mac":      m.Name,
				"category": "mac",
			},
			Criticality: models.CriticalityStandard,
		})
	}

	// Add banner as a detail on the scan result
	if scanResult.Details == nil {
		scanResult.Details = make(map[string]string)
	}
	scanResult.Details["ssh_banner"] = result.Banner
	scanResult.Details["ssh_software"] = result.ServerSW
	scanResult.Details["pq_ready"] = fmt.Sprintf("%v", result.PQReady)
	if result.PQReady {
		scanResult.Details["pq_algorithms"] = strings.Join(result.PQAlgos, ", ")
	}

	result.Duration = time.Since(start)
	scanResult.Duration = time.Since(start)
	return result, scanResult, nil
}

// readKEXINIT reads and parses an SSH_MSG_KEXINIT packet from the connection.
// SSH binary packet format:
//
//	uint32    packet_length (not including the length field itself or MAC)
//	byte      padding_length
//	byte[n1]  payload (n1 = packet_length - padding_length - 1)
//	byte[n2]  padding (n2 = padding_length)
//
// Inside the payload, SSH_MSG_KEXINIT (type 20) has:
//
//	byte      SSH_MSG_KEXINIT (20)
//	byte[16]  cookie (random bytes)
//	name-list kex_algorithms
//	name-list server_host_key_algorithms
//	name-list encryption_algorithms_client_to_server
//	name-list encryption_algorithms_server_to_client
//	name-list mac_algorithms_client_to_server
//	name-list mac_algorithms_server_to_client
//	name-list compression_algorithms_client_to_server
//	name-list compression_algorithms_server_to_client
//	... (languages, first_kex_packet_follows — we don't need these)
func readKEXINIT(reader *bufio.Reader) (*sshKEXINIT, error) {
	// Read packet length (4 bytes, big-endian)
	lenBuf := make([]byte, 4)
	if _, err := readFull(reader, lenBuf); err != nil {
		return nil, fmt.Errorf("reading packet length: %w", err)
	}
	packetLen := binary.BigEndian.Uint32(lenBuf)

	// Sanity check — SSH packets shouldn't exceed 256KB
	if packetLen > 262144 {
		return nil, fmt.Errorf("packet too large: %d bytes", packetLen)
	}

	// Read the full packet
	packet := make([]byte, packetLen)
	if _, err := readFull(reader, packet); err != nil {
		return nil, fmt.Errorf("reading packet data: %w", err)
	}

	// packet[0] = padding_length
	paddingLen := packet[0]
	if int(paddingLen)+1 > len(packet) {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}

	// payload starts at packet[1], ends at packet[packetLen - paddingLen - 1]
	payload := packet[1 : len(packet)-int(paddingLen)]
	if len(payload) < 17 { // 1 byte type + 16 bytes cookie minimum
		return nil, fmt.Errorf("payload too short: %d bytes", len(payload))
	}

	// First byte should be SSH_MSG_KEXINIT (20)
	if payload[0] != 20 {
		return nil, fmt.Errorf("expected SSH_MSG_KEXINIT (20), got %d", payload[0])
	}

	// Skip type byte (1) + cookie (16) = 17 bytes
	data := payload[17:]

	// Parse name-lists in order
	result := &sshKEXINIT{}
	var s string
	var err error

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("kex_algorithms: %w", err)
	}
	result.KexAlgorithms = s

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("server_host_key_algorithms: %w", err)
	}
	result.ServerHostKeyAlgos = s

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("ciphers_c2s: %w", err)
	}
	result.CiphersClientToServer = s

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("ciphers_s2c: %w", err)
	}
	result.CiphersServerToClient = s

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("macs_c2s: %w", err)
	}
	result.MACsClientToServer = s

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("macs_s2c: %w", err)
	}
	result.MACsServerToClient = s

	if s, data, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("compression_c2s: %w", err)
	}
	result.CompressionC2S = s

	if s, _, err = readNameList(data); err != nil {
		return nil, fmt.Errorf("compression_s2c: %w", err)
	}
	result.CompressionS2C = s

	return result, nil
}

// readNameList parses an SSH name-list: uint32 length + comma-separated string.
func readNameList(data []byte) (string, []byte, error) {
	if len(data) < 4 {
		return "", nil, fmt.Errorf("insufficient data for name-list length")
	}
	length := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if int(length) > len(data) {
		return "", nil, fmt.Errorf("name-list length %d exceeds remaining data %d", length, len(data))
	}
	return string(data[:length]), data[length:], nil
}

// readFull reads exactly len(buf) bytes from the reader.
func readFull(reader *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := reader.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// splitNameList splits a comma-separated SSH name-list into individual names.
func splitNameList(nameList string) []string {
	if nameList == "" {
		return nil
	}
	parts := strings.Split(nameList, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// classifySSHAlgorithms classifies a list of SSH algorithm names.
func classifySSHAlgorithms(names []string, category string) []SSHAlgorithm {
	result := make([]SSHAlgorithm, 0, len(names))
	for _, name := range names {
		zone, reason := classifySSHDeepAlgo(name, category)
		result = append(result, SSHAlgorithm{
			Name:     name,
			Zone:     zone,
			Reason:   reason,
			Category: category,
		})
	}
	return result
}

// classifySSHDeepAlgo provides quantum-risk classification for individual SSH algorithms.
// This is SSH-specific because the algorithm names don't match the universal classifier format.
// Named "Deep" to avoid collision with config.go's simpler classifySSHAlgo.
func classifySSHDeepAlgo(name string, category string) (models.Zone, string) {
	lower := strings.ToLower(name)

	switch category {
	case "kex":
		return classifySSHKEX(lower, name)
	case "host_key":
		return classifySSHHostKey(lower, name)
	case "cipher":
		return classifySSHCipher(lower, name)
	case "mac":
		return classifySSHMAC(lower, name)
	}

	// Fallback to universal classifier
	return classifier.ClassifyWithReason(name)
}

// classifySSHKEX classifies SSH key exchange algorithms.
func classifySSHKEX(lower, name string) (models.Zone, string) {
	// PQ-safe hybrid KEX — GREEN
	if strings.Contains(lower, "sntrup761") || strings.Contains(lower, "mlkem") ||
		strings.Contains(lower, "ml-kem") || strings.Contains(lower, "kyber") {
		return models.ZoneGreen, "Post-quantum hybrid key exchange — CNSA 2.0 compliant"
	}

	// Skip pseudo-algorithms
	if strings.HasPrefix(lower, "ext-info-") || strings.Contains(lower, "kex-strict-") {
		return models.ZoneGreen, "SSH extension negotiation — not a cryptographic algorithm"
	}

	// Curve25519 — quantum vulnerable but strongest classical option
	if strings.Contains(lower, "curve25519") || lower == "curve25519-sha256@libssh.org" {
		return models.ZoneRed, "ECDH Curve25519 — quantum vulnerable (Shor's algorithm), but strongest classical KEX"
	}

	// ECDH NIST curves — quantum vulnerable
	if strings.Contains(lower, "ecdh-sha2-nistp") {
		return models.ZoneRed, "ECDH NIST curve — quantum vulnerable (Shor's algorithm on elliptic curves)"
	}

	// Diffie-Hellman group exchange — quantum vulnerable
	if strings.Contains(lower, "diffie-hellman-group-exchange") {
		return models.ZoneRed, "DH group exchange — quantum vulnerable (Shor's algorithm on discrete log)"
	}

	// DH with specific groups — quantum vulnerable, some classically weak
	// Order matters: check group18/16/14 BEFORE group1 (group14 contains "group1")
	if strings.Contains(lower, "diffie-hellman-group18") {
		return models.ZoneRed, "DH group18 (8192-bit) — quantum vulnerable but highest classical margin"
	}
	if strings.Contains(lower, "diffie-hellman-group16") {
		return models.ZoneRed, "DH group16 (4096-bit) — quantum vulnerable but higher classical margin"
	}
	if strings.Contains(lower, "diffie-hellman-group14") {
		return models.ZoneRed, "DH group14 (2048-bit) — quantum vulnerable (Shor's algorithm)"
	}
	if strings.Contains(lower, "diffie-hellman-group1") {
		return models.ZoneRed, "DH group1 (Oakley Group 2, 1024-bit) — classically AND quantum vulnerable"
	}

	return models.ZoneRed, fmt.Sprintf("KEX algorithm '%s' — assumed quantum vulnerable", name)
}

// classifySSHHostKey classifies SSH host key algorithms.
func classifySSHHostKey(lower, name string) (models.Zone, string) {
	// PQ host key algorithms
	if strings.Contains(lower, "mldsa") || strings.Contains(lower, "ml-dsa") ||
		strings.Contains(lower, "dilithium") || strings.Contains(lower, "falcon") ||
		strings.Contains(lower, "sphincs") || strings.Contains(lower, "slh-dsa") {
		return models.ZoneGreen, "Post-quantum digital signature — CNSA 2.0 compliant"
	}

	// Ed25519 / Ed448
	if strings.Contains(lower, "ed25519") || strings.Contains(lower, "ed448") {
		return models.ZoneRed, "EdDSA — quantum vulnerable (Shor's algorithm on elliptic curves)"
	}

	// RSA with various hash algorithms
	if strings.Contains(lower, "rsa") {
		return models.ZoneRed, "RSA — quantum vulnerable (Shor's algorithm on integer factorization)"
	}

	// ECDSA
	if strings.Contains(lower, "ecdsa") {
		return models.ZoneRed, "ECDSA — quantum vulnerable (Shor's algorithm on elliptic curves)"
	}

	// DSA
	if strings.Contains(lower, "dss") || lower == "ssh-dss" {
		return models.ZoneRed, "DSA — classically deprecated AND quantum vulnerable"
	}

	return models.ZoneRed, fmt.Sprintf("Host key algorithm '%s' — assumed quantum vulnerable", name)
}

// classifySSHCipher classifies SSH encryption algorithms.
func classifySSHCipher(lower, name string) (models.Zone, string) {
	// ChaCha20-Poly1305 — best practice, quantum safe (symmetric)
	if strings.Contains(lower, "chacha20") {
		return models.ZoneGreen, "ChaCha20-Poly1305 — quantum-safe AEAD cipher"
	}

	// AES-GCM — quantum safe (symmetric, AEAD)
	if strings.Contains(lower, "aes") && strings.Contains(lower, "gcm") {
		bits := "256"
		if strings.Contains(lower, "128") {
			bits = "128"
		}
		return models.ZoneGreen, fmt.Sprintf("AES-%s-GCM — quantum-safe AEAD cipher", bits)
	}

	// AES-CTR — quantum safe (symmetric, good mode)
	if strings.Contains(lower, "aes") && strings.Contains(lower, "ctr") {
		return models.ZoneGreen, "AES-CTR — quantum-safe symmetric cipher"
	}

	// AES-CBC — quantum safe but vulnerable to padding oracle attacks
	if strings.Contains(lower, "aes") && strings.Contains(lower, "cbc") {
		return models.ZoneYellow, "AES-CBC — quantum-safe but vulnerable to padding oracle attacks (prefer GCM/CTR)"
	}

	// 3DES — classically weak
	if strings.Contains(lower, "3des") || strings.Contains(lower, "tripledes") {
		return models.ZoneRed, "3DES — classically deprecated (64-bit block, Sweet32 attack)"
	}

	// Blowfish — classically weak
	if strings.Contains(lower, "blowfish") {
		return models.ZoneRed, "Blowfish — classically deprecated (64-bit block)"
	}

	// RC4/Arcfour — classically broken
	if strings.Contains(lower, "arcfour") || strings.Contains(lower, "rc4") {
		return models.ZoneRed, "RC4/Arcfour — classically broken (biased keystream)"
	}

	// CAST — old cipher
	if strings.Contains(lower, "cast") {
		return models.ZoneRed, "CAST-128 — classically deprecated (64-bit block)"
	}

	// 'none' cipher — no encryption at all
	if lower == "none" {
		return models.ZoneRed, "No encryption — plaintext transmission"
	}

	return models.ZoneYellow, fmt.Sprintf("Cipher '%s' — classification uncertain", name)
}

// classifySSHMAC classifies SSH MAC algorithms.
func classifySSHMAC(lower, name string) (models.Zone, string) {
	// Encrypt-then-MAC variants are preferred (-etm suffix)
	isETM := strings.HasSuffix(lower, "-etm@openssh.com")

	// SHA-2 family MACs — quantum safe
	if strings.Contains(lower, "hmac-sha2-512") {
		reason := "HMAC-SHA2-512 — quantum-safe integrity"
		if isETM {
			reason += " (encrypt-then-MAC — best practice)"
		}
		return models.ZoneGreen, reason
	}
	if strings.Contains(lower, "hmac-sha2-256") {
		reason := "HMAC-SHA2-256 — quantum-safe integrity"
		if isETM {
			reason += " (encrypt-then-MAC — best practice)"
		}
		return models.ZoneGreen, reason
	}

	// UMAC — quantum safe (universal hash + AES
	if strings.Contains(lower, "umac-128") {
		reason := "UMAC-128 — quantum-safe universal MAC"
		if isETM {
			reason += " (encrypt-then-MAC)"
		}
		return models.ZoneGreen, reason
	}
	if strings.Contains(lower, "umac-64") {
		reason := "UMAC-64 — quantum-safe but short tag (64-bit)"
		if isETM {
			reason += " (encrypt-then-MAC)"
		}
		return models.ZoneYellow, reason
	}

	// SHA-1 based MACs — classically deprecated
	if strings.Contains(lower, "hmac-sha1") {
		return models.ZoneRed, "HMAC-SHA1 — SHA-1 deprecated (collision attacks demonstrated)"
	}

	// MD5 based MACs — classically broken
	if strings.Contains(lower, "hmac-md5") {
		return models.ZoneRed, "HMAC-MD5 — MD5 classically broken"
	}

	// RIPEMD
	if strings.Contains(lower, "ripemd") {
		return models.ZoneRed, "HMAC-RIPEMD — below CNSA 2.0 minimum hash security"
	}

	// 'none' — no integrity
	if lower == "none" {
		return models.ZoneRed, "No MAC — no integrity protection"
	}

	return models.ZoneYellow, fmt.Sprintf("MAC '%s' — classification uncertain", name)
}

// isPQSSHAlgo checks if an SSH algorithm is post-quantum.
func isPQSSHAlgo(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "sntrup761") ||
		strings.Contains(lower, "mlkem") ||
		strings.Contains(lower, "ml-kem") ||
		strings.Contains(lower, "kyber") ||
		strings.Contains(lower, "dilithium") ||
		strings.Contains(lower, "mldsa") ||
		strings.Contains(lower, "ml-dsa") ||
		strings.Contains(lower, "falcon") ||
		strings.Contains(lower, "sphincs") ||
		strings.Contains(lower, "slh-dsa")
}

// parseSSHBanner extracts the software identifier from an SSH banner.
// Banner format: SSH-protoversion-softwareversion [SP comments]
func parseSSHBanner(banner string) string {
	// Remove SSH-2.0- prefix
	if idx := strings.Index(banner, "-"); idx >= 0 {
		rest := banner[idx+1:]
		if idx2 := strings.Index(rest, "-"); idx2 >= 0 {
			sw := rest[idx2+1:]
			// Trim any comments after space
			if spIdx := strings.Index(sw, " "); spIdx >= 0 {
				sw = sw[:spIdx]
			}
			return sw
		}
	}
	return banner
}

// normalizeSSHDeepAlgo normalizes SSH host key algorithm names for the classifier.
func normalizeSSHDeepAlgo(name string) string {
	normalized := map[string]string{
		"ssh-rsa":                            "RSA-2048",
		"rsa-sha2-256":                       "RSA-SHA2-256",
		"rsa-sha2-512":                       "RSA-SHA2-512",
		"ssh-ed25519":                        "Ed25519",
		"ssh-ed448":                          "Ed448",
		"ecdsa-sha2-nistp256":                "ECDSA-P256",
		"ecdsa-sha2-nistp384":                "ECDSA-P384",
		"ecdsa-sha2-nistp521":                "ECDSA-P521",
		"ssh-dss":                            "DSA-1024",
		"sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-P256-SK",
		"sk-ssh-ed25519@openssh.com":         "Ed25519-SK",
		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-P256-WebAuthn",
	}

	if n, ok := normalized[strings.ToLower(name)]; ok {
		return n
	}
	return name
}

// normalizeSSHCipherAlgo normalizes SSH cipher names for display.
func normalizeSSHCipherAlgo(name string) string {
	normalized := map[string]string{
		"chacha20-poly1305@openssh.com": "ChaCha20-Poly1305",
		"aes128-gcm@openssh.com":        "AES-128-GCM",
		"aes256-gcm@openssh.com":        "AES-256-GCM",
		"aes128-ctr":                    "AES-128-CTR",
		"aes192-ctr":                    "AES-192-CTR",
		"aes256-ctr":                    "AES-256-CTR",
		"aes128-cbc":                    "AES-128-CBC",
		"aes192-cbc":                    "AES-192-CBC",
		"aes256-cbc":                    "AES-256-CBC",
		"3des-cbc":                      "3DES-CBC",
		"blowfish-cbc":                  "Blowfish-CBC",
		"arcfour":                       "RC4",
		"arcfour128":                    "RC4-128",
		"arcfour256":                    "RC4-256",
		"cast128-cbc":                   "CAST-128-CBC",
		"none":                          "None",
	}

	if n, ok := normalized[strings.ToLower(name)]; ok {
		return n
	}
	return name
}

// normalizeSSHMACAlgo normalizes SSH MAC names for display.
func normalizeSSHMACAlgo(name string) string {
	normalized := map[string]string{
		"hmac-sha2-256":                  "HMAC-SHA2-256",
		"hmac-sha2-256-etm@openssh.com":  "HMAC-SHA2-256-ETM",
		"hmac-sha2-512":                  "HMAC-SHA2-512",
		"hmac-sha2-512-etm@openssh.com":  "HMAC-SHA2-512-ETM",
		"hmac-sha1":                      "HMAC-SHA1",
		"hmac-sha1-etm@openssh.com":      "HMAC-SHA1-ETM",
		"hmac-sha1-96":                   "HMAC-SHA1-96",
		"hmac-sha1-96-etm@openssh.com":   "HMAC-SHA1-96-ETM",
		"hmac-md5":                       "HMAC-MD5",
		"hmac-md5-etm@openssh.com":       "HMAC-MD5-ETM",
		"hmac-md5-96":                    "HMAC-MD5-96",
		"hmac-md5-96-etm@openssh.com":    "HMAC-MD5-96-ETM",
		"umac-64@openssh.com":            "UMAC-64",
		"umac-64-etm@openssh.com":        "UMAC-64-ETM",
		"umac-128@openssh.com":           "UMAC-128",
		"umac-128-etm@openssh.com":       "UMAC-128-ETM",
		"hmac-ripemd160":                 "HMAC-RIPEMD160",
		"hmac-ripemd160-etm@openssh.com": "HMAC-RIPEMD160-ETM",
		"none":                           "None",
	}

	if n, ok := normalized[strings.ToLower(name)]; ok {
		return n
	}
	return name
}

// sshAlgoKeySize returns the effective key size for host key algorithms.
func sshAlgoKeySize(algo string) int {
	sizes := map[string]int{
		"ssh-rsa":             2048, // Conservative default
		"rsa-sha2-256":        2048,
		"rsa-sha2-512":        2048,
		"ssh-ed25519":         256,
		"ssh-ed448":           448,
		"ecdsa-sha2-nistp256": 256,
		"ecdsa-sha2-nistp384": 384,
		"ecdsa-sha2-nistp521": 521,
		"ssh-dss":             1024,
	}
	if s, ok := sizes[strings.ToLower(algo)]; ok {
		return s
	}
	return 0
}

// sshKEXKeySize returns the key exchange strength for KEX algorithms.
func sshKEXKeySize(algo string) int {
	lower := strings.ToLower(algo)
	switch {
	case strings.Contains(lower, "sntrup761"):
		return 761 // NTRU Prime parameter
	case strings.Contains(lower, "curve25519"):
		return 256
	case strings.Contains(lower, "nistp256"):
		return 256
	case strings.Contains(lower, "nistp384"):
		return 384
	case strings.Contains(lower, "nistp521"):
		return 521
	// Order matters: check group18/16/14 BEFORE group1 (group14 contains "group1")
	case strings.Contains(lower, "group18"):
		return 8192
	case strings.Contains(lower, "group16"):
		return 4096
	case strings.Contains(lower, "group14"):
		return 2048
	case strings.Contains(lower, "group1"):
		return 1024
	case strings.Contains(lower, "group-exchange"):
		return 2048 // Minimum typically offered
	default:
		return 0
	}
}

// sshCipherKeySize returns the key size for SSH ciphers.
func sshCipherKeySize(algo string) int {
	lower := strings.ToLower(algo)
	switch {
	case strings.Contains(lower, "chacha20"):
		return 256
	case strings.Contains(lower, "aes256") || strings.Contains(lower, "aes-256"):
		return 256
	case strings.Contains(lower, "aes192") || strings.Contains(lower, "aes-192"):
		return 192
	case strings.Contains(lower, "aes128") || strings.Contains(lower, "aes-128"):
		return 128
	case strings.Contains(lower, "3des"):
		return 168
	case strings.Contains(lower, "blowfish"):
		return 128
	case strings.Contains(lower, "arcfour256"):
		return 256
	case strings.Contains(lower, "arcfour128"):
		return 128
	case strings.Contains(lower, "arcfour"):
		return 128
	case strings.Contains(lower, "cast128"):
		return 128
	default:
		return 0
	}
}
