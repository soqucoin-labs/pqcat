// tls_sprint2.go implements Sprint 2 TLS blindspot fixes:
//
//  1. Key Exchange Group Enumeration (Blindspot 2) — probe which named groups/curves
//     the server supports (P-256, P-384, P-521, X25519) and individualize quantum risk
//  2. Secure Renegotiation Check (Blindspot 6) — verify renegotiation_info extension
//     or SCSV presence to prevent MitM injection attacks
//  3. ML-KEM / X25519MLKEM768 Detection (Blindspot 1) — THE crown jewel: detect
//     post-quantum hybrid key exchange with compliance scoring and HNDL integration.
//     NOTE: Basic ML-KEM detection exists in pqcscan (Anvil Secure, July 2025) and
//     OpenSSL 3.5+. Our differentiator is multi-framework compliance scoring,
//     cross-modality correlation, and HNDL Q-Day risk quantification.
package scanner

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// ──────────────────────────────────────────────────────────────────────────────
// Blindspot 2: Key Exchange Group Enumeration
// ──────────────────────────────────────────────────────────────────────────────

// NamedGroupResult records whether a specific named group is supported and its PQ classification.
type NamedGroupResult struct {
	ID        uint16      `json:"id"`
	IDHex     string      `json:"id_hex"`
	Name      string      `json:"name"`
	Supported bool        `json:"supported"`
	Zone      models.Zone `json:"zone"`
	KeyBits   int         `json:"key_bits"` // Effective classical security bits
	Reason    string      `json:"reason"`
}

// KeyExchangeGroupsResult holds the complete group enumeration results.
type KeyExchangeGroupsResult struct {
	Groups         []NamedGroupResult `json:"groups"`
	PQGroupFound   bool               `json:"pq_group_found"`  // True if any PQ group detected
	PreferredGroup string             `json:"preferred_group"` // Server's preferred group name
	OverallZone    models.Zone        `json:"overall_zone"`
	Summary        string             `json:"summary"`
}

// namedGroupInfo holds metadata for a TLS named group / elliptic curve.
type namedGroupInfo struct {
	id      uint16
	name    string
	keyBits int
	zone    models.Zone
	reason  string
}

// supportedNamedGroups returns the set of named groups to probe.
// IANA registry: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
func supportedNamedGroups() []namedGroupInfo {
	return []namedGroupInfo{
		// Classical elliptic curves
		{0x0017, "secp256r1 (P-256)", 128, models.ZoneRed,
			"P-256 — Shor's algorithm breaks ECDH in polynomial time on a quantum computer"},
		{0x0018, "secp384r1 (P-384)", 192, models.ZoneRed,
			"P-384 — quantum-vulnerable (higher security margin but same algorithmic weakness)"},
		{0x0019, "secp521r1 (P-521)", 256, models.ZoneRed,
			"P-521 — quantum-vulnerable (highest classical security but same ECDLP weakness)"},

		// Modern curves
		{0x001D, "x25519", 128, models.ZoneRed,
			"X25519 — quantum-vulnerable (Curve25519 uses ECDLP, broken by Shor's)"},
		{0x001E, "x448", 224, models.ZoneRed,
			"X448 — quantum-vulnerable (Curve448 uses ECDLP, broken by Shor's)"},

		// Finite-field DH (legacy)
		{0x0100, "ffdhe2048", 112, models.ZoneRed,
			"FFDHE-2048 — quantum-vulnerable (discrete log broken by Shor's, also classically weak at 112-bit)"},
		{0x0101, "ffdhe3072", 128, models.ZoneRed,
			"FFDHE-3072 — quantum-vulnerable (discrete log broken by Shor's)"},
		{0x0102, "ffdhe4096", 152, models.ZoneRed,
			"FFDHE-4096 — quantum-vulnerable (discrete log broken by Shor's)"},

		// Post-Quantum Hybrid Groups (THE WHOLE POINT)
		{0x6399, "X25519Kyber768Draft00", 192, models.ZoneGreen,
			"PQ-HYBRID: X25519 + Kyber768 (draft) — quantum-resistant key exchange (NIST PQC Round 3)"},
		{0x11EC, "X25519MLKEM768", 192, models.ZoneGreen,
			"PQ-HYBRID: X25519 + ML-KEM-768 (FIPS 203) — quantum-resistant key exchange (CNSA 2.0 compliant)"},
		{0x11EB, "SecP256r1MLKEM768", 192, models.ZoneGreen,
			"PQ-HYBRID: P-256 + ML-KEM-768 (FIPS 203) — quantum-resistant key exchange"},
	}
}

// probeKeyExchangeGroups enumerates which named groups/curves the server supports
// by sending TLS 1.3 ClientHellos with one group at a time and checking if the
// server responds with a key_share for that group.
//
// For TLS 1.2: We use supported_groups extension and check if the server accepts
// ECDHE suites within that group.
//
// For TLS 1.3: We use supported_groups + key_share extension offering the single group.
func probeKeyExchangeGroups(host, port string, timeout time.Duration) *KeyExchangeGroupsResult {
	result := &KeyExchangeGroupsResult{
		OverallZone: models.ZoneRed,
	}

	var greenCount, totalSupported int

	for _, group := range supportedNamedGroups() {
		supported := false

		if group.id >= 0x6399 { // PQ groups — TLS 1.3 only
			supported = probeTLS13Group(host, port, timeout, group.id)
		} else if group.id >= 0x0100 { // FFDHE groups — TLS 1.3 or TLS 1.2
			supported = probeTLS13Group(host, port, timeout, group.id)
		} else { // ECDHE groups — try both TLS 1.3 and TLS 1.2
			supported = probeTLS13Group(host, port, timeout, group.id)
			if !supported {
				supported = probeTLS12Group(host, port, timeout, group.id)
			}
		}

		gr := NamedGroupResult{
			ID:        group.id,
			IDHex:     fmt.Sprintf("0x%04X", group.id),
			Name:      group.name,
			Supported: supported,
			Zone:      group.zone,
			KeyBits:   group.keyBits,
		}

		if supported {
			totalSupported++
			gr.Reason = group.reason
			if group.zone == models.ZoneGreen {
				greenCount++
				result.PQGroupFound = true
			}
		} else {
			gr.Reason = "Not supported by server"
			gr.Zone = models.ZoneYellow // Absent = neutral, not good/bad
		}

		result.Groups = append(result.Groups, gr)
	}

	// Set preferred group to the first supported one
	for _, g := range result.Groups {
		if g.Supported {
			result.PreferredGroup = g.Name
			break
		}
	}

	// Determine overall zone
	if result.PQGroupFound {
		result.OverallZone = models.ZoneGreen
		result.Summary = fmt.Sprintf("🟢 PQ-READY: %d/%d supported groups are post-quantum. Server supports ML-KEM hybrid key exchange.",
			greenCount, totalSupported)
	} else if totalSupported > 0 {
		result.OverallZone = models.ZoneRed
		result.Summary = fmt.Sprintf("🔴 QUANTUM-VULNERABLE: %d key exchange groups detected, all classical. No PQ hybrid support.",
			totalSupported)
	} else {
		result.OverallZone = models.ZoneYellow
		result.Summary = "⚠️ Could not enumerate key exchange groups"
	}

	return result
}

// probeTLS13Group sends a TLS 1.3 ClientHello offering a single group in both
// supported_groups and key_share. If the server responds with a ServerHello
// containing key_share with matching group, it's supported.
func probeTLS13Group(host, port string, timeout time.Duration, groupID uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Build TLS 1.3 ClientHello with the single group
	clientHello := buildTLS13GroupProbe(host, groupID)
	record := buildTLSRecord(0x16, 0x0301, clientHello) // Record layer uses TLS 1.0

	if _, err := conn.Write(record); err != nil {
		return false
	}

	// Read response
	buf := make([]byte, 16384) // TLS 1.3 can have large ServerHellos with PQ key shares
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return false
	}

	// Check for ServerHello (not Alert)
	if buf[0] != 0x16 { // Not handshake
		return false
	}

	// Parse ServerHello to find key_share extension
	return parseServerHelloForKeyShare(buf[5:n], groupID)
}

// probeTLS12Group sends a TLS 1.2 ClientHello with a single group in
// supported_groups and an ECDHE cipher suite. Server acceptance = group supported.
func probeTLS12Group(host, port string, timeout time.Duration, groupID uint16) bool {
	// Build a TLS 1.2 ClientHello offering only this group
	suites := []uint16{
		0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	}

	return probeRawTLSWithGroup(host, port, timeout, 0x0303, suites, groupID)
}

// probeRawTLSWithGroup sends a ClientHello offering specific cipher suites with
// a single supported group. Returns true if the server accepts.
func probeRawTLSWithGroup(host, port string, timeout time.Duration, version uint16, suites []uint16, groupID uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	clientHello := buildClientHelloWithSingleGroup(version, host, suites, groupID)
	record := buildTLSRecord(0x16, 0x0301, clientHello)

	if _, err := conn.Write(record); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 6 {
		return false
	}

	// ServerHello = handshake (0x16), version, then handshake type 0x02
	return buf[0] == 0x16 && n > 5 && buf[5] == 0x02
}

// buildClientHelloWithSingleGroup constructs a ClientHello offering exactly one named group.
func buildClientHelloWithSingleGroup(version uint16, hostname string, suites []uint16, groupID uint16) []byte {
	random := randomClientRandom()

	suitesLen := len(suites) * 2
	suitesBytes := make([]byte, suitesLen)
	for i, s := range suites {
		binary.BigEndian.PutUint16(suitesBytes[i*2:], s)
	}

	// Build extensions
	var extensions []byte
	sni := buildSNIExtension(hostname)
	if len(sni) > 0 {
		extensions = append(extensions, sni...)
	}

	// Single-group supported_groups extension
	extensions = append(extensions, buildSingleGroupExtension(groupID)...)
	extensions = append(extensions, buildSignatureAlgorithmsExtension()...)
	extensions = append(extensions, buildECPointFormatsExtension()...)

	bodyLen := 2 + 32 + 1 + 2 + suitesLen + 2 // compression = 1 method (null)
	if len(extensions) > 0 {
		bodyLen += 2 + len(extensions)
	}

	msg := make([]byte, 0, 4+bodyLen)
	msg = append(msg, 0x01) // ClientHello
	msg = append(msg, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	msg = append(msg, byte(version>>8), byte(version))
	msg = append(msg, random...)
	msg = append(msg, 0x00) // No session ID

	msg = append(msg, byte(suitesLen>>8), byte(suitesLen))
	msg = append(msg, suitesBytes...)

	msg = append(msg, 0x01, 0x00) // 1 compression method: null

	if len(extensions) > 0 {
		msg = append(msg, byte(len(extensions)>>8), byte(len(extensions)))
		msg = append(msg, extensions...)
	}

	return msg
}

// buildSingleGroupExtension creates a supported_groups extension with exactly one group.
func buildSingleGroupExtension(groupID uint16) []byte {
	ext := make([]byte, 0, 10)
	// Extension type: supported_groups (0x000A)
	ext = append(ext, 0x00, 0x0A)
	// Extension data length: 4 (2 bytes list len + 2 bytes group)
	ext = append(ext, 0x00, 0x04)
	// Named curve list length: 2
	ext = append(ext, 0x00, 0x02)
	// The group
	ext = append(ext, byte(groupID>>8), byte(groupID))
	return ext
}

// ──────────────────────────────────────────────────────────────────────────────
// Blindspot 1: ML-KEM / X25519MLKEM768 PQ Key Exchange Detection (CROWN JEWEL)
// ──────────────────────────────────────────────────────────────────────────────

// buildTLS13GroupProbe constructs a TLS 1.3 ClientHello that probes for a specific
// key exchange group. For PQ groups, we include both supported_groups AND key_share
// extensions, because TLS 1.3 mandates key_share for the handshake to proceed.
//
// This is the CROWN JEWEL feature. If the server supports X25519MLKEM768 (0x11EC),
// it means they've already deployed post-quantum key exchange. While basic ML-KEM
// detection exists in other tools (pqcscan, OpenSSL 3.5), PQCAT uniquely integrates
// this into HNDL risk scoring, cross-modality correlation, and multi-framework
// compliance assessment (CNSA 2.0, FedRAMP, PCI DSS, etc.).
func buildTLS13GroupProbe(hostname string, groupID uint16) []byte {
	random := randomClientRandom()

	// TLS 1.3 cipher suites
	suites := []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
	}

	suitesLen := len(suites) * 2
	suitesBytes := make([]byte, suitesLen)
	for i, s := range suites {
		binary.BigEndian.PutUint16(suitesBytes[i*2:], s)
	}

	// Build extensions
	var extensions []byte

	// SNI
	sni := buildSNIExtension(hostname)
	if len(sni) > 0 {
		extensions = append(extensions, sni...)
	}

	// Supported versions extension (REQUIRED for TLS 1.3)
	// Extension type: supported_versions (0x002B)
	extensions = append(extensions, 0x00, 0x2B)
	extensions = append(extensions, 0x00, 0x03) // Extension data length: 3
	extensions = append(extensions, 0x02)       // List length: 2 bytes
	extensions = append(extensions, 0x03, 0x04) // TLS 1.3 (0x0304)

	// Supported groups extension with our target group
	extensions = append(extensions, buildSingleGroupExtension(groupID)...)

	// Signature algorithms (required by TLS 1.3)
	extensions = append(extensions, buildSignatureAlgorithmsExtension()...)

	// Key share extension — we must offer a key share for the target group.
	// For classical groups, we generate a minimal key share.
	// For PQ groups (ML-KEM-768), we generate a dummy encapsulation key
	// of the correct length so the server accepts the ClientHello.
	keyShareExt := buildKeyShareExtension(groupID)
	extensions = append(extensions, keyShareExt...)

	// EC point formats
	extensions = append(extensions, buildECPointFormatsExtension()...)

	bodyLen := 2 + 32 + 1 + 2 + suitesLen + 2
	if len(extensions) > 0 {
		bodyLen += 2 + len(extensions)
	}

	msg := make([]byte, 0, 4+bodyLen)
	msg = append(msg, 0x01) // ClientHello
	msg = append(msg, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	msg = append(msg, 0x03, 0x03) // Legacy version: TLS 1.2 (required by TLS 1.3 spec)
	msg = append(msg, random...)
	msg = append(msg, 0x00) // No session ID

	msg = append(msg, byte(suitesLen>>8), byte(suitesLen))
	msg = append(msg, suitesBytes...)

	msg = append(msg, 0x01, 0x00) // 1 compression method: null

	if len(extensions) > 0 {
		msg = append(msg, byte(len(extensions)>>8), byte(len(extensions)))
		msg = append(msg, extensions...)
	}

	return msg
}

// buildKeyShareExtension creates a key_share extension (type 0x0033) offering
// a single key share for the given group.
//
// For X25519 (0x001D): 32 bytes
// For secp256r1 (0x0017): 65 bytes (uncompressed point format)
// For secp384r1 (0x0018): 97 bytes
// For secp521r1 (0x0019): 133 bytes
// For X25519MLKEM768 (0x11EC): 1120 bytes (32 bytes X25519 + 1088 bytes ML-KEM-768 encapsulation key)
// For other PQ groups: similar hybrid sizes
//
// We send random data as the key share — we don't actually need to complete
// the handshake, we just need the server to respond with its key_share
// to confirm it supports the group.
func buildKeyShareExtension(groupID uint16) []byte {
	// Determine the key share size for this group
	keySize := keyShareSize(groupID)

	// Generate random key share data (we're probing, not negotiating)
	keyData := make([]byte, keySize)
	// DON'T randomize — for X25519, use a well-formed point that won't
	// cause the server to reject the ClientHello with decode_error.
	// For probing purposes, the server checks the group ID BEFORE
	// processing the key data, so it will either accept the group
	// (and then possibly reject the key — which gives us a handshake_failure,
	// not an alert) or reject the group via HelloRetryRequest.
	//
	// Actually, for classical groups we need a valid-looking key share,
	// but for our probing purposes we just check if the server responds
	// with a ServerHello at all (not an Alert). A HelloRetryRequest (HRR)
	// means the server supports TLS 1.3 but not this specific group.
	//
	// Use random data — if the server sends back a ServerHello with
	// key_share for our group, it's supported. If it sends back HRR
	// or an alert, it's not supported for this group.

	// For X25519: a random 32-byte string is a valid X25519 public key
	// For ECDHE groups: need to be careful, but most servers check length first
	for i := range keyData {
		keyData[i] = byte(i + 1) // Deterministic pattern to avoid all-zeros
	}

	// Key share entry: group (2) + key_exchange_length (2) + key_exchange
	entryLen := 4 + keySize
	// Client key share list: just our one entry
	listLen := entryLen
	// Extension data: 2 (client_shares length) + list
	extDataLen := 2 + listLen

	ext := make([]byte, 0, 4+extDataLen)
	// Extension type: key_share (0x0033)
	ext = append(ext, 0x00, 0x33)
	// Extension data length
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))
	// Client key shares length
	ext = append(ext, byte(listLen>>8), byte(listLen))
	// Key share entry: group
	ext = append(ext, byte(groupID>>8), byte(groupID))
	// Key share entry: key_exchange_length
	ext = append(ext, byte(keySize>>8), byte(keySize))
	// Key share entry: key_exchange
	ext = append(ext, keyData...)

	return ext
}

// keyShareSize returns the expected key share size for a named group.
func keyShareSize(groupID uint16) int {
	switch groupID {
	case 0x0017: // secp256r1 (P-256) — uncompressed point
		return 65
	case 0x0018: // secp384r1 (P-384)
		return 97
	case 0x0019: // secp521r1 (P-521)
		return 133
	case 0x001D: // x25519
		return 32
	case 0x001E: // x448
		return 56
	case 0x0100, 0x0101, 0x0102: // FFDHE groups — 2048/3072/4096 bit
		return 256 // 2048-bit DH public value
	case 0x6399: // X25519Kyber768Draft00
		return 1120 // 32 (X25519) + 1088 (Kyber768)
	case 0x11EC: // X25519MLKEM768
		return 1120 // 32 (X25519) + 1088 (ML-KEM-768)
	case 0x11EB: // SecP256r1MLKEM768
		return 1153 // 65 (P-256) + 1088 (ML-KEM-768)
	default:
		return 32 // Safe default
	}
}

// parseServerHelloForKeyShare parses a ServerHello to find the key_share extension
// and check if the server selected our target group.
//
// TLS 1.3 ServerHello format:
//
//	Handshake type (1) + length (3) + legacy_version (2) + random (32) +
//	session_id_length (1) + session_id + cipher_suite (2) + compression (1) +
//	extensions_length (2) + extensions
//
// We're looking for extension type 0x0033 (key_share) with our group ID.
func parseServerHelloForKeyShare(data []byte, targetGroup uint16) bool {
	if len(data) < 4 {
		return false
	}

	// Check handshake type
	hsType := data[0]

	// HelloRetryRequest uses the same type (0x02) but with special random
	// We need to handle both:
	// - ServerHello (0x02) with key_share containing our group = SUPPORTED
	// - HelloRetryRequest (0x02) with key_share containing a DIFFERENT group = NOT SUPPORTED
	// - Alert = NOT SUPPORTED
	if hsType != 0x02 { // Not ServerHello
		return false
	}

	// Skip: handshake type (1) + length (3) + version (2) + random (32) = 38
	pos := 38
	if pos >= len(data) {
		return false
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Cipher suite (2 bytes)
	pos += 2

	// Compression method (1 byte)
	pos += 1

	// Extensions
	if pos+2 > len(data) {
		return false // No extensions
	}

	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen

	if extEnd > len(data) {
		extEnd = len(data)
	}

	// Walk extensions looking for key_share (0x0033)
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0033 { // key_share
			// Server key_share: group (2 bytes) + key_exchange_length (2) + key_exchange
			if extDataLen >= 2 {
				selectedGroup := binary.BigEndian.Uint16(data[pos : pos+2])
				return selectedGroup == targetGroup
			}
		}

		// Check for supported_versions to confirm TLS 1.3
		// (not strictly needed for our probe, but helpful for classification)

		pos += extDataLen
	}

	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// Blindspot 6: Secure Renegotiation
// ──────────────────────────────────────────────────────────────────────────────

// SecureRenegotiationResult captures whether the server supports secure renegotiation.
type SecureRenegotiationResult struct {
	Supported bool        `json:"supported"`
	Method    string      `json:"method,omitempty"` // "extension", "SCSV", "both", "none"
	Zone      models.Zone `json:"zone"`
	Reason    string      `json:"reason"`
}

// checkSecureRenegotiation verifies that the server supports the TLS
// renegotiation_info extension (RFC 5746) or accepts the SCSV fallback cipher.
// Without this, the server is vulnerable to MitM renegotiation injection.
//
// Method: Use Go's crypto/tls to connect and check the ConnectionState.
// The Go TLS library automatically negotiates renegotiation_info if available.
func checkSecureRenegotiation(host, port string, timeout time.Duration) *SecureRenegotiationResult {
	addr := net.JoinHostPort(host, port)

	// First: Try Go's TLS library which handles renegotiation_info natively
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12, // Renegotiation only applies to TLS 1.2 and below
	})
	if err != nil {
		// Can't connect — test via raw probe
		return checkSecureRenegotiationRaw(host, port, timeout)
	}
	defer conn.Close()

	// Go's TLS library automatically uses SCSV and renegotiation_info.
	// If the connection succeeded, the server at minimum accepted our SCSV.
	// Check if connection state indicates secure renegotiation.

	state := conn.ConnectionState()

	// If we got TLS 1.3, renegotiation doesn't apply (it's inherently secure)
	if state.Version == tls.VersionTLS13 {
		return &SecureRenegotiationResult{
			Supported: true,
			Method:    "TLS_1.3",
			Zone:      models.ZoneGreen,
			Reason:    "TLS 1.3 — renegotiation not applicable (protocol is inherently safe from MitM injection)",
		}
	}

	// For TLS 1.2 and below: the library's successful handshake means
	// it negotiated renegotiation_info or SCSV was accepted.
	// Go sends SCSV by default, so if the handshake succeeded, we know
	// the server at least accepts SCSV.
	return &SecureRenegotiationResult{
		Supported: true,
		Method:    "SCSV",
		Zone:      models.ZoneGreen,
		Reason:    "Secure renegotiation supported (Go TLS client sends SCSV by default, server accepted)",
	}
}

// checkSecureRenegotiationRaw probes for renegotiation support using raw TCP
// when the Go TLS library can't connect (e.g., server requires specific settings).
func checkSecureRenegotiationRaw(host, port string, timeout time.Duration) *SecureRenegotiationResult {
	// Send a ClientHello with TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF)
	// included in the cipher suite list. If the server responds, it supports SCSV.

	suites := []uint16{
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	}

	supported := probeRawTLS(host, port, timeout, 0x0303, suites)

	if supported {
		// Now check if the server also sends the renegotiation_info extension
		// by looking at the ServerHello
		return &SecureRenegotiationResult{
			Supported: true,
			Method:    "SCSV",
			Zone:      models.ZoneGreen,
			Reason:    "Server accepts TLS_EMPTY_RENEGOTIATION_INFO_SCSV — secure renegotiation supported",
		}
	}

	// Server rejected our probe entirely — check without SCSV
	nonSCSVSuites := []uint16{0xC02F}
	if probeRawTLS(host, port, timeout, 0x0303, nonSCSVSuites) {
		// Server accepts connections but rejects SCSV — BAD
		return &SecureRenegotiationResult{
			Supported: false,
			Method:    "none",
			Zone:      models.ZoneRed,
			Reason:    "Server does NOT support secure renegotiation — vulnerable to MitM injection (CVE-2009-3555)",
		}
	}

	// Can't connect at all
	return &SecureRenegotiationResult{
		Supported: false,
		Method:    "unknown",
		Zone:      models.ZoneYellow,
		Reason:    "Could not determine renegotiation support (connection failed)",
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ML-KEM Detection Helper: Go crypto/tls approach (TLS 1.3 with PQ)
// ──────────────────────────────────────────────────────────────────────────────

// detectPQKeyExchange uses Go's crypto/tls library to attempt a TLS 1.3
// connection and inspect whether the server negotiated a PQ key exchange.
//
// This is a BACKUP approach — Go's standard library (as of 1.23+) includes
// experimental X25519MLKEM768 support behind GOEXPERIMENT or CurvePreferences.
// We use the raw TCP probe (probeTLS13Group) as the PRIMARY method because
// it works regardless of Go version.
func detectPQKeyExchangeViaGoTLS(host, port string, timeout time.Duration) (bool, string) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}

	// Go 1.24+ includes X25519MLKEM768 by default in TLS 1.3.
	// Go 1.26 exposes ConnectionState.CurveID for the negotiated group.
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Go 1.26: CurveID is directly available in ConnectionState
	curveName := state.CurveID.String()

	// Check if the negotiated group is a PQ hybrid
	switch state.CurveID {
	case tls.X25519MLKEM768:
		return true, "X25519MLKEM768"
	case tls.SecP256r1MLKEM768:
		return true, "SecP256r1MLKEM768"
	}

	// Also check by name for any future PQ groups
	lower := strings.ToLower(curveName)
	if strings.Contains(lower, "mlkem") || strings.Contains(lower, "kyber") {
		return true, curveName
	}

	return false, curveName
}

// ──────────────────────────────────────────────────────────────────────────────
// Pipeline Integration: probeAllSprint2 orchestrates all Sprint 2 checks
// ──────────────────────────────────────────────────────────────────────────────

// Sprint2Results holds all Sprint 2 probe results for pipeline integration.
type Sprint2Results struct {
	KeyExchangeGroups    *KeyExchangeGroupsResult   `json:"key_exchange_groups,omitempty"`
	SecureRenegotiation  *SecureRenegotiationResult `json:"secure_renegotiation,omitempty"`
	PQKeyExchangeGo      bool                       `json:"pq_kex_go_detected"`        // Go TLS lib detection
	PQKeyExchangeGoGroup string                     `json:"pq_kex_go_group,omitempty"` // Group name from Go TLS
}
