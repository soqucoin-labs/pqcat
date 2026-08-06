// tls_probe.go implements raw TCP-level probing for legacy SSL protocols
// that Go's crypto/tls library does not support (SSLv3, SSLv2).
//
// RATIONALE: If a customer has a rare SSLv3 endpoint and
// PQCAT doesn't detect it, they may certify as "PQC compliant" while retaining
// a quantum-vulnerable legacy component. This creates liability exposure.
// By crafting raw ClientHello messages, we can detect SSLv3/SSLv2 without
// needing Go's TLS library to negotiate them.
//
// Approach: Send a minimal ClientHello offering SSLv3/SSLv2 cipher suites.
// If the server responds with ServerHello, the protocol is supported.
// If it responds with an alert or closes the connection, it's not.
//
// This is the same technique used by:
//   - Qualys SSL Labs
//   - testssl.sh
//   - sslyze
//   - Nmap ssl-enum-ciphers
//
// No CGO required — pure Go using net.Conn (raw TCP).
package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// probeSSLv3 checks if the server accepts SSL 3.0 connections.
// SSL 3.0 is vulnerable to POODLE (CVE-2014-3566) and uses algorithms
// that are universally quantum-vulnerable.
func probeSSLv3(ctx context.Context, host, port string, timeout time.Duration, result *DeepTLSResult) {
	supported := probeRawTLS(ctx, host, port, timeout, 0x0300, sslv3CipherSuites())

	if supported {
		result.Protocols["ssl_3_0"] = &ProtocolResult{
			Supported: true,
			Zone:      models.ZoneRed,
			Reason:    "SSL 3.0 supported — CRITICAL: vulnerable to POODLE (CVE-2014-3566), all ciphers quantum-vulnerable",
		}
	} else {
		result.Protocols["ssl_3_0"] = &ProtocolResult{
			Supported: false,
			Zone:      models.ZoneGreen,
			Reason:    "SSL 3.0 correctly disabled",
		}
	}
}

// probeSSLv2 checks if the server accepts SSL 2.0 connections.
// SSL 2.0 uses a fundamentally different record format than SSL 3.0+.
// Any server supporting SSLv2 is severely misconfigured.
func probeSSLv2(ctx context.Context, host, port string, timeout time.Duration, result *DeepTLSResult) {
	supported := probeRawSSLv2(ctx, host, port, timeout)

	if supported {
		result.Protocols["ssl_2_0"] = &ProtocolResult{
			Supported: true,
			Zone:      models.ZoneRed,
			Reason:    "SSL 2.0 supported — CRITICAL: fundamentally broken protocol, enables DROWN attack (CVE-2016-0800)",
		}
	} else {
		result.Protocols["ssl_2_0"] = &ProtocolResult{
			Supported: false,
			Zone:      models.ZoneGreen,
			Reason:    "SSL 2.0 correctly disabled",
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Raw TLS ClientHello builder (SSLv3+)
// ──────────────────────────────────────────────────────────────────────────────

// probeRawTLS sends a crafted ClientHello at the specified protocol version
// and returns true if the server responds with a ServerHello.
func probeRawTLS(ctx context.Context, host, port string, timeout time.Duration, version uint16, suites []uint16) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := dialContext(ctx, "tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Set read/write deadline
	conn.SetDeadline(time.Now().Add(timeout))

	// Build ClientHello
	clientHello := buildClientHello(version, host, suites)

	// Wrap in TLS record layer
	record := buildTLSRecord(0x16, version, clientHello) // 0x16 = Handshake

	// Send
	if _, err := conn.Write(record); err != nil {
		return false
	}

	// Read response (at least 5 bytes for record header)
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return false
	}

	// Check if response is a Handshake record (0x16) with ServerHello (0x02)
	contentType := buf[0]
	if contentType == 0x16 && n >= 6 {
		// Handshake record — check handshake type
		handshakeType := buf[5]
		if handshakeType == 0x02 { // ServerHello
			return true
		}
	}

	// If we got an Alert (0x15), the server rejected the connection
	return false
}

// buildClientHello constructs a minimal TLS ClientHello message.
// Format (RFC 5246 §7.4.1.2):
//
//	HandshakeType:  1 byte  (0x01 = ClientHello)
//	Length:          3 bytes
//	ClientVersion:  2 bytes
//	Random:         32 bytes
//	SessionID:      1 byte  (0 = no session)
//	CipherSuites:   2 bytes length + N*2 bytes
//	Compression:    2 bytes (1 method: null)
//	Extensions:     variable (SNI)
func buildClientHello(version uint16, serverName string, suites []uint16) []byte {
	// Random (32 bytes — use CSPRNG to avoid scanner fingerprinting by WAFs/IDS)
	random := randomClientRandom()

	// Cipher suites
	suitesLen := len(suites) * 2
	suitesBytes := make([]byte, suitesLen)
	for i, s := range suites {
		binary.BigEndian.PutUint16(suitesBytes[i*2:], s)
	}

	// Build extensions
	var extensions []byte

	// SNI extension (required for virtual hosting)
	sni := buildSNIExtension(serverName)
	if len(sni) > 0 {
		extensions = append(extensions, sni...)
	}

	// Supported Groups extension (required for ECDHE suites)
	// Without this, servers won't negotiate ECDHE cipher suites.
	if version >= 0x0301 { // TLS 1.0+
		extensions = append(extensions, buildSupportedGroupsExtension()...)
	}

	// Signature Algorithms extension (required for TLS 1.2+ ECDHE suites)
	// RFC 5246 §7.4.1.4.1: clients MUST send this for TLS 1.2
	if version >= 0x0303 { // TLS 1.2+
		extensions = append(extensions, buildSignatureAlgorithmsExtension()...)
	}

	// EC Point Formats extension (some servers require this for ECDHE)
	if version >= 0x0301 {
		extensions = append(extensions, buildECPointFormatsExtension()...)
	}

	// Calculate total ClientHello body length
	bodyLen := 2 + // ClientVersion
		32 + // Random
		1 + // SessionID length (0)
		2 + len(suitesBytes) + // CipherSuites
		2 // Compression methods

	if len(extensions) > 0 {
		bodyLen += 2 + len(extensions) // Extensions length + extensions
	}

	// Build the message
	msg := make([]byte, 0, 4+bodyLen)

	// Handshake header
	msg = append(msg, 0x01)                                               // ClientHello
	msg = append(msg, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen)) // Length (3 bytes)

	// ClientVersion
	msg = append(msg, byte(version>>8), byte(version))

	// Random
	msg = append(msg, random...)

	// Session ID (empty)
	msg = append(msg, 0x00)

	// Cipher Suites
	msg = append(msg, byte(suitesLen>>8), byte(suitesLen))
	msg = append(msg, suitesBytes...)

	// Compression Methods (1 method: null)
	msg = append(msg, 0x01, 0x00)

	// Extensions
	if len(extensions) > 0 {
		msg = append(msg, byte(len(extensions)>>8), byte(len(extensions)))
		msg = append(msg, extensions...)
	}

	return msg
}

// buildTLSRecord wraps a handshake message in a TLS record.
func buildTLSRecord(contentType byte, version uint16, payload []byte) []byte {
	record := make([]byte, 5+len(payload))
	record[0] = contentType
	binary.BigEndian.PutUint16(record[1:3], version)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[5:], payload)
	return record
}

// buildSNIExtension creates a Server Name Indication extension.
func buildSNIExtension(hostname string) []byte {
	if hostname == "" || net.ParseIP(hostname) != nil {
		return nil // No SNI for IP addresses
	}

	nameLen := len(hostname)
	listLen := nameLen + 3    // 1 byte type + 2 bytes name length
	extDataLen := listLen + 2 // 2 bytes list length

	ext := make([]byte, 0, 4+extDataLen)
	// Extension type: server_name (0x0000)
	ext = append(ext, 0x00, 0x00)
	// Extension data length
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))
	// Server Name List length
	ext = append(ext, byte(listLen>>8), byte(listLen))
	// Name type: hostname (0x00)
	ext = append(ext, 0x00)
	// Hostname length
	ext = append(ext, byte(nameLen>>8), byte(nameLen))
	// Hostname
	ext = append(ext, []byte(hostname)...)

	return ext
}

// buildSupportedGroupsExtension creates an elliptic_curves / supported_groups
// extension (type 0x000A). Required for ECDHE suite negotiation — without this,
// the server doesn't know which curves the client supports and will reject
// ECDHE cipher suites.
func buildSupportedGroupsExtension() []byte {
	// Named curves: secp256r1 (P-256), secp384r1 (P-384), secp521r1 (P-521), x25519
	groups := []uint16{0x0017, 0x0018, 0x0019, 0x001D}

	listLen := len(groups) * 2
	extDataLen := 2 + listLen // 2 bytes for list length

	ext := make([]byte, 0, 4+extDataLen)
	// Extension type: supported_groups (0x000A)
	ext = append(ext, 0x00, 0x0A)
	// Extension data length
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))
	// Named Curve List length
	ext = append(ext, byte(listLen>>8), byte(listLen))
	// Named curves
	for _, g := range groups {
		ext = append(ext, byte(g>>8), byte(g))
	}
	return ext
}

// buildSignatureAlgorithmsExtension creates a signature_algorithms extension
// (type 0x000D). Required by RFC 5246 §7.4.1.4.1 for TLS 1.2 clients. Without
// this, servers may not negotiate ECDSA or RSA cipher suites.
func buildSignatureAlgorithmsExtension() []byte {
	// Common signature algorithms (2 bytes each: hash + sig)
	sigAlgs := []uint16{
		0x0401, // rsa_pkcs1_sha256
		0x0501, // rsa_pkcs1_sha384
		0x0601, // rsa_pkcs1_sha512
		0x0403, // ecdsa_secp256r1_sha256
		0x0503, // ecdsa_secp384r1_sha384
		0x0603, // ecdsa_secp521r1_sha512
		0x0201, // rsa_pkcs1_sha1 (legacy, some servers require)
		0x0203, // ecdsa_sha1 (legacy)
	}

	listLen := len(sigAlgs) * 2
	extDataLen := 2 + listLen

	ext := make([]byte, 0, 4+extDataLen)
	// Extension type: signature_algorithms (0x000D)
	ext = append(ext, 0x00, 0x0D)
	// Extension data length
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))
	// Signature Hash Algorithms length
	ext = append(ext, byte(listLen>>8), byte(listLen))
	// Algorithms
	for _, a := range sigAlgs {
		ext = append(ext, byte(a>>8), byte(a))
	}
	return ext
}

// buildECPointFormatsExtension creates an ec_point_formats extension (type 0x000B).
// Some servers require this to negotiate ECDHE suites. We advertise support for
// the uncompressed point format (0x00), which is universally supported.
func buildECPointFormatsExtension() []byte {
	ext := make([]byte, 0, 6)
	// Extension type: ec_point_formats (0x000B)
	ext = append(ext, 0x00, 0x0B)
	// Extension data length: 2 (formats length + 1 format)
	ext = append(ext, 0x00, 0x02)
	// EC Point Format List length: 1
	ext = append(ext, 0x01)
	// Formats: uncompressed (0x00)
	ext = append(ext, 0x00)
	return ext
}

// ──────────────────────────────────────────────────────────────────────────────
// SSLv2 probe (different record format)
// ──────────────────────────────────────────────────────────────────────────────

// probeRawSSLv2 uses the SSLv2 record format to detect SSLv2 support.
// SSLv2 ClientHello has a fundamentally different format from SSLv3+.
func probeRawSSLv2(ctx context.Context, host, port string, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, port)
	conn, err := dialContext(ctx, "tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// SSLv2 ClientHello format:
	// Record header: 2 bytes (MSB set = 2-byte header, length in lower 15 bits)
	// Message type: 1 byte (0x01 = ClientHello)
	// Client version: 2 bytes (0x0002 for SSLv2)
	// Cipher specs length: 2 bytes
	// Session ID length: 2 bytes
	// Challenge length: 2 bytes
	// Cipher specs: 3 bytes each
	// Challenge: 16 bytes

	// SSLv2 cipher suites (3 bytes each)
	sslv2Ciphers := []byte{
		0x07, 0x00, 0xC0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		0x05, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
		0x01, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
	}

	challenge := make([]byte, 16) // 16-byte challenge (zero-filled for probe)

	// Build SSLv2 ClientHello body
	body := make([]byte, 0, 9+len(sslv2Ciphers)+len(challenge))
	body = append(body, 0x01)       // msg_type = CLIENT-HELLO
	body = append(body, 0x00, 0x02) // version = SSL 2.0
	// Cipher specs length
	body = append(body, byte(len(sslv2Ciphers)>>8), byte(len(sslv2Ciphers)))
	// Session ID length (0)
	body = append(body, 0x00, 0x00)
	// Challenge length
	body = append(body, byte(len(challenge)>>8), byte(len(challenge)))
	// Cipher specs
	body = append(body, sslv2Ciphers...)
	// Challenge
	body = append(body, challenge...)

	// SSLv2 record header (2-byte format: MSB set, length = body length)
	recordLen := len(body)
	record := make([]byte, 2+recordLen)
	record[0] = byte(0x80 | (recordLen >> 8))
	record[1] = byte(recordLen)
	copy(record[2:], body)

	if _, err := conn.Write(record); err != nil {
		return false
	}

	// Read response
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 3 {
		return false
	}

	// SSLv2 ServerHello:
	// The first byte will have MSB set (2-byte record header)
	// The third byte (first byte of body) will be 0x04 (SERVER-HELLO)
	if n >= 3 && (buf[0]&0x80) != 0 {
		msgType := buf[2]
		if msgType == 0x04 { // SERVER-HELLO
			return true
		}
	}

	return false
}

// ──────────────────────────────────────────────────────────────────────────────
// Known cipher suite lists for legacy probing
// ──────────────────────────────────────────────────────────────────────────────

// sslv3CipherSuites returns a comprehensive set of SSLv3-era cipher suite IDs.
// These use 2-byte IDs (TLS format) not the 3-byte SSLv2 format.
func sslv3CipherSuites() []uint16 {
	return []uint16{
		0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x0004, // TLS_RSA_WITH_RC4_128_MD5
		0x0005, // TLS_RSA_WITH_RC4_128_SHA
		0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
		0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
		0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
		// Export ciphers (40-bit) — catching these is critical for compliance
		0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
		0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
		0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x000B, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
		0x000E, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
		0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
		0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
		// NULL ciphers (no encryption)
		0x0001, // TLS_RSA_WITH_NULL_MD5
		0x0002, // TLS_RSA_WITH_NULL_SHA
		// DES (56-bit)
		0x0009, // TLS_RSA_WITH_DES_CBC_SHA
	}
}

// ExportCipherDetected returns a human-readable description if an export cipher
// was found, for special alerting. Export ciphers are 40-bit and can be brute-forced
// by a classical computer in seconds, let alone a quantum computer.
func ExportCipherDetected(suiteID uint16) (bool, string) {
	exportSuites := map[uint16]string{
		0x0003: "RSA_EXPORT_WITH_RC4_40_MD5 (40-bit)",
		0x0006: "RSA_EXPORT_WITH_RC2_CBC_40_MD5 (40-bit)",
		0x0008: "RSA_EXPORT_WITH_DES40_CBC_SHA (40-bit)",
		0x000B: "DH_DSS_EXPORT_WITH_DES40_CBC_SHA (40-bit)",
		0x000E: "DH_RSA_EXPORT_WITH_DES40_CBC_SHA (40-bit)",
		0x0011: "DHE_DSS_EXPORT_WITH_DES40_CBC_SHA (40-bit)",
		0x0014: "DHE_RSA_EXPORT_WITH_DES40_CBC_SHA (40-bit)",
		0x0019: "DH_anon_EXPORT_WITH_DES40_CBC_SHA (40-bit)",
	}
	if desc, ok := exportSuites[suiteID]; ok {
		return true, fmt.Sprintf("CRITICAL: Export cipher detected — %s — can be broken in seconds", desc)
	}
	return false, ""
}

// ──────────────────────────────────────────────────────────────────────────────
// Go-dropped cipher suite probing
// ──────────────────────────────────────────────────────────────────────────────

// goDroppedSuite describes a TLS 1.2 cipher suite that Go's crypto/tls library
// no longer includes (removed in Go 1.22). These must be probed via raw TCP.
type goDroppedSuite struct {
	ID   uint16
	Name string
}

// goDroppedCipherSuites returns cipher suites that Go 1.22+ removed from
// tls.CipherSuites() and tls.InsecureCipherSuites(). These are AES-CBC
// suites with SHA-256/SHA-384 MACs — weak from a classical perspective
// (CBC padding oracles) but the symmetric encryption and MACs are
// quantum-resistant. The key exchange (ECDHE/RSA) is quantum-vulnerable.
//
// SSL Labs and testssl.sh still probe these. If PQCAT claims "full cipher
// suite enumeration" but omits them, customers with these suites enabled
// get an incomplete report. That's a liability gap.
func goDroppedCipherSuites() []goDroppedSuite {
	return []goDroppedSuite{
		{0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
		{0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
		{0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
	}
}

// probeGoDroppedSuites uses raw TCP ClientHello probes to detect cipher suites
// that Go's crypto/tls library no longer supports. Results are classified through
// the standard classifyCipherSuite() pipeline and appended to the deep result.
func probeGoDroppedSuites(ctx context.Context, host, port string, opts DeepTLSScanOptions, result *DeepTLSResult) {
	// Build a set of suite IDs already discovered by Go's TLS library
	alreadyFound := make(map[uint16]bool)
	for _, cs := range result.CipherSuites {
		alreadyFound[cs.ID] = true
	}

	for _, suite := range goDroppedCipherSuites() {
		if alreadyFound[suite.ID] {
			continue // Already found via Go's TLS (shouldn't happen, but safety)
		}

		// Probe at TLS 1.2 using raw ClientHello
		supported := probeRawTLS(ctx, host, port, opts.Timeout, 0x0303, []uint16{suite.ID})
		if supported {
			csr := classifyCipherSuite(suite.ID, suite.Name, 0x0303) // 0x0303 = TLS 1.2
			result.CipherSuites = append(result.CipherSuites, csr)
		}
	}
}
