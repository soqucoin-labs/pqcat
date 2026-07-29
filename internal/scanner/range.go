// Package scanner provides network range scanning capabilities.
package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/soqucoin-labs/pqcat/internal/models"
)

// RangeOptions configures batch scanning behavior.
type RangeOptions struct {
	// ScanType: "tls" or "ssh"
	ScanType string

	// Port to scan (default: 443 for TLS, 22 for SSH)
	Port int

	// Concurrency is the max number of parallel scans.
	Concurrency int

	// Timeout per individual host scan.
	Timeout time.Duration

	// Deep, when true and ScanType is "tls", runs the full deep TLS assessment
	// (cipher/protocol enumeration + quantum classification) per host instead of
	// the fast single-probe. This is what makes --deep apply to CIDR ranges; it is
	// slower, so it is opt-in. Ignored for SSH (no deep SSH equivalent).
	Deep bool

	// OnProgress is called after each host is scanned.
	// Args: completed count, total count, current target, result (may be nil on error)
	OnProgress func(done, total int, target string, result *models.ScanResult)
}

// DefaultRangeOptions returns sensible defaults for range scanning.
func DefaultRangeOptions(scanType string) RangeOptions {
	port := 443
	if scanType == "ssh" {
		port = 22
	}
	return RangeOptions{
		ScanType:    scanType,
		Port:        port,
		Concurrency: 20,
		Timeout:     5 * time.Second,
	}
}

// ScanRange scans all hosts in the given targets list. Targets can be:
//   - CIDR notation: "10.0.0.0/24"
//   - Single IPs: "10.0.0.1"
//   - Hostnames: "soqu.org"
//   - Host:port: "soqu.org:8443"
//   - Mixed list of any of the above
//
// Returns an aggregated ScanResult with all discovered assets from all hosts.
func ScanRange(targets []string, opts RangeOptions) (*models.ScanResult, error) {
	start := time.Now()

	// Expand all targets into individual host:port entries
	hosts, err := expandTargets(targets, opts.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to expand targets: %w", err)
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hosts to scan")
	}

	result := &models.ScanResult{
		Target:    strings.Join(targets, ", "),
		ScanType:  opts.ScanType + "-range",
		Timestamp: time.Now(),
		Assets:    make([]models.CryptoAsset, 0),
	}

	// Semaphore for concurrency control
	sem := make(chan struct{}, opts.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	done := 0
	total := len(hosts)
	hostsScanned := 0
	hostsReachable := 0
	var scanErrors []string
	var unreachableHosts []string

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore

		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			var hostResult *models.ScanResult
			var scanErr error

			switch opts.ScanType {
			case "tls":
				if opts.Deep {
					// Full per-host deep assessment. ScanTLSDeep already returns a
					// *models.ScanResult (second value), so it drops straight into
					// the range aggregation path.
					deepOpts := DefaultDeepTLSOptions()
					if opts.Port > 0 {
						deepOpts.Port = fmt.Sprintf("%d", opts.Port)
					}
					if opts.Timeout > deepOpts.Timeout {
						deepOpts.Timeout = opts.Timeout
					}
					_, hostResult, scanErr = ScanTLSDeep(target, deepOpts)
				} else {
					tlsOpts := TLSScanOptions{Timeout: opts.Timeout}
					hostResult, scanErr = ScanTLS(target, tlsOpts)
				}
			case "ssh":
				sshOpts := SSHScanOptions{Timeout: opts.Timeout}
				hostResult, scanErr = ScanSSH(target, sshOpts)
			}

			mu.Lock()
			done++
			hostsScanned++

			if scanErr == nil && hostResult != nil && len(hostResult.Assets) > 0 {
				hostsReachable++
				result.Assets = append(result.Assets, hostResult.Assets...)
			} else if scanErr != nil {
				scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", target, scanErr))
				unreachableHosts = append(unreachableHosts, target)
			}

			if opts.OnProgress != nil {
				opts.OnProgress(done, total, target, hostResult)
			}
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	result.Duration = time.Since(start)
	result.UnreachableHosts = unreachableHosts

	// Summary in Details
	result.Details = map[string]string{
		"hosts_total":     fmt.Sprintf("%d", total),
		"hosts_scanned":   fmt.Sprintf("%d", hostsScanned),
		"hosts_reachable": fmt.Sprintf("%d", hostsReachable),
		"scan_type":       opts.ScanType,
		"concurrency":     fmt.Sprintf("%d", opts.Concurrency),
	}

	if len(scanErrors) > 0 {
		// Truncate error list for readability
		maxErrors := 10
		if len(scanErrors) > maxErrors {
			result.Error = fmt.Sprintf("%d/%d hosts unreachable (showing first %d): %s",
				len(scanErrors), total, maxErrors,
				strings.Join(scanErrors[:maxErrors], "; "))
		} else {
			result.Error = fmt.Sprintf("%d/%d hosts unreachable: %s",
				len(scanErrors), total,
				strings.Join(scanErrors, "; "))
		}
	}

	return result, nil
}

// expandTargets takes a list of targets and expands CIDR ranges into individual
// host:port strings. Supports IPv4, IPv6, and mixed inputs.
//
// Accepted formats:
//   - IPv4 CIDR:    "10.0.0.0/24"
//   - IPv6 CIDR:    "2001:db8::/120"
//   - IPv4 host:    "10.0.0.1"
//   - IPv6 host:    "2001:db8::1"
//   - Hostname:     "soqu.org"
//   - IPv4 w/port:  "10.0.0.1:8443"
//   - IPv6 w/port:  "[2001:db8::1]:8443"
//   - Host w/port:  "soqu.org:8443"
func expandTargets(targets []string, defaultPort int) ([]string, error) {
	var hosts []string

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Check if it's a CIDR range (both IPv4 and IPv6)
		if strings.Contains(target, "/") {
			expanded, err := expandCIDR(target)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
			}
			for _, ip := range expanded {
				hosts = append(hosts, formatHostPort(ip, defaultPort))
			}
			continue
		}

		// Bracketed IPv6 with port: [2001:db8::1]:8443
		if strings.HasPrefix(target, "[") {
			hosts = append(hosts, target)
			continue
		}

		// Check if it's a bare IPv6 address (contains ":" but is a valid IP)
		if strings.Contains(target, ":") {
			if ip := net.ParseIP(target); ip != nil {
				// Bare IPv6 address — wrap in brackets and add port
				hosts = append(hosts, fmt.Sprintf("[%s]:%d", target, defaultPort))
				continue
			}
			// Otherwise it's host:port (IPv4 or hostname)
			hosts = append(hosts, target)
			continue
		}

		// Single host or IPv4 IP — add default port
		hosts = append(hosts, fmt.Sprintf("%s:%d", target, defaultPort))
	}

	return hosts, nil
}

// CountHosts returns the number of individual hosts the given targets expand
// to, counting each CIDR range as its full host count. The scan path uses this
// to enforce a license's per-scan asset limit before a range scan runs, so a
// broad CIDR is rejected up front rather than after the work is done.
func CountHosts(targets []string) (int, error) {
	hosts, err := expandTargets(targets, 0)
	if err != nil {
		return 0, err
	}
	return len(hosts), nil
}

// formatHostPort wraps an IP string with port, using brackets for IPv6.
func formatHostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		// IPv6 — needs brackets
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// expandCIDR enumerates all usable host IPs in a CIDR range.
// For IPv4: excludes network address and broadcast address.
// For IPv6: excludes network address only (no broadcast in IPv6).
// Safety: refuses ranges larger than 65536 hosts.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	isIPv6 := ip.To4() == nil

	// Safety: reject excessively large ranges before enumeration.
	// IPv4: /16 = 65534 hosts (max allowed)
	// IPv6: /112 = 65536 hosts (max allowed) — anything larger is unreasonable
	prefixLen, totalBits := ipNet.Mask.Size()
	hostBits := totalBits - prefixLen
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR range too large: /%d has 2^%d hosts (max prefix: /%d for %d-bit addresses)",
			prefixLen, hostBits, totalBits-16, totalBits)
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	if isIPv6 {
		// IPv6: no broadcast address. Just skip the network address (first).
		if len(ips) > 1 {
			ips = ips[1:]
		}
	} else {
		// IPv4: skip network address (first) and broadcast address (last).
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1]
		}
	}

	return ips, nil
}

// incrementIP adds 1 to an IP address in-place.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
