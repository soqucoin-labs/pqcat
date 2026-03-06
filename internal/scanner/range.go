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
				tlsOpts := TLSScanOptions{Timeout: opts.Timeout}
				hostResult, scanErr = ScanTLS(target, tlsOpts)
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
			}

			if opts.OnProgress != nil {
				opts.OnProgress(done, total, target, hostResult)
			}
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	result.Duration = time.Since(start)

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
// host:port strings.
func expandTargets(targets []string, defaultPort int) ([]string, error) {
	var hosts []string

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Check if it's a CIDR range
		if strings.Contains(target, "/") {
			ips, err := expandCIDR(target)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
			}
			for _, ip := range ips {
				hosts = append(hosts, fmt.Sprintf("%s:%d", ip, defaultPort))
			}
			continue
		}

		// Check if it already has a port
		if strings.Contains(target, ":") {
			hosts = append(hosts, target)
			continue
		}

		// Single host or IP — add default port
		hosts = append(hosts, fmt.Sprintf("%s:%d", target, defaultPort))
	}

	return hosts, nil
}

// expandCIDR enumerates all usable host IPs in a CIDR range.
// Excludes network address and broadcast address.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network address (first) and broadcast address (last)
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	// Safety: refuse to scan more than 65536 hosts at once
	if len(ips) > 65536 {
		return nil, fmt.Errorf("CIDR range too large: %d hosts (max 65536)", len(ips))
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
