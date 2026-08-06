// PQCAT — PQC Compliance Assessment Tool (Open-Source Scanner)
// Copyright 2026 Soqucoin Labs Inc. All rights reserved.
// Licensed under Apache 2.0.
//
// This is the open-source scanner CLI. For the full compliance engine
// (scoring, reports, dashboard, API), see PQCAT Pro:
//
//	https://github.com/soqucoin-labs/pqcat/releases
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/config"
	"github.com/soqucoin-labs/pqcat/internal/models"
	"github.com/soqucoin-labs/pqcat/internal/scanner"
)

// Version info injected by Makefile ldflags
var (
	Version   = "dev"
	BuildDate = ""
	GitCommit = ""
	Edition   = "Scanner"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		handleScan()
	case "config":
		handleConfig()
	case "version":
		fmt.Printf("pqcat v%s (%s) built %s commit %s\n", Version, Edition, BuildDate, GitCommit)
		fmt.Println("Soqucoin Labs Inc. — PQC Compliance Assessment Tool")
		fmt.Println("Open-source scanner — Apache 2.0")
	case "serve", "dashboard":
		fmt.Fprintln(os.Stderr, "Error: '"+os.Args[1]+"' requires PQCAT Pro edition.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "The Pro edition includes the compliance engine, web dashboard,")
		fmt.Fprintln(os.Stderr, "RBAC, reporting, and database. It is distributed as pre-built")
		fmt.Fprintln(os.Stderr, "signed binaries.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "  Download: https://github.com/soqucoin-labs/pqcat/releases")
		fmt.Fprintln(os.Stderr, "  Licensing: labs@soqu.org")
		os.Exit(1)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func handleConfig() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: pqcat config <subcommand>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Subcommands:")
		fmt.Fprintln(os.Stderr, "  init    Generate a template pqcat.yaml configuration file")
		os.Exit(1)
	}

	switch os.Args[2] {
	case "init":
		path := "pqcat.yaml"
		if len(os.Args) > 3 {
			path = os.Args[3]
		}
		if err := config.GenerateTemplate(path); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate config: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Configuration template written to %s\n", path)
	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func handleScan() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: pqcat scan <type> <target> [target2 ...] [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Types:")
		fmt.Fprintln(os.Stderr, "  tls    Scan TLS/SSL certificates and cipher suites")
		fmt.Fprintln(os.Stderr, "  ssh    Scan SSH host keys")
		fmt.Fprintln(os.Stderr, "  sbom   Analyze SBOM for cryptographic dependencies")
		fmt.Fprintln(os.Stderr, "  pki    Analyze PKI certificate files or directories")
		fmt.Fprintln(os.Stderr, "  code   Scan source code for crypto API usage")
		fmt.Fprintln(os.Stderr, "  hsm    Discover HSM, KMS, and hardware crypto modules")
		fmt.Fprintln(os.Stderr, "  scap   Import OpenSCAP XCCDF/ARF result XML")
		fmt.Fprintln(os.Stderr, "  all    Run all applicable scan types against targets")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Targets can be hostnames, IPs, host:port, or CIDR ranges (10.0.0.0/24)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  --json         Output as JSON")
		fmt.Fprintln(os.Stderr, "  --output FILE  Write JSON to file")
		fmt.Fprintln(os.Stderr, "  --workers N    Concurrent scan workers for range scans (default: 20)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Pro-only options (require PQCAT Pro):")
		fmt.Fprintln(os.Stderr, "  --framework, --pdf, --html, --ato, --siem, --briefing, --save-db")
		os.Exit(1)
	}

	scanType := os.Args[2]

	// Parse targets and flags
	var targets []string
	outputJSON := false
	outputFile := ""
	sbomFormat := scanner.FormatAuto
	workers := 20
	showThreatIntel := false
	var intelFile string

	i := 3
	for i < len(os.Args) {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--") {
			break
		}
		targets = append(targets, arg)
		i++
	}

	// Parse flags
	for i < len(os.Args) {
		switch os.Args[i] {
		case "--json":
			outputJSON = true
		case "--output":
			if i+1 < len(os.Args) {
				outputFile = os.Args[i+1]
				i++
			}
		case "--workers":
			if i+1 < len(os.Args) {
				n := 0
				fmt.Sscanf(os.Args[i+1], "%d", &n)
				if n > 0 {
					workers = n
				}
				i++
			}
		case "--threatintel":
			// M50: Set flag and let scan proceed; print intel after scan
			showThreatIntel = true
			if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "--") {
				intelFile = os.Args[i+1]
				i++
			}
		case "--framework", "--pdf", "--html", "--ato", "--siem", "--siem-format",
			"--vendor", "--briefing", "--baseline", "--save-baseline", "--watch",
			"--save-db", "--data-retention", "--q-day-year", "--environment",
			"--confidential", "--aggregate-only":
			fmt.Fprintf(os.Stderr, "Option %s requires PQCAT Pro edition.\n", os.Args[i])
			fmt.Fprintln(os.Stderr, "Download: https://github.com/soqucoin-labs/pqcat/releases")
			os.Exit(1)
		default:
			// M51: Catch unknown flags and stray args instead of ignoring them
			if strings.HasPrefix(os.Args[i], "--") {
				fmt.Fprintf(os.Stderr, "Unknown option: %s\nRun 'pqcat scan --help' for usage.\n", os.Args[i])
				os.Exit(1)
			}
		}
		i++
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no targets specified")
		os.Exit(1)
	}

	// Expand comma-separated targets
	var expandedTargets []string
	for _, t := range targets {
		parts := strings.Split(t, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				expandedTargets = append(expandedTargets, p)
			}
		}
	}

	// Detect if range scanning is needed
	needsRange := len(expandedTargets) > 1
	if !needsRange {
		for _, t := range expandedTargets {
			if strings.Contains(t, "/") || strings.Contains(t, ",") {
				needsRange = true
				break
			}
		}
	}

	// Every Scan* entry point takes a context. Wiring it to SIGINT is the
	// reason the plumbing exists: a range scan over a /16 used to run to
	// completion no matter what the operator did.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var result *models.ScanResult
	var err error

	switch scanType {
	case "tls", "ssh":
		if needsRange || len(expandedTargets) > 1 {
			opts := scanner.DefaultRangeOptions(scanType)
			opts.Concurrency = workers
			opts.OnProgress = func(done, total int, target string, r *models.ScanResult) {
				pct := float64(done) / float64(total) * 100
				status := "✓"
				assets := 0
				if r != nil {
					assets = len(r.Assets)
				}
				if r == nil || len(r.Assets) == 0 {
					status = "✗"
				}
				fmt.Fprintf(os.Stderr, "\r  [%3.0f%%] %d/%d  %s %-40s (%d assets)",
					pct, done, total, status, target, assets)
			}
			fmt.Fprintf(os.Stderr, "  Scanning %d targets (%s, %d workers)...\n", len(expandedTargets), scanType, workers)
			result, err = scanner.ScanRange(ctx, expandedTargets, opts)
			fmt.Fprintln(os.Stderr) // newline after progress
		} else {
			target := expandedTargets[0]
			switch scanType {
			case "tls":
				opts := scanner.DefaultTLSOptions()
				result, err = scanner.ScanTLS(ctx, target, opts)
			case "ssh":
				opts := scanner.DefaultSSHOptions()
				result, err = scanner.ScanSSH(ctx, target, opts)
			}
		}
	case "sbom":
		result, err = scanner.ScanSBOM(ctx, expandedTargets[0], sbomFormat)
	case "pki":
		result, err = scanner.ScanPKI(ctx, expandedTargets[0])
	case "code":
		result, err = scanner.ScanCode(ctx, expandedTargets[0])
	case "hsm":
		target := "auto"
		if len(expandedTargets) > 0 {
			target = expandedTargets[0]
		}
		result, err = scanner.ScanHSM(ctx, target)
	case "scap":
		if len(expandedTargets) == 0 {
			fmt.Fprintln(os.Stderr, "Error: SCAP scan requires a result XML file")
			os.Exit(1)
		}
		result, err = scanner.ScanSCAP(ctx, expandedTargets[0])
	case "all":
		opts := scanner.DefaultAggregateOptions()
		opts.Workers = workers
		opts.NetworkTargets = expandedTargets
		opts.SBOMFormat = sbomFormat
		opts.ScanHSM = true
		fmt.Fprintf(os.Stderr, "  Running aggregate scan across all modules...\n")
		result, err = scanner.ScanAggregate(ctx, opts)
	case "config":
		if len(expandedTargets) == 0 {
			fmt.Fprintln(os.Stderr, "Error: config scan requires a target file or directory")
			os.Exit(1)
		}
		result, err = scanner.ScanConfig(ctx, expandedTargets[0])
	default:
		fmt.Fprintf(os.Stderr, "Unknown scan type: %s (valid: tls, ssh, sbom, pki, code, hsm, scap, config, all)\n", scanType)
		os.Exit(1)
	}

	if err != nil && (result == nil || len(result.Assets) == 0) {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	// Output: write JSON to file
	if outputFile != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		if wErr := os.WriteFile(outputFile, data, 0644); wErr != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", wErr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Results written to %s\n", outputFile)
	}

	// Output: terminal
	if outputJSON {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		printTerminal(result)
	}

	// Show threat intel after the scan (not instead of it)
	if showThreatIntel {
		intelResult, intelErr := scanner.LoadThreatIntel(intelFile)
		if intelErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: threat intel load: %v\n", intelErr)
		}
		if intelResult != nil {
			scanner.PrintIntelSource(intelResult)
			scanner.PrintThreatIntelTerminal(intelResult.Intel)
		}
	}
}

// printTerminal renders scan results to the terminal (scanner-only, no compliance scoring).
func printTerminal(result *models.ScanResult) {
	if result == nil {
		return
	}

	fmt.Fprintf(os.Stderr, "\n═══ PQCAT Scan Results ═══\n")
	fmt.Fprintf(os.Stderr, "  Target:   %s\n", result.Target)
	fmt.Fprintf(os.Stderr, "  Duration: %s\n", result.Duration)
	fmt.Fprintf(os.Stderr, "  Assets:   %d discovered\n", len(result.Assets))
	fmt.Fprintf(os.Stderr, "═══════════════════════════\n\n")

	// Count zones
	zones := map[models.Zone]int{}
	for _, a := range result.Assets {
		zones[a.Zone]++
	}

	if g, ok := zones[models.ZoneGreen]; ok {
		fmt.Fprintf(os.Stderr, "  🟢 Quantum-Safe:    %d\n", g)
	}
	if y, ok := zones[models.ZoneYellow]; ok {
		fmt.Fprintf(os.Stderr, "  🟡 Transition:      %d\n", y)
	}
	if r, ok := zones[models.ZoneRed]; ok {
		fmt.Fprintf(os.Stderr, "  🔴 Vulnerable:      %d\n", r)
	}

	fmt.Fprintln(os.Stderr)

	// List assets
	for _, a := range result.Assets {
		zone := "?"
		switch a.Zone {
		case models.ZoneGreen:
			zone = "GREEN"
		case models.ZoneYellow:
			zone = "YELLOW"
		case models.ZoneRed:
			zone = "RED"
		}
		fmt.Fprintf(os.Stderr, "  [%-6s]  %-30s  %s\n", zone, a.Algorithm, a.Location)
	}

	fmt.Fprintf(os.Stderr, "\n  Tip: Use --json for machine-readable output.\n")
	fmt.Fprintf(os.Stderr, "  Tip: For compliance scoring, use PQCAT Pro (--framework nsm10).\n")
	fmt.Fprintln(os.Stderr)
}

func printUsage() {
	fmt.Println("PQCAT — PQC Compliance Assessment Tool (Open-Source Scanner)")
	fmt.Println("Soqucoin Labs Inc.")
	fmt.Println()
	fmt.Println("Usage: pqcat <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan      Scan targets for cryptographic assets")
	fmt.Println("  config    Manage configuration")
	fmt.Println("  version   Print version information")
	fmt.Println("  help      Show this help message")
	fmt.Println()
	fmt.Println("Scan Usage:")
	fmt.Println("  pqcat scan tls <host[:port]>              Scan single TLS endpoint")
	fmt.Println("  pqcat scan tls <host1> <host2> ...        Scan multiple hosts")
	fmt.Println("  pqcat scan tls <cidr>                     Scan entire subnet")
	fmt.Println("  pqcat scan ssh <host[:port]>              Scan SSH host key")
	fmt.Println("  pqcat scan sbom <file.json>               Analyze SBOM")
	fmt.Println("  pqcat scan pki <cert.pem | dir/>          Analyze PKI certificates")
	fmt.Println("  pqcat scan code <file | dir/>             Scan source code for crypto APIs")
	fmt.Println("  pqcat scan hsm [auto | path]              Discover HSMs, KMS, keystores")
	fmt.Println("  pqcat scan scap <xccdf-results.xml>       Import OpenSCAP results")
	fmt.Println("  pqcat scan all <targets>                  Run all scan modules")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --json         Output as JSON")
	fmt.Println("  --output FILE  Write JSON report to file")
	fmt.Println("  --workers N    Concurrent workers for batch scans (default: 20)")
	fmt.Println("  --threatintel  Show quantum threat intelligence")
	fmt.Println()
	fmt.Println("Pro Edition (pre-built binaries):")
	fmt.Println("  Adds: compliance scoring, PDF/HTML reports, ATO packages, SIEM export,")
	fmt.Println("  web dashboard, RBAC, database, scheduled scans, drift detection.")
	fmt.Println("  → https://github.com/soqucoin-labs/pqcat/releases")
	fmt.Println("  → Enterprise licensing: labs@soqu.org")
}
