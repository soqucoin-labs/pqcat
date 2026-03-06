// PQCAT — PQC Compliance Assessment Tool (Open Source Scanner)
// Copyright 2026 Soqucoin Labs Inc. All rights reserved.
// Licensed under Apache 2.0.
//
// This is the open-source scanner. For the full compliance engine
// (scoring, reports, dashboard, API), see github.com/soqucoin-labs/pqcat-engine.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/soqucoin-labs/pqcat/internal/classifier"
	"github.com/soqucoin-labs/pqcat/internal/config"
	"github.com/soqucoin-labs/pqcat/internal/models"
	"github.com/soqucoin-labs/pqcat/internal/scanner"
)

const version = "1.0.0-alpha"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("pqcat %s (open-source scanner)\n", version)
		fmt.Println("Full product: github.com/soqucoin-labs/pqcat-engine")
	case "scan":
		handleScan()
	case "config":
		handleConfig()
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleConfig() {
	if len(os.Args) < 3 || os.Args[2] != "init" {
		fmt.Println("Usage: pqcat config init")
		os.Exit(1)
	}
	if err := config.GenerateTemplate("pqcat.yaml"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated pqcat.yaml")
}

func handleScan() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: pqcat scan <type> <target>")
		fmt.Println("Types: tls, ssh, sbom, pki, code, hsm, cidr, scap, all")
		os.Exit(1)
	}

	scanType := os.Args[2]
	target := os.Args[3]

	// Load config
	configFile := ""
	framework := "nist"
	for i := 4; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--config":
			if i+1 < len(os.Args) {
				configFile = os.Args[i+1]
				i++
			}
		case "--framework":
			if i+1 < len(os.Args) {
				framework = os.Args[i+1]
				i++
			}
		}
	}

	cfg, _ := config.Load(configFile)
	if framework != "" {
		cfg.Framework = framework
	}

	// Execute scan
	var result *models.ScanResult
	var err error

	switch scanType {
	case "tls":
		result, err = scanner.ScanTLS(target)
	case "ssh":
		result, err = scanner.ScanSSH(target)
	case "sbom":
		result, err = scanner.ScanSBOM(target)
	case "pki":
		result, err = scanner.ScanPKI(target)
	case "code":
		result, err = scanner.ScanCode(target)
	case "hsm":
		result, err = scanner.ScanHSM(target)
	case "cidr":
		result, err = scanner.ScanCIDR(target)
	case "scap":
		result, err = scanner.ScanSCAP(target)
	case "all":
		result, err = scanner.ScanAll(target)
	default:
		fmt.Fprintf(os.Stderr, "Unknown scan type: %s\n", scanType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	// Classify assets
	for i := range result.Assets {
		result.Assets[i].Zone = classifier.ClassifyAlgorithm(
			result.Assets[i].Algorithm,
			result.Assets[i].KeySize,
		)
	}

	// Print results (terminal only — full reporting requires pqcat-engine)
	red, yellow, green := 0, 0, 0
	for _, a := range result.Assets {
		switch a.Zone {
		case "RED":
			red++
		case "YELLOW":
			yellow++
		case "GREEN":
			green++
		}
	}

	fmt.Printf("\n  PQCAT Scan Results — %s\n", target)
	fmt.Printf("  Framework: %s\n", strings.ToUpper(cfg.Framework))
	fmt.Println(strings.Repeat("─", 50))
	fmt.Printf("  Assets:  %d total\n", len(result.Assets))
	fmt.Printf("  RED:     %d (quantum-vulnerable)\n", red)
	fmt.Printf("  YELLOW:  %d (transitional)\n", yellow)
	fmt.Printf("  GREEN:   %d (CNSA 2.0 compliant)\n", green)
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println()
	fmt.Println("  For HTML reports, scoring, POA&M, and dashboard:")
	fmt.Println("  → github.com/soqucoin-labs/pqcat-engine")
	fmt.Println()
}

func printUsage() {
	fmt.Printf("PQCAT v%s — Post-Quantum Cryptography Compliance Assessment Tool\n\n", version)
	fmt.Println("Open-source scanner by Soqucoin Labs Inc.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  pqcat scan <type> <target>   Scan a target for cryptographic assets")
	fmt.Println("  pqcat config init            Generate default pqcat.yaml")
	fmt.Println("  pqcat version                Show version info")
	fmt.Println()
	fmt.Println("Scan types:")
	fmt.Println("  tls    TLS/SSL certificate and cipher analysis")
	fmt.Println("  ssh    SSH key exchange and host key analysis")
	fmt.Println("  sbom   SBOM crypto dependency analysis")
	fmt.Println("  pki    Certificate chain walking")
	fmt.Println("  code   Source code crypto pattern scanning")
	fmt.Println("  hsm    HSM/KMS key discovery")
	fmt.Println("  cidr   Subnet-wide TLS/SSH discovery")
	fmt.Println("  scap   OpenSCAP XCCDF import")
	fmt.Println("  all    Run all applicable modules")
	fmt.Println()
	fmt.Println("Full product (scoring, reports, dashboard, API):")
	fmt.Println("  → github.com/soqucoin-labs/pqcat-engine")
}
