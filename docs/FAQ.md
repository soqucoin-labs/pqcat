# PQCAT — Frequently Asked Questions

## General

### What is PQCAT?

PQCAT (Post-Quantum Cryptography Assessment Tool) is a compliance scanner that discovers cryptographic assets across your infrastructure, classifies their quantum vulnerability, and scores your readiness against 11 regulatory frameworks. It runs as a single static binary with zero runtime dependencies.

### What's the difference between Enclave and Pro?

**Enclave** is the free, open-source, air-gap-safe edition. It includes all 11 scanner modules, CLI workflows, TUI dashboard, and report generation. It has zero outbound network code compiled in — guaranteed by the Go compiler.

**Pro** adds the REST API, web dashboard, multi-user RBAC, SIEM integration, scheduled scans, branded reports, notification center, and Prometheus metrics. Licensed via ML-DSA-65 signed license files.

### Can I use PQCAT without a license?

Yes. The **Enclave** edition is fully functional without any license. The Pro edition requires an activated license file.

### How does air-gap mode work?

The Enclave edition is built without Go build tags that include network server code. The binary literally cannot make outbound connections beyond the scan targets you specify. This is enforced at compile time, not runtime configuration.

### Is PQCAT a SaaS product?

No. PQCAT is a self-hosted binary. You download it, run it locally or on your servers. No data leaves your environment. There are no cloud dependencies, telemetry, or phone-home features.

---

## Scanning

### What can PQCAT scan?

| Module | What It Scans |
|---|---|
| `tls` | TLS certificates, cipher suites, and signature algorithms |
| `ssh` | SSH host keys and key exchange algorithms |
| `sbom` | CycloneDX/SPDX BOMs for quantum-vulnerable libraries |
| `pki` | X.509 certificate stores, Java keystores, PEM directories |
| `code` | Source code for hardcoded keys, weak algorithms (579 patterns, 39+ file types) |
| `hsm` | HSMs, KMS, and hardware keystores |
| `cidr` | Subnet-wide discovery of TLS/SSH endpoints |
| `dns` | DNS DNSSEC and zone signing key algorithms |
| `vpn` | IPsec/IKE VPN configurations |

Or just run `pqcat scan target.com` — auto-detection will figure it out.

### How does scoring work?

Every cryptographic asset is classified into one of three zones:

- **Quantum Vulnerable (Red, 0-49):** Uses algorithms broken by quantum computers (RSA, ECDSA, Ed25519, DSA, DH, ECDH)
- **Transitional (Yellow, 50-79):** Hybrid or migration-path configurations (e.g., mixed classical+PQ cipher suites)
- **PQ Compliant (Green, 80-100):** Uses NIST-approved post-quantum algorithms (ML-DSA, ML-KEM, SLH-DSA)

The overall score is a weighted average factoring in asset criticality, data sensitivity, and framework requirements.

### What frameworks are supported?

| Framework | Flag | Sector |
|---|---|---|
| CNSA 2.0 | `--framework cnsa2` | Federal/Defense |
| NSM-10 | `--framework nsm10` | Federal/Defense |
| FISMA | `--framework fisma` | Federal |
| FedRAMP | `--framework fedramp` | Federal/Cloud |
| NIST SP 800-131A | `--framework sp800131a` | Federal |
| CMMC | `--framework cmmc` | DoD Supply Chain |
| PCI DSS 4.0 | `--framework pci` | Financial |
| SOX | `--framework sox` | Financial |
| HIPAA | `--framework hipaa` | Healthcare |
| NYDFS 500 | `--framework nydfs` | Financial (NY) |
| SWIFT CSP | `--framework swift` | Financial/Banking |

---

## Licensing

### How do I activate a license?

```bash
pqcat activate /path/to/license.pqcat
```

Or use the interactive first-run menu — option [1] guides you through activation with drag-and-drop path entry.

### Where does PQCAT look for license files?

Search order (highest precedence first):
1. `--license` CLI flag
2. `$PQCAT_LICENSE` environment variable
3. `./license.pqcat` (current directory)
4. `~/.pqcat/license.pqcat`
5. `/etc/pqcat/license.pqcat`

### How do I renew my license?

Contact **labs@soqu.org** with your current license ID (visible via `pqcat license status`). You'll receive a new `.pqcat` file. Activate it the same way:

```bash
pqcat activate new-license.pqcat
```

### How do I transfer my license to a new machine?

Licenses can optionally be bound to hardware fingerprints. If yours is machine-bound, contact Soqucoin Labs with:
1. Your license ID (`pqcat license status`)
2. The new machine's fingerprint (`pqcat license status` on the new machine)

We'll issue a re-keyed license within 24 hours.

### My license says "fingerprint mismatch"

This means the license file is bound to a different machine. See "How do I transfer my license" above. If you believe this is an error, run `pqcat doctor` and share the output with labs@soqu.org.

---

## Dashboard (Pro)

### What are persona views?

The Pro dashboard offers 4 tailored views optimized for different roles:

- **Auditor:** All scanner data, detailed findings, evidence export
- **CISO:** Risk overview, trend analysis, compliance scores
- **CIO:** Strategic summary, migration timeline, budget impact
- **Executive:** Board-ready summary with key metrics only

Switch between views using the persona selector in the top-right of the dashboard.

### How does the notification center work?

The bell icon in the dashboard header shows a real-time feed of system events:
- Scan completions (with score-based severity)
- Drift alerts
- License warnings
- System events

Click a notification to navigate to the relevant scan or event. Unread notifications show a red badge with count.

### What does "Quantum Vulnerable" mean?

It means the asset uses a cryptographic algorithm (like RSA-2048 or ECDSA P-256) that a sufficiently powerful quantum computer could break using Shor's algorithm. It does NOT mean the asset is currently compromised — it means it's at risk from future quantum computers.

---

## Troubleshooting

### Why does my scan show score 0?

Common causes:
1. **Network timeout** — the target isn't responding. Check `pqcat doctor` for network status.
2. **Wrong scan type** — you ran `scan ssh` against a web server. Try `pqcat scan target.com` (auto-detect).
3. **Firewall blocking** — your firewall may block outbound connections on port 443/22.

### The dashboard won't start

```bash
# Check if the port is in use
lsof -i :8443

# Check system health
pqcat doctor

# Make sure you're running the Pro edition
pqcat version    # Should show "Edition: Pro"
```

### Where is my data stored?

- **Database:** `$PQCAT_DB_PATH` or default `~/.pqcat/pqcat.db` (macOS/Linux) / `%APPDATA%\pqcat\pqcat.db` (Windows)
- **Config:** See the 6-level precedence chain in `pqcat config show`
- **Reports:** Wherever you specify with `--pdf`, `--html`, etc.

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the full error resolution guide.

---

## About

### Who builds PQCAT?

PQCAT is built by **Soqucoin Labs Inc.**, the same team that migrated a production blockchain from ECDSA to NIST FIPS 204 (ML-DSA). PQCAT is patent-pending (U.S. Application #63/999,796) and SDVOSB-eligible.

### How do I report a security vulnerability?

Email **security@soqu.org** with details. See [SECURITY.md](../SECURITY.md) for our disclosure policy. Do not open public GitHub issues for security vulnerabilities.

### How do I get support?

- **Community:** GitHub Issues, Discord
- **Enterprise:** labs@soqu.org
- **Federal:** Contact via SAM.gov (CAGE: 19WH7)
