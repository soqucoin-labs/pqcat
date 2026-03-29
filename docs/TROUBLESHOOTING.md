# PQCAT Troubleshooting Guide

Quick solutions to common issues. If your problem isn't listed here, run `pqcat doctor` first — it catches most configuration issues automatically.

---

## Installation Issues

### "command not found: pqcat"

**Cause:** PQCAT isn't in your PATH.

**Fix:**
```bash
# macOS/Linux — check if it was installed
ls -la /usr/local/bin/pqcat || ls -la ~/.local/bin/pqcat

# Re-install
curl -sSL https://install.pqcat.io | sh

# Or add manually
export PATH="$HOME/.local/bin:$PATH"
```

**Windows:**
```powershell
# Re-install (PowerShell as Administrator)
irm https://install.pqcat.io/windows | iex

# Or add to PATH manually
[Environment]::SetEnvironmentVariable("PATH", "$env:PATH;C:\Program Files\PQCAT", "Machine")
```

### "Permission denied" during install

**Cause:** The installer tries `/usr/local/bin/` which requires root.

**Fix:**
```bash
# Option 1: Use sudo
curl -sSL https://install.pqcat.io | sudo sh

# Option 2: Install to user directory (no sudo needed)
curl -sSL https://install.pqcat.io | INSTALL_DIR=~/.local/bin sh
```

### Self-update fails

```bash
# Check current version
pqcat version

# Try manual update
pqcat self-update --check    # See what's available

# If behind a proxy
HTTPS_PROXY=http://proxy:8080 pqcat self-update
```

---

## Scan Issues

### TLS scan returns no results

**Possible causes:**

1. **Firewall blocking outbound port 443:**
   ```bash
   # Test connectivity
   curl -sI https://target.com
   # If this works but pqcat doesn't, check your firewall rules
   ```

2. **Target requires SNI (Server Name Indication):**
   - PQCAT sends SNI by default. If you're scanning an IP address without a hostname, the server may not respond.
   ```bash
   # Try with hostname instead of IP
   pqcat scan tls example.com    # ✓
   pqcat scan tls 93.184.216.34  # May fail without SNI
   ```

3. **Timeout too short for slow targets:**
   ```yaml
   # pqcat.yaml
   scanner:
     timeout: 60s    # Increase from default 30s
   ```

### SSH scan "connection refused"

**Cause:** SSH isn't running on port 22, or the host is blocking your IP.

**Fix:**
```bash
# Test SSH connectivity
ssh -o ConnectTimeout=5 user@target 2>&1 | head -1

# If SSH is on a non-standard port, PQCAT auto-detects during CIDR scans
pqcat scan cidr 10.0.0.0/24    # Discovers SSH on any port
```

### Code scan is slow

**Cause:** Scanning very large repositories with many files.

**Fix:**
```bash
# Increase workers
pqcat scan code ./src/ --workers 8

# Use .pqcatignore to skip directories
echo "vendor/" >> .pqcatignore
echo "node_modules/" >> .pqcatignore
echo "*.min.js" >> .pqcatignore
```

### Scan score is 0

**Likely causes:**
1. No cryptographic assets found (wrong target or scan type)
2. Network error prevented scan from completing
3. Target returned empty response

**Debug:**
```bash
pqcat doctor                          # System health check
pqcat scan tls target.com --json     # See raw output
```

---

## License Issues

### "Not a valid .pqcat file"

**Cause:** You're trying to activate a file that isn't a PQCAT license.

**Fix:** License files have the `.pqcat` extension and are AES-256-GCM encrypted. Make sure you received the file from Soqucoin Labs and it hasn't been corrupted during transfer.

```bash
# Verify the file
file license.pqcat    # Should show "data" (binary)
pqcat activate license.pqcat
```

### "Registered to a different computer"

**Cause:** The license is hardware-bound to another machine.

**Fix:** Contact labs@soqu.org with:
1. Your license ID: `pqcat license status`
2. New machine fingerprint: `pqcat license status` (on the new machine)

### "License expired"

**Fix:**
```bash
# Check expiration details
pqcat license status

# Contact for renewal
# Email: labs@soqu.org with your license ID
```

### "License revoked"

**Cause:** The license has been added to the revocation list embedded in the binary.

**Fix:** Contact labs@soqu.org. This is typically due to a licensing violation or a replacement license being issued.

---

## Dashboard Issues (Pro)

### Dashboard won't start — "address already in use"

**Cause:** Port 8443 is occupied by another process.

**Fix:**
```bash
# Find what's using the port
lsof -i :8443    # macOS/Linux
netstat -ano | findstr 8443    # Windows

# Kill the process or use a different port
PQCAT_LISTEN=":9443" pqcat serve
```

### "Wrong Edition" error when running `serve`

**Cause:** You're running the Enclave (air-gapped) edition, which doesn't include the web server.

**Fix:** Install or build the Pro edition:
```bash
# Via install script (downloads Pro automatically with valid license)
curl -sSL https://install.pqcat.io | sh

# From source
go build -tags connected ./cmd/pqcat/
```

### Login page appears but credentials don't work

**Cause:** The admin password was generated on first run and shown only once.

**Fix:**
```bash
# Reset admin password via CLI
pqcat admin reset-password
```

### Dashboard tabs are missing

**Cause:** Tabs are now grouped into collapsible sections (Essentials, Discovery, Analysis, Compliance). They may be collapsed.

**Fix:** Click the section headers in the sidebar to expand them. Admin-only tabs (Users, Audit Log) are only visible to admin users.

---

## Report Issues

### PDF report is blank

**Possible causes:**

1. **Scan returned no results** — check with `pqcat scan target --json`
2. **Logo file not found** — verify `branding.logo_path` in `pqcat.yaml` points to a valid JPEG/PNG

### Logo doesn't appear in branded reports

**Requirements:**
- Format: JPEG or PNG (not SVG for PDF reports)
- Recommended size: 300×100px or similar aspect ratio
- Path must be absolute or relative to where you run `pqcat`

```yaml
# pqcat.yaml
branding:
  logo_path: "/absolute/path/to/logo.jpeg"    # ✓ Absolute
  logo_path: "./logo.jpeg"                     # ✓ Relative to CWD
  logo_path: "~/logo.jpeg"                     # ✗ Tilde not expanded
```

### Report shows garbled characters

**Cause:** PDF 1.4 Type1 fonts only support WinAnsi encoding. Special Unicode characters display incorrectly.

**Fix:** This is a known limitation. PQCAT uses ASCII-safe equivalents for all generated content. If you see garbled text, check your `organization_full` and other branding fields for special characters (em dashes, smart quotes, etc.).

---

## Configuration Issues

### "Config validation failed"

```bash
# See exactly what's wrong
pqcat config validate

# Show the active config (with source of each value)
pqcat config show
```

Common issues:
- YAML indentation errors
- Unknown framework name (must be one of: `cnsa2`, `nsm10`, `sp800131a`, `fisma`, `fedramp`, `pci`, `sox`, `hipaa`, `nydfs`, `swift`, `cmmc`)
- Invalid timeout format (use `30s`, `5m`, not `30`)

### Environment variables aren't taking effect

**Check precedence:** CLI flags override everything. A `pqcat.yaml` in the current directory overrides env vars.

```bash
# See what config is active and where each value comes from
pqcat config show
```

---

## Windows-Specific Issues

### "execution policy" error in PowerShell

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
irm https://install.pqcat.io/windows | iex
```

### Antivirus flags PQCAT

Some antivirus software flags unknown binaries. PQCAT is safe — all releases are signed with SHA-256 checksums. Add `C:\Program Files\PQCAT\` to your antivirus exclusion list.

### Windows Defender SmartScreen warning

Click "More info" → "Run anyway". This warning appears for new software that hasn't yet built a reputation with Microsoft.

---

## Getting Help

1. **Run diagnostics:** `pqcat doctor` — catches most issues automatically
2. **Check logs:** Dashboard logs appear in the terminal where `pqcat serve` is running
3. **Community:** GitHub Issues at [github.com/soqucoin-labs/pqcat](https://github.com/soqucoin-labs/pqcat)
4. **Enterprise support:** labs@soqu.org
5. **Security issues:** security@soqu.org (do not open public issues)
