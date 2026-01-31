# 🦇 SHADOW RECON v5

<p align="center">
  <img src="https://img.shields.io/badge/version-5.0.0-purple?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/bash-5.0+-green?style=for-the-badge&logo=gnu-bash" alt="Bash">
  <img src="https://img.shields.io/badge/platform-linux-blue?style=for-the-badge&logo=linux" alt="Platform">
</p>

<p align="center">
  <b>Modular Bug Bounty Reconnaissance Framework</b><br>
  <i>من الـ ASN لحد الـ XSS - كل شي automated</i>
</p>

---

## 🎯 Features

- **Modular Architecture**: 10 modules مستقلة، تشغّل اللي تبيه
- **State Management**: Resume scans، ما تضيع شغلك
- **Parallel Execution**: سرعة عالية مع rate limiting
- **Smart Deduplication**: لا تكرار، لا ضياع وقت
- **Multi-Source Recon**: APIs، archives، crawling
- **Auto Vulnerability Detection**: Nuclei، Dalfox، SQLMap

---

## 📁 Structure

```
shadow/
├── shadow.sh           # Main runner
├── install_tools.sh    # Tool installer
├── config/
│   ├── tools.conf      # Tool configurations
│   ├── rate.conf       # Rate limiting
│   └── scope.conf      # Scope management
├── modules/
│   ├── 01_intel.sh     # ASN & Organization
│   ├── 02_subdomains.sh# Subdomain enumeration
│   ├── 03_dns.sh       # DNS resolution
│   ├── 04_ports.sh     # Port scanning
│   ├── 05_http.sh      # HTTP probing
│   ├── 06_content.sh   # Content discovery
│   ├── 07_js.sh        # JavaScript analysis
│   ├── 08_params.sh    # Parameter discovery
│   ├── 09_vuln.sh      # Vulnerability scanning
│   └── 10_visual.sh    # Screenshots
├── utils/
│   ├── log.sh          # Logging utilities
│   ├── state.sh        # State management
│   ├── check.sh        # Dependency checker
│   └── dedupe.sh       # Deduplication
└── wordlists/
    ├── dirs.txt
    ├── params.txt
    └── subdomains.txt
```

---

## 🚀 Quick Start

### 1. Install Tools

```bash
chmod +x install_tools.sh
./install_tools.sh
```

### 2. Check Dependencies

```bash
./shadow.sh -c
```

### 3. Run Full Scan

```bash
./shadow.sh example.com
```

---

## 📖 Usage

```bash
./shadow.sh [OPTIONS] <target>

OPTIONS:
    -h, --help          Show help
    -v, --version       Show version
    -c, --check         Check dependencies
    -m, --module NUM    Run specific modules (1-10)
    -s, --skip NUM      Skip modules
    -r, --resume        Resume previous scan
    -f, --full          Full port scan (1-65535)
    -q, --quick         Quick scan
    -o, --output DIR    Custom output directory
    --debug             Debug mode
```

### Examples

```bash
# Full scan
./shadow.sh target.com

# Run only recon modules (1-5)
./shadow.sh -m 1,2,3,4,5 target.com

# Skip content discovery and screenshots
./shadow.sh -s 6,10 target.com

# Resume previous scan
./shadow.sh -r target.com

# Quick scan (skip heavy modules)
./shadow.sh -q target.com

# Full port scan
./shadow.sh -f target.com
```

---

## 🔧 Modules

### 01 - Intel Gathering
- ASN discovery
- CIDR ranges
- Organization mapping
- Reverse DNS

### 02 - Subdomain Enumeration
- Subfinder, Amass, Assetfinder
- Certificate Transparency
- Permutations (Gotator, AlterX)
- API sources (Chaos, SecurityTrails)

### 03 - DNS Resolution
- Mass DNS resolution
- CNAME extraction
- Subdomain takeover detection
- Wildcard filtering

### 04 - Port Scanning
- Top 1000 ports (Naabu)
- Service detection
- Full scan option (Masscan)

### 05 - HTTP Probing
- Technology detection
- Status code analysis
- CDN/WAF detection
- Interesting titles

### 06 - Content Discovery
- Directory brute-forcing (FFUF)
- Sensitive file detection
- Backup file hunting

### 07 - JavaScript Analysis
- JS file extraction
- Endpoint discovery (LinkFinder)
- Secret extraction
- AWS keys, JWT tokens

### 08 - Parameter Discovery
- URL collection (GAU, Wayback)
- Active crawling (Katana)
- GF pattern matching
- Hidden parameter discovery

### 09 - Vulnerability Scanning
- Nuclei templates
- XSS testing (Dalfox)
- SQLi detection
- SSRF, LFI testing
- CORS misconfiguration

### 10 - Visual Recon
- Screenshots (Gowitness)
- HTML gallery
- Visual analysis

---

## 🔑 API Keys (Optional)

For better results, export these environment variables:

```bash
export GITHUB_TOKEN="ghp_xxxxx"
export CHAOS_KEY="xxxxx"
export SHODAN_KEY="xxxxx"
export SECURITYTRAILS_KEY="xxxxx"
```

Add to `~/.bashrc` for persistence.

---

## 📊 Output Structure

```
logs/target.com_20260129_120000/
├── intel/
│   ├── asn.txt
│   ├── cidrs.txt
│   └── whois.txt
├── subs/
│   └── all_subs.txt
├── dns/
│   ├── alive.txt
│   ├── cnames.txt
│   └── potential_takeovers.txt
├── ports/
│   ├── naabu_top1000.txt
│   └── services/
├── http/
│   ├── alive.txt
│   ├── technologies.txt
│   └── interesting_titles.txt
├── content/
│   ├── ffuf_*.json
│   └── sensitive_files.txt
├── js/
│   ├── js_urls.txt
│   ├── endpoints.txt
│   └── secrets/
├── params/
│   ├── all_urls.txt
│   └── gf_*/
├── vulns/
│   ├── nuclei_critical.txt
│   ├── dalfox.txt
│   └── SUMMARY.txt
├── screenshots/
│   └── gallery.html
└── SCAN_SUMMARY.txt
```

---

## ⚙️ Configuration

### config/tools.conf
Tool-specific options and flags.

### config/rate.conf
Rate limiting profiles (stealth, normal, aggressive).

### config/scope.conf
In-scope and out-of-scope patterns.

---

## 🛠️ Required Tools

### Core (Required)
- subfinder
- amass
- assetfinder
- dnsx
- httpx
- naabu
- nuclei
- ffuf
- gau
- waybackurls

### Optional (Enhanced)
- gowitness
- dalfox
- katana
- gf
- arjun
- sqlmap
- metabigor

---

## 📝 Tips

1. **Start small**: Use `-m 1,2,3` first to test
2. **Check tools**: Run `./shadow.sh -c` before scanning
3. **Use resume**: If interrupted, use `-r` to continue
4. **Custom scope**: Edit `config/scope.conf` for filtering
5. **Rate limits**: Adjust `config/rate.conf` for target sensitivity

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. 

Always ensure you have:
- Written permission from the target owner
- Valid bug bounty program scope
- Understanding of applicable laws

The authors are not responsible for misuse.

---

## 🤝 Contributing

Pull requests welcome! For major changes, open an issue first.

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>🦇 Happy Hunting! 🦇</b>
</p>
