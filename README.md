# 🦇 SHADOW v3.0 - Decision-Driven Recon Orchestrator

```
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
       Decision-Driven Recon Orchestrator v3.0
```

**Automated recon with scored targets, JSONL pipelines, and actionable recommendations.**

[![CI](https://github.com/Ahmed-Herzalla0/shadow/actions/workflows/ci.yml/badge.svg)](https://github.com/Ahmed-Herzalla0/shadow/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚠️ LEGAL & ETHICAL NOTICE

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  AUTHORIZATION REQUIRED                                                      │
│                                                                              │
│  This tool is for AUTHORIZED security testing ONLY.                        │
│                                                                              │
│  Before running SHADOW, you MUST have:                                       │
│  • Written authorization from the target owner                              │
│  • A valid bug bounty program scope (if applicable)                         │
│  • Understanding of applicable laws in your jurisdiction                    │
│                                                                              │
│  Unauthorized use of this tool may violate:                                 │
│  • Computer Fraud and Abuse Act (CFAA) - USA                               │
│  • Computer Misuse Act - UK                                                 │
│  • Similar laws in other jurisdictions                                      │
│                                                                              │
│  THE AUTHORS ARE NOT RESPONSIBLE FOR MISUSE OF THIS TOOL.                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**You must agree to these terms before using this tool.**

---

## 🎯 What Makes SHADOW Different

| Traditional Tools | SHADOW |
|-------------------|--------|
| Separate files everywhere | Single SQLite database |
| No correlation between data | Everything linked with foreign keys |
| 10,000+ URLs to grep through | Top 20 ranked by score |
| Manual grep/awk/jq pipelines | SQL queries for anything |
| Raw data dumps | Decision-ready JSON reports |
| No prioritization | Automated action suggestions |

---

## 🚀 Quick Start

```bash
# Install
pip install -e .

# XSS-focused recon (default scope)
./shadow hunt target.com

# Full recon with all modules
./shadow hunt target.com --scope full

# Resume interrupted scan
./shadow hunt target.com --resume

# View top 20 targets (ranked by score)
./shadow top target.com --limit 20

# Export high-score URLs for nuclei/dalfox
./shadow export target.com --min-score 10 > interesting.txt

# View statistics
./shadow stats target.com

# Run destructive modules (nuclei with exploit templates)
./shadow hunt target.com --allow-destructive --confirm-legal

# Debug mode with verbose logging
./shadow hunt target.com --debug
```

### Advanced: Direct Orchestrator

```bash
# Run orchestrator directly for more control
python orchestrator.py target.com --output outdir --scope xss --debug
```

---

## 📦 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SHADOW v2.3                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │  Collectors  │───▶│   Database   │───▶│   Reports    │                   │
│  └──────────────┘    └──────────────┘    └──────────────┘                   │
│         │                   │                   │                            │
│         ▼                   ▼                   ▼                            │
│  - subfinder          - SQLite              - targets_ranked.json           │
│  - assetfinder        - Assets              - summary.json                  │
│  - amass              - Services            - notes.md                      │
│  - dnsx               - Endpoints           - targets.jsonl                 │
│  - httpx              - Findings                                            │
│  - katana                                                                    │
│  - nuclei                                                                    │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Scoring Engine                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Parameters (+pts)  │  Paths (+pts)    │  Tech (+pts)   │  Noise (-pts)    │
│  • id/user_id +3-4  │  • /api/ +3      │  • PHP +2      │  • .js/.css -5   │
│  • url/redirect +4  │  • /admin +4     │  • Spring +3   │  • CDN -4        │
│  • file/path +4-5   │  • /graphql +4   │  • Jenkins +4  │  • 404 -2        │
│  • cmd/exec +5      │  • /debug +5     │  • GraphQL +3  │                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Database Schema

```sql
-- All data in one SQLite file
Assets (hosts) → Services (ports) → Endpoints (URLs) → Findings (vulns)

-- Example query: Find PHP endpoints with IDOR parameters
SELECT a.domain, e.path, e.params, e.interesting_score
FROM endpoints e
JOIN services s ON e.service_id = s.id
JOIN assets a ON s.asset_id = a.id
WHERE s.technology LIKE '%PHP%'
  AND e.params LIKE '%id%'
ORDER BY e.interesting_score DESC;
```

---

## 📊 Scoring System

Every endpoint gets a score based on its characteristics. Higher score = more likely to be interesting.

### Parameters (+points)

| Parameter | Score | Why |
|-----------|-------|-----|
| `id`, `user_id`, `account_id` | +3-4 | IDOR candidate |
| `url`, `redirect`, `callback` | +3-4 | SSRF/Open Redirect |
| `file`, `filename`, `path` | +4-5 | LFI candidate |
| `cmd`, `exec`, `command` | +5 | RCE candidate |
| `search`, `query`, `q` | +2 | XSS candidate |
| `sort`, `order`, `filter` | +3 | SQLi candidate |

### Paths (+points)

| Pattern | Score | Why |
|---------|-------|-----|
| `/api/`, `/v1/`, `/v2/` | +2-3 | API endpoint |
| `/admin`, `/dashboard` | +3-4 | Admin panel |
| `/graphql` | +4 | GraphQL endpoint |
| `/debug`, `/console` | +5 | Debug exposure |
| `.git`, `.env` | +5 | Source/config exposure |
| `/actuator` | +5 | Spring Actuator |

### Priority Levels

| Score | Priority | Recommended Action |
|-------|----------|-------------------|
| ≥10 | 🔴 Critical | Immediate manual review |
| 7-9 | 🟠 High | Prioritize for testing |
| 4-6 | 🟡 Medium | Include in scan scope |
| 1-3 | 🟢 Low | Monitor |
| 0 | ⚫ Noise | Ignore |

---

## 🔧 Commands

### `hunt` - Full Recon

```bash
./shadow hunt example.com                    # Full scan
./shadow hunt example.com --skip-nuclei      # Skip vuln scanning
./shadow hunt example.com -o custom_output   # Custom output dir
```

**Output:**
- `output/example.com/shadow.db` - SQLite database
- `output/example.com/reports/targets_ranked.json` - Top targets
- `output/example.com/reports/summary.json` - Scan summary
- `output/example.com/reports/notes.md` - Human-readable notes

### `top` - Show Targets

```bash
./shadow top example.com          # Top 20 targets
./shadow top example.com -n 50    # Top 50 targets
```

### `export` - Export URLs

```bash
./shadow export example.com                  # All URLs
./shadow export example.com -s 5             # Score ≥ 5
./shadow export example.com -s 5 -f urls.txt # To file
```

### `stats` - Statistics

```bash
./shadow stats example.com
```

### `query` - Custom SQL

```bash
# Find endpoints with file parameter
./shadow query example.com "
SELECT a.domain, e.path, e.params 
FROM endpoints e
JOIN services s ON e.service_id = s.id
JOIN assets a ON s.asset_id = a.id
WHERE e.params LIKE '%file%'
"
```

---

## 📁 Project Structure

```
shadow/
├── orchestrator.py         # Main orchestrator CLI (v3.0)
├── shadow                   # Legacy CLI entry point
├── pyproject.toml           # Python packaging
├── core/
│   ├── db.py               # SQLite database layer
│   ├── scorer.py           # Scoring rules & heuristics
│   └── collectors.py       # Tool wrappers
├── decision/
│   └── decision.py         # Decision engine with tunable weights
├── schemas/
│   └── target.py           # Pydantic output schemas
├── modules/
│   └── 02_subdomains/
│       └── collector.py    # Canonical module example
├── utils/
│   ├── __init__.py         # Logging utilities (legacy)
│   ├── logging.py          # Structured JSON logging
│   ├── state.py            # State management & resume
│   ├── security.py         # Input validation
│   └── reports.py          # Report generation
├── tests/
│   ├── test_decision.py    # Scoring tests
│   ├── test_db.py          # Database tests
│   ├── test_cli.py         # CLI tests
│   └── test_module_smoke.py # Module smoke tests
├── reports/
│   └── targets_ranked_sample.json  # Sample output
├── .github/workflows/      # CI/CD
└── wordlists/
```

---

## 🎯 Scopes

| Scope | Description | Modules |
|-------|-------------|---------|
| `xss` | XSS-focused endpoint discovery (default) | subdomains, dns, http, content, js, params, vuln_xss |
| `api` | API attack surface mapping | subdomains, http |
| `js` | JavaScript-heavy endpoint discovery | subdomains, http, content, js |
| `full` | Complete reconnaissance | All modules |

---

## 🛡️ Safety Flags

| Flag | Purpose |
|------|---------|
| `--allow-destructive` | Enable modules that perform invasive actions (nuclei exploit templates, active probing) |
| `--confirm-legal` | Confirm legal authorization to scan the target |

**Both flags are required for destructive modules.** This ensures you explicitly acknowledge the risks.

---

## 🔌 Integration

### Burp Suite

```bash
./shadow export example.com -s 5 > urls.txt
# Import urls.txt in Burp → Target → Site map
```

### Nuclei (Manual)

```bash
./shadow export example.com -s 7 | nuclei -severity high,critical
```

---

## 🔧 Installation

### Requirements

- Python 3.8+
- External tools: subfinder, assetfinder, amass, dnsx, httpx, katana, nuclei

### Install

```bash
git clone https://github.com/Ahmed-Herzalla0/shadow.git
cd shadow
pip install -e .
./install_tools.sh
./shadow --help
```

### Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check core/ tests/
```

---

## 📋 Sample Output

### `reports/targets_ranked.json`

```json
{
  "generated_at": "2026-01-31T12:00:00.000000",
  "target": "example.com",
  "scope": "xss",
  "total_scored": 1247,
  "targets": [
    {
      "url": "https://admin.example.com/debug/console?cmd=whoami",
      "domain": "admin.example.com",
      "path": "/debug/console",
      "params": {"cmd": "whoami"},
      "score": 28,
      "priority": "critical",
      "action": "rce-verify",
      "reasons": [
        "+25: RCE param (cmd)",
        "+5: DEBUG path pattern",
        "+4: ADMIN subdomain bonus"
      ],
      "tags": ["rce", "debug", "admin", "high-value"],
      "source": "katana"
    }
  ]
}
```

### Output Directory Structure

```
output/example.com/
├── raw/                    # Raw JSONL from each module
│   ├── subdomains.jsonl
│   ├── http.jsonl
│   └── content.jsonl
├── data/                   # Normalized data
├── reports/                # Decision-ready outputs
│   └── targets_ranked.json
└── state.json              # Resume state
```

---

## 💡 Philosophy

```
One Database. One Query. One Answer.
```

- **No files everywhere** - Everything in SQLite
- **No grep/awk pipelines** - SQL queries for anything
- **No raw dumps** - Decision-ready outputs
- **No guessing** - Scored and prioritized targets

---

## 📝 License

MIT License

---

## 🙏 Credits

Built on: subfinder, assetfinder, amass, httpx, katana, nuclei
