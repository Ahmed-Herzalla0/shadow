# 🦇 SHADOW - SQLite-Powered Bug Bounty Recon

```
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
```

**أداة Recon تخزن كل شي في SQLite. لا files منفصلة.**

---

## 🎯 الفرق عن باقي الأدوات

| الأدوات العادية | SHADOW |
|----------------|--------|
| Files منفصلة | SQLite واحد |
| ما في correlation | كل شي مربوط |
| 10,000 URL | Top 20 مع score |
| grep و awk | SQL queries |

---

## 🚀 Quick Start

```bash
# Scan كامل
./shadow hunt example.com

# شوف أهم 20 target
./shadow top example.com

# Export للـ Burp
./shadow export example.com -s 5 > interesting.txt
```

---

## 📦 Database Structure

```
┌─────────┐    ┌──────────┐    ┌───────────┐    ┌──────────┐
│ Assets  │───▶│ Services │───▶│ Endpoints │───▶│ Findings │
│ (hosts) │    │ (ports)  │    │  (URLs)   │    │ (vulns)  │
└─────────┘    └──────────┘    └───────────┘    └──────────┘
```

كل شي مربوط. Query واحد بيعطيك:
- الـ domain
- الـ technology
- الـ endpoint
- الـ vulnerability

---

## 📊 Scoring System

كل endpoint عنده score بناءً على:

### Parameters (+points)
| Parameter | Score | Why |
|-----------|-------|-----|
| `id`, `user_id` | +3-4 | IDOR candidate |
| `url`, `redirect` | +3-4 | SSRF/Redirect |
| `file`, `path` | +4-5 | LFI candidate |
| `cmd`, `exec` | +5 | RCE candidate |
| `search`, `query` | +2 | XSS candidate |

### Paths (+points)
| Pattern | Score | Why |
|---------|-------|-----|
| `/api/` | +3 | API endpoint |
| `/admin` | +4 | Admin panel |
| `/graphql` | +4 | GraphQL |
| `/debug` | +5 | Debug endpoint |
| `.git` | +5 | Source exposure |

### Noise (-points)
| Pattern | Score | Why |
|---------|-------|-----|
| `.js`, `.css` | -5 | Static file |
| cloudfront | -4 | CDN |
| 404 | -2 | Dead page |

---

## 🔧 Commands

### `hunt` - Full Recon
```bash
./shadow hunt example.com
./shadow hunt example.com --skip-nuclei  # بدون vuln scan
./shadow hunt example.com -o custom_dir  # output مخصص
```

### `top` - Show Targets
```bash
./shadow top example.com          # Top 20
./shadow top example.com -n 50    # Top 50
```

### `export` - Export URLs
```bash
./shadow export example.com                    # All URLs
./shadow export example.com -s 5              # Score ≥ 5
./shadow export example.com -s 5 -f urls.txt  # To file
```

### `stats` - Statistics
```bash
./shadow stats example.com
```

Output:
```
  Assets:              150
  Services (alive):    89
  Endpoints:           2,340
  Interesting (≥5):    127

  Findings:            23
    Critical:          2
    High:              7
```

### `query` - Custom SQL
```bash
# أعطيني endpoints فيها file parameter
./shadow query example.com "
SELECT a.domain, e.path, e.params 
FROM endpoints e
JOIN services s ON e.service_id = s.id
JOIN assets a ON s.asset_id = a.id
WHERE e.params LIKE '%file%'
"

# أعطيني PHP endpoints بـ score عالي
./shadow query example.com "
SELECT a.domain, e.path, e.interesting_score
FROM endpoints e
JOIN services s ON e.service_id = s.id
JOIN assets a ON s.asset_id = a.id
WHERE s.technology LIKE '%PHP%'
  AND e.interesting_score >= 5
ORDER BY e.interesting_score DESC
"
```

---

## 🔌 Integration

### Burp Suite
```bash
./shadow export example.com -s 5 > urls.txt
# Import urls.txt في Burp → Target → Site map
```

### Nuclei Manual
```bash
./shadow export example.com -s 7 | nuclei -severity high,critical
```

### Other Tools
```bash
# SQLi testing
./shadow query example.com "
SELECT s.protocol || '://' || a.domain || e.path as url
FROM endpoints e
JOIN services s ON e.service_id = s.id  
JOIN assets a ON s.asset_id = a.id
WHERE e.tags LIKE '%sqli%'
" | sqlmap --batch

# SSRF testing  
./shadow query example.com "
SELECT s.protocol || '://' || a.domain || e.path as url
FROM endpoints e
JOIN services s ON e.service_id = s.id
JOIN assets a ON s.asset_id = a.id  
WHERE e.tags LIKE '%ssrf%'
" > ssrf_targets.txt
```

---

## 📁 Project Structure

```
shadow/
├── shadow              # CLI entry point
├── core/
│   ├── db.py          # SQLite database
│   ├── scorer.py      # Scoring rules
│   └── collectors.py  # Tool wrappers
├── output/
│   └── example.com/
│       └── shadow.db  # كل شي هون
└── wordlists/
```

---

## 🔧 Requirements

Tools (install with `./install_tools.sh`):
- subfinder
- assetfinder  
- amass
- dnsx
- httpx
- katana
- nuclei

Python 3.8+

---

## 💡 Philosophy

```
One Database. One Query. One Answer.
```

لا files منفصلة. لا grep. لا awk.
كل شي في SQLite. كل شي مربوط.

---

## License

MIT
