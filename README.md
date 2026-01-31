# 🦇 SHADOW v6 - Intelligence-Driven Bug Bounty Engine

<p align="center">
  <img src="https://img.shields.io/badge/version-6.0.0-purple?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/platform-linux-green?style=for-the-badge&logo=linux" alt="Platform">
</p>

<p align="center">
  <b>من "تشغيل أدوات" إلى "محرك قرارات"</b><br>
  <i>No scanner without reason. Automation stops when human reasoning is better.</i>
</p>

---

## 🚀 What's New in v6

### ❌ Old Approach (v5)
- تشغيل كل الأدوات blindly
- 10,000 URLs بدون تحليل
- أرقام scoring عشوائية
- ضجيج كثير، قيمة قليلة

### ✅ New Approach (v6)
- **Decision Engine**: كل أداة تشتغل لسبب
- **State Machine**: كل target عنده state يتطور
- **Real Scoring**: كل نقطة لها سبب
- **Attack Paths**: مسارات هجوم مقترحة
- **Top 20 Output**: أهم 20 target مع شرح "ليش؟"

---

## 🎯 Core Philosophy

```
Bash = Execution only (runs tools)
Python = Decision making (when, what, why)
```

### Scanner Discipline

| Condition | Tool | Why |
|-----------|------|-----|
| params reflect | dalfox | XSS likely |
| db error | sqlmap (manual) | SQLi confirmed |
| api detected | custom tests | Needs manual |
| cors header | corsy | Quick win |
| graphql | introspection | Full schema |

---

## 📁 Structure

```
shadow/
├── shadow6.sh              # New entry point
├── engine/                 # 🧠 Python Decision Engine
│   ├── state.py           # Target state machine
│   ├── scorer.py          # Intelligent scoring
│   ├── decision.py        # Decision engine
│   ├── context.py         # Execution context
│   ├── js_intel.py        # JS intelligence
│   ├── output.py          # Smart output generation
│   └── main.py            # CLI interface
├── modules/               # 🔧 Bash execution layer
├── config/
│   ├── tools.conf         # Tool conditions
│   ├── rate.conf          # Rate limiting + noise detection
│   └── scope.conf         # Scope management
├── utils/
│   └── noise.sh           # 🛑 Auto-pause on rate limit
└── output/                # 📊 Intelligence reports
```

---

## 🚀 Quick Start

```bash
# Full scan with decision engine
./shadow6.sh example.com

# Stealth mode (for sensitive targets)
./shadow6.sh example.com --stealth

# With Burp proxy
./shadow6.sh example.com --proxy

# Generate intelligence report
./shadow6.sh --report

# List all targets
./shadow6.sh --list

# Show target state
./shadow6.sh --state example.com

# Show what decisions would be made
./shadow6.sh --decisions example.com
```

---

## 🧠 State Machine

Every target has a state that evolves:

```json
{
  "domain": "example.com",
  "phase": "analysis",
  "score": 15,
  "priority": "high",
  
  "auth": {
    "has_login": true,
    "has_jwt": true,
    "has_oauth": false
  },
  
  "api": {
    "detected": true,
    "type": "graphql",
    "endpoints_count": 47
  },
  
  "params": {
    "total_count": 156,
    "xss_candidates": 12,
    "sqli_candidates": 3
  },
  
  "vuln_hints": {
    "admin_panel": true,
    "git_exposed": false,
    "cors_misconfigured": true
  }
}
```

---

## 📊 Scoring System

Real scoring with reasons:

| Factor | Points | Reason |
|--------|--------|--------|
| JWT Auth | +5 | Algorithm confusion, weak secrets |
| GraphQL | +6 | Introspection, nested queries |
| Admin Panel | +8 | High impact if bypassed |
| .git exposed | +7 | Full source + history |
| SSRF candidates | +6 | Cloud metadata access |
| Cloudflare WAF | -3 | Blocks automated attacks |

### Thresholds

| Score | Priority | Action |
|-------|----------|--------|
| < 4 | Low | Quick automated scan |
| 4-7 | Medium | Standard testing |
| 7-10 | High | Dedicated manual time |
| > 10 | Critical | DROP EVERYTHING |

---

## 🛑 Noise Detection

Automatic pause when server blocks us:

```bash
╔═══════════════════════════════════════════════════════════════╗
║  🛑 NOISE DETECTED - AUTO PAUSE                               ║
╠═══════════════════════════════════════════════════════════════╣
║  Reason: Rate Limit (429)                                     ║
║  Pausing for: 60 seconds...                                   ║
║  Stats: 403s=2 | 429s=3 | Timeouts=0                         ║
╚═══════════════════════════════════════════════════════════════╝
  ⏳ Resuming in  45 seconds...
```

Configure in `config/rate.conf`:
```properties
NOISE_PAUSE_TIME="60"
NOISE_MAX_429="3"
NOISE_MAX_403="10"
```

---

## 📊 Output

Instead of 10,000 URLs, you get:

### Top 20 Targets Report

```
═══════════════════════════════════════════════════════════════════
#1 🔴 api.example.com
   Score: 18 | Priority: CRITICAL
───────────────────────────────────────────────────────────────────
   📌 WHY INTERESTING:
      • GraphQL API: Introspection enabled
      • JWT Auth: Algorithm confusion possible
      • 47 hidden endpoints in JS

   ⚡ QUICK WINS:
      🎯 GraphQL introspection enabled - Extract full schema
      🔑 3 secrets in JS - Validate each

   🎯 ATTACK PATHS:
      → JWT Exploitation (30min - 1 hour)
      → GraphQL Exploitation (1-2 hours)
```

---

## 🔧 Legacy Mode (v5)

The old Bash-only mode still works:

```bash
./shadow.sh -d example.com
```

But we recommend using v6 for intelligent scanning.

---

## 📝 License

MIT License - Use responsibly for authorized testing only.
