# 👁 AUTONOMOUS PENTEST AGENT
### Made by MilkyWay Intelligence | Author: Sharlix

```
        /\
       /  \
      /    \
     /  👁  \     AUTONOMOUS PENTEST AGENT
    /________\    AI that thinks, attacks, learns, reports
  ══════════════
```

> **⚠️ LEGAL DISCLAIMER**: This tool is developed **strictly for authorized security research, vulnerability assessment, and educational purposes**. Use only on systems you own or have **explicit written permission** to test. Unauthorized use violates the IT Act 2000 and equivalent laws worldwide.

---

## 🚀 Quick Install (One Command)

```bash
git clone https://github.com/YourUsername/pentest-agent
cd pentest-agent
sudo bash install.sh
```

## ⚡ Quick Run (One Command)

```bash
# Quick scan
pentest-agent -u https://target.com

# Authenticated scan
pentest-agent -u https://target.com --creds admin:password

# Deep scan with AI + Groq
pentest-agent -u https://target.com --creds admin:password --deep --groq-key YOUR_KEY

# Stealth mode (Tor + slow)
pentest-agent -u https://target.com --creds user:pass --stealth

# Multiple targets
pentest-agent -f targets.txt --deep
```

---

## 📋 What It Tests

| Category | Tests |
|----------|-------|
| **Authentication** | JWT (none alg, weak secret, role tamper), OTP brute/reuse, session fixation |
| **Access Control** | IDOR (all ID types), privilege escalation, BAC, path bypass |
| **Business Logic** | Payment manipulation, quantity abuse, workflow skip, race conditions |
| **Injection** | SQLi (error/boolean/time), NoSQLi, SSRF, XSS, XXE, SSTI, LFI |
| **Configuration** | CORS misconfig, security headers, open redirect, mass assignment |
| **Attack Chains** | 30+ multi-bug chain combinations automatically detected |

---

## 🧠 AI Architecture

```
PRIMARY:  Ollama (local, offline) — llama3:8b
FALLBACK: Groq API (cloud, fast) — llama-3.1-70b
FALLBACK: Rule-based engine (no AI needed)
```

### Context Window Problem — SOLVED
Instead of sending all 5000 endpoints to AI:
- Sends TOP 15 untested endpoints (by priority)
- Sends LAST 5 AI actions (avoids repeating)
- Sends SUMMARY of findings (not full HTTP bodies)
- AI gets focused, relevant context → better decisions

### AI Priority Order
```
AUTH (10) > PAYMENT (10) > ADMIN (9) > GRAPHQL (8) >
PROFILE (7) > FILE (7) > API (6) > NORMAL (3)
```

---

## 🛡 WAF Detection + Bypass

Automatically detects: **Cloudflare, Akamai, AWS WAF, Imperva, F5, Sucuri, ModSecurity**

Bypass strategies (tried in order):
1. IP rotation headers (X-Forwarded-For)
2. Googlebot User-Agent
3. Referer tricks
4. Adaptive rate limiting (auto-increases delay on 429)
5. Tor IP rotation (`--tor` flag)

---

## 📁 Output Structure

```
results/
└── target_com_20260311_023912/     ← Timestamp in folder name (no duplicates)
    ├── scan.db                     ← Full SQLite database
    ├── report_023912.html          ← Dark-theme HTML report
    ├── findings.json               ← All findings (JSON)
    ├── ai_actions.json             ← AI decision log
    └── poc/
        ├── finding_1_IDOR.py
        ├── finding_2_JWT_NONE_ALGORITHM.py
        └── ...
```

---

## 🔧 CLI Options

```
INPUT:
  -u URL          Single target
  -f FILE         Multiple targets (one per line)

CREDENTIALS:
  --creds USER:PASS
  --creds-file FILE    (role:user:pass per line)
  --token BEARER_TOKEN
  --cookie COOKIE_STRING

AI:
  --ollama-model MODEL  (default: llama3:8b)
  --groq-key KEY        (Groq API key for fallback)
  --no-ai               Rule-based only

SCAN PROFILE:
  --quick    Fast (30 iterations, core engines)
  --deep     Full (400 iterations, all engines)
  --stealth  Slow + Tor

NETWORK:
  --tor              Enable Tor
  --rate N           Req/sec (default: 5)
  --max-time MINS    Timeout (default: 120)
  --max-iter N       AI loop limit (default: 200)

OUTPUT:
  -o DIR     Custom output directory
  --no-color Disable colors
```

---

## 🔗 30+ Attack Chains Detected

| Chain | Severity |
|-------|----------|
| IDOR → Account Takeover | 🔴 CRITICAL |
| JWT None Algorithm → Admin | 🔴 CRITICAL |
| SSRF → AWS Credential Theft | 🔴 CRITICAL |
| OTP No Rate Limit → Auth Bypass | 🔴 CRITICAL |
| SSTI → RCE | 🔴 CRITICAL |
| SQL Injection → Auth Bypass | 🔴 CRITICAL |
| Mass Assignment → Admin | 🔴 CRITICAL |
| Payment Manipulation → Free Purchase | 🔴 CRITICAL |
| Race Condition → Double Spend | 🟠 HIGH |
| Stored XSS + CSRF → Takeover | 🟠 HIGH |
| CORS + Credentials → Data Theft | 🔴 CRITICAL |
| ... 20+ more | ... |

---

## 💻 Requirements

- Python 3.10+
- Kali Linux / Ubuntu 22.04+ (recommended)
- 4GB RAM minimum (8GB for deep scans)
- Optional: Ollama for local AI
- Optional: Groq API key for cloud AI

---

*"AI that thinks. AI that attacks. AI that reports."*

