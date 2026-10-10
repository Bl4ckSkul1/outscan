"""
OutScan — OutSystems CVE Database & Known Vulnerability Patterns
Compiled from NVD, CERT.PL, OutSystems Support, Gemini Research, and original research.
Last updated: 2026-10-10

Sources:
- GitHub Advisory Database (GHSA)
- OutSystems Official Vulnerabilities: success.outsystems.com/support/security/vulnerabilities/
- OpenCVE: app.opencve.io/cve/?vendor=outsystems
- CERT Polska
- Exploit-DB
- Balwurk PoC Research
- HAAK Cybersecurity original 0-day research
"""

# =============================================================================
# OutSystems Platform CVEs (9 with CVE IDs)
# =============================================================================
OUTSYSTEMS_CVES = [
    # --- 2026 ---
    {
        "cve": "CVE-2026-40127",
        "title": "LifeTime Authorization Bypass via ApplicationID (IDOR)",
        "description": "OutSystems LifeTime does not verify user authorization for the ApplicationID parameter. Any authenticated user can manipulate ApplicationID to read Change Log entries for arbitrary applications, exposing actions and app names.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-639",
        "affected": "OutSystems LifeTime < 11.28.2.3955",
        "fixed_in": "LifeTime 11.28.2.3955",
        "module": "exposure",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/LifeTime"],
            "description": "Check if LifeTime is accessible and test ApplicationID parameter manipulation",
        },
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-40127",
            "https://cert.pl/en/posts/2026/05/CVE-2026-40127/",
        ],
    },
    {
        "cve": "CVE-2026-40126",
        "title": "Service Center DOM-based XSS via Malicious Filename",
        "description": "OutSystems Service Center is vulnerable to DOM-based XSS. A low-privileged attacker can upload a file with a malicious filename containing JavaScript code. The code executes when any user views the attachment. All file upload locations in Service Center are affected.",
        "severity": "medium",
        "cvss": 4.8,
        "cwe": "CWE-79",
        "affected": "OutSystems Service Center < 11.41.2",
        "fixed_in": "Service Center 11.41.2",
        "module": "exposure",
        "automatable": True,
        "detection": {
            "type": "version_check",
            "component": "ServiceCenter",
            "vulnerable_below": "11.41.2",
        },
        "references": [
            "https://cert.pl/en/posts/2026/08/CVE-2026-40126/",
        ],
    },

    # --- 2025 ---
    {
        "cve": "CVE-2025-61258",
        "title": "R.U.D.Y. Denial of Service via Content-Length Mismatch",
        "description": "OutSystems Platform Server allows DoS via crafted content-length mismatching body length. Less than 500 slow connections can exhaust the server (R.U.D.Y. attack). PoC: slowhttptest -c 10000 -B -o slowhttp -r 200 -u http://host/endpoint",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-400",
        "affected": "OutSystems Platform Server 11.18.1.37828",
        "fixed_in": "Platform Server 11.19+",
        "module": "config",
        "automatable": True,
        "detection": {
            "type": "version_check",
            "component": "PlatformServer",
            "vulnerable_below": "11.19.0",
        },
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-61258",
            "https://balwurk.github.io/CVE-2025-61258/",
        ],
    },
    {
        "cve": "CVE-2025-55315",
        "title": "HTTP Request Smuggling via .NET Runtime",
        "description": "Certain .NET versions used by OutSystems allow HTTP request smuggling. Affects customer applications with custom code compiled against vulnerable .NET versions.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-444",
        "affected": "OutSystems Developer Cloud (customer apps with vulnerable .NET)",
        "fixed_in": "Update .NET runtime",
        "module": "config",
        "automatable": False,
        "detection": {
            "type": "header_check",
            "description": "Check .NET version headers for affected versions",
        },
        "references": ["https://security.outsystems.com/"],
    },
    {
        "cve": "CVE-2025-28168",
        "title": "Unrestricted File Upload (Forge Multiple File Upload Component)",
        "description": "File extension and size validations enforced ONLY on client side. Intercept with Burp, modify supportedExtensions parameter, upload any file type. PoC available on GitHub.",
        "severity": "medium",
        "cvss": 4.3,
        "cwe": "CWE-434",
        "affected": "Multiple File Upload component < 3.1.0",
        "fixed_in": "3.1.0",
        "module": "config",
        "automatable": True,
        "detection": {
            "type": "active_test",
            "description": "Check for client-side-only validation on upload endpoints",
        },
        "references": [
            "https://gist.github.com/IamLeandrooooo/01090be3023f5e7c7397bb9b1f5505b9",
        ],
    },

    # --- 2022 ---
    {
        "cve": "CVE-2022-47636",
        "title": "DLL Hijacking in Service Studio",
        "description": "Opening .oml files loads DLLs from the same directory: av_libGLESv2.dll, libcef.DLL, user32.dll, d3d10warp.dll. Attacker places crafted DLL alongside malicious .oml.",
        "severity": "high",
        "cvss": 7.8,
        "cwe": "CWE-427",
        "affected": "Service Studio 11.53.30 (build 61739)",
        "fixed_in": "Later versions",
        "module": "config",
        "automatable": False,
        "detection": {"type": "info_only", "description": "Client-side — requires local access"},
        "references": ["https://www.exploit-db.com/exploits/51678"],
    },

    # --- 2021 ---
    {
        "cve": "CVE-2021-29357",
        "title": "SSRF in ECT Provider Component",
        "description": "ECT Provider component allows unauthenticated SSRF. Attacker can induce server to make HTTP requests to arbitrary domains, potentially accessing internal services.",
        "severity": "high",
        "cvss": 7.4,
        "cwe": "CWE-918",
        "affected": "Platform Server 10 < 10.0.1104.0, PS 11 < 11.9.0, LifeTime < 11.7.0",
        "fixed_in": "PS 10.0.1104.0 / 11.9.0 / LifeTime 11.7.0",
        "module": "config",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ECT_Provider/"],
            "description": "Check if ECT Provider is accessible and test for SSRF",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rtaf_2226/",
        ],
    },

    # --- 2020 ---
    {
        "cve": "CVE-2020-29441",
        "title": "Unauthenticated Arbitrary File Upload via Upload Widget",
        "description": "Upload widget allows unauthenticated attackers to upload arbitrary files in Traditional Web apps. Can exhaust DB space, corrupt async processing, block legitimate uploads.",
        "severity": "high",
        "cvss": 7.2,
        "cwe": "CWE-434",
        "affected": "Platform 10 < 10.0.1019.0, Platform 11 < OCT.19 CP4",
        "fixed_in": "10.0.1019.0 / OCT.19 CP4",
        "module": "config",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "description": "Attempt unauthenticated upload to widget endpoints",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpd_4310/",
        ],
    },
    {
        "cve": "CVE-2020-13639",
        "title": "Stored XSS in ECT Provider",
        "description": "Unauthenticated attacker stores malicious Feedback content via ECT_Provider endpoint. Executes with elevated privileges when admin views App Feedback.",
        "severity": "medium",
        "cvss": 6.1,
        "cwe": "CWE-79",
        "affected": "Pre-September 2020; Fixed: 10.0.1005.2 / 11.9.0 / LifeTime 11.7.0",
        "fixed_in": "10.0.1005.2 / 11.9.0",
        "module": "config",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ECT_Provider/"],
            "description": "Inject payload via ECT Provider feedback mechanism",
        },
        "references": [],
    },

    # --- 2019 ---
    {
        "cve": "CVE-2019-12273",
        "title": "CSRF in ImageResourceDetail.aspx",
        "description": "No CSRF token validation on ImageResourceDetail.aspx. Allows content modifications and file uploads via forged requests.",
        "severity": "medium",
        "cvss": 6.5,
        "cwe": "CWE-352",
        "affected": "Platform 10 through 11",
        "fixed_in": "Not publicly confirmed",
        "module": "config",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ImageResourceDetail.aspx"],
            "description": "Check for CSRF token on ImageResourceDetail.aspx",
        },
        "references": [],
    },
]

# =============================================================================
# OutSystems Official Advisories (Without Public CVE IDs) — 22 additional
# =============================================================================
OUTSYSTEMS_ADVISORIES = [
    # --- CRITICAL ---
    {
        "id": "RPM-3055",
        "title": "Deserialization / Privilege Escalation in Core Services",
        "description": "Vulnerable component in inter-service communication enables privilege escalation. Full access to all platform data. Requires activating 'Enhanced security for Remoting requests' (irreversible setting).",
        "severity": "critical",
        "cvss": 10.0,
        "cwe": "CWE-502",
        "affected": "ALL versions Platform Server + LifeTime",
        "fixed_in": "Platform Server 11.18.1, LifeTime 11.16.1",
        "automatable": True,
        "detection": {"type": "version_check", "component": "PlatformServer", "vulnerable_below": "11.18.1"},
        "references": ["https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_3055/"],
    },
    {
        "id": "RPM-3056",
        "title": "Unauthenticated Core Service Communication",
        "description": "Communication between OutSystems core services was NOT properly authenticated. Attacker with infrastructure access gets full platform data access. One confirmed exploitation in self-managed infrastructure.",
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-306",
        "affected": "ALL versions Platform Server + LifeTime",
        "fixed_in": "Platform Server 11.18.1, LifeTime 11.16.1",
        "automatable": True,
        "detection": {"type": "version_check", "component": "PlatformServer", "vulnerable_below": "11.18.1"},
        "references": [],
    },
    {
        "id": "RPD-5160",
        "title": "Path Traversal in Publishing Service",
        "description": "Path traversal allows developer to write arbitrary files to executable locations due to high-privilege service.",
        "severity": "critical",
        "cvss": 9.6,
        "cwe": "CWE-22",
        "affected": "ALL versions Platform Server + LifeTime",
        "fixed_in": "PS 10.0.1102.0, 11.9.0, LifeTime 11.7.0",
        "automatable": False,
        "detection": {"type": "version_check", "component": "PlatformServer"},
        "references": [],
    },
    {
        "id": "RPM-683",
        "title": "Arbitrary File Manipulation via Publishing",
        "description": "Authenticated attacker crafts malicious resource in OutSystems module to modify any file the server can access. Full data access.",
        "severity": "critical",
        "cvss": 9.9,
        "cwe": "CWE-434",
        "affected": "ALL versions Platform Server + LifeTime",
        "fixed_in": "PS 11.11.2, 11.10.4, 11.9.2, 11.8.4, 11.7.6, 10.0.1114.0",
        "automatable": False,
        "detection": {"type": "version_check", "component": "PlatformServer"},
        "references": [],
    },
    {
        "id": "RLIT-3368",
        "title": "SQL Injection in Service Center Sort Parameter",
        "description": "SQL injection via sort condition parameter. Authenticated ServiceCenter user can fully compromise all database data.",
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-89",
        "affected": "All Platform Server stacks",
        "fixed_in": "PS 10.0.1023.0, 11.7.3",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ServiceCenter"],
            "description": "Test sort parameters in ServiceCenter for SQLi",
        },
        "references": [],
    },
    {
        "id": "RPD-2322",
        "title": "SSRF via PingAddress API Endpoint",
        "description": "Undocumented PingAddress API endpoint in Service Center. Unauthenticated users can instruct platform to make HTTP GET requests to arbitrary addresses (SSRF). Can also crash app server.",
        "severity": "critical",
        "cvss": 9.6,
        "cwe": "CWE-918",
        "affected": "OS 9.1 < 9.1.609.0, OS 10 < 10.0.603.0 (OS 11 NOT affected)",
        "fixed_in": "9.1.609.0 / 10.0.603.0",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ServiceCenter/PingAddress"],
            "description": "Probe PingAddress endpoint for SSRF",
        },
        "references": [],
    },

    # --- HIGH ---
    {
        "id": "RPM-813",
        "title": "SQL Injection via Extension Publishing",
        "description": "Privileged user crafts malicious resource in OutSystems module to execute SQLi against environment database catalogs.",
        "severity": "high",
        "cvss": 7.2,
        "cwe": "CWE-89",
        "affected": "ALL versions Platform Server + LifeTime",
        "fixed_in": "PS 11.11.2, 11.10.4, 11.9.2, 11.8.4, 11.7.6, 10.0.1114.0",
        "automatable": False,
        "detection": {"type": "version_check", "component": "PlatformServer"},
        "references": ["https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_813/"],
    },
    {
        "id": "RPM-786",
        "title": "Service Center API Privilege Escalation",
        "description": "Improperly authenticated API in Service Center allows IT user privilege escalation. Full platform data access.",
        "severity": "high",
        "cvss": 8.8,
        "cwe": "CWE-269",
        "affected": "ALL versions Platform Server + LifeTime",
        "fixed_in": "PS 11.11.2, 10.0.1114.0",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ServiceCenter"],
            "description": "Attempt API calls with low-privilege tokens",
        },
        "references": [],
    },
    {
        "id": "RPD-3384",
        "title": "SQL Injection in Image Widget Endpoint",
        "description": "Unauthenticated SQLi via _image.aspx.cs (.NET) / _image.java (Java) endpoints. Image Widgets with Integer/Long Integer entity IDs are vulnerable. Default components affected: ServiceCenter, ECT_Provider, LifeTime.",
        "severity": "high",
        "cvss": 8.7,
        "cwe": "CWE-89",
        "affected": "OS 9.1 < 9.1.616.0, OS 10 < 10.0.828.0 (OS 11 NOT affected)",
        "fixed_in": "9.1.616.0 / 10.0.828.0",
        "automatable": True,
        "detection": {
            "type": "endpoint_check",
            "paths": ["/_image.aspx", "/_image.java"],
            "description": "Probe _image endpoints with SQLi payloads on integer parameters",
        },
        "references": [],
    },
    {
        "id": "RPM-6669",
        "title": "XSS via Malformed Filename in Platform Server",
        "description": "Attacker creates file with malformed filename allowing session hijacking of developer when imported into Service Studio or Service Center.",
        "severity": "medium",
        "cvss": 5.4,
        "cwe": "CWE-79",
        "affected": "OutSystems Platform Server < 11.41.2",
        "fixed_in": "Platform Server 11.41.2 (May 2026)",
        "automatable": True,
        "detection": {"type": "version_check", "component": "PlatformServer", "vulnerable_below": "11.41.2"},
        "references": ["https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_6669/"],
    },
    {
        "id": "RPM-6441",
        "title": "DLL Hijacking in Service Studio",
        "description": "Service Studio loads DLLs from the same directory when opening .oml files.",
        "severity": "high",
        "cvss": 7.8,
        "cwe": "CWE-427",
        "affected": "OutSystems Service Studio",
        "fixed_in": "See advisory",
        "automatable": False,
        "detection": {"type": "info_only"},
        "references": ["https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_6441/"],
    },
    {
        "id": "RPM-1278",
        "title": "RabbitMQ Exposure",
        "description": "RabbitMQ security flaws. Attacker with access to port 5672 gets full platform data. Cloud NOT affected.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-668",
        "affected": "All self-managed Platform Server + LifeTime",
        "fixed_in": "PS 11.13.2, LifeTime 11.10.4",
        "automatable": True,
        "detection": {
            "type": "port_check",
            "port": 5672,
            "description": "Check if RabbitMQ port 5672 is exposed",
        },
        "references": [],
    },
    {
        "id": "RTAF-2226",
        "title": "SSRF in ECT Provider (Original)",
        "description": "Unauthenticated SSRF in ECT Provider component.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-918",
        "affected": "OutSystems ECT Provider component",
        "fixed_in": "See advisory",
        "automatable": True,
        "detection": {"type": "endpoint_check", "paths": ["/ECT_Provider/"]},
        "references": ["https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rtaf_2226/"],
    },
    {
        "id": "RTAF-3379",
        "title": "SSRF in ECT Provider (Second Finding)",
        "description": "Additional SSRF vector in ECT Provider, separate from RTAF-2226.",
        "severity": "high",
        "cvss": 7.4,
        "cwe": "CWE-918",
        "affected": "All supported stacks",
        "fixed_in": "OS 10: 10.0.1106.0, OS 11: 11.9.1, LifeTime 11.7.3",
        "automatable": True,
        "detection": {"type": "endpoint_check", "paths": ["/ECT_Provider/"]},
        "references": [],
    },
    {
        "id": "RPD-3849",
        "title": "XSS with Privilege Escalation in ECT Provider",
        "description": "Unauthenticated attacker injects JavaScript into ECT Provider. Executes with elevated platform privileges when admin views App Feedback.",
        "severity": "high",
        "cvss": 8.1,
        "cwe": "CWE-79",
        "affected": "All supported stacks",
        "fixed_in": "10.0.1005.2 / Jan.2019 CP2+",
        "automatable": True,
        "detection": {"type": "endpoint_check", "paths": ["/ECT_Provider/"]},
        "references": [],
    },
    {
        "id": "RLIT-2388",
        "title": "Unauthenticated Service Center/LifeTime Pages",
        "description": "Some Service Center and LifeTime pages not protected from unauthenticated access. Exposes configuration parameters and mobile app compilation details.",
        "severity": "high",
        "cvss": 7.1,
        "cwe": "CWE-306",
        "affected": "OS 10 < 10.0.1005.2, OS 11 < Jan.2019 CP2",
        "fixed_in": "10.0.1005.2 / Jan.2019 CP2",
        "automatable": True,
        "detection": {"type": "endpoint_check", "paths": ["/ServiceCenter", "/LifeTime"]},
        "references": [],
    },
    {
        "id": "RPD-2903",
        "title": "Pass-the-Hash Authentication Bypass",
        "description": "Internal web services accept password hashes for authentication. Developers with DB access can extract hashes and replay them against Service Center login.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-836",
        "affected": "OS 9 < 9.1.614.0, OS 10 < 10.0.811.0 (OS 11 NOT affected)",
        "fixed_in": "9.1.614.0 / 10.0.811.0",
        "automatable": True,
        "detection": {"type": "active_test", "description": "Attempt hash-based auth against internal web services"},
        "references": [],
    },
    {
        "id": "RDEV-2256",
        "title": "Unauthorized API Access",
        "description": "Two APIs granted unauthorized access and modification of user data.",
        "severity": "high",
        "cvss": 8.3,
        "cwe": "CWE-862",
        "affected": "PS 11 Oct.2019 variants, 11.7.2, 11.7.3; LifeTime 11.4.2-11.5.3",
        "fixed_in": "PS 11.8.0, LifeTime 11.6.0",
        "automatable": True,
        "detection": {"type": "version_check", "component": "PlatformServer"},
        "references": [],
    },
    {
        "id": "RPD-4260",
        "title": "Privilege Abuse via Advanced Queries",
        "description": "Developer with 'Reuse & Monitor' role can manipulate or delete database contents via Service Studio advanced query functionality.",
        "severity": "high",
        "cvss": 7.6,
        "cwe": "CWE-269",
        "affected": "OS 10 < 10.0.1016.0, OS 11 < OCT.19 CP4",
        "fixed_in": "10.0.1016.0 / OCT.19 CP4",
        "automatable": False,
        "detection": {"type": "info_only", "description": "Requires developer role"},
        "references": [],
    },
    {
        "id": "RPM-4141",
        "title": "AI Mentor Studio Probe Authentication Bypass",
        "description": "Authentication issues between LifeTime and Code Analysis environment Probes in AI Mentor Studio.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-287",
        "affected": "OutSystems AI Mentor Studio Probes",
        "fixed_in": "See advisory",
        "automatable": True,
        "detection": {"type": "endpoint_check", "paths": ["/AIAnalysis/", "/CodeAnalysis/"]},
        "references": ["https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_4141/"],
    },
    {
        "id": "RCFT-4197",
        "title": "HTTP Request Smuggling in Cloud (ALB)",
        "description": "HTTP request smuggling poisons responses for other legitimate users. Cloud-only. Patched via WAF rules.",
        "severity": "high",
        "cvss": 7.6,
        "cwe": "CWE-444",
        "affected": "OutSystems Cloud with ALB",
        "fixed_in": "WAF rules deployed automatically",
        "automatable": False,
        "detection": {"type": "active_test", "description": "HTTP smuggling tests (cloud-specific)"},
        "references": [],
    },
]

# =============================================================================
# Original Research (HAAK Cybersecurity) — 0-day + architectural findings
# =============================================================================
HAAK_RESEARCH = [
    {
        "cve": "HAAK-OS-001 (CVE pending)",
        "title": "viewName Authorization Bypass in Reactive Web",
        "description": "OutSystems Platform Server 11.x enforces authorization at the Screen level, not Server Action level. The viewName parameter in screenservice POST requests is client-controlled. By specifying an anonymous screen viewName, attackers call server actions requiring authentication. Confirmed: 26 endpoints bypassed, ATO chain, verification code bypass, password hash exposure.",
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-863",
        "affected": "OutSystems Platform Server 11.x, Reactive Web applications",
        "fixed_in": "Not fixed — architectural design flaw",
        "automatable": True,
        "references": ["Original research by Adrian Martinez / HAAK Cybersecurity"],
    },
    {
        "cve": "HAAK-OS-002",
        "title": "model.js Entity Schema Information Disclosure",
        "description": "Auto-generated model.js files expose complete database entity schemas. 197 entities found in single engagement including Users, OIDC (ClientSecret/PrivateKey as plaintext), Sessions. ServiceCenter, Users, EPA_TaskBox, OIDC modules exposed.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-200",
        "affected": "OutSystems Platform Server 11.x",
        "fixed_in": "Not fixed — by design",
        "automatable": True,
        "references": ["Original research by Adrian Martinez / HAAK Cybersecurity"],
    },
    {
        "cve": "HAAK-OS-003",
        "title": "ServiceCenter/LifeTime/Users Admin Panel Internet Exposure",
        "description": "Management consoles exposed to internet providing attack surface for credential attacks and information disclosure.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-668",
        "affected": "OutSystems Platform Server 11.x",
        "fixed_in": "Configuration — restrict network access",
        "automatable": True,
        "references": ["Original research by Adrian Martinez / HAAK Cybersecurity"],
    },
]

# =============================================================================
# Architecture-Level Attack Patterns (10 scanner signatures)
# =============================================================================
ATTACK_PATTERNS = [
    {
        "id": "OS-ATK-001",
        "name": "model.js Information Disclosure",
        "description": "Every OutSystems module exposes model.js with complete entity schemas, attribute names, data types, relationships.",
        "technique": "GET /<ModuleName>/model.js — parse entity definitions",
        "severity": "medium",
        "cwe": "CWE-200",
        "automatable": True,
    },
    {
        "id": "OS-ATK-002",
        "name": "screenservices Endpoint Enumeration",
        "description": "Reactive apps expose /screenservices/ endpoints. Combined with model.js, attackers enumerate all server actions.",
        "technique": "POST /<Module>/screenservices/<Module>/<ActionName> with JSON body",
        "severity": "medium",
        "cwe": "CWE-200",
        "automatable": True,
    },
    {
        "id": "OS-ATK-003",
        "name": "moduleservices API Enumeration",
        "description": "Similar to screenservices, moduleservices expose backend logic.",
        "technique": "POST /<Module>/moduleservices/<ServiceName>",
        "severity": "medium",
        "cwe": "CWE-200",
        "automatable": True,
    },
    {
        "id": "OS-ATK-004",
        "name": "Client-Side-Only Authorization",
        "description": "Auth enforced only at screen/widget level, not server action level. Developers must manually add checks.",
        "technique": "Call endpoints directly via screenservices/moduleservices bypassing UI",
        "severity": "high",
        "cwe": "CWE-602",
        "automatable": True,
    },
    {
        "id": "OS-ATK-005",
        "name": "Integer Entity ID IDOR",
        "description": "OutSystems uses auto-incrementing integer IDs by default. Combined with model.js exposure, trivial to enumerate.",
        "technique": "Increment entity ID parameters in API calls",
        "severity": "high",
        "cwe": "CWE-639",
        "automatable": True,
    },
    {
        "id": "OS-ATK-006",
        "name": "ECT Provider Exposure (Recurring Attack Surface)",
        "description": "ECT Provider component has multiple CVEs (XSS, SSRF). Often left enabled when not needed.",
        "technique": "Check /ECT_Provider/ endpoint accessibility",
        "severity": "high",
        "cwe": "CWE-918",
        "automatable": True,
    },
    {
        "id": "OS-ATK-007",
        "name": "BPT (Business Process Technology) Exposure",
        "description": "BPT processes may expose workflow state, task assignments through EPA_TaskBox endpoints.",
        "technique": "Check /EPA_TaskBox/ endpoints for unauthenticated access",
        "severity": "medium",
        "cwe": "CWE-200",
        "automatable": True,
    },
    {
        "id": "OS-ATK-008",
        "name": "CSRF Token Absence on Legacy Endpoints",
        "description": "Traditional Web apps may lack CSRF protection on admin endpoints (ref: CVE-2019-12273).",
        "technique": "Check for absence of anti-CSRF tokens in forms and AJAX requests",
        "severity": "medium",
        "cwe": "CWE-352",
        "automatable": True,
    },
    {
        "id": "OS-ATK-009",
        "name": "REST API Default Public Exposure",
        "description": "OutSystems docs confirm: 'When screen is Anonymous, REST API is also public.' Making a screen anonymous also exposes related REST endpoints.",
        "technique": "Identify anonymous screens, test associated REST endpoints",
        "severity": "high",
        "cwe": "CWE-284",
        "automatable": True,
    },
    {
        "id": "OS-ATK-010",
        "name": "clientvariables Information Leakage",
        "description": "Client-side variables may contain sensitive config, feature flags, internal URLs accessible via JS console.",
        "technique": "Analyze clientvariables endpoints and JS bundles",
        "severity": "low",
        "cwe": "CWE-200",
        "automatable": True,
    },
]

# =============================================================================
# Mendix/PowerApps CVEs — Parallel patterns applicable to OutSystems
# =============================================================================
PARALLEL_CVES = [
    # Mendix
    {"cve": "CVE-2026-80465", "platform": "Mendix", "title": "SAML Account Hijacking", "cvss": 8.7, "relevance": "Test OutSystems SAML module for assertion validation bypass"},
    {"cve": "CVE-2026-7891", "platform": "Mendix", "title": "Insecure Inherited Permission", "cvss": 9.1, "relevance": "OutSystems role inheritance may have similar privilege escalation"},
    {"cve": "CVE-2024-50313", "platform": "Mendix", "title": "Race Condition in Basic Auth", "cvss": 5.3, "relevance": "OutSystems Basic Auth may be susceptible to race conditions"},
    {"cve": "CVE-2024-56841", "platform": "Mendix", "title": "LDAP Injection in Auth", "cvss": 7.4, "relevance": "OutSystems LDAP integrations may be vulnerable"},
    {"cve": "CVE-2024-39888", "platform": "Mendix", "title": "Hard-coded Encryption Key", "cvss": 7.5, "relevance": "Check OutSystems for hardcoded keys in model.js or JS bundles"},
    {"cve": "CVE-2024-33500", "platform": "Mendix", "title": "Improper Privilege Management", "cvss": 5.9, "relevance": "OutSystems role management escalation paths"},
    {"cve": "CVE-2023-25957", "platform": "Mendix", "title": "SAML Assertion Validation Bypass", "cvss": 9.1, "relevance": "OutSystems SAML Forge component — test assertion validation"},
    {"cve": "CVE-2022-46664", "platform": "Mendix", "title": "Workflow Commons Access Control", "cvss": 7.0, "relevance": "OutSystems BPT workflows access control"},
    # PowerApps
    {"cve": "CVE-2026-59118", "platform": "PowerApps", "title": "Privilege Escalation via Improper Auth", "cvss": 9.8, "relevance": "Role-based access bypass pattern"},
    {"cve": "CVE-2025-47733", "platform": "PowerApps", "title": "SSRF", "cvss": 9.1, "relevance": "Same pattern as OutSystems ECT Provider SSRF"},
]

# =============================================================================
# Utility functions
# =============================================================================
def get_all_cves() -> list[dict]:
    """Return all OutSystems CVEs + advisories + HAAK research"""
    return OUTSYSTEMS_CVES + OUTSYSTEMS_ADVISORIES + HAAK_RESEARCH

def get_automatable_checks() -> list[dict]:
    """Return only remotely automatable vulnerabilities"""
    return [v for v in get_all_cves() if v.get("automatable", False)]

def get_cves_by_severity(severity: str) -> list[dict]:
    """Filter CVEs by severity level"""
    return [v for v in get_all_cves() if v.get("severity") == severity]

def get_cves_for_version(version: str) -> list[dict]:
    """Return CVEs that may affect a given OutSystems version"""
    results = []
    for cve in get_all_cves():
        affected = cve.get("affected", "")
        fixed = cve.get("fixed_in", "")
        if "ALL versions" in affected or "Not fixed" in fixed:
            results.append(cve)
        elif version in affected:
            results.append(cve)
    return results

def get_stats() -> dict:
    """Return CVE database statistics"""
    all_cves = get_all_cves()
    return {
        "total_cves": len(OUTSYSTEMS_CVES),
        "total_advisories": len(OUTSYSTEMS_ADVISORIES),
        "total_haak_research": len(HAAK_RESEARCH),
        "total_attack_patterns": len(ATTACK_PATTERNS),
        "total_parallel_cves": len(PARALLEL_CVES),
        "total_all": len(all_cves),
        "automatable": len(get_automatable_checks()),
        "critical": len(get_cves_by_severity("critical")),
        "high": len(get_cves_by_severity("high")),
        "medium": len(get_cves_by_severity("medium")),
    }
