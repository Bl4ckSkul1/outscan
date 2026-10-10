"""
OutScan — OutSystems CVE Database & Known Vulnerability Patterns
Compiled from NVD, CERT.PL, OutSystems Support, and original research.
Last updated: 2026-10-10
"""

# =============================================================================
# OutSystems Platform CVEs
# =============================================================================
OUTSYSTEMS_CVES = [
    # --- 2026 ---
    {
        "cve": "CVE-2026-40127",
        "title": "LifeTime Authorization Bypass via ApplicationID",
        "description": "OutSystems LifeTime does not verify user authorization for the ApplicationID parameter. Any authenticated user can manipulate ApplicationID to read Change Log entries for arbitrary applications, exposing actions and app names.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-639",
        "affected": "OutSystems LifeTime < 11.28.2.3955",
        "fixed_in": "LifeTime 11.28.2.3955",
        "module": "exposure",
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
        "description": "OutSystems Service Center is vulnerable to DOM-based XSS. A low-privileged attacker can upload a file with a malicious filename containing JavaScript code. The code executes when any user views the attachment.",
        "severity": "medium",
        "cvss": 4.8,
        "cwe": "CWE-79",
        "affected": "OutSystems Service Center < 11.41.2",
        "fixed_in": "Service Center 11.41.2",
        "module": "exposure",
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
        "description": "OutSystems Platform Server 11.18.1 allows DoS via crafted content-length mismatching body length. Less than 500 slow connections can exhaust the server (R.U.D.Y. attack).",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-400",
        "affected": "OutSystems Platform Server 11.18.1.37828",
        "fixed_in": "Platform Server 11.19+",
        "module": "config",
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
        "description": "Certain .NET versions used by OutSystems allow HTTP request smuggling. Affects customer applications with custom code compiled against vulnerable .NET versions. ODC Platform itself is not vulnerable.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-444",
        "affected": "OutSystems Developer Cloud (customer apps with vulnerable .NET)",
        "fixed_in": "Update .NET runtime",
        "module": "config",
        "detection": {
            "type": "header_check",
            "description": "Check .NET version headers for affected versions",
        },
        "references": [
            "https://security.outsystems.com/",
        ],
    },

    # --- OutSystems Internal IDs (RPM/RTAF/RICT/RPD) ---
    {
        "cve": "RPM-6669",
        "title": "XSS via Malformed Filename in Platform Server",
        "description": "An attacker can create a file with a malformed filename that allows session hijacking of a developer when the file is imported into Service Studio or Service Center.",
        "severity": "medium",
        "cvss": 5.4,
        "cwe": "CWE-79",
        "affected": "OutSystems Platform Server < 11.41.2",
        "fixed_in": "Platform Server 11.41.2 (May 2026)",
        "module": "exposure",
        "detection": {
            "type": "version_check",
            "component": "PlatformServer",
            "vulnerable_below": "11.41.2",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_6669/",
        ],
    },
    {
        "cve": "RPM-813",
        "title": "SQL Injection in Application Publish Process",
        "description": "The Platform Server application publish process is vulnerable to SQL injection. An attacker can forge a specially crafted resource in an OutSystems module to inject SQL into the environment's database catalogs.",
        "severity": "critical",
        "cvss": 8.8,
        "cwe": "CWE-89",
        "affected": "OutSystems Platform Server (multiple versions)",
        "fixed_in": "See OutSystems advisory",
        "module": "config",
        "detection": {
            "type": "version_check",
            "component": "PlatformServer",
            "description": "Check platform version against advisory",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_813/",
        ],
    },
    {
        "cve": "RTAF-2226",
        "title": "SSRF in ECT Provider Component",
        "description": "The ECT Provider component allows unauthenticated SSRF. An attacker can induce the server-side application to make HTTP requests to arbitrary domains, potentially accessing internal services.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-918",
        "affected": "OutSystems ECT Provider component",
        "fixed_in": "See OutSystems advisory",
        "module": "config",
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ECT_Provider/"],
            "description": "Check if ECT Provider is accessible and test for SSRF",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rtaf_2226/",
        ],
    },
    {
        "cve": "RPM-6441",
        "title": "DLL Hijacking in Service Studio",
        "description": "OutSystems Service Studio loads DLLs from the same directory when opening .oml files. An attacker can execute arbitrary code by placing a crafted DLL alongside a malicious .oml file.",
        "severity": "high",
        "cvss": 7.8,
        "cwe": "CWE-427",
        "affected": "OutSystems Service Studio",
        "fixed_in": "See OutSystems advisory",
        "module": "config",
        "detection": {
            "type": "info_only",
            "description": "Client-side vulnerability in Service Studio — cannot be detected remotely",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_6441/",
        ],
    },
    {
        "cve": "RICT-2849",
        "title": "Service Studio File System Privilege Escalation",
        "description": "A low-privileged OS user can rewrite files they don't have access to through Service Studio's file system management.",
        "severity": "medium",
        "cvss": 5.5,
        "cwe": "CWE-269",
        "affected": "OutSystems Service Studio",
        "fixed_in": "See OutSystems advisory",
        "module": "config",
        "detection": {
            "type": "info_only",
            "description": "Client-side vulnerability — cannot be detected remotely",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rict_2849/",
        ],
    },
    {
        "cve": "RPM-4141",
        "title": "AI Mentor Studio Probe Authentication Bypass",
        "description": "Authentication issues between LifeTime and Code Analysis environment Probes in AI Mentor Studio could allow unauthorized access to code analysis data.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-287",
        "affected": "OutSystems AI Mentor Studio Probes",
        "fixed_in": "See OutSystems advisory",
        "module": "exposure",
        "detection": {
            "type": "endpoint_check",
            "paths": ["/AIAnalysis/", "/CodeAnalysis/"],
            "description": "Check if AI Mentor Studio probes are accessible",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpm_4141/",
        ],
    },
    {
        "cve": "RPD-4310",
        "title": "Arbitrary File Upload via Upload Widget",
        "description": "The Upload widget allows unauthenticated attackers to upload arbitrary files to the platform, potentially causing DoS or data corruption.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-434",
        "affected": "OutSystems Platform (Upload widget)",
        "fixed_in": "See OutSystems advisory",
        "module": "config",
        "detection": {
            "type": "endpoint_check",
            "description": "Test upload endpoints for authentication requirements",
        },
        "references": [
            "https://success.outsystems.com/support/security/vulnerabilities/vulnerability_rpd_4310/",
        ],
    },
    {
        "cve": "RPM-3055",
        "title": "Platform Server Information Disclosure",
        "description": "Platform Server endpoints expose internal information that could aid an attacker in further exploitation.",
        "severity": "low",
        "cvss": 3.7,
        "cwe": "CWE-200",
        "affected": "OutSystems Platform Server",
        "fixed_in": "See OutSystems advisory",
        "module": "exposure",
        "detection": {
            "type": "endpoint_check",
            "description": "Check for information disclosure in error responses and metadata endpoints",
        },
        "references": [
            "https://github.com/OutSystems/docs-support/blob/master/src/security/vulnerabilities/vulnerability-RPM-3055.md",
        ],
    },

    # --- Original Research (HAAK Cybersecurity) ---
    {
        "cve": "HAAK-OS-001 (CVE pending)",
        "title": "viewName Authorization Bypass in Reactive Web",
        "description": "OutSystems Platform Server 11.x enforces authorization at the Screen level, not Server Action level. The viewName parameter in screenservice POST requests is client-controlled and determines the authorization context. By specifying an anonymous screen viewName, attackers can call server actions that should require authentication.",
        "severity": "critical",
        "cvss": 9.1,
        "cwe": "CWE-863",
        "affected": "OutSystems Platform Server 11.x, Reactive Web applications",
        "fixed_in": "Not fixed — architectural design flaw",
        "module": "viewname",
        "detection": {
            "type": "active_test",
            "description": "Test screenservice endpoints with anonymous viewName values",
        },
        "references": [
            "Original research by Adrian Martinez / HAAK Cybersecurity",
        ],
    },
    {
        "cve": "HAAK-OS-002",
        "title": "model.js Entity Schema Information Disclosure",
        "description": "OutSystems auto-generates model.js files containing complete database entity schemas including field names, types, and relationships. Sensitive entities (Users, OIDC, Sessions) are exposed. OIDC ClientSecret and PrivateKey stored as plaintext Text fields.",
        "severity": "high",
        "cvss": 7.5,
        "cwe": "CWE-200",
        "affected": "OutSystems Platform Server 11.x",
        "fixed_in": "Not fixed — by design",
        "module": "model_js",
        "detection": {
            "type": "endpoint_check",
            "paths": ["/{module}/model.js", "/{module}/scripts/model.js"],
            "description": "Fetch model.js files and analyze for sensitive entities",
        },
        "references": [
            "Original research by Adrian Martinez / HAAK Cybersecurity",
        ],
    },
    {
        "cve": "HAAK-OS-003",
        "title": "ServiceCenter/LifeTime/Users Admin Panel Internet Exposure",
        "description": "OutSystems management consoles (ServiceCenter, LifeTime, Users, IdP) are often exposed to the internet, providing attack surface for credential attacks and information disclosure.",
        "severity": "medium",
        "cvss": 5.3,
        "cwe": "CWE-668",
        "affected": "OutSystems Platform Server 11.x",
        "fixed_in": "Configuration — restrict network access",
        "module": "exposure",
        "detection": {
            "type": "endpoint_check",
            "paths": ["/ServiceCenter", "/LifeTime", "/Users"],
            "description": "Check if admin panels are accessible from the internet",
        },
        "references": [
            "Original research by Adrian Martinez / HAAK Cybersecurity",
        ],
    },
]

# =============================================================================
# Mendix CVEs (parallel low-code platform — similar patterns may apply)
# =============================================================================
MENDIX_PARALLEL_CVES = [
    {
        "cve": "CVE-2026-80465",
        "title": "Account Hijacking via SAML Module",
        "cvss": 8.7,
        "cwe": "CWE-287",
        "relevance": "OutSystems also supports SAML — test for similar auth bypass in SSO flows",
    },
    {
        "cve": "CVE-2026-7891",
        "title": "Insecure Inherited Permission",
        "cvss": 9.1,
        "cwe": "CWE-276",
        "relevance": "OutSystems role inheritance may have similar privilege escalation",
    },
    {
        "cve": "CVE-2024-50313",
        "title": "Race Condition in Basic Authentication",
        "cvss": 5.3,
        "cwe": "CWE-362",
        "relevance": "OutSystems Basic Auth may be susceptible to similar race conditions",
    },
    {
        "cve": "CVE-2024-56841",
        "title": "LDAP Injection in Authentication",
        "cvss": 7.4,
        "cwe": "CWE-90",
        "relevance": "OutSystems LDAP integrations may be vulnerable to similar injection",
    },
    {
        "cve": "CVE-2024-39888",
        "title": "Hard-coded Encryption Key",
        "cvss": 7.5,
        "cwe": "CWE-321",
        "relevance": "Check OutSystems for hardcoded keys in model.js or JS bundles",
    },
    {
        "cve": "CVE-2024-33500",
        "title": "Improper Privilege Management",
        "cvss": 5.9,
        "cwe": "CWE-269",
        "relevance": "OutSystems role management may have similar escalation paths",
    },
]

# =============================================================================
# OutSystems-specific attack patterns (from research & bug bounties)
# =============================================================================
ATTACK_PATTERNS = [
    {
        "id": "OS-ATK-001",
        "name": "Screen Enumeration via OutSystems-Exploit",
        "description": "Test screens in production often don't require authentication. An attacker can enumerate ALL screens of an application to discover unprotected test/debug screens.",
        "technique": "Enumerate screens via JS bundle analysis and direct URL access",
        "severity": "medium",
        "cwe": "CWE-306",
    },
    {
        "id": "OS-ATK-002",
        "name": "IDOR via Client-Side ID Trust",
        "description": "OutSystems Reactive Web apps trust IDs from the frontend without server-side authorization checks. Sequential integer IDs in Server Actions are vulnerable to IDOR.",
        "technique": "Manipulate ID parameters in screenservice calls",
        "severity": "high",
        "cwe": "CWE-639",
    },
    {
        "id": "OS-ATK-003",
        "name": "XHR Monkey-Patch for Request Interception",
        "description": "OutSystems screenservice calls can be intercepted by monkey-patching XMLHttpRequest in the browser, revealing hidden actions and parameters.",
        "technique": "Inject JS to intercept all screenservice communications",
        "severity": "info",
        "cwe": "CWE-200",
    },
    {
        "id": "OS-ATK-004",
        "name": "Environment Hopping via Shared Infrastructure",
        "description": "Development, QA, and Production environments may share infrastructure. Credentials or tokens from lower environments may work in production.",
        "technique": "Test credentials across environments if multiple are discovered",
        "severity": "high",
        "cwe": "CWE-287",
    },
    {
        "id": "OS-ATK-005",
        "name": "REST API Authentication Bypass",
        "description": "OutSystems REST APIs may inherit the screen's anonymous status. If a REST API is defined in a module with anonymous screens, it may be publicly accessible.",
        "technique": "Enumerate /rest/ endpoints and test without authentication",
        "severity": "high",
        "cwe": "CWE-306",
    },
    {
        "id": "OS-ATK-006",
        "name": "Verbose Error Information Disclosure",
        "description": "OutSystems .NET stack traces often leak internal paths, database schema names, stored procedure names, and server configuration details.",
        "technique": "Trigger errors via malformed requests and analyze stack traces",
        "severity": "medium",
        "cwe": "CWE-209",
    },
    {
        "id": "OS-ATK-007",
        "name": "BPT (Business Process Technology) Exposure",
        "description": "OutSystems BPT processes may expose workflow state, task assignments, and business logic through EPA_TaskBox endpoints.",
        "technique": "Check /EPA_TaskBox/ endpoints for unauthenticated access",
        "severity": "medium",
        "cwe": "CWE-200",
    },
    {
        "id": "OS-ATK-008",
        "name": "clientvariables Information Leakage",
        "description": "OutSystems client-side variables (clientvariables) may contain sensitive configuration, feature flags, or internal URLs accessible via JavaScript console.",
        "technique": "Analyze clientvariables endpoints and JS bundles",
        "severity": "low",
        "cwe": "CWE-200",
    },
]

# =============================================================================
# Version-to-vulnerability mapping for automated detection
# =============================================================================
VERSION_VULNS = {
    # version_prefix: [list of CVE IDs that affect this version]
    "11.18": ["CVE-2025-61258"],
    "11.40": ["HAAK-OS-001", "HAAK-OS-002", "HAAK-OS-003"],
    "11.41.1": ["CVE-2026-40126", "RPM-6669"],
}

def get_vulns_for_version(version: str) -> list[dict]:
    """Return CVEs that may affect a given OutSystems version"""
    results = []
    for cve in OUTSYSTEMS_CVES:
        affected = cve.get("affected", "")
        fixed = cve.get("fixed_in", "")
        # Simple check — if version appears in affected range
        if version in affected or "multiple" in affected.lower() or "Not fixed" in fixed:
            results.append(cve)
    return results

def get_all_remotely_detectable() -> list[dict]:
    """Return CVEs that can be detected remotely (not client-side only)"""
    return [
        cve for cve in OUTSYSTEMS_CVES
        if cve.get("detection", {}).get("type") != "info_only"
    ]

def get_cves_by_module(module_name: str) -> list[dict]:
    """Return CVEs relevant to a specific OutScan module"""
    return [
        cve for cve in OUTSYSTEMS_CVES
        if cve.get("module") == module_name
    ]
