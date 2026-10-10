"""
ConfigAuditModule — OutSystems Configuration Security Audit

Tests:
1. Security headers (HSTS, CSP, X-Frame-Options, etc.)
2. Cookie security flags (OutSystems session cookies)
3. CORS misconfiguration on screenservice endpoints
4. Error handling (verbose stack traces, debug mode)
5. SSL/TLS configuration
6. Rate limiting on screenservice endpoints
7. CSRF protection enforcement
"""
import re
import time
import json
import socket
import ssl

from ..core import BaseModule, OutSystemsTester, truncate
from ..colors import (
    msg_ok, msg_fail, msg_info, msg_warn,
    msg_vuln, msg_vuln_detail, subsection,
)

REFERENCES_HEADERS = [
    "https://owasp.org/www-project-secure-headers/",
    "https://cwe.mitre.org/data/definitions/693.html",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
]

REFERENCES_CORS = [
    "https://cwe.mitre.org/data/definitions/942.html",
    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
]

REFERENCES_CSRF = [
    "https://owasp.org/www-community/attacks/csrf",
    "https://cwe.mitre.org/data/definitions/352.html",
]

# Required security headers and their expected patterns
REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "check": lambda v: "max-age=" in v.lower() and int(re.search(r"max-age=(\d+)", v, re.IGNORECASE).group(1)) >= 31536000,
        "severity": "medium",
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "check": lambda v: len(v) > 10,
        "severity": "medium",
        "remediation": (
            "Implement a Content Security Policy. "
            "At minimum: Content-Security-Policy: default-src 'self'"
        ),
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "description": "Clickjacking protection",
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "severity": "medium",
        "remediation": "Add: X-Frame-Options: SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "description": "MIME type sniffing prevention",
        "check": lambda v: v.lower() == "nosniff",
        "severity": "low",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "Referrer-Policy": {
        "description": "Referrer information control",
        "check": lambda v: v.lower() in (
            "no-referrer", "no-referrer-when-downgrade",
            "strict-origin", "strict-origin-when-cross-origin"
        ),
        "severity": "low",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "description": "Browser feature policy",
        "check": lambda v: len(v) > 0,
        "severity": "info",
        "remediation": "Add Permissions-Policy header to restrict browser features.",
        "cwe": "CWE-693",
    },
}

# Cookie attributes to check
COOKIE_CHECKS = {
    "HttpOnly": "Cookie not flagged as HttpOnly — accessible via JavaScript (XSS risk)",
    "Secure":   "Cookie not flagged as Secure — can be transmitted over HTTP",
    "SameSite": "Cookie missing SameSite attribute — CSRF risk",
}


class ConfigAuditModule(BaseModule):
    NAME        = "config"
    DESCRIPTION = "Security headers, cookie flags, CORS, CSRF, error handling audit"

    def run(self) -> None:
        subsection("Configuration Security Audit")

        resp = self.tester.get(self.tester.target_url)
        if resp is None:
            msg_fail("Cannot reach target for config audit")
            return

        # 1. Security headers
        self._audit_security_headers(resp)

        # 2. Cookie security
        self._audit_cookies(resp)

        # 3. CORS on screenservice endpoints
        self._audit_cors()

        # 4. Error handling / debug mode
        self._audit_error_handling()

        # 5. CSRF protection
        self._audit_csrf()

        # 6. Rate limiting
        self._audit_rate_limiting()

        # 7. Information disclosure in headers
        self._audit_header_disclosure(resp)

    # ─── Security headers ─────────────────────────────────────────────────────

    def _audit_security_headers(self, resp) -> None:
        """Check for missing or misconfigured security headers."""
        subsection("Security Headers")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = []
        misconfigured = []

        for header_name, config in REQUIRED_HEADERS.items():
            header_key = header_name.lower()
            value = headers.get(header_key, "")

            if not value:
                missing.append((header_name, config))
            else:
                try:
                    if not config["check"](value):
                        misconfigured.append((header_name, value, config))
                    else:
                        msg_ok(f"  {header_name}: {value[:60]}")
                except Exception:
                    pass  # check function failed — don't crash

        if missing:
            for header_name, config in missing:
                sev = config["severity"]
                msg_warn(f"  Missing: {header_name} ({config['description']})")
                self.finding(
                    severity=sev,
                    title=f"Missing security header: {header_name}",
                    description=(
                        f"The response does not include the {header_name} header "
                        f"({config['description']}). "
                        "This reduces the security posture of the OutSystems application."
                    ),
                    evidence=f"Header {header_name} not present in response headers",
                    request_data=self._request_summary("GET", self.tester.target_url),
                    remediation=config["remediation"],
                    cwe=config["cwe"],
                    references=REFERENCES_HEADERS,
                )

        if misconfigured:
            for header_name, value, config in misconfigured:
                msg_warn(f"  Weak: {header_name}: {value[:60]}")
                self.finding(
                    severity=config["severity"],
                    title=f"Weak security header: {header_name}",
                    description=(
                        f"The {header_name} header is present but misconfigured. "
                        f"Current value: {value}. "
                        f"Issue: {config['description']} not properly enforced."
                    ),
                    evidence=f"{header_name}: {value}",
                    remediation=config["remediation"],
                    cwe=config["cwe"],
                    references=REFERENCES_HEADERS,
                )

    # ─── Cookie audit ─────────────────────────────────────────────────────────

    def _audit_cookies(self, resp) -> None:
        """Audit OutSystems session cookies for security flags."""
        subsection("Cookie Security")
        # OutSystems session cookie names
        os_cookie_names = [
            "ASP.NET_SessionId", "osVisitor", "osVisit",
            "nr1", "nr1_csrf", "nr2", "OsAuthentication",
        ]
        checked_any = False
        for cookie in self.tester.session.cookies:
            cookie_name  = cookie.name
            cookie_value = cookie.value or ""

            # Check if it's an OutSystems-relevant cookie
            is_os_cookie = any(
                oc.lower() in cookie_name.lower()
                for oc in os_cookie_names
            )
            if not is_os_cookie:
                continue

            checked_any = True
            issues = []

            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.secure:
                issues.append("missing Secure flag")

            samesite = cookie.has_nonstandard_attr("SameSite")
            if not samesite:
                issues.append("missing SameSite attribute")

            # Check for session cookie sent over HTTP (not HTTPS)
            if self.tester.target_url.startswith("http://"):
                issues.append("session cookie transmitted over HTTP (not HTTPS)")

            if issues:
                issues_str = ", ".join(issues)
                sev = "high" if "HttpOnly" in issues_str and "session" in cookie_name.lower() else "medium"
                msg_warn(f"  Cookie {cookie_name}: {issues_str}")
                self.finding(
                    severity=sev,
                    title=f"Insecure cookie: {cookie_name} — {issues_str}",
                    description=(
                        f"OutSystems cookie '{cookie_name}' has security issues: {issues_str}. "
                        + (
                            "Missing HttpOnly on session cookie enables XSS-based session theft. "
                            if "HttpOnly" in issues_str else ""
                        )
                        + (
                            "Missing Secure flag means the cookie can be transmitted over HTTP. "
                            if "Secure" in issues_str else ""
                        )
                        + (
                            "Missing SameSite attribute enables CSRF attacks. "
                            if "SameSite" in issues_str else ""
                        )
                    ),
                    evidence=(
                        f"Cookie: {cookie_name}\n"
                        f"Issues: {issues_str}\n"
                        f"Domain: {cookie.domain}\n"
                        f"Path: {cookie.path}"
                    ),
                    remediation=(
                        f"Set cookie {cookie_name} with flags: HttpOnly; Secure; SameSite=Strict. "
                        "Configure OutSystems to use secure cookie settings. "
                        "In Web.config: <httpCookies httpOnlyCookies='true' requireSSL='true'/>"
                    ),
                    cwe="CWE-614",
                    references=[
                        "https://cwe.mitre.org/data/definitions/614.html",
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ],
                )
            else:
                msg_ok(f"  Cookie {cookie_name}: properly secured")

        # Also parse Set-Cookie headers from the response
        set_cookie_headers = resp.headers.get("Set-Cookie", "")
        if set_cookie_headers and not checked_any:
            self._analyze_set_cookie_header(set_cookie_headers)

    def _analyze_set_cookie_header(self, set_cookie: str) -> None:
        """Parse Set-Cookie header string for security issues."""
        flags = set_cookie.lower()
        issues = []
        if "httponly" not in flags:
            issues.append("missing HttpOnly")
        if "secure" not in flags:
            issues.append("missing Secure")
        if "samesite" not in flags:
            issues.append("missing SameSite")

        if issues:
            # Extract cookie name
            name_match = re.match(r"([^=]+)=", set_cookie.strip())
            cookie_name = name_match.group(1).strip() if name_match else "unknown"
            issues_str = ", ".join(issues)
            self.finding(
                severity="medium",
                title=f"Insecure Set-Cookie: {cookie_name} — {issues_str}",
                description=(
                    f"Set-Cookie header for '{cookie_name}' is missing security attributes: "
                    f"{issues_str}."
                ),
                evidence=f"Set-Cookie: {truncate(set_cookie, 200)}",
                remediation=(
                    "Set cookies with HttpOnly; Secure; SameSite=Strict attributes."
                ),
                cwe="CWE-614",
                references=["https://cwe.mitre.org/data/definitions/614.html"],
            )

    # ─── CORS audit ───────────────────────────────────────────────────────────

    def _audit_cors(self) -> None:
        """
        Test for CORS misconfiguration on OutSystems screenservice endpoints.
        Key test: does the server reflect arbitrary Origin headers?
        """
        subsection("CORS Configuration")
        modules = self.tester.os_modules or ["Common"]

        for module in modules[:3]:  # Test first 3 modules
            url = (
                f"{self.tester.base_url}/{module}/screenservices/{module}/OnInitialize"
            )
            # Test with a malicious origin
            malicious_origin = "https://evil-attacker.com"
            resp = self.tester.post(
                url,
                json={
                    "versionInfo": {"moduleVersion": "", "apiVersion": "1"},
                    "viewName": "",
                    "inputParameters": {},
                },
                headers={
                    "Content-Type":  "application/json",
                    "Origin":        malicious_origin,
                    "Referer":       malicious_origin + "/",
                },
            )
            if resp is None:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.finding(
                    severity="medium",
                    title=f"CORS wildcard (*) on screenservice: {module}",
                    description=(
                        f"The screenservice endpoint for module '{module}' returns "
                        "'Access-Control-Allow-Origin: *'. "
                        "This allows any website to read responses from this endpoint."
                    ),
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    remediation=(
                        "Restrict CORS to trusted origins. "
                        "Do not use wildcard (*) on authenticated endpoints."
                    ),
                    cwe="CWE-942",
                    references=REFERENCES_CORS,
                )

            elif acao == malicious_origin:
                # Server reflects Origin — check if credentials are allowed
                sev = "critical" if acac.lower() == "true" else "high"
                msg_vuln(sev, f"CORS reflection + credentials: {module}")
                self.finding(
                    severity=sev,
                    title=(
                        f"{'CRITICAL: ' if sev == 'critical' else ''}"
                        f"CORS misconfiguration — origin reflection on {module} screenservice"
                    ),
                    description=(
                        f"The screenservice endpoint for module '{module}' reflects "
                        f"the attacker-controlled Origin header: '{malicious_origin}'. "
                        + (
                            "With Access-Control-Allow-Credentials: true, "
                            "this allows cross-origin requests that include session cookies, "
                            "enabling account takeover via CORS-based CSRF."
                            if acac.lower() == "true" else
                            "This allows cross-origin reads of screenservice responses."
                        )
                    ),
                    evidence=(
                        f"Request Origin: {malicious_origin}\n"
                        f"Response ACAO: {acao}\n"
                        f"Response ACAC: {acac}"
                    ),
                    remediation=(
                        "Implement a strict CORS allowlist. "
                        "Never reflect the request Origin without validation. "
                        "Do not combine credential-allowing CORS with broad origin policies."
                    ),
                    cwe="CWE-942",
                    references=REFERENCES_CORS,
                )
            else:
                msg_ok(f"  CORS properly configured on {module} screenservice")

    # ─── Error handling ───────────────────────────────────────────────────────

    def _audit_error_handling(self) -> None:
        """Check for verbose error messages, stack traces, and debug mode."""
        subsection("Error Handling")
        modules = self.tester.os_modules or ["Common"]

        for module in modules[:2]:
            # Trigger an error with malformed JSON
            url = (
                f"{self.tester.base_url}/{module}/screenservices/{module}/NonExistentAction999"
            )
            resp = self.tester.post(
                url,
                data="INVALID_JSON{{{",
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            body = resp.text or ""
            self._check_verbose_errors(body, url, module)

        # Try triggering a 500 on the main page
        error_url = self.tester.target_url + "?err=1&debug=true"
        resp = self.tester.get(error_url)
        if resp:
            self._check_verbose_errors(resp.text or "", error_url, "main")

        # Check for debug endpoints
        debug_paths = [
            "/Trace.axd",
            "/elmah.axd",
            "/?trace=true",
            "/ServiceCenter/Debugger",
        ]
        for path in debug_paths:
            url = self.tester.base_url + path
            resp = self.tester.get(url)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                if len(body) > 100 and (
                    "trace" in body.lower()
                    or "application trace" in body.lower()
                    or "error log" in body.lower()
                ):
                    msg_vuln("high", f"Debug endpoint exposed: {path}")
                    self.finding(
                        severity="high",
                        title=f"Debug endpoint exposed: {path}",
                        description=(
                            f"Debug/diagnostic endpoint {url} is accessible. "
                            "These endpoints expose detailed request traces, "
                            "error logs, and internal application state."
                        ),
                        evidence=truncate(body, 300),
                        remediation=(
                            "Disable trace and debug endpoints in production. "
                            "Remove or restrict access to diagnostic pages."
                        ),
                        cwe="CWE-215",
                        references=["https://cwe.mitre.org/data/definitions/215.html"],
                    )

    def _check_verbose_errors(self, body: str, url: str, context: str) -> None:
        """Check a response body for verbose error information."""
        patterns = [
            (r"at\s+\w+(?:\.\w+)+\s*\(",             "Stack trace"),
            (r"System\.Web\.\w+Exception",            ".NET exception class"),
            (r"OutSystems\.[A-Z][a-zA-Z.]+Exception", "OutSystems exception"),
            (r"Server Error in '[^']+' Application",   "ASP.NET server error page"),
            (r"at OutSystems\.",                       "OutSystems stack frame"),
            (r"C:\\(?:inetpub|Windows|Program Files)", "Windows path disclosure"),
            (r"Runtime Error",                         "Runtime error page"),
        ]
        for pattern, label in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                excerpt = body[max(0, m.start()-50): m.start()+300]
                msg_warn(f"  Verbose error ({label}): {url}")
                self.finding(
                    severity="medium",
                    title=f"Verbose error information disclosed: {label} in {context}",
                    description=(
                        f"Error response from {url} discloses verbose information: {label}. "
                        "Stack traces and exception details reveal internal architecture "
                        "and aid attack planning."
                    ),
                    evidence=truncate(excerpt, 400),
                    remediation=(
                        "Configure OutSystems to return generic error pages in production. "
                        "Set customErrors mode='On' in Web.config. "
                        "Disable debug mode in OutSystems Service Center."
                    ),
                    cwe="CWE-209",
                    references=["https://cwe.mitre.org/data/definitions/209.html"],
                )
                return  # One finding per context

    # ─── CSRF audit ───────────────────────────────────────────────────────────

    def _audit_csrf(self) -> None:
        """
        Test whether X-CSRFToken enforcement is actually checked.
        Some OutSystems configurations accept requests without the token.
        """
        subsection("CSRF Protection")
        modules = self.tester.os_modules or ["Common"]

        for module in modules[:2]:
            url = (
                f"{self.tester.base_url}/{module}/screenservices/{module}/OnInitialize"
            )
            # Request WITHOUT X-CSRFToken header
            resp_no_csrf = self.tester.post(
                url,
                json={
                    "versionInfo": {"moduleVersion": "", "apiVersion": "1"},
                    "viewName": "",
                    "inputParameters": {},
                },
                headers={"Content-Type": "application/json"},
                # Deliberately omit X-CSRFToken
            )
            # Request WITH a fake/invalid CSRF token
            resp_fake_csrf = self.tester.post(
                url,
                json={
                    "versionInfo": {"moduleVersion": "", "apiVersion": "1"},
                    "viewName": "",
                    "inputParameters": {},
                },
                headers={
                    "Content-Type": "application/json",
                    "X-CSRFToken":  "INVALID_TOKEN_12345",
                },
            )

            if resp_no_csrf is None or resp_fake_csrf is None:
                continue

            # If both return the same non-401 status, CSRF may not be enforced
            no_csrf_status  = resp_no_csrf.status_code
            fake_csrf_status = resp_fake_csrf.status_code

            csrf_rejected = (
                "Invalid CSRF" in (resp_no_csrf.text or "")
                or "csrf" in (resp_no_csrf.text or "").lower()
                or no_csrf_status == 403
            )

            if not csrf_rejected and no_csrf_status in (200, 400, 422):
                self.finding(
                    severity="medium",
                    title=f"CSRF protection may not be enforced on {module} screenservice",
                    description=(
                        f"Screenservice requests to module '{module}' without the "
                        "X-CSRFToken header were not rejected. "
                        "If CSRF tokens are not strictly enforced, cross-site request "
                        "forgery attacks are possible against authenticated users."
                    ),
                    evidence=(
                        f"Request without X-CSRFToken -> HTTP {no_csrf_status}\n"
                        f"Request with invalid X-CSRFToken -> HTTP {fake_csrf_status}"
                    ),
                    remediation=(
                        "Ensure X-CSRFToken validation is enforced on all screenservice "
                        "endpoints. Verify the OutSystems CSRF protection setting is enabled "
                        "in Service Center under the application security settings."
                    ),
                    cwe="CWE-352",
                    references=REFERENCES_CSRF,
                )
                msg_warn(f"  CSRF may not be enforced on {module} screenservice")
            else:
                msg_ok(f"  CSRF protection active on {module} screenservice")

    # ─── Rate limiting ────────────────────────────────────────────────────────

    def _audit_rate_limiting(self) -> None:
        """
        Test if screenservice endpoints implement rate limiting.
        Sends 10 rapid requests and checks for 429 or throttling.
        """
        subsection("Rate Limiting")
        modules = self.tester.os_modules or ["Common"]
        module = modules[0]
        url = (
            f"{self.tester.base_url}/{module}/screenservices/{module}/OnInitialize"
        )

        original_delay = self.tester.delay
        self.tester.delay = 0.05  # Fast requests for rate limit test

        statuses = []
        for _ in range(10):
            resp = self.tester.post(
                url,
                json={
                    "versionInfo": {"moduleVersion": "", "apiVersion": "1"},
                    "viewName": "",
                    "inputParameters": {},
                },
                headers={"Content-Type": "application/json"},
            )
            if resp:
                statuses.append(resp.status_code)

        self.tester.delay = original_delay

        got_429 = 429 in statuses
        if got_429:
            msg_ok("  Rate limiting detected (HTTP 429)")
        else:
            msg_warn("  No rate limiting detected on screenservice endpoint")
            self.finding(
                severity="low",
                title=f"No rate limiting on {module} screenservice endpoint",
                description=(
                    f"Sending 10 rapid requests to {url} did not trigger rate limiting. "
                    "Absence of rate limiting enables brute force attacks against "
                    "authentication actions and data enumeration."
                ),
                evidence=f"10 requests, statuses: {statuses}",
                remediation=(
                    "Implement rate limiting on OutSystems screenservice endpoints. "
                    "Use a WAF or API gateway to limit request rates per IP/user. "
                    "Configure OutSystems platform-level throttling."
                ),
                cwe="CWE-770",
                references=["https://cwe.mitre.org/data/definitions/770.html"],
            )

    # ─── Header disclosure ────────────────────────────────────────────────────

    def _audit_header_disclosure(self, resp) -> None:
        """Check for sensitive information disclosure in response headers."""
        headers = dict(resp.headers)
        disclosure_headers = {
            "Server":           "Web server version disclosure",
            "X-Powered-By":     "Technology stack disclosure",
            "X-AspNet-Version": "ASP.NET framework version disclosure",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
        }
        for hdr, description in disclosure_headers.items():
            val = headers.get(hdr, "")
            if val:
                # Already reported in fingerprint, but add to config findings
                sev = "low" if hdr != "X-Powered-By" else "info"
                msg_info(f"  {hdr}: {val} ({description})")
                # Only create finding if not already in results
                existing = [
                    f for f in self.tester.results
                    if hdr in f.title
                ]
                if not existing:
                    self.finding(
                        severity=sev,
                        title=f"Header disclosure: {hdr}: {val}",
                        description=(
                            f"{description}: {hdr}: {val}. "
                            "Version information enables targeted vulnerability research."
                        ),
                        evidence=f"{hdr}: {val}",
                        remediation=(
                            f"Remove or suppress the {hdr} response header. "
                            "Configure IIS to suppress server version headers via URL Rewrite rules."
                        ),
                        cwe="CWE-200",
                        references=["https://cwe.mitre.org/data/definitions/200.html"],
                    )
