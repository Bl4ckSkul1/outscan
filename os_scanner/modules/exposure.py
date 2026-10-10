"""
ExposureModule — OutSystems Admin Panel and Infrastructure Exposure

Tests:
1. ServiceCenter exposure (admin panel, deployment console)
2. Users module exposure (user management portal)
3. LifeTime management console exposure
4. IdP/Identity Provider login pages
5. Monitoring and error log endpoints
6. Environment type detection
7. Default credential testing
"""
import re
import time

from ..core import BaseModule, OutSystemsTester, truncate
from ..colors import (
    msg_ok, msg_fail, msg_info, msg_warn,
    msg_vuln, msg_vuln_detail, subsection,
)
from ..data.os_common import (
    SERVICE_CENTER_PATHS, OIDC_PATHS, DEFAULT_CREDENTIALS,
)

REFERENCES = [
    "https://success.outsystems.com/Documentation/11/Setting_Up_OutSystems/OutSystems_network_requirements",
    "https://cwe.mitre.org/data/definitions/284.html",
    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
]

# Map of paths to their descriptions and severity if accessible
EXPOSURE_CHECKS = [
    # (path, description, severity, check_default_creds, is_critical)
    (
        "/ServiceCenter",
        "OutSystems ServiceCenter — deployment and configuration console",
        "high", True, True,
    ),
    (
        "/ServiceCenter/Error_Log.aspx",
        "ServiceCenter Error Log — application error details",
        "high", False, True,
    ),
    (
        "/ServiceCenter/ApplicationList.aspx",
        "ServiceCenter Application List — all deployed applications",
        "high", False, True,
    ),
    (
        "/ServiceCenter/Monitoring.aspx",
        "ServiceCenter Monitoring — real-time platform monitoring",
        "medium", False, False,
    ),
    (
        "/ServiceCenter/IntegrationLog.aspx",
        "ServiceCenter Integration Log — integration call details",
        "medium", False, False,
    ),
    (
        "/ServiceCenter/Timer_List.aspx",
        "ServiceCenter Timer List — background job schedules",
        "low", False, False,
    ),
    (
        "/ServiceCenter/ModuleList.aspx",
        "ServiceCenter Module List — all deployed modules",
        "high", False, True,
    ),
    (
        "/ServiceCenter/Deploy.aspx",
        "ServiceCenter Deployment — deployment pipeline access",
        "critical", False, True,
    ),
    (
        "/ServiceCenter/SolutionList.aspx",
        "ServiceCenter Solution List — platform solutions",
        "medium", False, False,
    ),
    (
        "/LifeTime",
        "LifeTime Management Console — full deployment pipeline access",
        "critical", True, True,
    ),
    (
        "/LifeTime/ApplicationList.aspx",
        "LifeTime Application List — all applications across environments",
        "critical", False, True,
    ),
    (
        "/Users",
        "OutSystems Users module — user management portal",
        "medium", True, False,
    ),
    (
        "/Users/Login.aspx",
        "Users module login page",
        "low", False, False,
    ),
    (
        "/Users/EditMyProfile.aspx",
        "Users module profile editor",
        "low", False, False,
    ),
]


class ExposureModule(BaseModule):
    NAME        = "exposure"
    DESCRIPTION = "Admin panel, management console, and infrastructure exposure"

    def run(self) -> None:
        subsection("Admin Panel & Infrastructure Exposure")

        exposed = []

        # 1. Check all known admin/management paths
        for path, description, severity, check_creds, is_critical in EXPOSURE_CHECKS:
            result = self._check_path(path, description, severity, is_critical)
            if result:
                exposed.append(result)
                if check_creds and result.get("accessible"):
                    self._test_default_credentials(path, result)

        # 2. Check OIDC/IdP endpoints
        self._check_oidc_exposure()

        # 3. Environment detection
        self._detect_environment()

        # 4. User enumeration via Users module
        if any(r.get("path", "").startswith("/Users") for r in exposed):
            self._test_user_enumeration()

        # Summary
        critical_count = sum(1 for r in exposed if r.get("severity") == "critical")
        high_count     = sum(1 for r in exposed if r.get("severity") == "high")

        if critical_count or high_count:
            msg_vuln(
                "critical" if critical_count else "high",
                f"{len(exposed)} admin/management endpoint(s) exposed to internet",
                f"{critical_count} critical, {high_count} high",
            )

    # ─── Path checks ──────────────────────────────────────────────────────────

    def _check_path(
        self,
        path:        str,
        description: str,
        severity:    str,
        is_critical: bool,
    ) -> dict | None:
        """
        Test if a path is accessible and generate a finding if so.
        Returns result dict if accessible, None otherwise.
        """
        url = self.tester.base_url + path
        resp = self.tester.get(url)
        if resp is None:
            return None

        status = resp.status_code

        # Not accessible
        if status in (404, 400):
            return None

        # Redirect to login = accessible but auth-gated
        if status in (301, 302):
            location = resp.headers.get("Location", "")
            if "login" in location.lower():
                # Still report — login page accessible means path confirmed
                self.finding(
                    severity="info",
                    title=f"Redirects to login: {path}",
                    description=(
                        f"{description} exists at {url}. "
                        "Access requires authentication (redirects to login). "
                        "Presence confirms this admin tool is deployed."
                    ),
                    evidence=f"HTTP {status} -> Location: {location}",
                    cwe="CWE-200",
                )
                return {"path": path, "url": url, "accessible": False, "severity": "info"}
            # Redirect elsewhere
            return None

        # Accessible (200, 401, 403, 500)
        accessible = status == 200
        body = resp.text or ""
        content_length = len(resp.content)

        # Check if this is a real OutSystems page (not a generic server error)
        is_os_page = self._is_outsystems_page(body)
        if not is_os_page and status in (401, 403):
            return None

        sev = "critical" if (accessible and is_critical) else severity

        if accessible:
            msg_vuln(sev, f"EXPOSED (HTTP 200): {path}", description[:60])
        else:
            msg_warn(f"  Auth-gated {path} confirmed (HTTP {status})")
            sev = "info"

        # Extract version from ServiceCenter if accessible
        if accessible and "servicecenter" in path.lower():
            version = self._extract_sc_version(body)
            if version and not self.tester.os_version:
                self.tester.os_version = version

        self.finding(
            severity=sev,
            title=(
                f"{'CRITICAL EXPOSURE' if sev == 'critical' else 'Exposed'}: "
                f"{path} — {description.split('—')[0].strip()}"
            ),
            description=(
                f"{description} is {'accessible without authentication' if accessible else 'reachable'} "
                f"at {url} (HTTP {status}). "
                + (
                    "An attacker can access this administrative interface without credentials. "
                    if accessible else
                    "While authentication is enforced, the presence of this admin interface "
                    "on an internet-facing host increases attack surface. "
                )
                + (
                    "This endpoint provides deployment control, configuration access, "
                    "and platform management capabilities. Exposure to the internet is "
                    "a severe security misconfiguration."
                    if is_critical else ""
                )
            ),
            evidence=(
                f"URL: {url}\n"
                f"HTTP status: {status}\n"
                f"Content length: {content_length}\n"
                f"Body preview: {truncate(body, 200)}"
            ),
            request_data=self._request_summary("GET", url),
            response_data={
                "status":   status,
                "headers":  dict(resp.headers),
                "body":     truncate(body, 500),
            },
            remediation=(
                "Restrict access to OutSystems management tools (ServiceCenter, LifeTime, Users) "
                "via network firewall to trusted IP ranges only. "
                "These tools should NEVER be accessible from the internet. "
                "Reference: OutSystems network requirements documentation."
            ),
            cwe="CWE-284",
            references=REFERENCES,
        )

        return {
            "path":       path,
            "url":        url,
            "accessible": accessible,
            "severity":   sev,
            "body":       body,
            "status":     status,
        }

    # ─── Default credential testing ───────────────────────────────────────────

    def _test_default_credentials(self, path: str, access_result: dict) -> None:
        """
        Test default OutSystems credentials against the identified login endpoint.
        Only runs if the admin panel is directly accessible (HTTP 200).
        """
        if not access_result.get("accessible"):
            return

        # Determine login URL
        if "servicecenter" in path.lower():
            login_url = self.tester.base_url + "/ServiceCenter/Login.aspx"
        elif "lifetime" in path.lower():
            login_url = self.tester.base_url + "/LifeTime/Login.aspx"
        elif "users" in path.lower():
            login_url = self.tester.base_url + "/Users/Login.aspx"
        else:
            return

        msg_info(f"  Testing default credentials for {path}...")

        for username, password in DEFAULT_CREDENTIALS:
            if self._try_login(login_url, username, password):
                msg_vuln(
                    "critical",
                    f"Default credentials work: {username}/{password}",
                    f"on {path}",
                )
                self.finding(
                    severity="critical",
                    title=(
                        f"Default credentials valid: {username}/{password} "
                        f"on {path}"
                    ),
                    description=(
                        f"The OutSystems default credentials username='{username}' / "
                        f"password='{password}' are valid on {login_url}. "
                        "An attacker can log in with full administrative access to the "
                        "OutSystems platform."
                    ),
                    evidence=(
                        f"Login URL: {login_url}\n"
                        f"Credentials: {username} / {password}\n"
                        f"Result: Authentication successful"
                    ),
                    remediation=(
                        "IMMEDIATE: Change all default OutSystems passwords. "
                        "Disable or delete default accounts that are not in use. "
                        "Apply strong password policies. "
                        "Restrict access to admin consoles via network controls."
                    ),
                    cwe="CWE-1392",
                    references=[
                        "https://cwe.mitre.org/data/definitions/1392.html",
                        "https://success.outsystems.com/Documentation/11/Setting_Up_OutSystems/",
                    ],
                )
                return  # One confirmed cred is enough

    def _try_login(self, login_url: str, username: str, password: str) -> bool:
        """
        Attempt to authenticate to an OutSystems login page.
        Returns True if login appears successful.
        """
        # First, get the login page to extract any required tokens
        resp = self.tester.get(login_url)
        if resp is None or resp.status_code != 200:
            return False

        html = resp.text or ""

        # Extract VIEWSTATE and EventValidation (ASP.NET WebForms)
        viewstate = self._extract_hidden_field(html, "__VIEWSTATE")
        event_val = self._extract_hidden_field(html, "__EVENTVALIDATION")
        viewstate_gen = self._extract_hidden_field(html, "__VIEWSTATEGENERATOR")

        # Extract CSRF if present
        csrf = self.tester._get_csrf_token()

        # Build POST body — OutSystems ServiceCenter uses ASP.NET form
        data = {
            "__EVENTTARGET":       "",
            "__EVENTARGUMENT":     "",
            "__VIEWSTATE":         viewstate,
            "__VIEWSTATEGENERATOR": viewstate_gen,
            "__EVENTVALIDATION":   event_val,
            "Username":            username,
            "Password":            password,
            "Login":               "Login",
        }
        if csrf:
            data["__RequestVerificationToken"] = csrf

        post_resp = self.tester.post(
            login_url,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": login_url,
            },
            allow_redirects=True,
        )
        if post_resp is None:
            return False

        # Success indicators:
        # - Redirect to a non-login page
        # - Response contains user-specific content
        # - No error message in response
        body = post_resp.text or ""
        fail_signals = [
            "invalid username",
            "invalid password",
            "incorrect password",
            "login failed",
            "authentication failed",
            "Username or password incorrect",
        ]
        if any(sig.lower() in body.lower() for sig in fail_signals):
            return False

        success_signals = [
            "Logout",
            "logout",
            "ApplicationList",
            "ServiceCenter/Default",
            "Welcome,",
        ]
        return any(sig in body for sig in success_signals)

    def _extract_hidden_field(self, html: str, field_name: str) -> str:
        """Extract a hidden form field value from HTML."""
        pattern = (
            r'<input[^>]+name=["\']' + re.escape(field_name) + r'["\']'
            r'[^>]+value=["\']([^"\']*)["\']'
        )
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)
        # Try reverse attribute order
        pattern2 = (
            r'<input[^>]+value=["\']([^"\']*)["\']'
            r'[^>]+name=["\']' + re.escape(field_name) + r'["\']'
        )
        m2 = re.search(pattern2, html, re.IGNORECASE)
        return m2.group(1) if m2 else ""

    # ─── OIDC / IdP exposure ──────────────────────────────────────────────────

    def _check_oidc_exposure(self) -> None:
        """Check for exposed OIDC/OAuth configuration endpoints."""
        subsection("OIDC/IdP Exposure")
        for path in OIDC_PATHS:
            url = self.tester.base_url + path
            resp = self.tester.get(url)
            if resp is None:
                continue
            if resp.status_code == 200:
                body = resp.text or ""
                # Check if it's a real OIDC configuration
                if (
                    '"issuer"' in body
                    or '"authorization_endpoint"' in body
                    or '"jwks_uri"' in body
                ):
                    msg_warn(f"  OIDC configuration exposed: {url}")
                    self._analyze_oidc_config(url, body)

    def _analyze_oidc_config(self, url: str, body: str) -> None:
        """Analyze exposed OIDC configuration for security issues."""
        import json as _json
        config = {}
        try:
            config = _json.loads(body)
        except Exception:
            pass

        issues = []
        # Check for sensitive OIDC config details
        if config.get("client_secret"):
            issues.append("client_secret exposed in config")
        if config.get("private_key"):
            issues.append("private_key exposed in config")

        # Check for insecure grant types
        grant_types = config.get("grant_types_supported", [])
        if "password" in grant_types:
            issues.append("password grant type enabled (deprecated/insecure)")
        if "implicit" in grant_types:
            issues.append("implicit grant type enabled (deprecated)")

        severity = "critical" if issues else "medium"
        self.finding(
            severity=severity,
            title=f"OIDC configuration endpoint exposed: {url}",
            description=(
                f"OutSystems OIDC/OAuth configuration is publicly accessible at {url}. "
                + (f"Security issues: {', '.join(issues)}. " if issues else "")
                + "This reveals identity provider configuration, endpoints, and "
                "supported grant types to unauthenticated users."
            ),
            evidence=truncate(body, 600),
            request_data=self._request_summary("GET", url),
            remediation=(
                "Restrict OIDC configuration endpoints to authorized consumers only. "
                "Remove sensitive configuration values from public endpoints. "
                "Disable deprecated grant types (password, implicit)."
            ),
            cwe="CWE-284",
            references=REFERENCES + [
                "https://datatracker.ietf.org/doc/html/rfc6749",
            ],
        )

    # ─── Environment detection ────────────────────────────────────────────────

    def _detect_environment(self) -> None:
        """
        Determine if this appears to be a Production, QA, Dev, or PreProd environment.
        Based on URL patterns, response headers, and ServiceCenter content.
        """
        url = self.tester.target_url.lower()
        env_type = "Unknown"
        confidence = "low"

        # URL-based detection
        if any(kw in url for kw in ("prod", "production", "live")):
            env_type = "Production"
            confidence = "high"
        elif any(kw in url for kw in ("dev", "desa", "desarrollo", "develop")):
            env_type = "Development"
            confidence = "high"
        elif any(kw in url for kw in ("qa", "test", "uat", "staging", "stage")):
            env_type = "QA/Staging"
            confidence = "high"
        elif any(kw in url for kw in ("preprod", "pre-prod", "pre.")):
            env_type = "Pre-Production"
            confidence = "high"
        else:
            # Try ServiceCenter environment info
            sc_url = self.tester.base_url + "/ServiceCenter"
            resp = self.tester.get(sc_url)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                env_match = re.search(
                    r'Environment\s*(?:Name|Type)?\s*[:\-]\s*([A-Za-z][A-Za-z0-9\s_-]{2,30})',
                    body,
                )
                if env_match:
                    env_type = env_match.group(1).strip()
                    confidence = "medium"

        self.finding(
            severity="info",
            title=f"Environment type: {env_type} (confidence: {confidence})",
            description=(
                f"The target appears to be a {env_type} OutSystems environment "
                f"(detection confidence: {confidence})."
                + (
                    " Production environment exposure of management consoles "
                    "is a critical security risk."
                    if env_type == "Production" else ""
                )
            ),
            evidence=f"URL: {self.tester.target_url}, Environment: {env_type}",
            cwe="CWE-200",
        )

        if env_type == "Production":
            msg_warn("  PRODUCTION environment detected — all findings are HIGH impact")

    # ─── User enumeration ─────────────────────────────────────────────────────

    def _test_user_enumeration(self) -> None:
        """
        Test if the Users module login response differs between
        valid and invalid usernames (user enumeration).
        """
        login_url = self.tester.base_url + "/Users/Login.aspx"
        resp = self.tester.get(login_url)
        if resp is None or resp.status_code != 200:
            return

        html = resp.text or ""

        # Attempt with known-invalid username
        viewstate = self._extract_hidden_field(html, "__VIEWSTATE")
        event_val = self._extract_hidden_field(html, "__EVENTVALIDATION")

        fake_user_resp = self.tester.post(
            login_url,
            data={
                "__VIEWSTATE": viewstate,
                "__EVENTVALIDATION": event_val,
                "Username": "nonexistent_user_abc123xyz",
                "Password": "wrongpassword",
                "Login": "Login",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        admin_user_resp = self.tester.post(
            login_url,
            data={
                "__VIEWSTATE": viewstate,
                "__EVENTVALIDATION": event_val,
                "Username": "admin",
                "Password": "wrongpassword",
                "Login": "Login",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if fake_user_resp is None or admin_user_resp is None:
            return

        # Compare responses — different messages = user enumeration possible
        fake_body  = fake_user_resp.text or ""
        admin_body = admin_user_resp.text or ""

        user_enum_patterns = [
            ("user not found", "user does not exist"),
            ("invalid user", "invalid password"),
            ("no account", "wrong password"),
        ]
        for fake_kw, admin_kw in user_enum_patterns:
            if fake_kw.lower() in fake_body.lower() and fake_kw.lower() not in admin_body.lower():
                self.finding(
                    severity="low",
                    title="User enumeration possible via Users module login",
                    description=(
                        "The OutSystems Users module login page returns different error "
                        "messages for non-existent vs existing usernames. "
                        "This allows enumeration of valid usernames."
                    ),
                    evidence=(
                        f"Non-existent user response: ...{fake_body[100:300]}...\n"
                        f"Existing user response: ...{admin_body[100:300]}..."
                    ),
                    remediation=(
                        "Return a uniform 'Invalid username or password' message "
                        "regardless of whether the username exists."
                    ),
                    cwe="CWE-204",
                    references=["https://cwe.mitre.org/data/definitions/204.html"],
                )
                return

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _is_outsystems_page(self, body: str) -> bool:
        """Check if an HTML body looks like an OutSystems page."""
        os_signals = [
            "outsystems", "ServiceCenter", "LifeTime",
            "OutSystems", "_osBlock", "OSController",
        ]
        body_lower = body[:3000].lower()
        return any(sig.lower() in body_lower for sig in os_signals)

    def _extract_sc_version(self, body: str) -> str | None:
        """Extract version from ServiceCenter HTML."""
        patterns = [
            r"Platform Server\s+([0-9]+\.[0-9]+\.[0-9.]+)",
            r"OutSystems\s+([0-9]+\.[0-9]+\.[0-9.]+)",
            r"Version\s*:\s*([0-9]+\.[0-9]+\.[0-9.]+)",
        ]
        for pat in patterns:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _extract_hidden_field(self, html: str, field_name: str) -> str:
        """Extract a hidden ASP.NET form field."""
        pattern = (
            r'<input[^>]+name=["\']' + re.escape(field_name) + r'["\']'
            r'[^>]+value=["\']([^"\']*)["\']'
        )
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)
        pattern2 = (
            r'<input[^>]+value=["\']([^"\']*)["\']'
            r'[^>]+name=["\']' + re.escape(field_name) + r'["\']'
        )
        m2 = re.search(pattern2, html, re.IGNORECASE)
        return m2.group(1) if m2 else ""
