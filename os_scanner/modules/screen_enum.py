"""
ScreenEnumModule — OutSystems Screen and Server Action Enumeration

Tests:
1. Screen name discovery via HTML/JS parsing and common patterns
2. Server action enumeration via screenservice probing
3. Input parameter discovery from error responses
4. REST API endpoint detection and authentication testing
"""
import re
import json
import urllib.parse

from ..core import (
    BaseModule, OutSystemsTester, is_json_response,
    response_has_data, truncate,
)
from ..colors import (
    msg_ok, msg_fail, msg_info, msg_warn,
    msg_vuln, subsection, progress_bar,
)
from ..data.os_common import (
    COMMON_MODULES, ANONYMOUS_SCREENS, COMMON_ACTIONS,
    REST_API_PATHS, INTERESTING_STATUS_CODES,
)

REFERENCES = [
    "https://cwe.mitre.org/data/definitions/200.html",
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "https://success.outsystems.com/Documentation/11/Developing_an_Application/Secure_the_Application/",
]


class ScreenEnumModule(BaseModule):
    NAME        = "screen_enum"
    DESCRIPTION = "Screen and server action enumeration via screenservice probing"

    def run(self) -> None:
        subsection("Screen & Server Action Enumeration")

        modules_to_test = self._get_target_modules()
        if not modules_to_test:
            msg_info("No modules to enumerate — run fingerprint first")
            return

        for module in modules_to_test:
            msg_info(f"Enumerating: {module}")
            self._enumerate_module(module)

        # REST API discovery across all modules
        self._discover_rest_apis()

    # ─── Per-module enumeration ───────────────────────────────────────────────

    def _enumerate_module(self, module: str) -> None:
        # 1. Fetch the module's main page and parse screens
        screens = self._discover_screens(module)

        # 2. Enumerate server actions (unauthenticated probe)
        self._enumerate_server_actions(module)

        # 3. Error message analysis — what do screenservice errors reveal?
        self._analyze_error_messages(module)

    def _discover_screens(self, module: str) -> list[str]:
        """
        Discover screen names for a module via:
        a) HTML links in the module's main page
        b) JavaScript routing patterns
        c) Common screen name patterns
        """
        screens = set()

        # Fetch main module page
        url = f"{self.tester.base_url}/{module}/"
        resp = self.tester.get(url)
        if resp is None or resp.status_code not in (200, 302):
            return []

        html = resp.text or ""
        self.tester.extract_csrf_from_html(html)

        # Parse <a href> and <form action> links
        for m in re.finditer(
            r'(?:href|action)=["\'][^"\']*[/.]([A-Za-z][A-Za-z0-9_]{2,50})(?:["\'/\?#])',
            html,
            re.IGNORECASE,
        ):
            candidate = m.group(1)
            if candidate.lower() not in (
                "css", "js", "png", "jpg", "gif", "ico", "aspx", "html",
                "htm", "php", "json", "xml", "txt",
            ):
                screens.add(candidate)

        # Parse JavaScript router patterns — OutSystems uses these
        for m in re.finditer(
            r'["\'](?:' + module + r'\.)?([A-Z][A-Za-z0-9_]{2,50})["\']'
            r'\s*(?:,|\)|:|\})\s*(?://.*)?$',
            html,
            re.MULTILINE,
        ):
            screens.add(m.group(1))

        # Parse OutSystems-specific screen references
        for m in re.finditer(
            r'data-screen=["\']([A-Za-z][A-Za-z0-9_.]{2,60})["\']',
            html,
        ):
            screens.add(m.group(1))

        # Add screens discovered by other modules (viewname_bypass)
        existing = self.tester.os_screens.get(module, [])
        screens.update(existing)

        # Store in tester state
        if module not in self.tester.os_screens:
            self.tester.os_screens[module] = []
        for s in screens:
            if s not in self.tester.os_screens[module]:
                self.tester.os_screens[module].append(s)

        if screens:
            msg_ok(f"  Screens discovered: {', '.join(sorted(screens)[:10])}"
                   + (" ..." if len(screens) > 10 else ""))
            self.finding(
                severity="info",
                title=f"Screens enumerated in module {module}: {len(screens)} screens",
                description=(
                    f"The following screen names were enumerated for module '{module}': "
                    f"{', '.join(sorted(screens)[:20])}."
                ),
                evidence=f"Screens: {', '.join(sorted(screens))}",
                cwe="CWE-200",
            )

        return list(screens)

    def _enumerate_server_actions(self, module: str) -> None:
        """
        Enumerate server actions by probing the screenservice endpoint.
        Response codes reveal existence:
        - 404: action does not exist
        - 400/422: action exists, parameter error
        - 401/403: action exists, auth required
        - 200: action accessible
        - 500: action exists, server error (possibly verbose)
        """
        confirmed_actions = []
        auth_required_actions = []
        error_actions = []
        total = len(COMMON_ACTIONS)

        msg_info(f"  Probing {total} common server actions in {module}...")

        for i, action in enumerate(COMMON_ACTIONS):
            progress_bar(i + 1, total, label=action[:25], width=20)
            resp = self.tester.post(
                f"{self.tester.base_url}/{module}/screenservices/{module}/{action}",
                json={
                    "versionInfo": {"moduleVersion": "", "apiVersion": "1"},
                    "viewName": "",
                    "inputParameters": {},
                },
                headers={"Content-Type": "application/json"},
            )
            if resp is None:
                continue

            status = resp.status_code
            body   = resp.text or ""

            if status == 404:
                continue  # not found

            elif status in (400, 422):
                # Parameter error — action exists, validation running
                param_info = self._extract_param_info(body)
                confirmed_actions.append({
                    "action":     action,
                    "status":     status,
                    "params":     param_info,
                    "evidence":   truncate(body, 300),
                })

            elif status in (401, 403):
                # Auth enforced — action exists but properly protected
                auth_required_actions.append(action)

            elif status == 200:
                # Action accessible (may or may not return data)
                confirmed_actions.append({
                    "action":   action,
                    "status":   200,
                    "params":   [],
                    "evidence": truncate(body, 300),
                })

            elif status == 500:
                # Server error — might reveal stack traces
                stack_trace = self._check_for_stack_trace(body)
                error_actions.append({
                    "action":      action,
                    "status":      500,
                    "stack_trace": stack_trace,
                    "evidence":    truncate(body, 300),
                })

        print()  # newline after progress bar

        # Store enumerated actions
        if module not in self.tester.os_server_actions:
            self.tester.os_server_actions[module] = []
        for a in confirmed_actions:
            if a["action"] not in self.tester.os_server_actions[module]:
                self.tester.os_server_actions[module].append(a["action"])

        # Report
        if confirmed_actions:
            action_list = ", ".join(a["action"] for a in confirmed_actions)
            msg_ok(f"  {len(confirmed_actions)} server actions confirmed in {module}")
            self.finding(
                severity="medium",
                title=f"Server actions enumerated in module {module}: {len(confirmed_actions)} actions",
                description=(
                    f"The following server actions were confirmed to exist in module "
                    f"'{module}' via screenservice probing: {action_list}. "
                    "Action existence disclosure enables targeted attack planning. "
                    "Actions returning HTTP 400/422 reveal parameter expectations."
                ),
                evidence=(
                    f"Confirmed actions: {action_list}\n"
                    f"Sample parameter info: "
                    f"{confirmed_actions[0]['params'] if confirmed_actions[0]['params'] else 'N/A'}"
                ),
                remediation=(
                    "Return a uniform 404 for non-existent and unauthorized actions "
                    "to prevent enumeration. "
                    "Do not disclose whether an action exists before checking authorization."
                ),
                cwe="CWE-200",
                references=REFERENCES,
            )

        if error_actions:
            for err in error_actions:
                if err["stack_trace"]:
                    msg_vuln("medium", f"Stack trace in {module}/{err['action']} response")
                    self.finding(
                        severity="medium",
                        title=f"Stack trace disclosed in {module}/{err['action']} error response",
                        description=(
                            f"Server action '{err['action']}' in module '{module}' returns "
                            "an HTTP 500 error with a full .NET stack trace. "
                            "Stack traces reveal internal file paths, class names, and "
                            "framework versions that aid attack planning."
                        ),
                        evidence=truncate(err["stack_trace"], 500),
                        remediation=(
                            "Configure OutSystems to return generic error messages in production. "
                            "Disable debug mode. Set customErrors mode='On' in Web.config."
                        ),
                        cwe="CWE-209",
                        references=["https://cwe.mitre.org/data/definitions/209.html"],
                    )

    def _analyze_error_messages(self, module: str) -> None:
        """
        Test for information disclosure in screenservice error messages.
        OutSystems error responses can reveal action names, parameter types,
        and internal paths.
        """
        # Test with an obviously wrong payload to trigger verbose errors
        test_url = (
            f"{self.tester.base_url}/{module}/screenservices/{module}/"
            "GetUsers"  # common action name
        )
        resp = self.tester.post(
            test_url,
            json={"invalid_key": "invalid_value"},
            headers={"Content-Type": "application/json"},
        )
        if resp is None:
            return

        body = resp.text or ""
        if resp.status_code == 500 and len(body) > 100:
            # Check for internal path disclosure
            path_patterns = [
                r"C:\\[^<\n\"']+\\[^<\n\"']+\.(?:cs|aspx|config|dll)",
                r"/(?:inetpub|var|opt|home)/[^\s<\"']{5,80}",
                r"at\s+\w+(?:\.\w+)+\s+in\s+[^\n]+\.cs",
                r"OutSystems\.[A-Z][a-zA-Z.]+Exception",
            ]
            for pattern in path_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self.finding(
                        severity="low",
                        title=f"Internal path/class disclosure in {module} error response",
                        description=(
                            f"Error responses from module '{module}' screenservice endpoint "
                            "disclose internal file paths, class names, or OutSystems exception "
                            "types. This information aids attack planning and reconnaissance."
                        ),
                        evidence=truncate(body, 400),
                        remediation=(
                            "Configure OutSystems platform to suppress verbose error information. "
                            "Enable custom error pages in the OutSystems Service Center."
                        ),
                        cwe="CWE-209",
                        references=["https://cwe.mitre.org/data/definitions/209.html"],
                    )
                    break

    # ─── REST API discovery ───────────────────────────────────────────────────

    def _discover_rest_apis(self) -> None:
        """
        Discover OutSystems REST API endpoints across all known modules.
        Check for Swagger/OpenAPI spec exposure.
        """
        subsection("REST API Discovery")
        modules = self.tester.os_modules or COMMON_MODULES[:10]
        rest_found = []

        for module in modules:
            for path_template in REST_API_PATHS:
                url = f"{self.tester.base_url}/{module}{path_template}"
                resp = self.tester.get(url)
                if resp is None:
                    continue

                if resp.status_code in (200, 401, 403):
                    rest_found.append({
                        "module": module,
                        "url":    url,
                        "status": resp.status_code,
                        "auth":   resp.status_code in (401, 403),
                    })

                    if resp.status_code == 200:
                        msg_warn(f"  REST API accessible (no auth): {url}")
                        self._check_rest_endpoint(module, url, resp)

        # Check for OpenAPI specs
        self._check_openapi_specs(modules)

        if rest_found:
            unauthed = [r for r in rest_found if not r["auth"]]
            if unauthed:
                urls = ", ".join(r["url"] for r in unauthed[:5])
                self.finding(
                    severity="high",
                    title=f"Unauthenticated REST API endpoints found: {len(unauthed)}",
                    description=(
                        f"{len(unauthed)} REST API endpoints are accessible without "
                        f"authentication: {urls}."
                    ),
                    evidence=f"Unauthenticated endpoints: {urls}",
                    remediation=(
                        "Apply authentication to all OutSystems REST API methods. "
                        "Use the 'Authentication' property in OutSystems Service Studio "
                        "to require authentication on REST APIs."
                    ),
                    cwe="CWE-284",
                    references=REFERENCES,
                )

    def _check_rest_endpoint(self, module: str, url: str, resp) -> None:
        """Analyze a REST endpoint response for sensitive data."""
        from ..core import contains_pii
        body = resp.text or ""
        pii = contains_pii(body)
        if pii:
            self.finding(
                severity="critical",
                title=f"Unauthenticated REST API exposes sensitive data: {url}",
                description=(
                    f"The REST API endpoint {url} is accessible without authentication "
                    f"and returns sensitive data: {', '.join(pii)}."
                ),
                evidence=truncate(body, 400),
                remediation=(
                    "IMMEDIATE: Enable authentication on this REST API endpoint. "
                    "Review all REST API methods for authentication requirements."
                ),
                cwe="CWE-284",
                references=REFERENCES,
            )

    def _check_openapi_specs(self, modules: list[str]) -> None:
        """Check for exposed Swagger/OpenAPI specifications."""
        swagger_paths = [
            "/{module}/rest/swagger",
            "/{module}/rest/swagger.json",
            "/{module}/rest/openapi.json",
            "/{module}/rest/v1/swagger",
            "/{module}/api/swagger",
            "/{module}/api-docs",
        ]
        for module in modules[:10]:
            for path_template in swagger_paths:
                url = self.tester.base_url + path_template.replace("{module}", module)
                resp = self.tester.get(url)
                if resp and resp.status_code == 200:
                    body = resp.text or ""
                    if (
                        '"swagger"' in body or '"openapi"' in body
                        or "swaggerVersion" in body
                    ):
                        msg_warn(f"OpenAPI/Swagger spec exposed: {url}")
                        self.finding(
                            severity="medium",
                            title=f"OpenAPI/Swagger spec exposed: {url}",
                            description=(
                                f"An OpenAPI/Swagger specification is exposed at {url} "
                                "without authentication. This provides a complete map of "
                                "all API endpoints, methods, parameters, and data structures "
                                "to an attacker."
                            ),
                            evidence=truncate(body, 500),
                            remediation=(
                                "Restrict access to API documentation in production environments. "
                                "Apply authentication to Swagger/OpenAPI spec endpoints."
                            ),
                            cwe="CWE-200",
                            references=REFERENCES,
                        )

    # ─── Parsing helpers ──────────────────────────────────────────────────────

    def _extract_param_info(self, body: str) -> list[str]:
        """
        Extract parameter names from error responses.
        OutSystems validation errors often mention missing/invalid parameters.
        """
        params = []
        patterns = [
            r'"parameter"\s*:\s*"([^"]{1,60})"',
            r'"field"\s*:\s*"([^"]{1,60})"',
            r'"property"\s*:\s*"([^"]{1,60})"',
            r"parameter\s+'([A-Za-z][A-Za-z0-9_]{1,40})'",
            r"required\s+(?:input\s+)?parameter\s+([A-Za-z][A-Za-z0-9_]{1,40})",
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, body, re.IGNORECASE):
                param = m.group(1)
                if param not in params:
                    params.append(param)
        return params[:10]

    def _check_for_stack_trace(self, body: str) -> str | None:
        """Extract and return a stack trace from an error response body."""
        patterns = [
            r"at\s+\w+(?:\.\w+)+\s*\(",
            r"System\.Web\.",
            r"OutSystems\.[A-Z][a-zA-Z.]+Exception",
            r"Server Error in '[^']*' Application",
        ]
        for pattern in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 50)
                return body[start:start + 500]
        return None

    def _get_target_modules(self) -> list[str]:
        if self.options.get("module_name"):
            return [self.options["module_name"]]
        if self.tester.os_modules:
            return self.tester.os_modules
        return COMMON_MODULES[:10]
