"""
FingerprintModule — Detect and identify the OutSystems platform.

Checks:
1. Platform detection via headers, cookies, HTML, JavaScript patterns
2. Version extraction from multiple sources
3. Server stack identification (IIS/.NET, Java)
4. Platform type: OutSystems 11, ODC, LifeTime, ServiceCenter
5. Module / application discovery
"""
import re
import time
import urllib.parse

from ..core import BaseModule, OutSystemsTester, truncate
from ..colors import (
    msg_ok, msg_fail, msg_info, msg_warn, msg_debug,
    subsection, progress_bar,
)
from ..data.os_common import (
    OS_FINGERPRINTS, COMMON_MODULES, VERSION_PATTERNS,
    SERVICE_CENTER_PATHS, INTERNAL_MODULES,
)


class FingerprintModule(BaseModule):
    NAME        = "fingerprint"
    DESCRIPTION = "Detect and fingerprint the OutSystems platform"

    def run(self) -> None:
        subsection("Fingerprint — Platform Detection")

        # 1. Fetch the target URL
        resp = self.tester.get(self.tester.target_url)
        if resp is None:
            self.finding(
                severity="info",
                title="Target unreachable",
                description="Could not connect to the target URL.",
                evidence=self.tester.target_url,
                remediation="Verify the URL is correct and the host is reachable.",
                cwe="",
            )
            msg_fail(f"Cannot reach {self.tester.target_url}")
            return

        # 2. Platform detection
        confidence, signals = self._detect_outsystems(resp)
        self._log(f"Platform confidence: {confidence}, signals: {signals}")

        if confidence == 0:
            msg_info("No OutSystems signatures detected — may not be an OutSystems platform")
            self.finding(
                severity="info",
                title="OutSystems platform not detected",
                description=(
                    "No OutSystems-specific headers, cookies, or HTML patterns "
                    "were found in the target response. The target may not be running "
                    "OutSystems or it may be heavily customized."
                ),
                evidence=f"HTTP {resp.status_code} — no OS signatures in response",
                cwe="",
            )
            return

        # Confirmed or partial detection
        self.tester.os_platform = self._classify_platform(resp)
        msg_ok(f"OutSystems platform detected (confidence: {confidence}/10, signals: {len(signals)})")
        for sig in signals:
            self._log(f"  signal: {sig}")

        self.finding(
            severity="info",
            title="OutSystems platform identified",
            description=(
                f"Target is running OutSystems Platform. "
                f"Platform type: {self.tester.os_platform}. "
                f"Detection confidence: {confidence}/10."
            ),
            evidence=f"Signals: {'; '.join(signals[:8])}",
            request_data=self._request_summary("GET", self.tester.target_url),
            response_data={
                "status":  resp.status_code,
                "headers": dict(resp.headers),
                "signals": signals,
            },
            cwe="CWE-200",
        )

        # 3. Version detection
        version = self._detect_version(resp)
        if version:
            self.tester.os_version = version
            msg_ok(f"OutSystems version: {version}")
            self.finding(
                severity="info",
                title=f"OutSystems version disclosed: {version}",
                description=(
                    f"The OutSystems platform version ({version}) is disclosed in the "
                    "response. This enables targeted vulnerability research against "
                    "known version-specific issues."
                ),
                evidence=f"Detected version: {version}",
                remediation=(
                    "Remove version information from HTTP headers, HTML comments, "
                    "and JavaScript files. Update to the latest OutSystems platform version."
                ),
                cwe="CWE-200",
                references=[
                    "https://success.outsystems.com/Support/Release_Notes",
                ],
            )
        else:
            msg_info("OutSystems version not disclosed")

        # 4. Server stack
        self._detect_server_stack(resp)

        # 5. Module discovery
        self._discover_modules(resp)

        # 6. CSRF token extraction (useful for later modules)
        self.tester.extract_csrf_from_html(resp.text or "")

    # ─── Detection helpers ────────────────────────────────────────────────────

    def _detect_outsystems(self, resp) -> tuple[int, list[str]]:
        """
        Score OutSystems presence based on multiple signals.
        Returns (confidence 0-10, list of matched signals).
        """
        score = 0
        signals = []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        text = resp.text or ""
        cookies = [c.lower() for c in self.tester.session.cookies.keys()]

        # Check headers
        for hdr_name, hdr_value in OS_FINGERPRINTS["headers"]:
            val = headers.get(hdr_name.lower(), "")
            if hdr_value == "" and val:
                score += 2
                signals.append(f"Header: {hdr_name}: {val}")
            elif hdr_value and hdr_value.lower() in val.lower():
                score += 1
                signals.append(f"Header: {hdr_name}: {val}")

        # Check cookies
        for cookie_name in OS_FINGERPRINTS["cookies"]:
            if any(cookie_name.lower() in c for c in cookies):
                score += 2
                signals.append(f"Cookie: {cookie_name}")

        # Check HTML patterns
        for pattern in OS_FINGERPRINTS["html_patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                score += 1
                signals.append(f"HTML pattern: {pattern}")

        # Check JS patterns
        for pattern in OS_FINGERPRINTS["js_patterns"]:
            if re.search(pattern, text, re.IGNORECASE):
                score += 1
                signals.append(f"JS pattern: {pattern}")

        # Check URL path patterns
        for path in OS_FINGERPRINTS["url_patterns"]:
            if path in (resp.url or ""):
                score += 1
                signals.append(f"URL pattern: {path}")

        # Probe known OS paths (ServiceCenter, Users, LifeTime)
        for path in OS_FINGERPRINTS["path_probes"]:
            probe_url = self.tester.base_url + path
            probe = self.tester.head(probe_url)
            if probe and probe.status_code in (200, 302, 401, 403):
                score += 2
                signals.append(f"Path probe: {path} -> HTTP {probe.status_code}")

        return min(score, 10), signals

    def _classify_platform(self, resp) -> str:
        """
        Determine OutSystems platform variant from URL and response content.
        """
        url = self.tester.target_url.lower()
        text = (resp.text or "").lower()

        # OutSystems Developer Cloud
        if "outsystems.app" in url or "cloud.outsystems.com" in url:
            return "ODC"

        # LifeTime management console
        if "/lifetime" in url or "lifetime" in text[:2000]:
            return "LifeTime"

        # ServiceCenter
        if "/servicecenter" in url or "servicecenter" in text[:1000]:
            return "ServiceCenter"

        # Traditional OutSystems 11
        if re.search(r"platform server\s+11|outsystems\s+11", text, re.IGNORECASE):
            return "11"

        return "11"  # Default assumption

    def _detect_version(self, resp) -> str | None:
        """
        Extract version string from response headers, HTML, and JavaScript.
        Also probes /ServiceCenter for version information.
        """
        sources = [resp.text or ""]

        # Check response headers
        for hdr in ("X-OutSystems-Version", "X-Powered-By", "Server"):
            val = resp.headers.get(hdr, "")
            if val:
                sources.append(val)

        # Probe ServiceCenter for version
        sc_url = self.tester.base_url + "/ServiceCenter"
        sc_resp = self.tester.get(sc_url)
        if sc_resp and sc_resp.status_code in (200, 302):
            sources.append(sc_resp.text or "")

        # Try JS files referenced in page
        for js_url in self._extract_js_urls(resp):
            js_resp = self.tester.get(js_url)
            if js_resp and js_resp.status_code == 200:
                sources.append(js_resp.text or "")

        # Apply version patterns to all sources
        for source in sources:
            for pattern, group in VERSION_PATTERNS:
                m = re.search(pattern, source, re.IGNORECASE)
                if m:
                    return m.group(group)
        return None

    def _detect_server_stack(self, resp) -> None:
        """Detect the underlying server stack and set tester.os_server_type."""
        headers = resp.headers

        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")
        aspnet = headers.get("X-AspNet-Version", "")

        if "Microsoft-IIS" in server:
            self.tester.os_server_type = "IIS"
            msg_ok(f"Server stack: IIS ({server})")
            self.finding(
                severity="info",
                title=f"Server disclosure: {server}",
                description=(
                    f"The web server version is disclosed in the Server header: {server}. "
                    "This enables targeted research against known IIS vulnerabilities."
                ),
                evidence=f"Server: {server}",
                remediation="Configure IIS to suppress the Server header.",
                cwe="CWE-200",
            )

        elif "nginx" in server.lower():
            self.tester.os_server_type = "nginx"
            msg_ok(f"Server stack: nginx ({server})")

        elif "apache" in server.lower():
            self.tester.os_server_type = "Apache"
            msg_ok(f"Server stack: Apache ({server}) — possibly Java stack")

        if x_powered:
            msg_info(f"X-Powered-By: {x_powered}")

        if aspnet:
            msg_info(f"ASP.NET version: {aspnet}")
            self.finding(
                severity="low",
                title=f"ASP.NET version disclosed: {aspnet}",
                description=(
                    f"The ASP.NET framework version ({aspnet}) is disclosed via "
                    "X-AspNet-Version header. Known vulnerabilities exist for specific versions."
                ),
                evidence=f"X-AspNet-Version: {aspnet}",
                remediation=(
                    'Set <httpRuntime enableVersionHeader="false"/> in Web.config '
                    "and configure the Server header to be suppressed."
                ),
                cwe="CWE-200",
                references=[
                    "https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/web/httpruntime-element"
                ],
            )

    def _discover_modules(self, resp) -> None:
        """
        Discover deployed OutSystems modules / applications.
        Sources:
        - Links in the landing page HTML
        - ServiceCenter ApplicationList.aspx (if accessible)
        - Brute-force common module names
        """
        subsection("Module Discovery")
        found_modules = set()

        # 1. Parse links from the landing page
        html = resp.text or ""
        for m in re.finditer(
            r'href=["\'](?:https?://[^"\']*)?/([A-Za-z][A-Za-z0-9_]{2,40})/[^"\']*["\']',
            html
        ):
            candidate = m.group(1)
            if candidate not in (
                "css", "js", "img", "images", "static", "assets",
                "fonts", "icons", "scripts", "content",
            ):
                found_modules.add(candidate)

        # 2. ServiceCenter ApplicationList.aspx
        sc_list_url = self.tester.base_url + "/ServiceCenter/ApplicationList.aspx"
        sc_resp = self.tester.get(sc_list_url)
        if sc_resp and sc_resp.status_code == 200:
            msg_warn("ServiceCenter ApplicationList accessible — UNAUTHENTICATED")
            for m in re.finditer(r'/(\w+)/[^"\']*\.aspx', sc_resp.text or ""):
                found_modules.add(m.group(1))

        # 3. Brute-force common module names
        total = len(COMMON_MODULES)
        msg_info(f"Probing {total} common module names...")

        for i, mod in enumerate(COMMON_MODULES):
            progress_bar(i + 1, total, label=mod, width=25)
            url = f"{self.tester.base_url}/{mod}/"
            probe = self.tester.get(url)
            if probe and probe.status_code in (200, 302, 401, 403):
                found_modules.add(mod)
                self._log(f"  found module: {mod} -> HTTP {probe.status_code}")

        print()  # newline after progress bar

        # Register found modules
        for mod in sorted(found_modules):
            if mod not in self.tester.os_modules:
                self.tester.os_modules.append(mod)

        if self.tester.os_modules:
            msg_ok(f"Discovered {len(self.tester.os_modules)} module(s): "
                   f"{', '.join(self.tester.os_modules[:10])}"
                   + (" ..." if len(self.tester.os_modules) > 10 else ""))

            # Flag internal modules exposed to internet
            exposed_internal = [
                m for m in self.tester.os_modules if m in INTERNAL_MODULES
            ]
            if exposed_internal:
                self.finding(
                    severity="medium",
                    title=f"Internal OutSystems modules accessible: {', '.join(exposed_internal)}",
                    description=(
                        "OutSystems internal/system modules are accessible from the internet. "
                        "These modules are intended for internal use only and their exposure "
                        "increases the attack surface."
                    ),
                    evidence=f"Accessible modules: {', '.join(exposed_internal)}",
                    remediation=(
                        "Restrict access to internal OutSystems modules "
                        "(ServiceCenter, LifeTime, ECT_Provider, EPA_TaskBox) "
                        "via firewall rules or network segmentation."
                    ),
                    cwe="CWE-284",
                    references=[
                        "https://success.outsystems.com/Documentation/11/Setting_Up_OutSystems/OutSystems_network_requirements",
                    ],
                )
        else:
            msg_info("No OutSystems modules discovered")
            self.finding(
                severity="info",
                title="No OutSystems modules enumerated",
                description="No specific OutSystems application modules were identified.",
                evidence="Module probe: no modules responded",
                cwe="",
            )

    # ─── Utilities ────────────────────────────────────────────────────────────

    def _extract_js_urls(self, resp, max_scripts: int = 5) -> list[str]:
        """Extract absolute URLs to JS files referenced in the page."""
        urls = []
        html = resp.text or ""
        base = self.tester.base_url

        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html, re.IGNORECASE):
            src = m.group(1)
            if src.startswith("http"):
                urls.append(src)
            elif src.startswith("/"):
                urls.append(base + src)
            else:
                urls.append(base + "/" + src)
            if len(urls) >= max_scripts:
                break
        return urls
