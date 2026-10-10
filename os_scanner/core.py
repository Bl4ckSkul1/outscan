"""
OutScan core engine — HTTP session management, finding model,
OutSystems-specific helpers.
"""
import time
import re
import json
import uuid
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests
import urllib3

# Suppress InsecureRequestWarning when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Finding model ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A security finding produced by any OutScan module."""
    severity:      str          # critical, high, medium, low, info
    title:         str
    description:   str
    evidence:      str
    module:        str          # fingerprint | viewname | model_js | screen_enum | exposure | config
    request_data:  dict
    response_data: dict
    remediation:   str
    cwe:           str
    references:    list
    timestamp:     str = field(default_factory=lambda: datetime.now().isoformat())
    id:            str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "severity":     self.severity,
            "title":        self.title,
            "description":  self.description,
            "evidence":     self.evidence,
            "module":       self.module,
            "request":      self.request_data,
            "response":     self.response_data,
            "remediation":  self.remediation,
            "cwe":          self.cwe,
            "references":   self.references,
            "timestamp":    self.timestamp,
        }


# ─── Core tester ──────────────────────────────────────────────────────────────

class OutSystemsTester:
    """
    Core HTTP engine and state container for OutSystems security testing.

    All modules share a single instance of this class so discovered
    information (modules, screens, entities) accumulates across modules.
    """

    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        target_url:  str,
        headers:     Optional[dict] = None,
        cookies:     Optional[dict] = None,
        proxy:       Optional[str]  = None,
        delay:       float          = 0.5,
        timeout:     int            = 15,
        verify_ssl:  bool           = False,
        verbose:     bool           = False,
    ):
        self.target_url  = target_url.rstrip("/")
        self.base_url    = self._extract_base_url(target_url)
        self.verbose     = verbose
        self.delay       = delay
        self.timeout     = timeout

        # HTTP session
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "User-Agent": self.DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        self.proxy = {"http": proxy, "https": proxy} if proxy else None

        # Findings accumulator
        self.results: list[Finding] = []
        self.request_count: int = 0

        # ── OutSystems-specific state (populated during scanning) ──────────
        self.os_version:          Optional[str]  = None
        self.os_platform:         Optional[str]  = None   # "11", "ODC", "LifeTime"
        self.os_server_type:      Optional[str]  = None   # "IIS", "nginx", "Apache"
        self.os_modules:          list[str]       = []    # discovered app/module names
        self.os_screens:          dict            = {}    # module -> [screen names]
        self.os_entities:         dict            = {}    # module -> [entity schemas]
        self.os_anonymous_screens: list[str]      = []    # viewNames that don't require auth
        self.os_server_actions:   dict            = {}    # module -> [action names]
        self.os_csrf_token:       Optional[str]  = None

        # Track scan start time
        self._start_time = time.time()

    # ─── HTTP helpers ─────────────────────────────────────────────────────────

    def request(
        self,
        method:  str,
        url:     str,
        **kwargs
    ) -> Optional[requests.Response]:
        """
        Execute an HTTP request, honouring delay and proxy settings.
        Returns None on connection errors (caller decides how to handle).
        """
        kwargs.setdefault("timeout", self.timeout)
        if self.proxy:
            kwargs["proxies"] = self.proxy

        if self.delay > 0:
            time.sleep(self.delay)

        try:
            resp = self.session.request(method, url, **kwargs)
            self.request_count += 1
            return resp
        except requests.exceptions.SSLError:
            if self.verbose:
                from .colors import msg_warn
                msg_warn(f"SSL error for {url} — use --no-verify to skip SSL validation")
            return None
        except requests.exceptions.ConnectionError:
            if self.verbose:
                from .colors import msg_debug
                msg_debug(f"Connection error: {url}")
            return None
        except requests.exceptions.Timeout:
            if self.verbose:
                from .colors import msg_debug
                msg_debug(f"Timeout: {url}")
            return None
        except requests.exceptions.RequestException as e:
            if self.verbose:
                from .colors import msg_debug
                msg_debug(f"Request error ({url}): {e}")
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("HEAD", url, **kwargs)

    # ─── Finding management ───────────────────────────────────────────────────

    def add_finding(
        self,
        severity:      str,
        title:         str,
        description:   str,
        evidence:      str,
        module:        str           = "unknown",
        request_data:  Optional[dict]= None,
        response_data: Optional[dict]= None,
        remediation:   str           = "",
        cwe:           str           = "",
        references:    Optional[list]= None,
    ) -> Finding:
        """Create a Finding and append it to results."""
        f = Finding(
            severity=     severity.lower(),
            title=        title,
            description=  description,
            evidence=     evidence,
            module=       module,
            request_data= request_data  or {},
            response_data=response_data or {},
            remediation=  remediation,
            cwe=          cwe,
            references=   references    or [],
        )
        self.results.append(f)
        return f

    def get_findings(self) -> list[Finding]:
        return self.results

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.results if f.severity == severity.lower()]

    def get_stats(self) -> dict:
        from collections import Counter
        counts = Counter(f.severity for f in self.results)
        elapsed = time.time() - self._start_time
        return {
            "total":         len(self.results),
            "critical":      counts.get("critical", 0),
            "high":          counts.get("high",     0),
            "medium":        counts.get("medium",   0),
            "low":           counts.get("low",      0),
            "info":          counts.get("info",     0),
            "request_count": self.request_count,
            "elapsed":       round(elapsed, 2),
            "target":        self.target_url,
            "os_version":    self.os_version,
            "os_platform":   self.os_platform,
            "os_modules":    self.os_modules,
        }

    # ─── OutSystems-specific helpers ──────────────────────────────────────────

    def build_screenservice_url(self, module: str) -> str:
        """
        Build the base screenservice endpoint URL for a module.
        OutSystems screenservices follow the pattern:
            /{module}/screenservices/{module}
        """
        return f"{self.base_url}/{module}/screenservices/{module}"

    def call_screen_service(
        self,
        module:     str,
        action:     str,
        view_name:  Optional[str] = None,
        payload:    Optional[dict]= None,
    ) -> Optional[requests.Response]:
        """
        Call an OutSystems screenservice action.

        The viewName parameter is the core of the auth bypass:
        by specifying an anonymous screen's viewName the platform
        skips role verification and executes the server action.

        Args:
            module:    OutSystems module name (e.g. "MyApp")
            action:    Server action name (e.g. "GetUsers")
            view_name: viewName to inject — use an anonymous screen name
                       to attempt auth bypass.
            payload:   Additional input parameters / screen data.

        Returns:
            requests.Response or None on connection error.
        """
        base = self.build_screenservice_url(module)
        url = f"{base}/{action}"

        csrf = self._get_csrf_token()
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/plain, */*",
        }
        if csrf:
            headers["X-CSRFToken"] = csrf

        # OutSystems screenservice request envelope
        body = {
            "versionInfo": {
                "moduleVersion":  "",
                "apiVersion":     "1",
            },
            "viewName":     view_name or "",
            "screenData":   {},
            "inputParameters": payload or {},
        }

        return self.post(url, json=body, headers=headers)

    def call_module_service(
        self,
        module:  str,
        action:  str,
        payload: Optional[dict] = None,
    ) -> Optional[requests.Response]:
        """
        Call an OutSystems moduleservice endpoint (server-side aggregates).
        Pattern: /{module}/moduleservices/{module}/{action}
        """
        url = f"{self.base_url}/{module}/moduleservices/{module}/{action}"
        headers = {
            "Content-Type": "application/json; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
        }
        csrf = self._get_csrf_token()
        if csrf:
            headers["X-CSRFToken"] = csrf

        body = payload or {}
        return self.post(url, json=body, headers=headers)

    def _get_csrf_token(self) -> str:
        """
        Return a CSRF token for use in screenservice requests.
        First try cookies (OutSystems sets nr1_csrf or similar),
        fall back to the cached token, then return an empty string.
        """
        # Check cookies for OutSystems CSRF token names
        for name in ("nr1_csrf", "nr1", "CSRF-Token", "csrftoken"):
            val = self.session.cookies.get(name)
            if val:
                self.os_csrf_token = val
                return val

        # Return cached token if we found one earlier (e.g. from a page scrape)
        if self.os_csrf_token:
            return self.os_csrf_token

        return ""

    def extract_csrf_from_html(self, html: str) -> Optional[str]:
        """
        Attempt to extract a CSRF token from an OutSystems HTML page.
        OutSystems embeds it as a meta tag or in JavaScript.
        """
        patterns = [
            r'<meta\s+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
            r'__CSRFTOKEN__\s*=\s*["\']([^"\']{10,})',
            r'"csrfToken"\s*:\s*"([^"]{10,})"',
            r'nr1_csrf["\s]*[=:]["\s]*([a-zA-Z0-9_\-]{10,})',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                self.os_csrf_token = m.group(1)
                return self.os_csrf_token
        return None

    def _extract_base_url(self, url: str) -> str:
        """
        Extract the scheme + host from a URL.
        e.g. https://target.example.com/SomeApp  ->  https://target.example.com
        """
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return base

    def is_outsystems(self) -> bool:
        """True if fingerprinting has confirmed this is an OutSystems platform."""
        return bool(self.os_platform)

    def elapsed(self) -> float:
        return time.time() - self._start_time


# ─── Base module ──────────────────────────────────────────────────────────────

class BaseModule:
    """
    Abstract base class for all OutScan modules.

    Each module receives the shared OutSystemsTester instance and
    appends findings to it via self.finding().
    """
    NAME        = "base"
    DESCRIPTION = ""

    def __init__(self, tester: OutSystemsTester, options: Optional[dict] = None):
        self.tester  = tester
        self.options = options or {}

    def run(self) -> None:
        """Execute the module. Must be implemented by subclasses."""
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")

    def finding(
        self,
        severity:     str,
        title:        str,
        description:  str,
        evidence:     str,
        **kwargs,
    ) -> Finding:
        """Convenience wrapper — adds module name automatically."""
        return self.tester.add_finding(
            severity=    severity,
            title=       title,
            description= description,
            evidence=    evidence,
            module=      self.NAME,
            **kwargs,
        )

    def _log(self, msg: str) -> None:
        if self.tester.verbose:
            from .colors import msg_debug
            msg_debug(f"[{self.NAME}] {msg}")

    def _parse_json_response(self, resp: requests.Response) -> Optional[dict]:
        """Safely parse a JSON response body."""
        if resp is None:
            return None
        try:
            return resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            return None

    def _response_summary(self, resp: Optional[requests.Response]) -> dict:
        """Compact summary of a response for storing in finding.response_data."""
        if resp is None:
            return {"status": "no_response"}
        body = resp.text[:2000] if resp.text else ""
        return {
            "status":  resp.status_code,
            "headers": dict(resp.headers),
            "body":    body,
            "length":  len(resp.content),
        }

    def _request_summary(
        self,
        method:  str,
        url:     str,
        body:    Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> dict:
        """Compact summary of a request for storing in finding.request_data."""
        return {
            "method":  method,
            "url":     url,
            "headers": headers or {},
            "body":    body or {},
        }


# ─── Utility functions ────────────────────────────────────────────────────────

def is_json_response(resp: Optional[requests.Response]) -> bool:
    """True if response has a JSON content-type."""
    if resp is None:
        return False
    ct = resp.headers.get("Content-Type", "")
    return "application/json" in ct or "text/json" in ct


def response_has_data(resp: Optional[requests.Response]) -> bool:
    """
    Heuristic: does the response contain actual data (not an error/empty)?
    Used to detect whether an auth bypass returned real content.
    """
    if resp is None:
        return False
    if resp.status_code not in (200, 201):
        return False
    if not resp.text or len(resp.text) < 10:
        return False
    # OutSystems error responses often contain these patterns
    body = resp.text
    error_patterns = [
        "Invalid CSRF token",
        "Session expired",
        "Not authorized",
        "Access denied",
        '"success":false',
        '"Success":false',
        '"error":',
        '"Error":',
        "InvalidPermissions",
    ]
    for pat in error_patterns:
        if pat.lower() in body.lower():
            return False
    return True


def contains_pii(text: str) -> list[str]:
    """
    Check text for patterns that suggest PII or sensitive data exposure.
    Returns list of matched pattern descriptions.
    """
    findings = []
    patterns = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
         "email address"),
        (r'"password"\s*:\s*"[^"]{4,}"',
         "password field"),
        (r'"hash"\s*:\s*"[a-fA-F0-9]{32,}"',
         "password hash"),
        (r'"token"\s*:\s*"[A-Za-z0-9\-_.]{20,}"',
         "auth token"),
        (r'"secret"\s*:\s*"[^"]{6,}"',
         "secret field"),
        (r'"clientSecret"\s*:\s*"[^"]{6,}"',
         "OAuth client secret"),
        (r'"privateKey"\s*:\s*"[^"]{10,}"',
         "private key"),
        (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
         "credit card number pattern"),
        (r'\b\d{3}-\d{2}-\d{4}\b',
         "SSN pattern"),
        (r'"ssn"\s*:\s*"[^"]{5,}"',
         "SSN field"),
    ]
    for pattern, description in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            findings.append(description)
    return findings


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate long strings for evidence fields."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [truncated, {len(text)} total chars]"
