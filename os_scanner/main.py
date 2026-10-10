"""
OutScan main orchestrator — argument parsing, module execution, reporting.
"""
import argparse
import sys
import os
import json
import time
from datetime import datetime
from typing import Optional

from . import __version__
from .core import OutSystemsTester, Finding
from .colors import (
    banner, msg_ok, msg_fail, msg_info, msg_warn,
    msg_vuln, section, subsection, table, print_summary,
)
from .modules import ALL_MODULES


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()

    # Banner
    banner(version=__version__, quiet=args.quiet)

    # Determine targets
    targets = _collect_targets(args)
    if not targets:
        msg_fail("No targets specified. Use -u <url> or -L <file>")
        sys.exit(1)

    # Run each target
    all_results = []
    for i, target in enumerate(targets):
        if len(targets) > 1:
            section(f"Target {i+1}/{len(targets)}: {target}")
        results = _run_target(target, args)
        all_results.extend(results)

    # Final output
    if len(targets) > 1 and not args.quiet:
        section("MULTI-TARGET SUMMARY")
        msg_info(f"Targets scanned: {len(targets)}")
        msg_info(f"Total findings:  {len(all_results)}")
        critical = sum(1 for f in all_results if f.severity == "critical")
        high     = sum(1 for f in all_results if f.severity == "high")
        if critical:
            msg_vuln("critical", f"{critical} critical findings across all targets")
        elif high:
            msg_vuln("high", f"{high} high severity findings across all targets")

    # Save combined report if requested
    if args.output and len(targets) > 1:
        _save_json_report(all_results, args.output, targets=targets)


# ─── Target runner ────────────────────────────────────────────────────────────

def _run_target(target_url: str, args: argparse.Namespace) -> list[Finding]:
    """
    Full scan pipeline for a single target.
    Returns list of findings.
    """
    start_time = time.time()

    if not args.quiet:
        msg_info(f"Target: {target_url}")
        msg_info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if args.proxy:
            msg_info(f"Proxy:   {args.proxy}")
        print()

    # Build custom headers
    custom_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                custom_headers[k.strip()] = v.strip()

    # Build cookies
    custom_cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                custom_cookies[k.strip()] = v.strip()

    # Auth token
    if args.token:
        custom_headers["Authorization"] = f"Bearer {args.token}"

    # Create tester
    tester = OutSystemsTester(
        target_url= target_url,
        headers=    custom_headers,
        cookies=    custom_cookies,
        proxy=      args.proxy,
        delay=      args.delay,
        timeout=    args.timeout,
        verify_ssl= getattr(args, "verify_ssl", False),
        verbose=    getattr(args, "verbose", False),
    )

    # Determine which modules to run
    modules_to_run = _resolve_modules(args)
    if not args.quiet:
        msg_info(f"Modules: {', '.join(modules_to_run)}")
        print()

    # Module options (passed to each module)
    options = {
        "module_name":    args.module_name,
        "viewname_value": getattr(args, "viewname_value", None),
        "deep":           args.deep,
    }

    # ── Run modules ────────────────────────────────────────────────────────
    # Fingerprint ALWAYS runs first (other modules depend on its discoveries)
    if "fingerprint" in modules_to_run:
        _run_module("fingerprint", tester, options, args)

    for module_name in modules_to_run:
        if module_name == "fingerprint":
            continue  # already ran
        _run_module(module_name, tester, options, args)

    # ── Reporting ──────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    findings = tester.get_findings()
    stats    = tester.get_stats()

    if not args.quiet:
        print_summary(findings, elapsed, tester.request_count)
        _print_findings_detail(findings, args)

    # Save JSON report
    if args.output:
        _save_json_report(findings, args.output, stats=stats, target=target_url)
        msg_ok(f"JSON report saved: {args.output}")

    # Save HTML report
    if args.html:
        _save_html_report(findings, args.html, stats=stats, target=target_url)
        msg_ok(f"HTML report saved: {args.html}")

    return findings


def _run_module(
    module_name: str,
    tester:      OutSystemsTester,
    options:     dict,
    args:        argparse.Namespace,
) -> None:
    """Instantiate and run a single module, with error isolation."""
    module_class = ALL_MODULES.get(module_name)
    if not module_class:
        msg_warn(f"Unknown module: {module_name}")
        return

    if not args.quiet:
        msg_info(f"Running module: {module_name} — {module_class.DESCRIPTION}")

    try:
        module = module_class(tester=tester, options=options)
        module.run()
    except KeyboardInterrupt:
        msg_warn(f"Module {module_name} interrupted by user")
        raise
    except Exception as e:
        msg_fail(f"Module {module_name} error: {e}")
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()


# ─── Argument parsing ─────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="outscan",
        description="OutScan — OutSystems Platform Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  outscan.py -u https://target.example.com
  outscan.py -u https://target.example.com --deep -o report.json
  outscan.py -u https://target.example.com --viewname --module-name MyApp
  outscan.py -u https://target.example.com --all --html report.html
  outscan.py -L targets.txt --exposure --config -o findings.json

Based on original 0-day research by Adrian Martinez | HAAK Cybersecurity
        """,
    )

    # ── Target ──────────────────────────────────────────────────────────────
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-u", "--url",
        metavar="URL",
        help="Target OutSystems URL (e.g. https://target.example.com)",
    )
    target_group.add_argument(
        "-L", "--list",
        metavar="FILE",
        help="File containing target URLs, one per line",
    )

    # ── Module selection ─────────────────────────────────────────────────────
    module_group = parser.add_argument_group("Module Selection")
    module_group.add_argument(
        "--all",
        action="store_true",
        help="Run all modules",
    )
    module_group.add_argument(
        "--modules",
        metavar="LIST",
        help="Comma-separated module list: fingerprint,viewname,model_js,screen_enum,exposure,config",
    )
    module_group.add_argument(
        "--fingerprint",
        action="store_true",
        help="Platform fingerprinting and module discovery",
    )
    module_group.add_argument(
        "--viewname",
        action="store_true",
        help="viewName authorization bypass (0-day, CWE-863)",
    )
    module_group.add_argument(
        "--model-js",
        action="store_true",
        dest="model_js",
        help="model.js entity schema exposure (CWE-200)",
    )
    module_group.add_argument(
        "--screens",
        action="store_true",
        help="Screen and server action enumeration",
    )
    module_group.add_argument(
        "--exposure",
        action="store_true",
        help="Admin panel and management console exposure",
    )
    module_group.add_argument(
        "--config",
        action="store_true",
        help="Configuration security audit (headers, CORS, CSRF, cookies)",
    )
    module_group.add_argument(
        "--deep",
        action="store_true",
        help="Deep scan: all modules with extended enumeration",
    )

    # ── Authentication ───────────────────────────────────────────────────────
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "-c", "--cookie",
        metavar="COOKIE",
        help="Session cookies (e.g. 'ASP.NET_SessionId=abc; nr1=xyz')",
    )
    auth_group.add_argument(
        "-t", "--token",
        metavar="TOKEN",
        help="Bearer auth token",
    )
    auth_group.add_argument(
        "-H", "--header",
        action="append",
        metavar="HEADER",
        help="Custom header (e.g. 'X-Custom: value'). Can repeat.",
    )

    # ── OutSystems-specific ──────────────────────────────────────────────────
    os_group = parser.add_argument_group("OutSystems-Specific")
    os_group.add_argument(
        "--module-name",
        metavar="MODULE",
        dest="module_name",
        help="Test a specific OutSystems module by name",
    )
    os_group.add_argument(
        "--viewname-value",
        metavar="VIEWNAME",
        dest="viewname_value",
        help="Specific viewName to use for bypass testing",
    )

    # ── Connection ───────────────────────────────────────────────────────────
    conn_group = parser.add_argument_group("Connection")
    conn_group.add_argument(
        "--proxy",
        metavar="PROXY",
        help="HTTP proxy URL (e.g. http://127.0.0.1:8080)",
    )
    conn_group.add_argument(
        "--delay",
        type=float,
        default=0.5,
        metavar="SECONDS",
        help="Delay between requests in seconds (default: 0.5)",
    )
    conn_group.add_argument(
        "--timeout",
        type=int,
        default=15,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 15)",
    )
    conn_group.add_argument(
        "--no-verify",
        action="store_true",
        dest="no_verify",
        help="Disable SSL certificate verification",
    )
    conn_group.add_argument(
        "--verify-ssl",
        action="store_true",
        dest="verify_ssl",
        help="Enable SSL certificate verification (default: disabled)",
    )

    # ── Output ───────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save findings as JSON report",
    )
    output_group.add_argument(
        "--html",
        metavar="FILE",
        help="Save findings as HTML report",
    )
    output_group.add_argument(
        "--engagement",
        metavar="ID",
        help="HAAK engagement ID to associate with this scan",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and progress output",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose debug output",
    )

    args = parser.parse_args()

    # Validate: need at least one target
    if not args.url and not args.list:
        parser.print_help()
        print()
        msg_fail("Error: provide a target with -u URL or -L targets.txt")
        sys.exit(1)

    # --deep implies --all
    if args.deep:
        args.all = True

    # ssl verify logic
    if hasattr(args, "no_verify") and args.no_verify:
        args.verify_ssl = False
    elif not hasattr(args, "verify_ssl"):
        args.verify_ssl = False

    return args


# ─── Module resolution ────────────────────────────────────────────────────────

def _resolve_modules(args: argparse.Namespace) -> list[str]:
    """
    Determine the ordered list of modules to run based on CLI arguments.
    Fingerprint always runs first.
    """
    if args.all or args.deep:
        # All modules in logical dependency order
        return ["fingerprint", "exposure", "model_js", "screen_enum", "viewname", "config"]

    if args.modules:
        requested = [m.strip() for m in args.modules.split(",")]
        # Ensure fingerprint runs first
        if "fingerprint" not in requested:
            requested.insert(0, "fingerprint")
        return [m for m in requested if m in ALL_MODULES]

    # Individual flags
    selected = []
    if args.fingerprint:
        selected.append("fingerprint")
    if args.exposure:
        selected.append("exposure")
    if args.model_js:
        selected.append("model_js")
    if args.screens:
        selected.append("screen_enum")
    if args.viewname:
        selected.append("viewname")
    if args.config:
        selected.append("config")

    # Default: fingerprint + exposure if nothing selected
    if not selected:
        selected = ["fingerprint", "exposure"]

    # Fingerprint always first
    if "fingerprint" not in selected:
        selected.insert(0, "fingerprint")

    return selected


# ─── Target collection ────────────────────────────────────────────────────────

def _collect_targets(args: argparse.Namespace) -> list[str]:
    """Collect target URLs from -u and/or -L arguments."""
    targets = []

    if args.url:
        url = args.url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        targets.append(url)

    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith(("http://", "https://")):
                            line = "https://" + line
                        targets.append(line)
        except FileNotFoundError:
            msg_fail(f"Target list file not found: {args.list}")
            sys.exit(1)

    return targets


# ─── Output printing ──────────────────────────────────────────────────────────

def _print_findings_detail(findings: list[Finding], args: argparse.Namespace) -> None:
    """Print detailed findings to stdout."""
    if not findings:
        return

    # Filter out info-only if not verbose
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

    section("FINDINGS")
    for f in sorted_findings:
        if f.severity == "info" and not getattr(args, "verbose", False):
            continue  # Skip info findings unless verbose

        print()
        msg_vuln(f.severity, f.title)
        if f.description:
            _print_wrapped(f"     Description: {f.description}", 80)
        if f.evidence:
            _print_wrapped(f"     Evidence:    {f.evidence[:300]}", 80)
        if f.cwe:
            from .colors import _c, _C
            print(f"     CWE:         {_c(_C.BCYAN, f.cwe)}")
        if f.module:
            from .colors import _c, _C
            print(f"     Module:      {_c(_C.DIM, f.module)}")
        if f.remediation and getattr(args, "verbose", False):
            _print_wrapped(f"     Fix:         {f.remediation[:200]}", 80)

    print()


def _print_wrapped(text: str, width: int) -> None:
    """Print text with simple word-wrap."""
    from .colors import _c, _C
    lines = []
    indent_match = len(text) - len(text.lstrip())
    indent = text[:indent_match]
    key_val = text[indent_match:]

    # Split on ": " to keep key intact
    if ": " in key_val and len(key_val) > width:
        colon_idx = key_val.index(": ")
        key  = key_val[:colon_idx + 2]
        rest = key_val[colon_idx + 2:]
        print(f"{indent}{_c(_C.DIM, key)}{rest[:width - indent_match - len(key)]}")
        remaining = rest[width - indent_match - len(key):]
        while remaining:
            chunk = remaining[:width - indent_match - 5]
            print(f"{indent}     {chunk}")
            remaining = remaining[len(chunk):]
    else:
        print(text[:width + indent_match])


# ─── JSON report ──────────────────────────────────────────────────────────────

def _save_json_report(
    findings: list[Finding],
    output_path: str,
    stats: Optional[dict] = None,
    target: Optional[str] = None,
    targets: Optional[list] = None,
) -> None:
    """Save findings as a structured JSON report."""
    report = {
        "tool":      "OutScan",
        "version":   __version__,
        "author":    "Adrian Martinez | HAAK Cybersecurity",
        "generated": datetime.now().isoformat(),
        "target":    target or (targets[0] if targets else ""),
        "targets":   targets or ([target] if target else []),
        "stats":     stats or {},
        "findings":  [f.to_dict() for f in findings],
    }
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
    except OSError as e:
        msg_fail(f"Could not write JSON report: {e}")


# ─── HTML report ──────────────────────────────────────────────────────────────

def _save_html_report(
    findings: list[Finding],
    output_path: str,
    stats: Optional[dict] = None,
    target: Optional[str] = None,
) -> None:
    """Save findings as a self-contained HTML report."""
    from collections import Counter
    sev_counts = Counter(f.severity for f in findings)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

    sev_colors = {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#2563eb",
        "info":     "#0891b2",
    }

    def _esc(s: str) -> str:
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    finding_cards = []
    for f in sorted_findings:
        color = sev_colors.get(f.severity, "#64748b")
        refs_html = ""
        if f.references:
            refs_html = "<ul>" + "".join(
                f'<li><a href="{_esc(r)}" target="_blank">{_esc(r)}</a></li>'
                for r in f.references
            ) + "</ul>"

        req_html = ""
        if f.request_data:
            req_html = f'<pre>{_esc(json.dumps(f.request_data, indent=2))}</pre>'

        card = f"""
        <div class="finding" style="border-left: 4px solid {color}">
          <div class="finding-header">
            <span class="badge" style="background:{color}">{_esc(f.severity.upper())}</span>
            <span class="finding-title">{_esc(f.title)}</span>
            <span class="finding-id">#{_esc(f.id)}</span>
          </div>
          <div class="finding-body">
            <p><strong>Description:</strong> {_esc(f.description)}</p>
            <p><strong>Evidence:</strong></p>
            <pre class="evidence">{_esc(f.evidence)}</pre>
            {"<p><strong>Request:</strong></p>" + req_html if req_html else ""}
            {"<p><strong>CWE:</strong> " + _esc(f.cwe) + "</p>" if f.cwe else ""}
            {"<p><strong>Remediation:</strong> " + _esc(f.remediation) + "</p>" if f.remediation else ""}
            {"<p><strong>References:</strong>" + refs_html + "</p>" if refs_html else ""}
            <p class="meta">Module: {_esc(f.module)} | Time: {_esc(f.timestamp)}</p>
          </div>
        </div>"""
        finding_cards.append(card)

    stats_html = ""
    if stats:
        stats_html = f"""
        <div class="stats-grid">
          <div class="stat-card stat-critical">CRITICAL<br><strong>{sev_counts.get('critical', 0)}</strong></div>
          <div class="stat-card stat-high">HIGH<br><strong>{sev_counts.get('high', 0)}</strong></div>
          <div class="stat-card stat-medium">MEDIUM<br><strong>{sev_counts.get('medium', 0)}</strong></div>
          <div class="stat-card stat-low">LOW<br><strong>{sev_counts.get('low', 0)}</strong></div>
          <div class="stat-card stat-info">INFO<br><strong>{sev_counts.get('info', 0)}</strong></div>
          <div class="stat-card stat-total">TOTAL<br><strong>{len(findings)}</strong></div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OutScan Report — {_esc(target or '')}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    h1 {{ color: #38bdf8; font-size: 2rem; margin-bottom: 0.5rem; }}
    h2 {{ color: #94a3b8; font-size: 1rem; font-weight: normal; margin-bottom: 2rem; }}
    .meta-bar {{ background: #1e293b; padding: 1rem; border-radius: 8px;
                 margin-bottom: 1.5rem; font-size: 0.85rem; color: #64748b; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(6, 1fr);
                   gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: #1e293b; border-radius: 8px; padding: 1rem;
                  text-align: center; font-size: 0.75rem; color: #94a3b8; }}
    .stat-card strong {{ display: block; font-size: 2rem; margin-top: 0.25rem; }}
    .stat-critical strong {{ color: #dc2626; }}
    .stat-high strong {{ color: #ea580c; }}
    .stat-medium strong {{ color: #d97706; }}
    .stat-low strong {{ color: #2563eb; }}
    .stat-info strong {{ color: #0891b2; }}
    .stat-total strong {{ color: #e2e8f0; }}
    .finding {{ background: #1e293b; border-radius: 8px; margin-bottom: 1rem;
                overflow: hidden; }}
    .finding-header {{ padding: 1rem; display: flex; align-items: center; gap: 0.75rem;
                       cursor: pointer; }}
    .badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.7rem;
              font-weight: 700; color: white; white-space: nowrap; }}
    .finding-title {{ font-weight: 600; flex: 1; }}
    .finding-id {{ font-size: 0.75rem; color: #475569; }}
    .finding-body {{ padding: 0 1rem 1rem; font-size: 0.875rem; line-height: 1.6; }}
    .finding-body p {{ margin: 0.5rem 0; }}
    pre.evidence {{ background: #0f172a; padding: 0.75rem; border-radius: 6px;
                    overflow-x: auto; font-size: 0.8rem; color: #a5b4fc;
                    white-space: pre-wrap; word-break: break-word; }}
    pre {{ background: #0f172a; padding: 0.75rem; border-radius: 6px;
           overflow-x: auto; font-size: 0.8rem; white-space: pre-wrap; }}
    a {{ color: #38bdf8; }}
    .meta {{ font-size: 0.75rem; color: #475569; margin-top: 1rem; }}
    .footer {{ margin-top: 3rem; text-align: center; color: #334155;
               font-size: 0.8rem; }}
    @media (max-width: 768px) {{ .stats-grid {{ grid-template-columns: repeat(3, 1fr); }} }}
  </style>
</head>
<body>
  <h1>OutScan Security Report</h1>
  <h2>OutSystems Platform Security Scanner — by Adrian Martinez | HAAK Cybersecurity</h2>
  <div class="meta-bar">
    Target: <strong>{_esc(target or 'N/A')}</strong> &nbsp;|&nbsp;
    Generated: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong> &nbsp;|&nbsp;
    OutScan v{_esc(__version__)} &nbsp;|&nbsp;
    Requests: <strong>{stats.get('request_count', '?') if stats else '?'}</strong> &nbsp;|&nbsp;
    Elapsed: <strong>{stats.get('elapsed', '?') if stats else '?'}s</strong>
    {(" &nbsp;|&nbsp; Platform: <strong>" + _esc(stats.get('os_platform', '')) + " v" + _esc(stats.get('os_version', '') or 'unknown') + "</strong>") if stats else ""}
  </div>
  {stats_html}
  <div id="findings">
    {''.join(finding_cards) if finding_cards else '<p style="color:#64748b">No findings.</p>'}
  </div>
  <div class="footer">
    OutScan v{_esc(__version__)} &nbsp;|&nbsp;
    Adrian Martinez / HAAK Cybersecurity &nbsp;|&nbsp;
    Based on original 0-day research &nbsp;|&nbsp;
    This report is confidential
  </div>
</body>
</html>"""

    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write(html)
    except OSError as e:
        msg_fail(f"Could not write HTML report: {e}")


if __name__ == "__main__":
    main()
