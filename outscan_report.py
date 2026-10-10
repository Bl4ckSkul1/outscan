#!/usr/bin/env python3
"""
outscan_report.py — OutScan HTML Report Generator
OutSystems Platform Security Scanner
HAAK Cybersecurity Consulting / Adrian Martinez

Usage: python3 outscan_report.py scan_results.json output.html
"""

import json
import sys
import html
import os
from datetime import datetime, timezone


# ─── Helpers ─────────────────────────────────────────────────────────────────

def h(text):
    """HTML-escape a value safely."""
    if text is None:
        return ""
    return html.escape(str(text))


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def severity_order(s):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s.lower(), 5)


# ─── Section Builders ────────────────────────────────────────────────────────

def build_header(meta):
    target   = h(meta.get("target", "N/A"))
    date_val = h(meta.get("date", "N/A"))
    eng      = h(meta.get("engagement", "N/A"))
    dur      = meta.get("duration_seconds", 0)
    dur_str  = f"{dur}s" if dur < 60 else f"{dur // 60}m {dur % 60}s"
    ver      = h(meta.get("version", "1.0.0"))
    return f"""
<header class="report-header">
  <div class="header-glow"></div>
  <div class="header-inner">
    <div class="logo-row">
      <div class="logo-block">
        <span class="logo-out">OUT</span><span class="logo-scan">SCAN</span>
        <span class="logo-version">v{ver}</span>
      </div>
      <div class="logo-sub">OutSystems Platform Security Report</div>
    </div>
    <div class="header-meta">
      <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value target-url">{target}</span></div>
      <div class="meta-item"><span class="meta-label">Date</span><span class="meta-value">{date_val}</span></div>
      <div class="meta-item"><span class="meta-label">Engagement</span><span class="meta-value accent">{eng}</span></div>
      <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">{dur_str}</span></div>
    </div>
    <div class="header-credit">
      Based on original 0-day research by <strong>Adrian Martinez</strong> — HAAK Cybersecurity Consulting
    </div>
  </div>
</header>"""


def build_platform_overview(platform):
    if not platform:
        return ""
    detected = platform.get("detected", False)
    if not detected:
        return """<section id="platform" class="section"><h2 class="section-title">Platform Overview</h2>
        <div class="card"><p class="text-muted">OutSystems platform not detected on this target.</p></div></section>"""

    ver       = h(platform.get("version", "Unknown"))
    ptype     = h(platform.get("platform_type", "OutSystems"))
    server    = h(platform.get("server", "Unknown"))
    stack     = h(platform.get("stack", "Unknown"))
    env       = h(platform.get("environment", "Unknown"))
    modules   = platform.get("modules_found", [])
    entities  = platform.get("total_entities", 0)
    screens   = platform.get("total_screens", 0)
    actions   = platform.get("total_actions", 0)
    n_modules = len(modules)

    env_class = "badge-critical" if env.lower() == "production" else "badge-medium"

    modules_html = "".join(f'<span class="tag">{h(m)}</span>' for m in modules)

    return f"""
<section id="platform" class="section">
  <h2 class="section-title">Platform Overview</h2>
  <div class="platform-card card">
    <div class="platform-main">
      <div class="platform-identity">
        <div class="os-icon">⬡</div>
        <div>
          <div class="platform-name">{ptype}</div>
          <div class="platform-version">{ver}</div>
        </div>
        <span class="badge {env_class}">{env}</span>
      </div>
      <div class="platform-stack">
        <div class="stack-item"><span class="stack-label">Server</span><span class="stack-val">{server}</span></div>
        <div class="stack-item"><span class="stack-label">Stack</span><span class="stack-val">{stack}</span></div>
      </div>
      <div class="modules-tags">{modules_html}</div>
    </div>
    <div class="platform-metrics">
      <div class="metric-card"><div class="metric-val" data-count="{n_modules}">{n_modules}</div><div class="metric-label">Modules Found</div></div>
      <div class="metric-card"><div class="metric-val" data-count="{entities}">{entities}</div><div class="metric-label">Entities Exposed</div></div>
      <div class="metric-card"><div class="metric-val" data-count="{screens}">{screens}</div><div class="metric-label">Screens Discovered</div></div>
      <div class="metric-card"><div class="metric-val" data-count="{actions}">{actions}</div><div class="metric-label">Actions Found</div></div>
    </div>
  </div>
</section>"""


def build_executive_summary(stats, meta):
    crit  = stats.get("findings_critical", 0)
    high  = stats.get("findings_high", 0)
    med   = stats.get("findings_medium", 0)
    low   = stats.get("findings_low", 0)
    info  = stats.get("findings_info", 0)
    total_findings = crit + high + med + low + info
    total_tests    = stats.get("total_tests", 0)
    total_reqs     = meta.get("total_requests", 0)

    if crit > 0:
        risk_label = "CRITICAL"
        risk_class = "risk-critical"
    elif high > 0:
        risk_label = "HIGH"
        risk_class = "risk-high"
    elif med > 0:
        risk_label = "MEDIUM"
        risk_class = "risk-medium"
    else:
        risk_label = "LOW"
        risk_class = "risk-low"

    return f"""
<section id="summary" class="section">
  <h2 class="section-title">Executive Summary</h2>
  <div class="summary-grid">
    <div class="sev-card sev-critical"><div class="sev-count" data-count="{crit}">{crit}</div><div class="sev-label">Critical</div></div>
    <div class="sev-card sev-high"><div class="sev-count" data-count="{high}">{high}</div><div class="sev-label">High</div></div>
    <div class="sev-card sev-medium"><div class="sev-count" data-count="{med}">{med}</div><div class="sev-label">Medium</div></div>
    <div class="sev-card sev-low"><div class="sev-count" data-count="{low}">{low}</div><div class="sev-label">Low</div></div>
    <div class="sev-card sev-info"><div class="sev-count" data-count="{info}">{info}</div><div class="sev-label">Info</div></div>
  </div>
  <div class="summary-bottom">
    <div class="risk-badge {risk_class}">Overall Risk: {risk_label}</div>
    <div class="summary-stats">
      <span><strong>{total_findings}</strong> Findings</span>
      <span><strong>{total_tests}</strong> Tests Run</span>
      <span><strong>{total_reqs}</strong> Requests Made</span>
    </div>
  </div>
</section>"""


def build_viewname_section(vn):
    if not vn:
        return ""
    anon_screens    = vn.get("anonymous_screens_found", [])
    bypassed_count  = vn.get("bypassed_actions", 0)
    bypassed_list   = vn.get("bypassed_action_list", [])

    screens_html = "".join(f'<code class="screen-tag">{h(s)}</code>' for s in anon_screens)

    rows = ""
    for item in bypassed_list:
        mod    = h(item.get("module", ""))
        action = h(item.get("action", ""))
        vname  = h(item.get("viewname_used", ""))
        exposed = item.get("data_exposed", False)
        exposed_badge = '<span class="badge badge-critical">YES</span>' if exposed else '<span class="badge badge-low">NO</span>'
        rows += f"<tr><td><span class='tag'>{mod}</span></td><td><code>{action}</code></td><td><code class='vname-code'>{vname}</code></td><td>{exposed_badge}</td></tr>"

    table_html = f"""
<table class="findings-table">
  <thead><tr><th>Module</th><th>Action</th><th>viewName Used</th><th>Data Exposed</th></tr></thead>
  <tbody>{rows}</tbody>
</table>""" if rows else "<p class='text-muted'>No bypassed actions recorded.</p>"

    return f"""
<section id="viewname" class="section">
  <h2 class="section-title">
    <span class="zero-day-badge">0-DAY</span>
    viewName Authorization Bypass
  </h2>
  <div class="vn-card card">
    <div class="vn-header">
      <div class="vn-title-row">
        <span class="vn-icon">⚠</span>
        <div>
          <div class="vn-title">viewName Authorization Bypass — ATO Chain</div>
          <div class="vn-subtitle">OutSystems screen-level authentication can be bypassed by spoofing the viewName parameter, exposing server actions to unauthenticated callers.</div>
        </div>
      </div>
    </div>

    <div class="vn-stats">
      <div class="vn-stat"><span class="vn-stat-val">{bypassed_count}</span><span class="vn-stat-label">Bypassed Actions</span></div>
      <div class="vn-stat"><span class="vn-stat-val">{len(anon_screens)}</span><span class="vn-stat-label">Anonymous Screens Found</span></div>
    </div>

    <div class="vn-section-label">Anonymous Screens (Attack Vectors)</div>
    <div class="screens-list">{screens_html}</div>

    <div class="attack-chain">
      <div class="ac-title">Attack Chain</div>
      <div class="ac-steps">
        <div class="ac-step">
          <div class="ac-step-icon">👤</div>
          <div class="ac-step-label">Unauthenticated<br>Attacker</div>
        </div>
        <div class="ac-arrow">→</div>
        <div class="ac-step">
          <div class="ac-step-icon">🔓</div>
          <div class="ac-step-label">Anonymous Screen<br><code>viewName=Login</code></div>
        </div>
        <div class="ac-arrow">→</div>
        <div class="ac-step">
          <div class="ac-step-icon">⚙</div>
          <div class="ac-step-label">Protected<br>Server Action</div>
        </div>
        <div class="ac-arrow">→</div>
        <div class="ac-step ac-step-danger">
          <div class="ac-step-icon">💀</div>
          <div class="ac-step-label">Data Access<br>/ ATO</div>
        </div>
      </div>
    </div>

    <div class="vn-section-label">Bypassed Actions</div>
    {table_html}
  </div>
</section>"""


def build_modeljs_section(mjs):
    if not mjs:
        return ""
    total_ent   = mjs.get("total_entities", 0)
    sensitive   = mjs.get("sensitive_entities", 0)
    mods        = mjs.get("modules_exposed", [])
    fields      = mjs.get("sensitive_fields_found", [])

    mods_html   = "".join(f'<tr><td><span class="tag">{h(m)}</span></td><td><span class="badge badge-high">Exposed</span></td></tr>' for m in mods)
    fields_html = "".join(f'<code class="field-tag">{h(f)}</code>' for f in fields)

    return f"""
<section id="modeljs" class="section">
  <h2 class="section-title">model.js Analysis</h2>
  <div class="card">
    <div class="mjs-stats">
      <div class="metric-card"><div class="metric-val" data-count="{total_ent}">{total_ent}</div><div class="metric-label">Total Entities</div></div>
      <div class="metric-card mjs-sensitive"><div class="metric-val" data-count="{sensitive}">{sensitive}</div><div class="metric-label">Sensitive Entities</div></div>
    </div>

    <div class="mjs-section-label">Exposed Sensitive Modules</div>
    <table class="findings-table"><thead><tr><th>Module</th><th>Status</th></tr></thead><tbody>{mods_html}</tbody></table>

    <div class="mjs-section-label" style="margin-top:1.5rem">Sensitive Fields Discovered</div>
    <div class="fields-list">{fields_html}</div>

    <div class="remediation-box">
      <strong>Remediation:</strong> Remove model.js exposure from production environments or implement authentication
      before serving entity metadata. Rotate all exposed credentials and secrets immediately.
    </div>
  </div>
</section>"""


def build_findings_section(findings):
    if not findings:
        return """<section id="findings" class="section"><h2 class="section-title">Findings</h2>
        <div class="card"><p class="text-muted">No findings recorded.</p></div></section>"""

    sorted_findings = sorted(findings, key=lambda f: severity_order(f.get("severity", "info")))

    # Collect unique modules for filter
    modules = sorted(set(f.get("module", "unknown") for f in sorted_findings))
    mod_btns = '<button class="filter-btn active" data-module="all">All</button>' + \
               "".join(f'<button class="filter-btn" data-module="{h(m)}">{h(m)}</button>' for m in modules)

    cards = ""
    for i, finding in enumerate(sorted_findings):
        sev    = finding.get("severity", "info").lower()
        title  = h(finding.get("title", "Untitled"))
        desc   = h(finding.get("description", ""))
        evid   = h(finding.get("evidence", ""))
        mod    = h(finding.get("module", "unknown"))
        rem    = h(finding.get("remediation", ""))
        cwe    = h(finding.get("cwe", ""))
        refs   = finding.get("references", [])

        req_d  = finding.get("request_data", {})
        res_d  = finding.get("response_data", {})

        req_json  = h(json.dumps(req_d, indent=2)) if req_d else ""
        res_json  = h(json.dumps(res_d, indent=2)) if res_d else ""

        refs_html = "".join(f'<a class="ref-link" href="{h(r)}" target="_blank">{h(r)}</a>' for r in refs)

        req_block = f"""
<div class="collapsible">
  <button class="collapsible-btn" onclick="toggleCollapse(this)">Request / Response ▾</button>
  <div class="collapsible-content">
    <div class="req-label">Request</div><pre class="code-block">{req_json}</pre>
    <div class="req-label">Response</div><pre class="code-block">{res_json}</pre>
  </div>
</div>""" if req_json or res_json else ""

        cwe_html = f'<span class="cwe-badge">{cwe}</span>' if cwe else ""

        cards += f"""
<div class="finding-card" data-severity="{sev}" data-module="{mod}">
  <div class="finding-header">
    <span class="badge badge-{sev}">{sev.upper()}</span>
    <span class="badge badge-module">{mod}</span>
    {cwe_html}
    <button class="copy-btn" onclick="copyFinding(this, {i})" title="Copy finding">⎘</button>
  </div>
  <div class="finding-title">{title}</div>
  <div class="finding-desc">{desc}</div>
  {"<div class='evidence-block'><div class='evidence-label'>Evidence</div><pre class='code-block evidence'>" + evid + "</pre></div>" if evid else ""}
  {req_block}
  {"<div class='remediation-box'><strong>Remediation:</strong> " + rem + "</div>" if rem else ""}
  {"<div class='refs-block'>" + refs_html + "</div>" if refs_html else ""}
</div>"""

    return f"""
<section id="findings" class="section">
  <h2 class="section-title">Findings <span class="count-badge">{len(findings)}</span></h2>
  <div class="filter-bar">
    <div class="sev-filters">
      <button class="filter-btn active" data-sev="all">All</button>
      <button class="filter-btn" data-sev="critical">Critical</button>
      <button class="filter-btn" data-sev="high">High</button>
      <button class="filter-btn" data-sev="medium">Medium</button>
      <button class="filter-btn" data-sev="low">Low</button>
      <button class="filter-btn" data-sev="info">Info</button>
    </div>
    <div class="mod-filters">{mod_btns}</div>
    <input class="search-input" id="findingSearch" placeholder="Search findings…" oninput="filterFindings()">
  </div>
  <div id="findingsContainer">
    {cards}
  </div>
</section>"""


def build_modules_section(stats):
    mstats = stats.get("modules_stats", {})
    if not mstats:
        return ""

    items = ""
    for mod, data in mstats.items():
        tests    = data.get("tests", 0)
        findings = data.get("findings", 0)
        bar_pct  = min(100, int((findings / max(tests, 1)) * 100))
        items += f"""
<div class="accordion-item">
  <button class="accordion-btn" onclick="toggleAccordion(this)">
    <span class="mod-name">{h(mod)}</span>
    <span class="mod-stats"><span>{tests} tests</span><span class="badge badge-{'critical' if findings > 3 else 'medium' if findings > 1 else 'low'}">{findings} findings</span></span>
    <span class="acc-arrow">▾</span>
  </button>
  <div class="accordion-content">
    <div class="mod-bar-wrap"><div class="mod-bar" style="width:{bar_pct}%"></div></div>
    <p class="text-muted" style="margin:0.5rem 0 0">Finding rate: {bar_pct}% — {findings} of {tests} tests triggered a finding.</p>
  </div>
</div>"""

    return f"""
<section id="modules" class="section">
  <h2 class="section-title">Module Results</h2>
  <div class="accordion">{items}</div>
</section>"""


def build_methodology_section(meta, stats):
    modules_run = meta.get("modules_run", [])
    ver         = h(meta.get("version", "1.0.0"))
    total_tests = stats.get("total_tests", 0)
    total_reqs  = meta.get("total_requests", 0)
    dur         = meta.get("duration_seconds", 0)
    dur_str     = f"{dur}s" if dur < 60 else f"{dur // 60}m {dur % 60}s"

    mods_html = "".join(f'<span class="tag">{h(m)}</span>' for m in modules_run)

    return f"""
<section id="methodology" class="section">
  <h2 class="section-title">Methodology</h2>
  <div class="card methodology-grid">
    <div>
      <div class="meth-label">Modules Executed</div>
      <div class="modules-tags">{mods_html}</div>
    </div>
    <div class="meth-stats">
      <div><span class="meth-key">Tool Version</span><span class="meth-val">{ver}</span></div>
      <div><span class="meth-key">Total Tests</span><span class="meth-val">{total_tests}</span></div>
      <div><span class="meth-key">Total Requests</span><span class="meth-val">{total_reqs}</span></div>
      <div><span class="meth-key">Duration</span><span class="meth-val">{dur_str}</span></div>
    </div>
    <div class="meth-desc">
      <p>OutScan performs automated security assessment of OutSystems platform deployments.
      The viewName bypass module implements the original research technique documented by
      Adrian Martinez (HAAK Cybersecurity). All tests are read-only; no data is modified.</p>
    </div>
  </div>
</section>"""


def build_footer(meta):
    ver  = h(meta.get("version", "1.0.0"))
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""
<footer class="report-footer">
  <div class="footer-inner">
    <div class="footer-brand">Generated by <strong>OutScan v{ver}</strong> — HAAK Cybersecurity Consulting</div>
    <div class="footer-credit">Based on original 0-day research — CVE pending | Adrian Martinez</div>
    <div class="footer-disclaimer">
      This report is confidential and intended solely for the authorized recipient.
      Findings represent the security posture at time of assessment. HAAK Cybersecurity assumes no
      liability for actions taken based on this report without proper authorization.
    </div>
    <div class="footer-ts">Report generated: {date_str}</div>
  </div>
</footer>"""


# ─── CSS ─────────────────────────────────────────────────────────────────────

CSS = """
:root{
  --bg-primary:#060a14;--bg-card:#0d1321;--bg-card2:#111827;
  --border:rgba(0,200,255,0.08);--border2:rgba(0,200,255,0.15);
  --accent:#00c8ff;--accent-purple:#8b5cf6;--os-orange:#f25c2a;
  --critical:#ff0040;--high:#ff6b00;--medium:#ffaa00;--low:#22c55e;--info:#3b82f6;
  --text:#e2e8f0;--text-muted:#64748b;--text-dim:#94a3b8;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-primary);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;display:flex;min-height:100vh}

/* ── Sidebar ── */
.sidebar{width:220px;min-height:100vh;background:#08101e;border-right:1px solid var(--border2);position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0;padding:1.5rem 0}
.sidebar-logo{padding:0 1.25rem 1.5rem;border-bottom:1px solid var(--border);margin-bottom:1rem}
.sidebar-logo .sl{font-size:1.2rem;font-weight:800;letter-spacing:2px}
.sidebar-logo .sl .out{color:var(--os-orange)}.sidebar-logo .sl .scan{color:var(--accent)}
.sidebar-logo .sl-sub{font-size:0.7rem;color:var(--text-muted);margin-top:0.15rem}
.nav-item{display:block;padding:0.55rem 1.25rem;color:var(--text-dim);text-decoration:none;font-size:0.8rem;border-left:2px solid transparent;transition:all 0.2s}
.nav-item:hover,.nav-item.active{color:var(--accent);background:rgba(0,200,255,0.04);border-left-color:var(--accent)}
.nav-section{padding:0.25rem 1.25rem;font-size:0.65rem;color:var(--text-muted);letter-spacing:1px;text-transform:uppercase;margin-top:0.75rem}

/* ── Main ── */
.main{flex:1;overflow-x:hidden}

/* ── Header ── */
.report-header{position:relative;background:linear-gradient(135deg,#060a14 0%,#0d1321 50%,#0a0d18 100%);border-bottom:1px solid var(--border2);padding:3rem 2.5rem 2rem;overflow:hidden}
.header-glow{position:absolute;top:-60px;left:-60px;width:400px;height:400px;background:radial-gradient(circle,rgba(0,200,255,0.07),transparent 70%);pointer-events:none}
.header-inner{position:relative}
.logo-row{display:flex;align-items:baseline;gap:1.5rem;flex-wrap:wrap;margin-bottom:1.5rem}
.logo-block{display:flex;align-items:baseline;gap:0.25rem}
.logo-out{font-size:2.8rem;font-weight:900;color:var(--os-orange);letter-spacing:1px}
.logo-scan{font-size:2.8rem;font-weight:900;background:linear-gradient(90deg,var(--accent),var(--accent-purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.logo-version{font-size:0.75rem;color:var(--text-muted);margin-left:0.25rem;align-self:flex-end;padding-bottom:0.5rem}
.logo-sub{font-size:0.95rem;color:var(--text-dim);padding-bottom:0.4rem}
.header-meta{display:flex;flex-wrap:wrap;gap:1.5rem;margin-bottom:1rem}
.meta-item{display:flex;flex-direction:column;gap:0.15rem}
.meta-label{font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px}
.meta-value{font-size:0.9rem;font-weight:600}
.meta-value.target-url{color:var(--accent);font-family:monospace}
.meta-value.accent{color:var(--accent-purple)}
.header-credit{font-size:0.75rem;color:var(--text-muted);border-top:1px solid var(--border);padding-top:0.75rem;margin-top:0.5rem}
.header-credit strong{color:var(--accent)}

/* ── Sections ── */
.section{padding:2rem 2.5rem;border-bottom:1px solid var(--border)}
.section-title{font-size:1.1rem;font-weight:700;margin-bottom:1.25rem;display:flex;align-items:center;gap:0.75rem;color:var(--text)}

/* ── Card ── */
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:1.5rem}

/* ── Platform ── */
.platform-card{display:flex;flex-direction:column;gap:1.5rem}
.platform-main{display:flex;flex-direction:column;gap:1rem}
.platform-identity{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.os-icon{width:48px;height:48px;background:linear-gradient(135deg,var(--os-orange),#c0392b);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:1.5rem;flex-shrink:0}
.platform-name{font-size:1.3rem;font-weight:700;color:var(--accent)}
.platform-version{font-size:0.8rem;color:var(--text-muted);font-family:monospace}
.platform-stack{display:flex;gap:2rem;flex-wrap:wrap}
.stack-item{display:flex;gap:0.5rem;align-items:center}
.stack-label{font-size:0.7rem;color:var(--text-muted);text-transform:uppercase}
.stack-val{font-size:0.85rem;font-weight:600}
.modules-tags{display:flex;flex-wrap:wrap;gap:0.5rem}
.tag{background:rgba(0,200,255,0.07);border:1px solid rgba(0,200,255,0.2);color:var(--accent);padding:0.2rem 0.6rem;border-radius:4px;font-size:0.75rem;font-family:monospace}
.platform-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}
.metric-card{background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}
.metric-val{font-size:2rem;font-weight:800;color:var(--accent);line-height:1}
.metric-label{font-size:0.7rem;color:var(--text-muted);margin-top:0.4rem;text-transform:uppercase;letter-spacing:0.5px}
.mjs-sensitive .metric-val{color:var(--critical)}

/* ── Executive Summary ── */
.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.25rem}
.sev-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:1.25rem;text-align:center;border-top-width:3px}
.sev-card.sev-critical{border-top-color:var(--critical)}.sev-card.sev-high{border-top-color:var(--high)}
.sev-card.sev-medium{border-top-color:var(--medium)}.sev-card.sev-low{border-top-color:var(--low)}.sev-card.sev-info{border-top-color:var(--info)}
.sev-count{font-size:2.2rem;font-weight:800;line-height:1}
.sev-card.sev-critical .sev-count{color:var(--critical)}.sev-card.sev-high .sev-count{color:var(--high)}
.sev-card.sev-medium .sev-count{color:var(--medium)}.sev-card.sev-low .sev-count{color:var(--low)}.sev-card.sev-info .sev-count{color:var(--info)}
.sev-label{font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-top:0.3rem}
.summary-bottom{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem}
.risk-badge{padding:0.5rem 1.25rem;border-radius:6px;font-size:0.85rem;font-weight:700;letter-spacing:1px}
.risk-critical{background:rgba(255,0,64,0.12);border:1px solid var(--critical);color:var(--critical)}
.risk-high{background:rgba(255,107,0,0.12);border:1px solid var(--high);color:var(--high)}
.risk-medium{background:rgba(255,170,0,0.12);border:1px solid var(--medium);color:var(--medium)}
.risk-low{background:rgba(34,197,94,0.12);border:1px solid var(--low);color:var(--low)}
.summary-stats{display:flex;gap:1.5rem;font-size:0.85rem;color:var(--text-dim)}
.summary-stats strong{color:var(--text)}

/* ── Badges ── */
.badge{padding:0.2rem 0.55rem;border-radius:4px;font-size:0.7rem;font-weight:700;letter-spacing:0.5px;text-transform:uppercase}
.badge-critical{background:rgba(255,0,64,0.15);color:var(--critical);border:1px solid rgba(255,0,64,0.3)}
.badge-high{background:rgba(255,107,0,0.15);color:var(--high);border:1px solid rgba(255,107,0,0.3)}
.badge-medium{background:rgba(255,170,0,0.15);color:var(--medium);border:1px solid rgba(255,170,0,0.3)}
.badge-low{background:rgba(34,197,94,0.15);color:var(--low);border:1px solid rgba(34,197,94,0.3)}
.badge-info{background:rgba(59,130,246,0.15);color:var(--info);border:1px solid rgba(59,130,246,0.3)}
.badge-module{background:rgba(139,92,246,0.12);color:var(--accent-purple);border:1px solid rgba(139,92,246,0.25)}
.cwe-badge{font-size:0.7rem;color:var(--text-muted);background:rgba(255,255,255,0.04);border:1px solid var(--border);padding:0.2rem 0.5rem;border-radius:4px;font-family:monospace}
.count-badge{background:rgba(0,200,255,0.1);color:var(--accent);border:1px solid rgba(0,200,255,0.2);padding:0.15rem 0.6rem;border-radius:12px;font-size:0.75rem;font-weight:600}

/* ── viewName 0-day Section ── */
.zero-day-badge{background:linear-gradient(90deg,var(--critical),var(--os-orange));color:#fff;padding:0.2rem 0.7rem;border-radius:4px;font-size:0.7rem;font-weight:800;letter-spacing:1px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.7}}
.vn-card{background:var(--bg-card);border:1px solid transparent;border-radius:12px;padding:0;overflow:hidden;position:relative;background-clip:padding-box}
.vn-card::before{content:'';position:absolute;inset:0;border-radius:12px;padding:1px;background:linear-gradient(135deg,var(--critical),var(--os-orange),var(--accent-purple));-webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.vn-card{box-shadow:0 0 40px rgba(255,0,64,0.08),0 0 80px rgba(242,92,42,0.05)}
.vn-header{background:linear-gradient(135deg,rgba(255,0,64,0.06),rgba(242,92,42,0.04),rgba(139,92,246,0.04));padding:1.5rem;border-bottom:1px solid rgba(255,0,64,0.1)}
.vn-title-row{display:flex;gap:1rem;align-items:flex-start}
.vn-icon{font-size:2rem;flex-shrink:0;margin-top:0.1rem}
.vn-title{font-size:1.1rem;font-weight:700;color:var(--critical);margin-bottom:0.35rem}
.vn-subtitle{font-size:0.82rem;color:var(--text-dim);line-height:1.5}
.vn-stats{display:flex;gap:1.5rem;padding:1.25rem 1.5rem;border-bottom:1px solid rgba(255,0,64,0.08)}
.vn-stat{text-align:center}
.vn-stat-val{display:block;font-size:2rem;font-weight:800;color:var(--critical);line-height:1}
.vn-stat-label{font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px}
.vn-section-label{font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin:1.5rem 1.5rem 0.5rem}
.screens-list{display:flex;flex-wrap:wrap;gap:0.5rem;padding:0 1.5rem 1.5rem}
.screen-tag{background:rgba(255,0,64,0.08);border:1px solid rgba(255,0,64,0.2);color:var(--critical);padding:0.25rem 0.6rem;border-radius:5px;font-size:0.8rem}
.vname-code{color:var(--os-orange)}

/* Attack Chain */
.attack-chain{background:rgba(0,0,0,0.3);border:1px solid rgba(255,0,64,0.12);border-radius:8px;padding:1.25rem 1.5rem;margin:0 1.5rem 1.5rem}
.ac-title{font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:1rem}
.ac-steps{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:0.75rem}
.ac-step{text-align:center;min-width:90px}
.ac-step-icon{font-size:1.6rem;line-height:1;margin-bottom:0.4rem}
.ac-step-label{font-size:0.7rem;color:var(--text-dim);line-height:1.3}
.ac-step-label code{font-size:0.65rem;color:var(--os-orange)}
.ac-step-danger .ac-step-icon{filter:drop-shadow(0 0 8px var(--critical))}
.ac-arrow{font-size:1.2rem;color:var(--os-orange);font-weight:700}

/* Findings */
.filter-bar{background:var(--bg-card2);border:1px solid var(--border);border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.25rem;display:flex;flex-direction:column;gap:0.75rem}
.sev-filters,.mod-filters{display:flex;flex-wrap:wrap;gap:0.5rem}
.filter-btn{background:transparent;border:1px solid var(--border2);color:var(--text-dim);padding:0.3rem 0.75rem;border-radius:4px;cursor:pointer;font-size:0.75rem;transition:all 0.2s}
.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
.filter-btn.active{background:rgba(0,200,255,0.1);border-color:var(--accent);color:var(--accent)}
.search-input{background:rgba(0,0,0,0.3);border:1px solid var(--border2);color:var(--text);padding:0.4rem 0.85rem;border-radius:5px;font-size:0.8rem;outline:none;width:100%;max-width:320px}
.search-input:focus{border-color:var(--accent)}
.finding-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:1.25rem;margin-bottom:1rem;border-left:3px solid transparent;transition:border-color 0.2s}
.finding-card[data-severity="critical"]{border-left-color:var(--critical)}
.finding-card[data-severity="high"]{border-left-color:var(--high)}
.finding-card[data-severity="medium"]{border-left-color:var(--medium)}
.finding-card[data-severity="low"]{border-left-color:var(--low)}
.finding-card[data-severity="info"]{border-left-color:var(--info)}
.finding-header{display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem}
.finding-title{font-size:0.95rem;font-weight:600;margin-bottom:0.5rem;color:var(--text)}
.finding-desc{font-size:0.82rem;color:var(--text-dim);margin-bottom:0.75rem;line-height:1.6}
.evidence-block{margin-bottom:0.75rem}
.evidence-label,.req-label,.mjs-section-label,.vn-section-label-inner{font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:0.4rem}
.code-block{background:#050b14;border:1px solid var(--border);border-radius:6px;padding:0.85rem 1rem;font-family:'Consolas','Courier New',monospace;font-size:0.75rem;overflow-x:auto;white-space:pre;color:#a5f3fc;line-height:1.5;max-height:240px;overflow-y:auto}
.code-block.evidence{color:var(--text-dim)}
.remediation-box{background:rgba(34,197,94,0.05);border:1px solid rgba(34,197,94,0.15);border-radius:6px;padding:0.85rem 1rem;font-size:0.8rem;color:var(--text-dim);margin-top:0.75rem;line-height:1.5}
.remediation-box strong{color:var(--low)}
.refs-block{margin-top:0.5rem;display:flex;flex-wrap:wrap;gap:0.5rem}
.ref-link{font-size:0.72rem;color:var(--accent);text-decoration:none;border-bottom:1px dotted rgba(0,200,255,0.3)}
.ref-link:hover{border-bottom-color:var(--accent)}
.copy-btn{margin-left:auto;background:transparent;border:1px solid var(--border2);color:var(--text-muted);padding:0.15rem 0.5rem;border-radius:4px;cursor:pointer;font-size:0.8rem}
.copy-btn:hover{color:var(--accent);border-color:var(--accent)}

/* Collapsible */
.collapsible{margin-bottom:0.75rem}
.collapsible-btn{background:rgba(0,200,255,0.04);border:1px solid var(--border2);color:var(--text-dim);padding:0.45rem 0.85rem;border-radius:5px;cursor:pointer;font-size:0.78rem;width:100%;text-align:left}
.collapsible-btn:hover{color:var(--accent)}
.collapsible-content{display:none;padding-top:0.5rem}
.collapsible-content.open{display:block}
.req-label{font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin:0.5rem 0 0.3rem}

/* model.js */
.mjs-stats{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;margin-bottom:1.5rem}
.mjs-section-label{font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:0.6rem}
.field-tag{background:rgba(255,0,64,0.08);border:1px solid rgba(255,0,64,0.2);color:var(--critical);padding:0.25rem 0.6rem;border-radius:4px;font-size:0.78rem;margin:0.2rem}
.fields-list{display:flex;flex-wrap:wrap;gap:0.4rem}

/* Findings table */
.findings-table{width:100%;border-collapse:collapse;font-size:0.8rem}
.findings-table th{background:rgba(0,200,255,0.04);padding:0.6rem 0.85rem;text-align:left;font-size:0.65rem;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);border-bottom:1px solid var(--border2)}
.findings-table td{padding:0.6rem 0.85rem;border-bottom:1px solid var(--border);color:var(--text-dim)}
.findings-table tr:hover td{background:rgba(0,200,255,0.02)}
.findings-table code{font-family:monospace;font-size:0.78rem;color:var(--text-dim)}

/* Modules accordion */
.accordion{display:flex;flex-direction:column;gap:0.5rem}
.accordion-item{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.accordion-btn{width:100%;background:transparent;border:none;padding:0.85rem 1.25rem;display:flex;align-items:center;gap:1rem;cursor:pointer;color:var(--text);text-align:left}
.accordion-btn:hover{background:rgba(0,200,255,0.03)}
.mod-name{font-weight:600;font-size:0.88rem;flex:1}
.mod-stats{display:flex;align-items:center;gap:0.75rem;font-size:0.8rem;color:var(--text-muted)}
.acc-arrow{color:var(--text-muted);font-size:0.8rem;transition:transform 0.2s}
.accordion-btn.open .acc-arrow{transform:rotate(180deg)}
.accordion-content{display:none;padding:1rem 1.25rem;border-top:1px solid var(--border)}
.accordion-content.open{display:block}
.mod-bar-wrap{height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden}
.mod-bar{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent-purple));border-radius:3px;transition:width 0.8s ease}

/* Methodology */
.methodology-grid{display:flex;flex-direction:column;gap:1.25rem}
.meth-label{font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--text-muted);margin-bottom:0.5rem}
.meth-stats{display:flex;flex-direction:column;gap:0.5rem}
.meth-stats>div{display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0;border-bottom:1px solid var(--border)}
.meth-key{font-size:0.8rem;color:var(--text-muted)}.meth-val{font-size:0.85rem;font-weight:600}
.meth-desc p{font-size:0.82rem;color:var(--text-dim);line-height:1.6}

/* Footer */
.report-footer{background:#050810;border-top:1px solid var(--border2);padding:2rem 2.5rem;text-align:center}
.footer-inner{max-width:640px;margin:0 auto;display:flex;flex-direction:column;gap:0.5rem}
.footer-brand{font-weight:700;font-size:0.88rem}.footer-brand strong{color:var(--accent)}
.footer-credit{font-size:0.78rem;color:var(--accent-purple)}
.footer-disclaimer{font-size:0.72rem;color:var(--text-muted);line-height:1.5;margin-top:0.5rem}
.footer-ts{font-size:0.7rem;color:var(--text-muted)}
.text-muted{color:var(--text-muted)}

/* Print */
@media print{
  .sidebar{display:none}
  body{display:block}
  .section{break-inside:avoid}
  .code-block{max-height:none}
}
@media(max-width:768px){
  .sidebar{display:none}
  .platform-metrics{grid-template-columns:repeat(2,1fr)}
  .summary-grid{grid-template-columns:repeat(3,1fr)}
}
"""


# ─── JS ──────────────────────────────────────────────────────────────────────

JS = """
// Count-up animation
function countUp(el, target, duration) {
  const start = Date.now();
  const step = () => {
    const elapsed = Date.now() - start;
    const progress = Math.min(elapsed / duration, 1);
    const val = Math.floor(progress * target);
    el.textContent = val;
    if (progress < 1) requestAnimationFrame(step);
    else el.textContent = target;
  };
  requestAnimationFrame(step);
}
document.querySelectorAll('[data-count]').forEach(el => {
  const target = parseInt(el.dataset.count, 10);
  if (!isNaN(target)) countUp(el, target, 1200);
});

// Sidebar active nav
const sections = document.querySelectorAll('section[id], header.report-header');
const navItems = document.querySelectorAll('.nav-item');
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      navItems.forEach(n => n.classList.remove('active'));
      const active = document.querySelector('.nav-item[href="#' + e.target.id + '"]');
      if (active) active.classList.add('active');
    }
  });
}, { threshold: 0.3, rootMargin: '-80px 0px -60% 0px' });
sections.forEach(s => observer.observe(s));

// Collapsible
function toggleCollapse(btn) {
  const content = btn.nextElementSibling;
  content.classList.toggle('open');
  btn.textContent = btn.textContent.includes('▾')
    ? btn.textContent.replace('▾', '▸')
    : btn.textContent.replace('▸', '▾');
}

// Accordion
function toggleAccordion(btn) {
  const content = btn.nextElementSibling;
  const isOpen = content.classList.contains('open');
  document.querySelectorAll('.accordion-content.open').forEach(c => {
    c.classList.remove('open');
    c.previousElementSibling.classList.remove('open');
  });
  if (!isOpen) { content.classList.add('open'); btn.classList.add('open'); }
}

// Findings filter
let currentSev = 'all', currentMod = 'all';

document.querySelectorAll('.sev-filters .filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.sev-filters .filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentSev = btn.dataset.sev;
    filterFindings();
  });
});
document.querySelectorAll('.mod-filters .filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.mod-filters .filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentMod = btn.dataset.module;
    filterFindings();
  });
});

function filterFindings() {
  const q = (document.getElementById('findingSearch')?.value || '').toLowerCase();
  document.querySelectorAll('.finding-card').forEach(card => {
    const sevOk = currentSev === 'all' || card.dataset.severity === currentSev;
    const modOk = currentMod === 'all' || card.dataset.module === currentMod;
    const textOk = !q || card.textContent.toLowerCase().includes(q);
    card.style.display = (sevOk && modOk && textOk) ? '' : 'none';
  });
}

// Copy finding
const findingsData = [];
function copyFinding(btn, idx) {
  const card = btn.closest('.finding-card');
  const text = card.innerText;
  navigator.clipboard?.writeText(text).then(() => {
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = '⎘', 1500);
  });
}
"""


# ─── Sidebar Nav Builder ──────────────────────────────────────────────────────

def build_sidebar(data):
    vn  = data.get("viewname_results")
    mjs = data.get("model_js_summary")
    return f"""
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="sl"><span class="out">OUT</span><span class="scan">SCAN</span></div>
    <div class="sl-sub">Security Report</div>
  </div>
  <span class="nav-section">Report</span>
  <a class="nav-item active" href="#platform">Platform Overview</a>
  <a class="nav-item" href="#summary">Executive Summary</a>
  {"<a class='nav-item' href='#viewname'>⚠ viewName Bypass</a>" if vn else ""}
  {"<a class='nav-item' href='#modeljs'>model.js Analysis</a>" if mjs else ""}
  <a class="nav-item" href="#findings">Findings</a>
  <a class="nav-item" href="#modules">Module Results</a>
  <a class="nav-item" href="#methodology">Methodology</a>
</nav>"""


# ─── Assembler ───────────────────────────────────────────────────────────────

def generate_html(data):
    meta     = data.get("meta", {})
    platform = data.get("platform", {})
    findings = data.get("findings", [])
    stats    = data.get("stats", {})
    vn       = data.get("viewname_results")
    mjs      = data.get("model_js_summary")

    sidebar  = build_sidebar(data)
    header   = build_header(meta)
    plat     = build_platform_overview(platform)
    exec_sum = build_executive_summary(stats, meta)
    vn_sec   = build_viewname_section(vn) if vn else ""
    mjs_sec  = build_modeljs_section(mjs) if mjs else ""
    find_sec = build_findings_section(findings)
    mod_sec  = build_modules_section(stats)
    meth_sec = build_methodology_section(meta, stats)
    footer   = build_footer(meta)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OutScan Report — {h(meta.get('target',''))}</title>
<style>{CSS}</style>
</head>
<body>
{sidebar}
<div class="main">
  {header}
  {plat}
  {exec_sum}
  {vn_sec}
  {mjs_sec}
  {find_sec}
  {mod_sec}
  {meth_sec}
  {footer}
</div>
<script>{JS}</script>
</body>
</html>"""


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 outscan_report.py scan_results.json output.html", file=sys.stderr)
        sys.exit(1)

    input_path  = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.isfile(input_path):
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[OutScan] Loading: {input_path}")
    data = load_json(input_path)

    print("[OutScan] Generating HTML report…")
    html_content = generate_html(data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    size_kb = os.path.getsize(output_path) / 1024
    findings = data.get("findings", [])
    stats    = data.get("stats", {})
    crit     = stats.get("findings_critical", 0)
    high     = stats.get("findings_high", 0)

    print(f"[OutScan] Report written: {output_path} ({size_kb:.1f} KB)")
    print(f"[OutScan] Findings: {len(findings)} total — {crit} critical, {high} high")
    print(f"[OutScan] Done.")


if __name__ == "__main__":
    main()
