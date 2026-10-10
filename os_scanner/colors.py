"""
OutScan terminal colors and output formatting.
HAAK Cybersecurity style — consistent with HaakWAF / HaakAuth / HaakJS.
"""
import sys
import os

# ─── Color constants ──────────────────────────────────────────────────────────

# Detect color support
_USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

class _C:
    """ANSI color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDER   = "\033[4m"

    # Foreground
    BLACK   = "\033[30m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"

    # Bright foreground
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"
    BMAGENTA= "\033[95m"
    BCYAN   = "\033[96m"
    BWHITE  = "\033[97m"

    # Background
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"
    BG_MAGENTA= "\033[45m"
    BG_CYAN   = "\033[46m"


def _c(code: str, text: str) -> str:
    """Apply color code if color is supported."""
    if _USE_COLOR:
        return f"{code}{text}{_C.RESET}"
    return text


# ─── Banner ───────────────────────────────────────────────────────────────────

BANNER = r"""
  ██████╗ ██╗   ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
 ██║   ██║██║   ██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╔╝╚██████╔╝   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

def banner(version: str = "1.0.0", quiet: bool = False) -> None:
    """Print the OutScan ASCII art banner."""
    if quiet:
        return
    art = _c(_C.BOLD + _C.BCYAN, BANNER.rstrip())
    title   = _c(_C.BOLD + _C.BWHITE, "  OutSystems Platform Security Scanner")
    author  = _c(_C.DIM  + _C.WHITE,  "  By Adrian Martinez | HAAK Cybersecurity")
    research= _c(_C.DIM  + _C.YELLOW, "  Based on original 0-day research")
    ver     = _c(_C.DIM  + _C.CYAN,   f"  v{version}")
    sep     = _c(_C.DIM  + _C.WHITE,  "  " + "─" * 55)
    print(art)
    print(title)
    print(author)
    print(research)
    print(ver)
    print(sep)
    print()


# ─── Message helpers ──────────────────────────────────────────────────────────

def msg_ok(text: str) -> None:
    """Green success message."""
    prefix = _c(_C.BOLD + _C.BGREEN, "[+]")
    print(f"{prefix} {text}")


def msg_fail(text: str) -> None:
    """Red failure / error message."""
    prefix = _c(_C.BOLD + _C.BRED, "[-]")
    print(f"{prefix} {text}")


def msg_info(text: str) -> None:
    """Cyan informational message."""
    prefix = _c(_C.BOLD + _C.BCYAN, "[*]")
    print(f"{prefix} {text}")


def msg_warn(text: str) -> None:
    """Yellow warning message."""
    prefix = _c(_C.BOLD + _C.BYELLOW, "[!]")
    print(f"{prefix} {text}")


def msg_debug(text: str) -> None:
    """Dim debug message."""
    prefix = _c(_C.DIM + _C.WHITE, "[~]")
    print(f"{prefix} {_c(_C.DIM, text)}")


# ─── Vulnerability output ─────────────────────────────────────────────────────

_SEVERITY_STYLES = {
    "critical": (_C.BOLD + _C.BG_RED   + _C.BWHITE,  "CRITICAL"),
    "high":     (_C.BOLD + _C.BRED,                   "HIGH    "),
    "medium":   (_C.BOLD + _C.BYELLOW,                "MEDIUM  "),
    "low":      (_C.BOLD + _C.BBLUE,                  "LOW     "),
    "info":     (_C.BOLD + _C.BCYAN,                  "INFO    "),
}

def msg_vuln(severity: str, title: str, detail: str = "") -> None:
    """Print a vulnerability finding with severity badge."""
    sev = severity.lower()
    style, label = _SEVERITY_STYLES.get(sev, (_C.BWHITE, sev.upper().ljust(8)))
    badge = _c(style, f" {label} ")
    title_str = _c(_C.BOLD + _C.BWHITE, title)
    print(f"  {badge} {title_str}")
    if detail:
        print(f"         {_c(_C.DIM, detail)}")


def msg_vuln_detail(key: str, value: str) -> None:
    """Print a key-value detail line under a vuln."""
    k = _c(_C.DIM + _C.CYAN, f"  {key}:")
    v = _c(_C.WHITE, str(value))
    print(f"  {k} {v}")


# ─── Section headers ──────────────────────────────────────────────────────────

def section(title: str) -> None:
    """Print a prominent section separator."""
    width = 60
    bar = "═" * width
    padded = f"  {title}  "
    side = "═" * ((width - len(padded)) // 2)
    header = f"{side}{padded}{side}"
    if len(header) < width:
        header += "═"
    print()
    print(_c(_C.BOLD + _C.BBLUE, f"╔{bar}╗"))
    print(_c(_C.BOLD + _C.BBLUE, f"║{header}║"))
    print(_c(_C.BOLD + _C.BBLUE, f"╚{bar}╝"))
    print()


def subsection(title: str) -> None:
    """Print a lighter subsection header."""
    line = _c(_C.BOLD + _C.BCYAN, f"  ── {title} {'─' * max(0, 50 - len(title))}")
    print(line)


# ─── Progress ─────────────────────────────────────────────────────────────────

def progress_bar(current: int, total: int, label: str = "", width: int = 30) -> None:
    """
    Print an in-place progress bar.
    Call with current == total for the final newline.
    """
    if total == 0:
        return
    filled = int(width * current / total)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * current / total)
    bar_str  = _c(_C.BCYAN, bar)
    pct_str  = _c(_C.BWHITE, f"{pct:3d}%")
    cnt_str  = _c(_C.DIM, f"{current}/{total}")
    lbl_str  = _c(_C.DIM, f" {label}" if label else "")
    line = f"\r  [{bar_str}] {pct_str} {cnt_str}{lbl_str}"
    if current >= total:
        print(line + " " * 10)
    else:
        print(line, end="", flush=True)


# ─── Table ────────────────────────────────────────────────────────────────────

def table(headers: list[str], rows: list[list[str]], title: str = "") -> None:
    """
    Print a formatted table.

    Args:
        headers: Column header strings.
        rows:    List of rows, each a list of strings.
        title:   Optional table title.
    """
    if not rows:
        msg_info("No results.")
        return

    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(cell)))

    sep = "  +" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_row = "  |" + "|".join(
        _c(_C.BOLD + _C.BCYAN, f" {h.ljust(col_widths[i])} ")
        for i, h in enumerate(headers)
    ) + "|"

    if title:
        print()
        print(_c(_C.BOLD + _C.BWHITE, f"  {title}"))
    print(sep)
    print(header_row)
    print(sep)

    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            val = str(cell)
            # Color severity cells
            sev = val.strip().lower()
            if sev in _SEVERITY_STYLES:
                style, _ = _SEVERITY_STYLES[sev]
                colored = _c(style, val.ljust(col_widths[i]))
            else:
                colored = val.ljust(col_widths[i])
            cells.append(f" {colored} ")
        print("  |" + "|".join(cells) + "|")

    print(sep)
    print()


# ─── Summary helpers ──────────────────────────────────────────────────────────

def print_summary(findings: list, elapsed: float, request_count: int) -> None:
    """Print a findings summary table and scan statistics."""
    from collections import Counter
    counts = Counter(f.severity.lower() for f in findings)

    section("SCAN SUMMARY")

    # Severity counts
    rows = []
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        n = counts.get(sev, 0)
        if n > 0:
            rows.append([sev.upper(), str(n)])

    if rows:
        table(["Severity", "Count"], rows, title="Findings by Severity")
    else:
        msg_ok("No vulnerabilities found.")

    # Stats line
    total = len(findings)
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    stat_line = (
        f"  Total: {_c(_C.BOLD + _C.BWHITE, str(total))} findings  |  "
        f"Requests: {_c(_C.BCYAN, str(request_count))}  |  "
        f"Time: {_c(_C.BCYAN, f'{elapsed:.1f}s')}"
    )
    print(stat_line)

    if critical:
        print()
        msg_vuln("critical", f"{critical} CRITICAL issue(s) require immediate attention")
    elif high:
        print()
        msg_warn(f"{high} HIGH severity issue(s) found")
    print()
