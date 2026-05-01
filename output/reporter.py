import json
import sys
from collections import defaultdict
from pathlib import Path

from ..core.flow_tracker import Finding
from ..core.sinks import Severity

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


SEVERITY_ORDER = [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value]

_COLORS = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[33m",   # yellow
    "MEDIUM":   "\033[36m",   # cyan
    "LOW":      "\033[37m",   # white
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "GREEN":    "\033[92m",
}


def _c(color: str, text: str) -> str:
    if not HAS_COLOR and sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['RESET']}"


def _short_path(path: str, repo_root: str) -> str:
    try:
        return str(Path(path).relative_to(repo_root))
    except ValueError:
        return path


def print_terminal_report(findings: list[Finding], repo_root: str, verbose: bool = False):
    if not findings:
        print(_c("GREEN", "\n  No findings. Clean scan.\n"))
        return

    by_severity: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    total = len(findings)
    counts = {s: len(by_severity.get(s, [])) for s in SEVERITY_ORDER}

    print()
    print(_c("BOLD", "=" * 70))
    print(_c("BOLD", " SINKHOLE -- Trust Boundary Analysis"))
    print(_c("BOLD", "=" * 70))
    print(f"  Total findings: {_c('BOLD', str(total))}")
    for sev in SEVERITY_ORDER:
        if counts[sev]:
            print(f"    {_c(sev, sev):30s} {counts[sev]}")
    print()

    for sev in SEVERITY_ORDER:
        group = by_severity.get(sev, [])
        if not group:
            continue
        print(_c(sev, f"-- {sev} ({len(group)}) " + "-" * (55 - len(sev))))
        for f in group:
            src_short = _short_path(f.source_file, repo_root)
            sink_short = _short_path(f.sink_file, repo_root)
            print(
                f"  {_c('BOLD', f.finding_id)}  {_c('DIM', f.category)}\n"
                f"    {_c('DIM', 'src')}  {src_short}:{f.source_line}  "
                f"{_c('DIM', f'[{f.source_type}]')} {_c('BOLD', f.source_variable)}\n"
                f"    {_c('DIM', 'sink')} {sink_short}:{f.sink_line}  "
                f"{_c('DIM', f.sink_function)}\n"
                f"    {_c('DIM', f.description)}"
            )
            if verbose and f.suggested_fix:
                print(f"    {_c('GREEN', 'fix:')} {f.suggested_fix}")
            if verbose and f.chain:
                for step in f.chain:
                    step_short = _short_path(step.file, repo_root)
                    print(f"    {_c('DIM', '->')} {step_short}:{step.line}  {step.code}")
            print()


def write_json_report(findings: list[Finding], output_path: str, repo_root: str):
    data = {
        "tool": "sinkhole",
        "target": Path(repo_root).name,
        "total": len(findings),
        "findings": [
            {
                "finding_id": f.finding_id,
                "severity": f.severity,
                "category": f.category,
                "source": {
                    "file": _short_path(f.source_file, repo_root),
                    "line": f.source_line,
                    "type": f.source_type,
                    "variable": f.source_variable,
                },
                "sink": {
                    "file": _short_path(f.sink_file, repo_root),
                    "line": f.sink_line,
                    "type": f.sink_type,
                    "function": f.sink_function,
                },
                "chain": [
                    {
                        "file": _short_path(s.file, repo_root),
                        "line": s.line,
                        "code": s.code,
                    }
                    for s in f.chain
                ],
                "description": f.description,
                "suggested_fix": f.suggested_fix,
            }
            for f in findings
        ],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
