"""
sinkhole — static trust boundary analysis for Python ML/AI projects
Usage: python -m sinkhole <target_repo_path> [options]
"""

import argparse
import sys
import os
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sinkhole",
        description="Map trust boundary crossings in Python ML/AI projects",
    )
    parser.add_argument("target", help="Path to the repository to scan")
    parser.add_argument(
        "--severity",
        help="Comma-separated severity filter (e.g. CRITICAL,HIGH)",
        default=None,
    )
    parser.add_argument(
        "--category",
        help="Comma-separated category filter (e.g. CODE_EXEC,DESERIALIZATION)",
        default=None,
    )
    parser.add_argument(
        "--output",
        help="Path for JSON report output (default: sinkhole_report.json)",
        default="sinkhole_report.json",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show suggested fixes and chain steps in terminal output",
    )
    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Skip writing JSON report",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Generate an interactive attack graph HTML file alongside the JSON report",
    )
    return parser.parse_args()


def main():
    args = _parse_args()
    target = Path(args.target).resolve()

    if not target.exists():
        print(f"[sinkhole] error: target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)
    if not target.is_dir():
        print(f"[sinkhole] error: target must be a directory: {target}", file=sys.stderr)
        sys.exit(1)

    severity_filter: set[str] | None = None
    if args.severity:
        severity_filter = {s.strip().upper() for s in args.severity.split(",")}

    category_filter: set[str] | None = None
    if args.category:
        category_filter = {c.strip().upper() for c in args.category.split(",")}

    # Lazy imports so startup is fast even if something is wrong
    from .core.ast_walker import walk_repo
    from .core.flow_tracker import analyze_file
    from .rules.ml_specific import run_ml_rules
    from .rules.general import run_general_rules
    from .output.reporter import print_terminal_report, write_json_report
    from .output.graph_builder import build_graph
    from .output.graph_renderer import render

    print(f"[sinkhole] scanning {target} ...")
    parsed_files = walk_repo(target)
    print(f"[sinkhole] found {len(parsed_files)} Python files")

    all_findings = []
    for pf in parsed_files:
        all_findings.extend(analyze_file(pf))
        all_findings.extend(run_ml_rules(pf))
        all_findings.extend(run_general_rules(pf))

    # Deduplicate by (sink_file, sink_line, category, source_variable)
    seen: set[tuple] = set()
    deduped = []
    for f in all_findings:
        key = (f.sink_file, f.sink_line, f.category, f.source_variable, f.sink_function)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Apply filters
    findings = deduped
    if severity_filter:
        findings = [f for f in findings if f.severity in severity_filter]
    if category_filter:
        findings = [f for f in findings if f.category in category_filter]

    print_terminal_report(findings, str(target), verbose=args.verbose)

    if not args.no_json:
        write_json_report(findings, args.output, str(target))
        print(f"[sinkhole] JSON report written to {args.output}")

        if args.graph:
            graph_path = str(Path(args.output).with_suffix(".html").with_stem(
                Path(args.output).stem.replace("sinkhole_report", "attack_graph")
                if "sinkhole_report" in Path(args.output).stem
                else Path(args.output).stem + "_graph"
            ))
            graph = build_graph(args.output)
            render(graph, graph_path)
            print(f"[sinkhole] attack graph written to {graph_path}")

    # Exit code: non-zero if CRITICAL or HIGH findings
    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
