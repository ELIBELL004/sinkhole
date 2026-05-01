"""
Build a vis.js-compatible graph data structure from a sinkhole_report.json.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path


def _nid(node_type: str, file: str, line: int, extra: str = "") -> str:
    raw = f"{node_type}:{file}:{line}:{extra}"
    return "n" + hashlib.md5(raw.encode()).hexdigest()[:10]


def _short_file(file: str) -> str:
    """Last 2 path components for display labels."""
    parts = Path(file).parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else file


def build_graph(report_path: str) -> dict:
    """Read a sinkhole JSON report and return a graph dict for the renderer."""
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    findings = report.get("findings", [])
    target = report.get("target", Path(report_path).stem)

    # node_id -> node dict  (deduped by file+line+type)
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    # (from_id, to_id) -> edge_id  (deduplication)
    edge_seen: dict[tuple, str] = {}

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def upsert_node(
        nid: str, label: str, node_type: str, severity: str,
        file: str, line: int, detail: str, finding_ref: dict,
    ) -> None:
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "label": label,
                "type": node_type,
                "severity": severity,
                "file": file,
                "line": line,
                "detail": detail,
                # findings: [{id, severity}] — used by JS for chain highlight + filters
                "findings": [],
            }
        # Avoid duplicate finding refs on the same node
        if not any(f["id"] == finding_ref["id"] for f in nodes[nid]["findings"]):
            nodes[nid]["findings"].append(finding_ref)

    def upsert_edge(
        from_id: str, to_id: str, label: str, finding_ref: dict,
    ) -> None:
        key = (from_id, to_id)
        if key not in edge_seen:
            eid = f"e{len(edges)}"
            edge_seen[key] = eid
            edges.append({
                "id": eid,
                "from": from_id,
                "to": to_id,
                "label": label,
                "findings": [finding_ref],
            })
        else:
            eid = edge_seen[key]
            edge = next(e for e in edges if e["id"] == eid)
            if not any(f["id"] == finding_ref["id"] for f in edge["findings"]):
                edge["findings"].append(finding_ref)

    for finding in findings:
        fid = finding["finding_id"]
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1
        finding_ref = {"id": fid, "severity": severity}

        src = finding["source"]
        sink = finding["sink"]
        chain = finding.get("chain", [])

        # ── Source node ────────────────────────────────────────────────────
        src_id = _nid("src", src["file"], src["line"])
        src_file_short = _short_file(src["file"])
        src_label = f"{src['variable']}\n{src_file_short}:{src['line']}"
        src_detail = (
            f"[{src['type']}] {src['variable']}\n"
            f"{src['file']}:{src['line']}"
        )
        upsert_node(src_id, src_label, "source", severity,
                    src["file"], src["line"], src_detail, finding_ref)

        # ── Sink node ──────────────────────────────────────────────────────
        # Include sink.function in the dedup key: two different sinks at same
        # line (e.g. chained calls) should be separate nodes.
        sink_id = _nid("sink", sink["file"], sink["line"], sink["function"])
        sink_file_short = _short_file(sink["file"])
        func_short = sink["function"].split(".")[-1]
        sink_label = f"{func_short}()\n{sink_file_short}:{sink['line']}"
        sink_detail = (
            f"[{finding['category']}] {sink['function']}()\n"
            f"{sink['file']}:{sink['line']}\n"
            f"{finding['description']}\n"
            f"Fix: {finding['suggested_fix']}"
        )
        upsert_node(sink_id, sink_label, "sink", severity,
                    sink["file"], sink["line"], sink_detail, finding_ref)

        # ── Intermediate (chain) nodes ─────────────────────────────────────
        prev_id = src_id
        for step in chain:
            # Skip steps that are the same location as source or sink
            if step["file"] == src["file"] and step["line"] == src["line"]:
                continue
            if step["file"] == sink["file"] and step["line"] == sink["line"]:
                continue

            mid_id = _nid("intermediate", step["file"], step["line"])
            code = step.get("code", "")
            code_trunc = (code[:28] + "...") if len(code) > 28 else code
            mid_file_short = _short_file(step["file"])
            mid_label = code_trunc if code_trunc else f":{step['line']}"
            mid_detail = f"{step['file']}:{step['line']}\n{code}"
            upsert_node(mid_id, mid_label, "intermediate", severity,
                        step["file"], step["line"], mid_detail, finding_ref)

            upsert_edge(prev_id, mid_id, "flows", finding_ref)
            prev_id = mid_id

        # ── Edge to sink ───────────────────────────────────────────────────
        edge_label = finding["category"].lower().replace("_", " ")
        upsert_edge(prev_id, sink_id, edge_label, finding_ref)

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "meta": {
            "target": target,
            "total_findings": report.get("total", len(findings)),
            "critical": counts.get("CRITICAL", 0),
            "high":     counts.get("HIGH", 0),
            "medium":   counts.get("MEDIUM", 0),
            "low":      counts.get("LOW", 0),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }
