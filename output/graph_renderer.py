"""
Render a sinkhole graph dict as a self-contained HTML attack graph (vis.js).
"""

import json
from pathlib import Path


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SINKHOLE // ATTACK GRAPH — {TARGET}</title>
<link rel="stylesheet"
  href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/dist/vis-network.min.css">
<script
  src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/dist/vis-network.min.js">
</script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; background: #0d1117; color: #e6edf3; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; }

  #toolbar {
    display: flex; align-items: center; flex-wrap: wrap; gap: 10px;
    padding: 10px 16px; background: #161b22; border-bottom: 1px solid #30363d;
    z-index: 10; position: relative;
  }
  #toolbar .title { font-size: 15px; font-weight: 700; color: #58a6ff; letter-spacing: 1px; }
  #toolbar .stats { display: flex; gap: 8px; flex-wrap: wrap; }
  #toolbar .stat { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .stat-total  { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
  .stat-critical { background: #3d0000; color: #ff7b72; border: 1px solid #6e1f1f; }
  .stat-high   { background: #2e1a00; color: #ffa657; border: 1px solid #5a3400; }
  .stat-medium { background: #1c2a00; color: #e3b341; border: 1px solid #3a4a00; }
  .stat-low    { background: #001a2e; color: #79c0ff; border: 1px solid #003a5e; }
  #toolbar .target-badge { color: #8b949e; font-size: 11px; }

  .filters { display: flex; gap: 6px; margin-left: auto; align-items: center; }
  .filters span { color: #8b949e; font-size: 11px; }
  .filter-btn {
    padding: 3px 10px; border-radius: 4px; border: 1px solid transparent;
    cursor: pointer; font-family: inherit; font-size: 11px; font-weight: 600;
    transition: opacity 0.15s, border-color 0.15s;
  }
  .filter-btn.inactive { opacity: 0.35; }
  .filter-btn.f-all    { background: #21262d; color: #c9d1d9; border-color: #30363d; }
  .filter-btn.f-critical { background: #3d0000; color: #ff7b72; border-color: #6e1f1f; }
  .filter-btn.f-high   { background: #2e1a00; color: #ffa657; border-color: #5a3400; }
  .filter-btn.f-medium { background: #1c2a00; color: #e3b341; border-color: #3a4a00; }
  .filter-btn.f-low    { background: #001a2e; color: #79c0ff; border-color: #003a5e; }

  #canvas-wrap { position: relative; flex: 1; overflow: hidden; }
  #network { width: 100%; height: 100%; }

  #loading {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center; background: #0d1117;
    z-index: 5; gap: 12px;
  }
  #loading .spinner {
    width: 36px; height: 36px; border: 3px solid #30363d;
    border-top-color: #58a6ff; border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  #loading .load-text { color: #8b949e; font-size: 12px; }

  #info-card {
    position: absolute; top: 12px; right: 12px; width: 300px;
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 14px; display: none; z-index: 20;
    box-shadow: 0 8px 32px rgba(0,0,0,0.6);
    max-height: calc(100% - 24px); overflow-y: auto;
  }
  #info-card .card-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
  #info-card .type-badge {
    padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .badge-source   { background: #0e3d20; color: #3fb950; border: 1px solid #2ea043; }
  .badge-sink     { background: #3d0000; color: #ff7b72; border: 1px solid #6e1f1f; }
  .badge-intermediate { background: #1c2228; color: #8b949e; border: 1px solid #30363d; }
  .sev-badge {
    padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700;
    text-transform: uppercase; margin-left: auto;
  }
  .sev-CRITICAL { background: #3d0000; color: #ff7b72; border: 1px solid #6e1f1f; }
  .sev-HIGH     { background: #2e1a00; color: #ffa657; border: 1px solid #5a3400; }
  .sev-MEDIUM   { background: #1c2a00; color: #e3b341; border: 1px solid #3a4a00; }
  .sev-LOW      { background: #001a2e; color: #79c0ff; border: 1px solid #003a5e; }
  .sev-NONE     { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
  #info-card .card-loc { color: #8b949e; font-size: 11px; margin-bottom: 8px; word-break: break-all; }
  #info-card .card-detail {
    background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
    padding: 8px; font-size: 11px; color: #c9d1d9;
    white-space: pre-wrap; word-break: break-all; margin-bottom: 8px;
  }
  #info-card .card-findings { display: flex; flex-wrap: wrap; gap: 4px; }
  #info-card .fid-chip {
    padding: 1px 6px; border-radius: 3px; font-size: 10px;
    background: #21262d; color: #8b949e; border: 1px solid #30363d;
  }
  #info-card .card-close {
    position: absolute; top: 10px; right: 10px; background: none; border: none;
    color: #8b949e; cursor: pointer; font-size: 16px; line-height: 1;
  }
  #info-card .card-close:hover { color: #e6edf3; }
  #info-card .card-hint { color: #484f58; font-size: 10px; margin-top: 6px; }

  #legend {
    display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
    padding: 7px 16px; background: #161b22; border-top: 1px solid #30363d;
  }
  .legend-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #8b949e; }
  .legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }
  .legend-box { width: 14px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .l-source   { background: #2ea043; }
  .l-critical { background: #6e1f1f; border: 1px solid #ff7b72; border-radius: 2px; }
  .l-high     { background: #5a3400; border: 1px solid #ffa657; border-radius: 2px; }
  .l-medium   { background: #3a4a00; border: 1px solid #e3b341; border-radius: 2px; }
  .l-low      { background: #003a5e; border: 1px solid #79c0ff; border-radius: 2px; }
  .l-intermediate { background: #30363d; border-radius: 50%; }

  body { display: flex; flex-direction: column; }
  #canvas-wrap { flex: 1; }
</style>
</head>
<body>

<div id="toolbar">
  <span class="title">SINKHOLE // ATTACK GRAPH</span>
  <div class="stats">
    <span class="stat stat-total">TOTAL <strong id="s-total">0</strong></span>
    <span class="stat stat-critical">CRITICAL <strong id="s-critical">0</strong></span>
    <span class="stat stat-high">HIGH <strong id="s-high">0</strong></span>
    <span class="stat stat-medium">MEDIUM <strong id="s-medium">0</strong></span>
    <span class="stat stat-low">LOW <strong id="s-low">0</strong></span>
  </div>
  <span class="target-badge" id="target-label"></span>
  <div class="filters">
    <span>filter:</span>
    <button class="filter-btn f-all"      onclick="filterAll()">ALL</button>
    <button class="filter-btn f-critical" onclick="toggleFilter('CRITICAL')" data-sev="CRITICAL">CRIT</button>
    <button class="filter-btn f-high"     onclick="toggleFilter('HIGH')"     data-sev="HIGH">HIGH</button>
    <button class="filter-btn f-medium"   onclick="toggleFilter('MEDIUM')"   data-sev="MEDIUM">MED</button>
    <button class="filter-btn f-low"      onclick="toggleFilter('LOW')"      data-sev="LOW">LOW</button>
  </div>
</div>

<div id="canvas-wrap">
  <div id="loading">
    <div class="spinner"></div>
    <div class="load-text">Laying out graph&hellip;</div>
  </div>
  <div id="network"></div>

  <div id="info-card">
    <button class="card-close" onclick="closeCard()">&#x2715;</button>
    <div class="card-header">
      <span class="type-badge" id="c-type"></span>
      <span class="sev-badge"  id="c-sev"></span>
    </div>
    <div class="card-loc" id="c-loc"></div>
    <div class="card-detail" id="c-detail"></div>
    <div class="card-findings" id="c-findings"></div>
    <div class="card-hint">double-click canvas to reset highlight</div>
  </div>
</div>

<div id="legend">
  <div class="legend-item"><div class="legend-dot l-source"></div> Source (untrusted input)</div>
  <div class="legend-item"><div class="legend-box l-critical"></div> Sink — CRITICAL</div>
  <div class="legend-item"><div class="legend-box l-high"></div> Sink — HIGH</div>
  <div class="legend-item"><div class="legend-box l-medium"></div> Sink — MEDIUM</div>
  <div class="legend-item"><div class="legend-box l-low"></div> Sink — LOW</div>
  <div class="legend-item"><div class="legend-dot l-intermediate"></div> Intermediate step</div>
</div>

<script>
const GRAPH = __GRAPH_JSON__;

const NODE_COLORS = {
  source:       { bg: '#0e3d20', border: '#2ea043', font: '#3fb950' },
  sink: {
    CRITICAL:   { bg: '#3d0000', border: '#ff7b72', font: '#ff7b72' },
    HIGH:       { bg: '#2e1a00', border: '#ffa657', font: '#ffa657' },
    MEDIUM:     { bg: '#1c2a00', border: '#e3b341', font: '#e3b341' },
    LOW:        { bg: '#001a2e', border: '#79c0ff', font: '#79c0ff' },
  },
  intermediate: { bg: '#1c2228', border: '#30363d', font: '#8b949e' },
  dim:          { bg: '#0d1117', border: '#21262d', font: '#30363d' },
  dimEdge:      '#161b22',
};

const EDGE_COLOR_ACTIVE  = '#30363d';
const EDGE_COLOR_HIGHLIGHT = '#58a6ff';

function nodeColor(n) {
  if (n.type === 'source')       return NODE_COLORS.source;
  if (n.type === 'sink')         return NODE_COLORS.sink[n.severity] || NODE_COLORS.sink.LOW;
  return NODE_COLORS.intermediate;
}

function toVisNode(n) {
  const c = nodeColor(n);
  const isSource = n.type === 'source';
  const isSink   = n.type === 'sink';
  return {
    id: n.id,
    label: n.label,
    shape: isSource ? 'ellipse' : isSink ? 'box' : 'dot',
    size: isSource ? 18 : isSink ? undefined : 8,
    color: { background: c.bg, border: c.border, highlight: { background: c.bg, border: '#e6edf3' } },
    font: { color: c.font, size: isSink ? 11 : 10, face: 'ui-monospace,Consolas,monospace', multi: false },
    borderWidth: isSink ? 2 : 1,
    _orig: { color: { background: c.bg, border: c.border }, font: { color: c.font } },
  };
}

function toVisEdge(e) {
  return {
    id: e.id,
    from: e.from,
    to: e.to,
    label: e.label,
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
    color: { color: EDGE_COLOR_ACTIVE, highlight: EDGE_COLOR_HIGHLIGHT },
    font: { color: '#484f58', size: 9, face: 'ui-monospace,Consolas,monospace', strokeWidth: 0 },
    smooth: { type: 'curvedCW', roundness: 0.1 },
    _orig: { color: { color: EDGE_COLOR_ACTIVE } },
  };
}

// ── Populate toolbar stats ─────────────────────────────────────────────────
const meta = GRAPH.meta;
document.getElementById('s-total').textContent    = meta.total_findings;
document.getElementById('s-critical').textContent = meta.critical;
document.getElementById('s-high').textContent     = meta.high;
document.getElementById('s-medium').textContent   = meta.medium;
document.getElementById('s-low').textContent      = meta.low;
document.getElementById('target-label').textContent = '▸ ' + meta.target;

// ── Build vis DataSets ─────────────────────────────────────────────────────
const visNodes = new vis.DataSet(GRAPH.nodes.map(toVisNode));
const visEdges = new vis.DataSet(GRAPH.edges.map(toVisEdge));

// ── Finding → node/edge maps (for chain highlight) ─────────────────────────
const findingNodeMap = {};  // finding_id -> Set<node_id>
const findingEdgeMap = {};  // finding_id -> Set<edge_id>
GRAPH.nodes.forEach(n => {
  (n.findings || []).forEach(f => {
    if (!findingNodeMap[f.id]) findingNodeMap[f.id] = new Set();
    findingNodeMap[f.id].add(n.id);
  });
});
GRAPH.edges.forEach(e => {
  (e.findings || []).forEach(f => {
    if (!findingEdgeMap[f.id]) findingEdgeMap[f.id] = new Set();
    findingEdgeMap[f.id].add(e.id);
  });
});

// Quick lookup: node_id -> raw node data
const nodeMap = {};
GRAPH.nodes.forEach(n => { nodeMap[n.id] = n; });

// ── vis.Network ────────────────────────────────────────────────────────────
const container = document.getElementById('network');
const network = new vis.Network(container, { nodes: visNodes, edges: visEdges }, {
  physics: {
    enabled: true,
    solver: 'forceAtlas2Based',
    forceAtlas2Based: {
      gravitationalConstant: -60,
      centralGravity: 0.005,
      springLength: 120,
      springConstant: 0.06,
      damping: 0.5,
    },
    stabilization: { iterations: 300, updateInterval: 30 },
  },
  interaction: {
    hover: true,
    tooltipDelay: 200,
    zoomView: true,
    dragView: true,
  },
  edges: { width: 1.2 },
  nodes: { margin: { top: 6, bottom: 6, left: 8, right: 8 } },
  layout: { improvedLayout: false },
});

network.on('stabilizationIterationsDone', () => {
  network.setOptions({ physics: { enabled: false } });
  document.getElementById('loading').style.display = 'none';
});

// ── Highlight chain ────────────────────────────────────────────────────────
function highlightChain(clickedNodeId) {
  const raw = nodeMap[clickedNodeId];
  if (!raw) return;

  // Collect all node/edge ids in every finding that touches this node
  const activeNodeIds = new Set();
  const activeEdgeIds = new Set();
  (raw.findings || []).forEach(f => {
    (findingNodeMap[f.id] || new Set()).forEach(nid => activeNodeIds.add(nid));
    (findingEdgeMap[f.id] || new Set()).forEach(eid => activeEdgeIds.add(eid));
  });

  // Dim all, then restore active
  const allNodeUpdates = visNodes.getIds().map(nid => {
    if (activeNodeIds.has(nid)) {
      const orig = nodeMap[nid];
      const c = nodeColor(orig);
      return { id: nid, color: { background: c.bg, border: c.border }, font: { color: c.font }, opacity: 1.0 };
    }
    return { id: nid, color: NODE_COLORS.dim, font: { color: NODE_COLORS.dim.font }, opacity: 0.25 };
  });
  const allEdgeUpdates = visEdges.getIds().map(eid => {
    if (activeEdgeIds.has(eid)) {
      return { id: eid, color: { color: EDGE_COLOR_HIGHLIGHT }, opacity: 1.0, width: 2 };
    }
    return { id: eid, color: { color: NODE_COLORS.dimEdge }, opacity: 0.15, width: 0.8 };
  });

  visNodes.update(allNodeUpdates);
  visEdges.update(allEdgeUpdates);
}

function resetHighlight() {
  const nodeUpdates = GRAPH.nodes.map(n => {
    const c = nodeColor(n);
    return { id: n.id, color: { background: c.bg, border: c.border }, font: { color: c.font }, opacity: 1.0 };
  });
  const edgeUpdates = GRAPH.edges.map(e => ({
    id: e.id, color: { color: EDGE_COLOR_ACTIVE }, opacity: 1.0, width: 1.2,
  }));
  visNodes.update(nodeUpdates);
  visEdges.update(edgeUpdates);
}

// ── Info card ─────────────────────────────────────────────────────────────
function showCard(nodeId) {
  const raw = nodeMap[nodeId];
  if (!raw) return;

  document.getElementById('c-type').textContent = raw.type.toUpperCase();
  document.getElementById('c-type').className = 'type-badge badge-' + raw.type;

  const topSev = topSeverity(raw.findings);
  const sevEl = document.getElementById('c-sev');
  sevEl.textContent = topSev || raw.severity || '';
  sevEl.className = 'sev-badge sev-' + (topSev || raw.severity || 'NONE');

  document.getElementById('c-loc').textContent = raw.file + ':' + raw.line;
  document.getElementById('c-detail').textContent = raw.detail || '';

  const findingsEl = document.getElementById('c-findings');
  findingsEl.innerHTML = '';
  (raw.findings || []).forEach(f => {
    const chip = document.createElement('span');
    chip.className = 'fid-chip';
    chip.textContent = f.id;
    findingsEl.appendChild(chip);
  });

  document.getElementById('info-card').style.display = 'block';
}

function closeCard() {
  document.getElementById('info-card').style.display = 'none';
}

function topSeverity(findings) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  if (!findings || !findings.length) return null;
  const sevs = new Set(findings.map(f => f.severity));
  return order.find(s => sevs.has(s)) || null;
}

// ── Network events ─────────────────────────────────────────────────────────
network.on('click', params => {
  if (params.nodes.length > 0) {
    highlightChain(params.nodes[0]);
    showCard(params.nodes[0]);
  } else {
    closeCard();
  }
});

network.on('doubleClick', () => {
  resetHighlight();
  closeCard();
});

// ── Severity filters ───────────────────────────────────────────────────────
let activeSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

function applyFilters() {
  // Hidden node ids
  const hiddenNodes = new Set();
  const nodeUpdates = GRAPH.nodes.map(n => {
    const sevs = (n.findings || []).map(f => f.severity);
    const visible = sevs.some(s => activeSeverities.has(s));
    if (!visible) hiddenNodes.add(n.id);
    return { id: n.id, hidden: !visible };
  });
  visNodes.update(nodeUpdates);

  const edgeUpdates = GRAPH.edges.map(e => ({
    id: e.id,
    hidden: hiddenNodes.has(e.from) || hiddenNodes.has(e.to),
  }));
  visEdges.update(edgeUpdates);

  // Update button states
  ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(sev => {
    const btn = document.querySelector(`.filter-btn[data-sev="${sev}"]`);
    if (btn) btn.classList.toggle('inactive', !activeSeverities.has(sev));
  });
}

function toggleFilter(sev) {
  if (activeSeverities.has(sev)) {
    if (activeSeverities.size === 1) return; // keep at least one
    activeSeverities.delete(sev);
  } else {
    activeSeverities.add(sev);
  }
  applyFilters();
  resetHighlight();
  closeCard();
}

function filterAll() {
  activeSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
  applyFilters();
  resetHighlight();
  closeCard();
}
</script>
</body>
</html>
"""


def render(graph: dict, output_path: str) -> None:
    html = _build_html(graph)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


def _build_html(graph: dict) -> str:
    target = graph.get("meta", {}).get("target", "unknown")
    graph_json = json.dumps(graph, ensure_ascii=False).replace("</", "<\\/")
    return (
        _HTML_TEMPLATE
        .replace("{TARGET}", target)
        .replace("__GRAPH_JSON__", graph_json)
    )
