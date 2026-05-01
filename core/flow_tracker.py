"""
Intra-file taint tracking: identify tainted variable names, then check if
they reach sinks without passing through sanitizers.

Strategy: single-pass AST walk per file.
1. Collect all assignments where the RHS is a known source call/attr.
2. Propagate taint through assignments (A = tainted_var).
3. Check each Call node: if any arg/kwarg is tainted and the call is a sink → finding.
4. Special handling for prompt injection (f-strings / .format with tainted vars).
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path

from .ast_walker import ParsedFile, resolve_import_alias, attr_chain, get_line
from .sinks import Sink, Category, get_sinks_for_func, get_sinks_for_module_func, SINKS
from .sources import (
    SourceType, TAINTED_VARNAMES, TAINTED_CALL_NAMES, REQUEST_TAINT_ATTRS,
    SOURCE_PATTERNS,
)


SANITIZER_NAMES: frozenset[str] = frozenset({
    "normpath", "abspath", "realpath", "resolve",
    "escape", "quote", "secure_filename", "clean",
    "sanitize", "validate", "sanitise", "safe_encode",
    "bleach_clean",
})

SANITIZER_KEYWORDS: tuple[str, ...] = (
    "sanitize", "sanitise", "validate", "clean", "escape", "safe",
)

PROMPT_KEYWORDS: tuple[str, ...] = (
    "system", "instruction", "role", "assistant", "you are", "your task",
    "system_prompt", "sys_prompt", "system_message",
)


@dataclass
class ChainStep:
    file: str
    line: int
    code: str


@dataclass
class Finding:
    finding_id: str
    severity: str
    category: str
    source_file: str
    source_line: int
    source_type: str
    source_variable: str
    sink_file: str
    sink_line: int
    sink_type: str
    sink_function: str
    chain: list[ChainStep]
    description: str
    suggested_fix: str


_finding_counter = 0


def _next_id() -> str:
    global _finding_counter
    _finding_counter += 1
    return f"SINK-{_finding_counter:04d}"


def _is_sanitizer_call(node: ast.expr) -> bool:
    """Return True if node is a call to a known sanitizer."""
    if not isinstance(node, ast.Call):
        return False
    chain = attr_chain(node.func)
    if chain is None:
        return False
    last = chain.split(".")[-1].lower()
    if last in SANITIZER_NAMES:
        return True
    for kw in SANITIZER_KEYWORDS:
        if kw in last:
            return True
    return False


def _name_looks_like_sanitized(name: str) -> bool:
    n = name.lower()
    for kw in SANITIZER_KEYWORDS:
        if kw in n:
            return True
    return False


class FileAnalyzer(ast.NodeVisitor):
    def __init__(self, parsed: ParsedFile):
        self.parsed = parsed
        self.file_str = str(parsed.path)
        self.import_aliases = resolve_import_alias(parsed.tree)
        # varname → (source_line, source_type, source_varname)
        self.tainted: dict[str, tuple[int, str, str]] = {}
        self.findings: list[Finding] = []
        self._scope_stack: list[dict[str, tuple[int, str, str]]] = []

    # ------------------------------------------------------------------ #
    # Taint propagation helpers                                            #
    # ------------------------------------------------------------------ #

    def _is_tainted_node(self, node: ast.expr) -> bool:
        """Return True if node evaluates to tainted data."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.Attribute):
            # request.args, request.form, etc.
            if node.attr in REQUEST_TAINT_ATTRS:
                return True
            owner = attr_chain(node.value) if isinstance(node.value, ast.expr) else None
            if owner and owner in self.tainted:
                return True
        if isinstance(node, ast.Call):
            chain = attr_chain(node.func) if node.func else None
            if chain:
                last = chain.split(".")[-1]
                if last in TAINTED_CALL_NAMES:
                    return True
            if _is_sanitizer_call(node):
                return False
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Add)):
            return self._any_arg_tainted(self._flatten_fstring(node))
        if isinstance(node, ast.Subscript):
            return self._is_tainted_node(node.value)
        return False

    def _flatten_fstring(self, node: ast.expr) -> list[ast.expr]:
        """Extract all value nodes from a JoinedStr (f-string)."""
        if isinstance(node, ast.JoinedStr):
            return [v for v in node.values if isinstance(v, ast.FormattedValue)]
        return []

    def _any_arg_tainted(self, nodes: list[ast.expr]) -> bool:
        return any(self._is_tainted_node(n.value if isinstance(n, ast.FormattedValue) else n) for n in nodes)

    def _taint_info(self, name: str) -> tuple[int, str, str]:
        return self.tainted.get(name, (0, "UNKNOWN", name))

    def _resolve_module(self, chain: str) -> str:
        """Resolve 'np.load' → 'numpy.load' using import aliases."""
        parts = chain.split(".")
        if parts[0] in self.import_aliases:
            parts[0] = self.import_aliases[parts[0]]
        return ".".join(parts)

    # ------------------------------------------------------------------ #
    # Source detection                                                     #
    # ------------------------------------------------------------------ #

    def _node_is_source(self, node: ast.expr) -> tuple[bool, str, str]:
        """Return (is_source, source_type_str, description)."""
        if isinstance(node, ast.Name):
            if node.id in TAINTED_VARNAMES:
                return True, SourceType.USER_CONTENT.value, f"tainted varname: {node.id}"
        if isinstance(node, ast.Attribute):
            if node.attr in REQUEST_TAINT_ATTRS:
                return True, SourceType.HTTP_INPUT.value, f"request.{node.attr}"
            ch = attr_chain(node)
            if ch:
                resolved = self._resolve_module(ch)
                for sp in SOURCE_PATTERNS:
                    if sp.attr and resolved.endswith(sp.attr):
                        return True, sp.source_type.value, sp.description
        if isinstance(node, ast.Call):
            ch = attr_chain(node.func) if node.func else None
            if ch:
                resolved = self._resolve_module(ch)
                last = resolved.split(".")[-1]
                if last in TAINTED_CALL_NAMES:
                    return True, SourceType.RAG_RETRIEVAL.value, f"call: {ch}"
                for sp in SOURCE_PATTERNS:
                    if sp.attr and (resolved.endswith(sp.attr) or last == sp.attr.split(".")[-1]):
                        return True, sp.source_type.value, sp.description
                # sys.argv subscript propagation handled separately
        return False, "", ""

    # ------------------------------------------------------------------ #
    # AST visitors                                                         #
    # ------------------------------------------------------------------ #

    def visit_Assign(self, node: ast.Assign):
        is_src, src_type, src_desc = self._node_is_source(node.value)
        # Also propagate taint if RHS contains tainted names
        if not is_src:
            is_src = self._is_tainted_node(node.value)
            if is_src:
                # pick up source info from the tainted var
                for n in ast.walk(node.value):
                    if isinstance(n, ast.Name) and n.id in self.tainted:
                        _, src_type, src_desc = self._taint_info(n.id)
                        break
                if not src_type:
                    src_type = SourceType.USER_CONTENT.value
                    src_desc = "propagated taint"

        for target in node.targets:
            if isinstance(target, ast.Name):
                if is_src and not _name_looks_like_sanitized(target.id):
                    self.tainted[target.id] = (node.lineno, src_type, src_desc)
                elif target.id in self.tainted and _is_sanitizer_call(node.value):
                    del self.tainted[target.id]

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is None:
            return
        is_src, src_type, src_desc = self._node_is_source(node.value)
        if not is_src:
            is_src = self._is_tainted_node(node.value)
            src_type = src_type or SourceType.USER_CONTENT.value
            src_desc = src_desc or "propagated taint"
        if isinstance(node.target, ast.Name) and is_src:
            if not _name_looks_like_sanitized(node.target.id):
                self.tainted[node.target.id] = (node.lineno, src_type, src_desc)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        self._check_sink_call(node)
        self.generic_visit(node)

    def _check_sink_call(self, node: ast.Call):
        ch = attr_chain(node.func)
        if ch is None:
            # Could be a Name node (builtin)
            if isinstance(node.func, ast.Name):
                ch = node.func.id
            else:
                return

        resolved = self._resolve_module(ch)
        parts = resolved.split(".")
        func_name = parts[-1]
        module_part = ".".join(parts[:-1]) if len(parts) > 1 else ""

        # Get matching sinks
        sinks: list[Sink] = []
        if module_part:
            sinks = get_sinks_for_module_func(module_part, func_name)
        if not sinks:
            sinks = get_sinks_for_func(func_name)

        all_args = list(node.args) + [kw.value for kw in node.keywords]

        for sink in sinks:
            # Special case: numpy.load only dangerous with allow_pickle=True
            if sink.danger_kwarg:
                found_dangerous = False
                for kw in node.keywords:
                    if kw.arg == sink.danger_kwarg:
                        if isinstance(kw.value, ast.Constant) and kw.value.value == sink.danger_kwarg_value:
                            found_dangerous = True
                if not found_dangerous:
                    continue

            # Special case: open() — only flag write modes
            if sink.name == "open_write":
                is_write = False
                # mode is second positional arg or 'mode' kwarg
                mode_node = None
                if len(node.args) >= 2:
                    mode_node = node.args[1]
                else:
                    for kw in node.keywords:
                        if kw.arg == "mode":
                            mode_node = kw.value
                if mode_node and isinstance(mode_node, ast.Constant):
                    if any(c in str(mode_node.value) for c in ("w", "a", "x")):
                        is_write = True
                if not is_write:
                    continue

            # Check if any argument is tainted
            tainted_args = [a for a in all_args if self._is_tainted_node(a)]
            if not tainted_args:
                continue

            # Build chain
            tainted_var = None
            src_line = node.lineno
            src_type = "UNKNOWN"
            src_var = "?"
            for a in tainted_args:
                if isinstance(a, ast.Name) and a.id in self.tainted:
                    tainted_var = a.id
                    src_line, src_type, src_var = self.tainted[a.id]
                    break
                elif isinstance(a, ast.Attribute):
                    ch2 = attr_chain(a)
                    if ch2:
                        for name, info in self.tainted.items():
                            if ch2.startswith(name):
                                tainted_var = name
                                src_line, src_type, src_var = info
                                break

            chain_step = ChainStep(
                file=self.file_str,
                line=src_line,
                code=get_line(self.parsed, src_line),
            )

            self.findings.append(Finding(
                finding_id=_next_id(),
                severity=sink.severity.value,
                category=sink.category.value,
                source_file=self.file_str,
                source_line=src_line,
                source_type=src_type,
                source_variable=tainted_var or src_var,
                sink_file=self.file_str,
                sink_line=node.lineno,
                sink_type=sink.name,
                sink_function=ch,
                chain=[chain_step],
                description=sink.description,
                suggested_fix=sink.suggested_fix,
            ))

    def visit_JoinedStr(self, node: ast.JoinedStr):
        """Check f-strings for prompt injection."""
        self._check_prompt_injection_fstring(node)
        self.generic_visit(node)

    def _check_prompt_injection_fstring(self, node: ast.JoinedStr):
        # Collect the static string parts
        static_parts = []
        tainted_vals = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                static_parts.append(val.value.lower())
            elif isinstance(val, ast.FormattedValue):
                if self._is_tainted_node(val.value):
                    tainted_vals.append(val.value)

        if not tainted_vals:
            return

        combined = " ".join(static_parts)
        if not any(kw in combined for kw in PROMPT_KEYWORDS):
            return

        # Find source info
        src_line = node.lineno
        src_type = SourceType.RAG_RETRIEVAL.value
        src_var = "retrieved_content"
        for tv in tainted_vals:
            if isinstance(tv, ast.Name) and tv.id in self.tainted:
                src_line, src_type, src_var = self.tainted[tv.id]
                break

        sink = next(s for s in SINKS if s.name == "prompt_template_injection")
        self.findings.append(Finding(
            finding_id=_next_id(),
            severity=sink.severity.value,
            category=sink.category.value,
            source_file=self.file_str,
            source_line=src_line,
            source_type=src_type,
            source_variable=src_var,
            sink_file=self.file_str,
            sink_line=node.lineno,
            sink_type=sink.name,
            sink_function="f-string prompt template",
            chain=[ChainStep(self.file_str, src_line, get_line(self.parsed, src_line))],
            description=sink.description,
            suggested_fix=sink.suggested_fix,
        ))

    def analyze(self) -> list[Finding]:
        # Pre-seed tainted with obvious variable names found at module scope
        for node in ast.walk(self.parsed.tree):
            if isinstance(node, ast.Name) and node.id in TAINTED_VARNAMES:
                if node.id not in self.tainted:
                    self.tainted[node.id] = (getattr(node, "lineno", 0), SourceType.USER_CONTENT.value, node.id)
        self.visit(self.parsed.tree)
        return self.findings


def analyze_file(parsed: ParsedFile) -> list[Finding]:
    return FileAnalyzer(parsed).analyze()
