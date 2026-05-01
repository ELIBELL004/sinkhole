"""
ML-specific rules that generic SAST tools miss.
Each rule returns a list of Finding objects.
"""

import ast
from pathlib import Path

from ..core.ast_walker import ParsedFile, resolve_import_alias, attr_chain, get_line
from ..core.flow_tracker import Finding, ChainStep, _next_id
from ..core.sinks import Severity, Category


PROMPT_CONTEXT_VARNAMES: frozenset[str] = frozenset({
    "contextTexts", "context_texts", "context", "retrieved_docs", "retrieved_chunks",
    "search_results", "chunks", "documents", "doc_content", "retrieved", "results",
    "rag_context", "rag_results", "docs",
})

SYSTEM_PROMPT_KEYWORDS: tuple[str, ...] = (
    "system", "instruction", "role", "you are", "your task",
    "system_prompt", "sys_prompt", "system_message",
)

SAFE_MODE_VARNAMES: frozenset[str] = frozenset({
    "safe_mode", "safe", "enable_safety", "sandbox", "safety_enabled",
    "enable_sandbox", "safe_execution",
})

MODEL_LOAD_DANGEROUS: dict[str, str] = {
    "keras.models.load_model": "keras",
    "tf.saved_model.load": "tensorflow",
    "torch.load": "torch",
}


def _make_finding(
    severity: str, category: str,
    src_file: str, src_line: int, src_type: str, src_var: str,
    sink_file: str, sink_line: int, sink_type: str, sink_func: str,
    description: str, fix: str,
) -> Finding:
    return Finding(
        finding_id=_next_id(),
        severity=severity,
        category=category,
        source_file=src_file,
        source_line=src_line,
        source_type=src_type,
        source_variable=src_var,
        sink_file=sink_file,
        sink_line=sink_line,
        sink_type=sink_type,
        sink_function=sink_func,
        chain=[ChainStep(src_file, src_line, get_line(parsed=None, lineno=src_line) if False else "")],
        description=description,
        suggested_fix=fix,
    )


def rule_contextTexts_to_prompt(parsed: ParsedFile) -> list[Finding]:
    """RAG retrieval results flowing into system prompt construction."""
    findings: list[Finding] = []
    aliases = resolve_import_alias(parsed.tree)
    file_str = str(parsed.path)

    # Find assignments where RHS looks like a RAG source
    rag_vars: dict[str, int] = {}
    for node in ast.walk(parsed.tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            val = node.value
            if val is None:
                continue
            for t in targets:
                if isinstance(t, ast.Name) and t.id in PROMPT_CONTEXT_VARNAMES:
                    rag_vars[t.id] = node.lineno

    # Now look for f-strings / format calls that use these vars AND contain system prompt keywords
    for node in ast.walk(parsed.tree):
        if isinstance(node, ast.JoinedStr):
            static = []
            uses_rag = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    static.append(v.value.lower())
                elif isinstance(v, ast.FormattedValue):
                    inner = v.value
                    if isinstance(inner, ast.Name) and inner.id in rag_vars:
                        uses_rag.append((inner.id, rag_vars[inner.id]))

            if uses_rag and any(kw in " ".join(static) for kw in SYSTEM_PROMPT_KEYWORDS):
                var_name, src_line = uses_rag[0]
                findings.append(Finding(
                    finding_id=_next_id(),
                    severity=Severity.HIGH.value,
                    category=Category.PROMPT_INJECTION.value,
                    source_file=file_str,
                    source_line=src_line,
                    source_type="RAG_RETRIEVAL",
                    source_variable=var_name,
                    sink_file=file_str,
                    sink_line=node.lineno,
                    sink_type="prompt_template_injection",
                    sink_function="f-string system prompt",
                    chain=[ChainStep(file_str, src_line, get_line(parsed, src_line))],
                    description="RAG retrieval results inserted directly into LLM system prompt — prompt injection",
                    suggested_fix="Wrap retrieved content in XML delimiters (<context>...</context>) and instruct the model to treat it as data only",
                ))

        # .format() calls
        if isinstance(node, ast.Call):
            ch = attr_chain(node.func)
            if ch and ch.endswith(".format"):
                fmt_str_node = node.func.value if isinstance(node.func, ast.Attribute) else None
                if fmt_str_node and isinstance(fmt_str_node, ast.Constant) and isinstance(fmt_str_node.value, str):
                    static = fmt_str_node.value.lower()
                    if any(kw in static for kw in SYSTEM_PROMPT_KEYWORDS):
                        for arg in list(node.args) + [kw.value for kw in node.keywords]:
                            if isinstance(arg, ast.Name) and arg.id in rag_vars:
                                src_line = rag_vars[arg.id]
                                findings.append(Finding(
                                    finding_id=_next_id(),
                                    severity=Severity.HIGH.value,
                                    category=Category.PROMPT_INJECTION.value,
                                    source_file=file_str,
                                    source_line=src_line,
                                    source_type="RAG_RETRIEVAL",
                                    source_variable=arg.id,
                                    sink_file=file_str,
                                    sink_line=node.lineno,
                                    sink_type="prompt_template_injection",
                                    sink_function=".format() system prompt",
                                    chain=[ChainStep(file_str, src_line, get_line(parsed, src_line))],
                                    description="RAG retrieval results inserted directly into LLM system prompt via .format() — prompt injection",
                                    suggested_fix="Wrap retrieved content in XML delimiters and instruct the model to treat it as data only",
                                ))

    return findings


def rule_safe_mode_hardcoded(parsed: ParsedFile) -> list[Finding]:
    """Safety mode booleans hardcoded to False or set from config/env."""
    findings: list[Finding] = []
    file_str = str(parsed.path)

    for node in ast.walk(parsed.tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        val = node.value
        if val is None:
            continue
        for t in targets:
            if not isinstance(t, ast.Name):
                continue
            if t.id.lower() not in {n.lower() for n in SAFE_MODE_VARNAMES}:
                continue
            # Hardcoded False
            if isinstance(val, ast.Constant) and val.value is False:
                findings.append(Finding(
                    finding_id=_next_id(),
                    severity=Severity.HIGH.value,
                    category=Category.SAFE_MODE_BYPASS.value,
                    source_file=file_str,
                    source_line=node.lineno,
                    source_type="CONFIG_INPUT",
                    source_variable=t.id,
                    sink_file=file_str,
                    sink_line=node.lineno,
                    sink_type="safe_mode_false",
                    sink_function=t.id,
                    chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                    description=f"Safety flag '{t.id}' is hardcoded to False",
                    suggested_fix="Remove the hardcoded False; default safety flags to True and require explicit opt-out with justification",
                ))
            # Set from os.environ / config / argparse
            elif _is_external_config_source(val):
                findings.append(Finding(
                    finding_id=_next_id(),
                    severity=Severity.MEDIUM.value,
                    category=Category.SAFE_MODE_BYPASS.value,
                    source_file=file_str,
                    source_line=node.lineno,
                    source_type="CONFIG_INPUT",
                    source_variable=t.id,
                    sink_file=file_str,
                    sink_line=node.lineno,
                    sink_type="safe_mode_false",
                    sink_function=t.id,
                    chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                    description=f"Safety flag '{t.id}' is user-controllable via environment/config/args",
                    suggested_fix="Do not allow safety flags to be disabled by users; enforce safe mode server-side",
                ))

    return findings


def _is_external_config_source(node: ast.expr) -> bool:
    ch = attr_chain(node) if isinstance(node, (ast.Attribute, ast.Name)) else None
    if ch and ("environ" in ch or "getenv" in ch or "argv" in ch):
        return True
    if isinstance(node, ast.Call):
        ch2 = attr_chain(node.func)
        if ch2 and ("getenv" in ch2 or "get" in ch2 or "parse_args" in ch2):
            return True
    return False


def rule_pickle_in_disguise(parsed: ParsedFile) -> list[Finding]:
    """joblib.load, torch.load (no weights_only), dill, numpy allow_pickle — already in sinks.py,
    but this rule adds a clearer description for ML context."""
    # Covered by sinks.py + flow_tracker. Return empty to avoid duplicates.
    return []


def rule_model_load_rce(parsed: ParsedFile) -> list[Finding]:
    """keras.models.load_model, tf.saved_model.load, torch.load without weights_only=True."""
    findings: list[Finding] = []
    file_str = str(parsed.path)
    aliases = resolve_import_alias(parsed.tree)

    for node in ast.walk(parsed.tree):
        if not isinstance(node, ast.Call):
            continue
        ch = attr_chain(node.func)
        if ch is None:
            continue
        # Resolve aliases
        parts = ch.split(".")
        if parts[0] in aliases:
            parts[0] = aliases[parts[0]]
        resolved = ".".join(parts)

        if "torch.load" in resolved:
            weights_only = False
            for kw in node.keywords:
                if kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    weights_only = True
            if not weights_only:
                findings.append(Finding(
                    finding_id=_next_id(),
                    severity=Severity.CRITICAL.value,
                    category=Category.DESERIALIZATION.value,
                    source_file=file_str,
                    source_line=node.lineno,
                    source_type="FILE_INPUT",
                    source_variable="model_file",
                    sink_file=file_str,
                    sink_line=node.lineno,
                    sink_type="model_load_rce",
                    sink_function=ch,
                    chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                    description="torch.load() without weights_only=True deserializes arbitrary Python objects via pickle",
                    suggested_fix="Use torch.load(..., weights_only=True) to prevent arbitrary code execution",
                ))

        elif "keras" in resolved and "load_model" in resolved:
            findings.append(Finding(
                finding_id=_next_id(),
                severity=Severity.HIGH.value,
                category=Category.DESERIALIZATION.value,
                source_file=file_str,
                source_line=node.lineno,
                source_type="FILE_INPUT",
                source_variable="model_file",
                sink_file=file_str,
                sink_line=node.lineno,
                sink_type="model_load_rce",
                sink_function=ch,
                chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                description="keras.models.load_model() can execute arbitrary code via Lambda layers or custom objects",
                suggested_fix="Only load models from trusted sources; disable custom_objects for untrusted inputs",
            ))

        elif "saved_model.load" in resolved or ("tf" in resolved and "load" in resolved):
            findings.append(Finding(
                finding_id=_next_id(),
                severity=Severity.HIGH.value,
                category=Category.DESERIALIZATION.value,
                source_file=file_str,
                source_line=node.lineno,
                source_type="FILE_INPUT",
                source_variable="model_file",
                sink_file=file_str,
                sink_line=node.lineno,
                sink_type="model_load_rce",
                sink_function=ch,
                chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                description="tf.saved_model.load() can execute arbitrary code embedded in the SavedModel",
                suggested_fix="Only load SavedModels from trusted sources; use model signing/verification",
            ))

    return findings


def rule_unauth_destructive(parsed: ParsedFile) -> list[Finding]:
    """DELETE/PUT/POST route handlers calling destructive filesystem ops without auth check."""
    findings: list[Finding] = []
    file_str = str(parsed.path)

    DESTRUCTIVE_OPS = {"rmtree", "remove", "unlink", "rmdir", "move"}
    AUTH_DECORATORS = {"login_required", "require_auth", "auth_required", "jwt_required",
                       "requires_auth", "authenticated", "permission_required"}

    for node in ast.walk(parsed.tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check for HTTP method decorators
        http_methods = set()
        has_auth = False
        for dec in node.decorator_list:
            dec_str = ast.unparse(dec).lower() if hasattr(ast, "unparse") else ""
            if any(m in dec_str for m in ("delete", "put", "post", "patch")):
                http_methods.add(dec_str)
            if any(a in dec_str for a in AUTH_DECORATORS):
                has_auth = True

        if not http_methods or has_auth:
            continue

        # Check body for destructive ops
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            ch = attr_chain(child.func)
            if ch is None:
                continue
            last = ch.split(".")[-1]
            if last in DESTRUCTIVE_OPS:
                findings.append(Finding(
                    finding_id=_next_id(),
                    severity=Severity.HIGH.value,
                    category=Category.FILESYSTEM.value,
                    source_file=file_str,
                    source_line=child.lineno,
                    source_type="HTTP_INPUT",
                    source_variable="route_handler",
                    sink_file=file_str,
                    sink_line=child.lineno,
                    sink_type="unauth_destructive",
                    sink_function=ch,
                    chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                    description=f"Destructive operation {ch}() in HTTP handler without authentication decorator",
                    suggested_fix="Add @login_required or equivalent auth decorator to this route handler",
                ))

    return findings


ALL_ML_RULES = [
    rule_contextTexts_to_prompt,
    rule_safe_mode_hardcoded,
    rule_model_load_rce,
    rule_unauth_destructive,
]


def run_ml_rules(parsed: ParsedFile) -> list[Finding]:
    findings = []
    for rule in ALL_ML_RULES:
        findings.extend(rule(parsed))
    return findings
