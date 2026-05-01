"""
General Python dangerous patterns beyond what the sink registry catches.
These are structural/contextual rules.
"""

import ast
from ..core.ast_walker import ParsedFile, get_line
from ..core.flow_tracker import Finding, ChainStep, _next_id
from ..core.sinks import Severity, Category


def rule_shell_true_subprocess(parsed: ParsedFile) -> list[Finding]:
    """subprocess calls with shell=True are extra dangerous."""
    findings: list[Finding] = []
    file_str = str(parsed.path)

    for node in ast.walk(parsed.tree):
        if not isinstance(node, ast.Call):
            continue
        func_str = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        if not any(x in func_str for x in ("subprocess.", "Popen", "call", "run", "check_output")):
            continue
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                findings.append(Finding(
                    finding_id=_next_id(),
                    severity=Severity.CRITICAL.value,
                    category=Category.COMMAND_EXEC.value,
                    source_file=file_str,
                    source_line=node.lineno,
                    source_type="CODE_PATTERN",
                    source_variable="shell=True",
                    sink_file=file_str,
                    sink_line=node.lineno,
                    sink_type="subprocess_shell_true",
                    sink_function=func_str,
                    chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                    description="subprocess call with shell=True - shell metacharacters in any argument cause command injection",
                    suggested_fix="Remove shell=True and pass args as a list; use shlex.quote if shell is unavoidable",
                ))

    return findings


def rule_yaml_load_no_loader(parsed: ParsedFile) -> list[Finding]:
    """yaml.load() without explicit SafeLoader."""
    findings: list[Finding] = []
    file_str = str(parsed.path)

    for node in ast.walk(parsed.tree):
        if not isinstance(node, ast.Call):
            continue
        func_str = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        if not func_str.endswith("yaml.load") and not func_str == "load":
            continue
        # Check if Loader kwarg is present and is SafeLoader
        has_safe_loader = False
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader_str = ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                if "Safe" in loader_str:
                    has_safe_loader = True
        # Check positional Loader arg (2nd arg)
        if len(node.args) >= 2:
            loader_str = ast.unparse(node.args[1]) if hasattr(ast, "unparse") else ""
            if "Safe" in loader_str:
                has_safe_loader = True

        if not has_safe_loader and "yaml.load" in func_str:
            findings.append(Finding(
                finding_id=_next_id(),
                severity=Severity.HIGH.value,
                category=Category.DESERIALIZATION.value,
                source_file=file_str,
                source_line=node.lineno,
                source_type="FILE_INPUT",
                source_variable="yaml_data",
                sink_file=file_str,
                sink_line=node.lineno,
                sink_type="yaml_unsafe_load",
                sink_function=func_str,
                chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                description="yaml.load() without SafeLoader can execute arbitrary Python objects",
                suggested_fix="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
            ))

    return findings


def rule_os_path_join_traversal(parsed: ParsedFile) -> list[Finding]:
    """os.path.join where first arg is a base but subsequent args contain tainted vars."""
    # Structural rule: flag os.path.join calls where a non-first arg is a Name
    # that looks like user input. Real taint tracking is in flow_tracker.
    findings: list[Finding] = []
    file_str = str(parsed.path)

    USER_INPUT_HINTS = {"filename", "path", "name", "user", "input", "query", "dir", "folder", "file"}

    for node in ast.walk(parsed.tree):
        if not isinstance(node, ast.Call):
            continue
        func_str = ast.unparse(node.func) if hasattr(ast, "unparse") else ""
        if "path.join" not in func_str:
            continue
        for arg in node.args[1:]:  # skip first (base) arg
            if isinstance(arg, ast.Name):
                if any(hint in arg.id.lower() for hint in USER_INPUT_HINTS):
                    findings.append(Finding(
                        finding_id=_next_id(),
                        severity=Severity.HIGH.value,
                        category=Category.PATH_TRAVERSAL.value,
                        source_file=file_str,
                        source_line=node.lineno,
                        source_type="USER_CONTENT",
                        source_variable=arg.id,
                        sink_file=file_str,
                        sink_line=node.lineno,
                        sink_type="os.path.join_traversal",
                        sink_function=func_str,
                        chain=[ChainStep(file_str, node.lineno, get_line(parsed, node.lineno))],
                        description=f"os.path.join() with potentially user-controlled '{arg.id}' — path traversal risk",
                        suggested_fix="Normalize with os.path.normpath and verify result is within the intended base directory",
                    ))

    return findings


ALL_GENERAL_RULES = [
    rule_shell_true_subprocess,
    rule_yaml_load_no_loader,
    rule_os_path_join_traversal,
]


def run_general_rules(parsed: ParsedFile) -> list[Finding]:
    findings = []
    for rule in ALL_GENERAL_RULES:
        findings.extend(rule(parsed))
    return findings
