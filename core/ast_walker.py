import ast
import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ParsedFile:
    path: Path
    tree: ast.Module
    source: str
    lines: list[str]


def walk_repo(repo_path: str | Path) -> list[ParsedFile]:
    """Recursively parse all .py files under repo_path."""
    repo_path = Path(repo_path)
    results: list[ParsedFile] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "env", "node_modules", ".tox", "dist", "build"}

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            fpath = Path(dirpath) / fname
            try:
                source = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(fpath))
                results.append(ParsedFile(
                    path=fpath,
                    tree=tree,
                    source=source,
                    lines=source.splitlines(),
                ))
            except SyntaxError:
                pass  # skip unparseable files
            except OSError:
                pass

    return results


def get_line(parsed: ParsedFile, lineno: int) -> str:
    """Return the source line (1-indexed), stripped."""
    if 1 <= lineno <= len(parsed.lines):
        return parsed.lines[lineno - 1].strip()
    return ""


def resolve_import_alias(tree: ast.Module) -> dict[str, str]:
    """
    Build a map from local alias → canonical module.full.name for imports.
    e.g. `import os` → {"os": "os"}
         `import numpy as np` → {"np": "numpy"}
         `from flask import request` → {"request": "flask.request"}
         `from subprocess import run` → {"run": "subprocess.run"}
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                canonical = f"{module}.{alias.name}" if module else alias.name
                aliases[local] = canonical
    return aliases


def attr_chain(node: ast.expr) -> str | None:
    """
    Return a dot-joined string for attribute chains like `os.path.join`.
    Returns None if not a pure name/attr chain.
    """
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None
