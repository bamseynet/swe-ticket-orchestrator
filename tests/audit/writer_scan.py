"""Static scan for audit writers (fails closed).

A writer is anything that produces audit ops. The scan does not trust names, signatures or
registration: it reads the source of every module under ``src/sto`` and reports

* a class with a method called ``ops``, or any method with a parameter annotated ``AuditEntry``,
  or a ``__call__`` with a parameter called ``entry`` (renamed, starred or extended signatures,
  nested classes and classes built inside a function are all found, because it walks the tree);
* any use of the audit seam or table (``AuditEntry``, ``AuditWriter``, ``ChainedAuditWriter``,
  ``AUDIT``, ``CHAIN_SK``, or the strings ``"CHAIN"`` and ``"audit"``) in a module that is not on
  the allow list, which catches a writer that transacts directly.

Allowed modules may hold only the registered writer classes.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

SEAM_NAMES = frozenset({"AuditEntry", "AuditWriter", "ChainedAuditWriter", "AUDIT", "CHAIN_SK"})
SEAM_STRINGS = frozenset({"CHAIN", "audit"})


def _is_protocol(cls: ast.ClassDef) -> bool:
    return any(
        (isinstance(b, ast.Name) and b.id == "Protocol")
        or (isinstance(b, ast.Attribute) and b.attr == "Protocol")
        for b in cls.bases
    )


def _annotated_entry(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    args = [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
    args += [a for a in (fn.args.vararg, fn.args.kwarg) if a is not None]
    for a in args:
        ann = a.annotation
        if isinstance(ann, ast.Name) and ann.id == "AuditEntry":
            return True
        if isinstance(ann, ast.Constant) and ann.value == "AuditEntry":
            return True
        if isinstance(ann, ast.Attribute) and ann.attr == "AuditEntry":
            return True
    return False


def writer_classes(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef) or _is_protocol(cls):
            continue
        for fn in ast.walk(cls):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            names = {a.arg for a in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]}
            if (
                fn.name == "ops"
                or _annotated_entry(fn)
                or (fn.name == "__call__" and "entry" in names)
            ):
                found.add(cls.name)
    return found


def seam_uses(tree: ast.AST) -> set[str]:
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in SEAM_NAMES:
            used.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in SEAM_NAMES:
            used.add(node.attr)
        elif isinstance(node, ast.alias) and node.name.split(".")[-1] in SEAM_NAMES:
            used.add(node.name)
        elif isinstance(node, ast.Constant) and node.value in SEAM_STRINGS:
            used.add(repr(node.value))
    return used


def violations(
    sources: Iterable[tuple[str, str]], allowed_modules: set[str], registered: set[str]
) -> list[str]:
    """``sources`` are ``(module path, source text)``. Returns one line per problem."""
    out: list[str] = []
    for path, text in sources:
        tree = ast.parse(text)
        classes = writer_classes(tree)
        if path not in allowed_modules:
            if classes:
                out.append(
                    f"{path}: writer-shaped class(es) {sorted(classes)} outside the allow list"
                )
            if used := seam_uses(tree):
                out.append(f"{path}: uses the audit seam {sorted(used)} outside the allow list")
        elif extra := classes - registered:
            out.append(f"{path}: unregistered writer class(es) {sorted(extra)}")
    return out


def read_sources(root: Path) -> list[tuple[str, str]]:
    return [(str(p.relative_to(root.parent)), p.read_text()) for p in sorted(root.rglob("*.py"))]
