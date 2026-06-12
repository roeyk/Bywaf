"""Import graph helpers for architecture metric collection.

Used by:
- maintainers measuring coupling, complexity, documentation pressure, and
  release-readiness signals.
- CI/manual validation runs that track architecture drift.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable


def internal_imports(
    tree: ast.AST,
    current_module: str,
    package: str,
    modules: set[str],
    packages: set[str],
) -> Iterable[str]:
    """Yield normalized imports that point inside the measured package.

    Called by: `collect_architecture_metrics()` while building the dependency
    graph.
    """

    known = modules | packages
    for node in runtime_import_nodes(tree):
        match node:
            case ast.Import(names=names):
                for alias in names:
                    # `import pkg.child.symbol` is collapsed to the nearest
                    # known internal module/package so graph nodes stay stable.
                    normalized = normalize_absolute_import(alias.name, package, known)
                    if normalized is not None:
                        yield normalized
            case ast.ImportFrom(module=module, level=level, names=names):
                if level:
                    imported = resolve_relative_import(current_module, module, level)
                else:
                    imported = module or ""
                normalized = normalize_absolute_import(imported, package, known)
                normalized_children = []
                for alias in names:
                    # `from pkg.child import symbol` may reference either the
                    # parent module or an importable child module; prefer the
                    # child when it exists.
                    child = f"{imported}.{alias.name}" if imported else alias.name
                    normalized_child = normalize_absolute_import(child, package, known)
                    if normalized_child is not None:
                        normalized_children.append(normalized_child)
                if normalized is not None and not normalized_children:
                    # If no imported child is known, the `from` module itself is
                    # still a runtime dependency.
                    yield normalized
                yield from normalized_children


def runtime_import_nodes(tree: ast.AST) -> Iterable[ast.Import | ast.ImportFrom]:
    """Yield runtime import statements, excluding `TYPE_CHECKING` branches.

    Called by: `internal_imports()`.
    """

    class Visitor(ast.NodeVisitor):
        """Collect related behavior for `Visitor`."""
        def __init__(self) -> None:
            self.imports: list[ast.Import | ast.ImportFrom] = []

        def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
            self.imports.append(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
            self.imports.append(node)

        def visit_If(self, node: ast.If) -> None:  # noqa: N802
            if is_type_checking_guard(node.test):
                # TYPE_CHECKING bodies affect static typing, not runtime import
                # coupling; still visit `else` because that branch is runtime.
                for child in node.orelse:
                    self.visit(child)
                return
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(tree)
    return tuple(visitor.imports)


def is_type_checking_guard(node: ast.AST) -> bool:
    """Return whether an `if` test is a `TYPE_CHECKING` guard.

    Called by: `runtime_import_nodes()`.
    """

    match node:
        case ast.Name(id="TYPE_CHECKING"):
            return True
        case ast.Attribute(value=ast.Name(id="typing"), attr="TYPE_CHECKING"):
            return True
        case _:
            return False


def normalize_absolute_import(imported: str, package: str, known: set[str]) -> str | None:
    """Collapse an import target to the nearest known internal module/package.

    Called by: `internal_imports()`.
    """

    if imported != package and not imported.startswith(f"{package}."):
        return None
    candidate = imported
    while candidate:
        if candidate in known:
            return candidate
        # Walk `pkg.a.b.c` back toward `pkg.a` until a real module/package node
        # is found; this handles imports of names inside a module.
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return package if package in known else None


def resolve_relative_import(current_module: str, imported: str | None, level: int) -> str:
    """Resolve `from .x import y` style imports to dotted module candidates.

    Called by: `internal_imports()`.
    """

    package_parts = current_module.split(".")[:-1]
    if level > 1:
        package_parts = package_parts[: -(level - 1)]
    if imported:
        package_parts.extend(imported.split("."))
    return ".".join(package_parts)


def strongly_connected_components(adjacency: dict[str, set[str]]) -> list[set[str]]:
    """Return Tarjan strongly connected components for dependency cycles.

    Called by: `collect_architecture_metrics()`.
    """

    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[set[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        # Tarjan assigns a discovery index and a lowlink. A node starts a cycle
        # component when its lowlink points back to itself.
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in adjacency[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] != indices[node]:
            return
        component: set[str] = set()
        while True:
            # Pop the completed strongly connected component off the DFS stack.
            current = stack.pop()
            on_stack.remove(current)
            component.add(current)
            if current == node:
                break
        components.append(component)

    for node in adjacency:
        if node not in indices:
            visit(node)
    return components
