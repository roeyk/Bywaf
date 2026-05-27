"""Documentation cohesion and coupling metrics.

Provides Markdown size, link, stale-term, and audience-mixing signals used by
the architecture metrics report.

Used by:
- architecture metrics: combine source-code and documentation pressure signals.
- maintainers: find oversized or over-coupled docs before documentation drifts.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True, slots=True)
class DocumentMetric:
    """Metrics for one Markdown document."""

    path: str
    nonblank_lines: int
    words: int
    headings: int
    outbound_links: int
    inbound_links: int
    duplicate_headings: int
    stale_terms: int
    audience_hits: int


@dataclass(frozen=True, slots=True)
class DocumentationMetrics:
    """Repository-level documentation pressure metrics."""

    document_count: int
    link_count: int
    broken_links: tuple[str, ...]
    documents: tuple[DocumentMetric, ...]


MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

STALE_DOC_TERMS = (
    "command run",
    "run id",
    "run=",
    "runs",
    "load plugin=",
    "--from-topic",
    "--from-step",
)

DOC_AUDIENCE_TERMS = (
    "operator",
    "plugin author",
    "maintainer",
    "packager",
    "security reviewer",
    "developer",
    "contributor",
)


def collect_documentation_metrics(repo_root: Path, *, docs_root: Path | None = None) -> DocumentationMetrics:
    """Collect cohesion and coupling signals for Markdown documentation."""
    docs_root = (docs_root or repo_root / "docs").resolve()
    document_paths = markdown_documents(repo_root, docs_root)
    links_by_doc: dict[Path, tuple[str, ...]] = {}
    incoming: defaultdict[Path, int] = defaultdict(int)
    broken_links: list[str] = []

    for path in document_paths:
        links = tuple(markdown_links(path.read_text(encoding="utf-8")))
        links_by_doc[path] = links
        for target in links:
            resolved = resolve_markdown_link(path, target)
            if resolved is None:
                continue
            if resolved.exists():
                if resolved in document_paths:
                    incoming[resolved] += 1
            else:
                broken_links.append(f"{path.relative_to(repo_root)} -> {target}")

    documents = []
    for path in document_paths:
        text = path.read_text(encoding="utf-8")
        headings = normalized_headings(text)
        lowered = text.casefold()
        documents.append(
            DocumentMetric(
                path=path.relative_to(repo_root).as_posix(),
                nonblank_lines=sum(1 for line in text.splitlines() if line.strip()),
                words=len(re.findall(r"\b[\w./=-]+\b", text)),
                headings=len(headings),
                outbound_links=len(links_by_doc[path]),
                inbound_links=incoming[path],
                duplicate_headings=len(headings) - len(set(headings)),
                stale_terms=sum(lowered.count(term) for term in STALE_DOC_TERMS),
                audience_hits=sum(1 for term in DOC_AUDIENCE_TERMS if term in lowered),
            )
        )

    return DocumentationMetrics(
        document_count=len(document_paths),
        link_count=sum(len(links) for links in links_by_doc.values()),
        broken_links=tuple(sorted(broken_links)),
        documents=tuple(sorted(documents, key=lambda document: document.path)),
    )


def markdown_documents(repo_root: Path, docs_root: Path) -> set[Path]:
    """Return Markdown documents that form the primary docs surface."""
    paths = set()
    for root in (docs_root, repo_root):
        if not root.exists():
            continue
        if root.is_file() and root.suffix == ".md":
            paths.add(root.resolve())
            continue
        for path in root.glob("*.md"):
            paths.add(path.resolve())
    if docs_root.exists():
        paths.update(path.resolve() for path in docs_root.rglob("*.md"))
    return paths


def markdown_links(text: str) -> Iterable[str]:
    """Yield Markdown links that point to local files or anchors."""
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = match.group(1).strip()
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        yield target


def resolve_markdown_link(source: Path, target: str) -> Path | None:
    """Resolve a Markdown link target to a local path when it names a file."""
    target = target.split("#", 1)[0]
    if not target:
        return None
    return (source.parent / target).resolve()


def normalized_headings(text: str) -> tuple[str, ...]:
    """Return lowercase heading text for duplicate-heading checks."""
    headings = []
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if match:
            headings.append(match.group(2).strip().casefold())
    return tuple(headings)
