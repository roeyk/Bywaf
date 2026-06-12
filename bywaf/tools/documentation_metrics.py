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
    """Metrics for one Markdown document.

    Constructed by: `collect_documentation_metrics()`.
    Consumed by: `bywaf.tools.documentation_report` when it ranks oversized,
    over-linked, stale, or audience-mixed documentation.
    """

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
    """Repository-level documentation pressure metrics.

    Constructed by: `collect_documentation_metrics()`.
    Consumed by: architecture metrics formatting, which combines this summary
    with source-code complexity and coupling signals.
    """

    document_count: int
    link_count: int
    broken_links: tuple[str, ...]
    documents: tuple[DocumentMetric, ...]


@dataclass(frozen=True, slots=True)
class DocumentImpact:
    """One related document for a documentation impact query.

    Constructed by: `collect_documentation_impact()` for each likely follow-up
    document a maintainer should inspect after changing one Markdown file.
    """

    path: str
    score: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DocumentationImpact:
    """Ranked documents to inspect after changing one Markdown file.

    Constructed by: `collect_documentation_impact()`.
    Consumed by: documentation review workflows that need a short, ranked list
    instead of scanning every Markdown file manually.
    """

    source: str
    related: tuple[DocumentImpact, ...]


MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")

# Heuristic stale-terminology table used by `collect_documentation_metrics()`
# and `collect_documentation_impact()` to flag docs that may still describe
# older runtime vocabulary or legacy selector syntax.
STALE_DOC_TERMS = (
    "command run",
    "run id",
    "run=",
    "runs",
    "load plugin=",
    "--from-topic",
    "--from-step",
)

# Audience-role terms used by `collect_documentation_metrics()` as a rough
# signal that one document may be mixing operator, plugin-author, maintainer,
# packaging, and security-reviewer concerns.
DOC_AUDIENCE_TERMS = (
    "operator",
    "plugin author",
    "maintainer",
    "packager",
    "security reviewer",
    "developer",
    "contributor",
)

# Stop words for `important_doc_terms()`. These keep impact ranking focused on
# project vocabulary, paths, symbols, and command names instead of generic prose.
GENERIC_DOC_WORDS = {
    "and",
    "are",
    "but",
    "can",
    "code",
    "for",
    "from",
    "how",
    "into",
    "not",
    "one",
    "page",
    "run",
    "see",
    "the",
    "this",
    "that",
    "use",
    "when",
    "with",
    "you",
}


def collect_documentation_metrics(repo_root: Path, *, docs_root: Path | None = None) -> DocumentationMetrics:
    """Collect cohesion and coupling signals for Markdown documentation.

    Called by: `bywaf.tools.architecture.collect_architecture_metrics()`
    when the architecture report includes documentation pressure.
    """
    docs_root = (docs_root or repo_root / "docs").resolve()
    document_paths = markdown_documents(repo_root, docs_root)
    links_by_doc: dict[Path, tuple[str, ...]] = {}
    incoming: defaultdict[Path, int] = defaultdict(int)
    broken_links: list[str] = []

    # First pass: gather outbound links and invert them into incoming-link
    # counts so each document can report both coupling directions.
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

    # Second pass: compute per-document size, heading, terminology, and
    # audience-mixing signals now that incoming-link counts are known.
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


def collect_documentation_impact(
    repo_root: Path,
    source: Path,
    *,
    docs_root: Path | None = None,
    top: int = 12,
) -> DocumentationImpact:
    """Rank docs likely to need review after source changes.

    Called by: maintainers/Codex during documentation refactors to decide which
    linked or vocabulary-adjacent files should be inspected together.
    """
    repo_root = repo_root.resolve()
    docs_root = (docs_root or repo_root / "docs").resolve()
    document_paths = markdown_documents(repo_root, docs_root)
    source_path = source.resolve()
    if source_path not in document_paths:
        raise ValueError(f"not a tracked Markdown document: {source}")

    source_text = source_path.read_text(encoding="utf-8")
    source_links = linked_paths(source_path, document_paths)
    source_keywords = important_doc_terms(source_text)
    source_headings = set(normalized_headings(source_text))

    impacts = []
    for path in sorted(document_paths):
        if path == source_path:
            continue
        text = path.read_text(encoding="utf-8")
        reasons: list[str] = []
        score = 0

        # Impact scoring is intentionally additive and explainable. Each score
        # contribution adds a reason string so the caller can show why a related
        # doc was suggested instead of presenting an opaque similarity number.
        #
        # Direct links dominate the score because they are explicit maintainer
        # intent. Shared headings/terms/stale terms are weaker hints that catch
        # drift in docs that discuss the same concepts without linking.

        # Direct links are the strongest evidence that two docs should be
        # reviewed together after one changes.
        if path in source_links:
            score += 45
            reasons.append("source links to it")
        if source_path in linked_paths(path, document_paths):
            score += 45
            reasons.append("links to source")

        # Shared headings catch recurring sections such as Audience, Related
        # Documents, or Validation that may need synchronized wording.
        shared_headings = source_headings & set(normalized_headings(text))
        if shared_headings:
            score += min(20, len(shared_headings) * 5)
            reasons.append(f"shared headings={len(shared_headings)}")

        # Shared domain terms catch conceptual coupling even when docs do not
        # directly link to each other.
        shared_terms = source_keywords & important_doc_terms(text)
        if shared_terms:
            score += min(30, len(shared_terms) * 2)
            preview = ", ".join(sorted(shared_terms)[:5])
            reasons.append(f"shared terms={preview}")

        # Stale-term overlap is kept separate so old vocabulary can be cleaned
        # consistently rather than fixed one document at a time.
        stale_overlap = stale_terms_in(source_text) & stale_terms_in(text)
        if stale_overlap:
            score += len(stale_overlap) * 3
            reasons.append(f"shared stale terms={', '.join(sorted(stale_overlap))}")

        if score:
            impacts.append(DocumentImpact(path=path.relative_to(repo_root).as_posix(), score=score, reasons=tuple(reasons)))

    related = tuple(sorted(impacts, key=lambda impact: (-impact.score, impact.path))[:top])
    return DocumentationImpact(source=source_path.relative_to(repo_root).as_posix(), related=related)


def linked_paths(source: Path, document_paths: set[Path]) -> set[Path]:
    """Return local Markdown documents linked by source.

    Used by: `collect_documentation_impact()` to score direct outgoing and
    incoming documentation relationships.
    """
    linked = set()
    text = source.read_text(encoding="utf-8")
    for target in markdown_links(text):
        resolved = resolve_markdown_link(source, target)
        if resolved in document_paths:
            linked.add(resolved)
    return linked


def important_doc_terms(text: str) -> set[str]:
    """Return repeated or domain-looking terms useful for impact ranking.

    Used by: `collect_documentation_impact()` to identify conceptual coupling
    between docs even when they do not link to each other.

    This intentionally favors code spans, paths, dotted names, and repeated
    nouns. It is a heuristic for reviewer attention, not a natural-language
    classifier.
    """
    terms: defaultdict[str, int] = defaultdict(int)
    for term in re.findall(r"`([^`]+)`|([A-Za-z][A-Za-z0-9_./=-]{2,})", text):
        # Each regex match has either a code-span group or a prose-token group.
        # Normalize the present group before applying stop-word and URL filters.
        value = normalize_doc_term(term[0] or term[1])
        if not value or value in GENERIC_DOC_WORDS or value.startswith("http"):
            continue
        terms[value] += 1
    # Keep repeated terms plus symbol/path-like terms. Single ordinary words are
    # too noisy to be useful as impact signals.
    return {term for term, count in terms.items() if count > 1 or "." in term or "/" in term or "_" in term or "=" in term}


def normalize_doc_term(term: str) -> str:
    """Normalize one extracted doc term for impact comparison.

    Used by: `important_doc_terms()` before counting candidate vocabulary.
    """
    value = term.casefold().strip().strip(".,;:()[]{}<>\"'")
    return value if any(character.isalnum() for character in value) else ""


def stale_terms_in(text: str) -> set[str]:
    """Return stale terminology markers present in text.

    Used by: `collect_documentation_impact()` so related documents with the
    same obsolete wording can be reviewed together.
    """
    lowered = text.casefold()
    return {term for term in STALE_DOC_TERMS if term in lowered}


def markdown_documents(repo_root: Path, docs_root: Path) -> set[Path]:
    """Return Markdown documents that form the primary docs surface.

    Called by: documentation metric and impact collectors. Top-level Markdown
    files are included with the recursive `docs/` tree because both are public
    documentation surfaces.
    """
    paths = set()
    for root in (docs_root, repo_root):
        if not root.exists():
            continue
        if root.is_file() and root.suffix == ".md":
            paths.add(root.resolve())
            continue
        # Top-level Markdown files are public documentation too, but only one
        # level is scanned at repo root so private support trees or generated
        # artifacts outside `docs/` do not pollute the public-doc metrics.
        for path in root.glob("*.md"):
            paths.add(path.resolve())
    if docs_root.exists():
        # The `docs/` tree is intentionally recursive because role guides,
        # plugin-author docs, and subsystem references live below it.
        paths.update(path.resolve() for path in docs_root.rglob("*.md"))
    return paths


def markdown_links(text: str) -> Iterable[str]:
    """Yield Markdown links that point to local files or anchors.

    Used by: documentation metric and impact collectors before resolving links
    relative to their source file.
    """
    for match in MARKDOWN_LINK_RE.finditer(text):
        target = match.group(1).strip()
        # External links do not create repository maintenance coupling, so the
        # metric keeps them out of broken-link and impact calculations.
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        yield target


def resolve_markdown_link(source: Path, target: str) -> Path | None:
    """Resolve a Markdown link target to a local path when it names a file.

    Used by: link counting, broken-link detection, and impact ranking.
    """
    target = target.split("#", 1)[0]
    # Pure anchor links stay inside the current document; they do not point at a
    # separate file to include in cross-document metrics.
    if not target:
        return None
    return (source.parent / target).resolve()


def normalized_headings(text: str) -> tuple[str, ...]:
    """Return lowercase heading text for duplicate-heading checks.

    Used by: metrics and impact ranking to detect repeated sections and shared
    structural headings across docs.
    """
    headings = []
    for line in text.splitlines():
        match = HEADING_RE.match(line)
        if match:
            headings.append(match.group(2).strip().casefold())
    return tuple(headings)
