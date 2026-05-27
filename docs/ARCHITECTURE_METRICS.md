# Architecture Metrics

Bywaf tracks architecture health with lightweight, repeatable metrics. These
numbers do not replace engineering judgment, but they make refactoring pressure
visible before one module quietly becomes the whole control plane.

Run the current report from a source checkout:

```bash
python scripts/architecture_metrics.py
```

Include local git churn when you want to find files that are both complicated
and frequently edited:

```bash
python scripts/architecture_metrics.py --churn
```

For machine-readable output:

```bash
python scripts/architecture_metrics.py --json
```

## What We Measure Now

The built-in metrics report currently covers:

- **Source size:** non-empty, non-comment lines per Python module. This flags
  modules that may need splitting, but length alone is not a defect.
- **Fan-out:** how many internal Bywaf modules a module imports. High fan-out
  often means the module is coordinating too many subsystems.
- **Fan-in:** how many internal modules import a module. High fan-in is normal
  for stable facades and risky for unstable internals.
- **Hub score:** fan-in plus fan-out. High hub modules deserve review because
  they are both widely used and widely dependent.
- **Import cycles:** strongly connected components in internal imports. Cycles
  are not always fatal, but they make testing, packaging, and refactoring harder.
- **Complexity:** an AST-based branch/control-flow score per module and per
  highest-complexity function. High values point to places where dispatch
  tables, smaller helpers, or clearer state machines may help.
- **Test references:** rough counts of module references from `tests/`. This is
  not coverage, but it highlights high-hub modules that appear weakly exercised
  by focused tests.
- **Git churn:** optional commit-touch counts from local history. Churn matters
  most when combined with size or complexity.
- **Security-surface hits:** rough token hits for secrets, credentials,
  capabilities, subprocesses, sockets, artifacts, and similar review-sensitive
  areas.
- **Documentation size:** word and heading counts for Markdown pages. This is a
  readability pressure signal, not a strict limit.
- **Documentation coupling:** inbound and outbound local Markdown links. High
  link coupling can be right for indexes and routing pages, but it means
  changes need link review.
- **Documentation cohesion hints:** duplicate headings, stale vocabulary hits,
  and audience-mixing hints. These point to pages that may need splitting,
  rerouting, or terminology cleanup.

## What Else Matters

Dependency metrics are only the first automated layer. For a security framework,
we also care about:

- **Cohesion:** whether a module has one clear reason to change. This is partly
  qualitative; size and mixed-domain imports are clues, not proof.
- **Documentation cohesion:** whether a page has one clear reader goal. A page
  that mixes operator workflow, plugin author contracts, and framework internals
  may need to become a short index plus focused child pages.
- **Documentation coupling:** whether one conceptual change forces edits across
  many pages. Some coupling is healthy through indexes and canonical model
  pages; accidental duplication is not.
- **Security surface:** secret handling, plugin capability enforcement, process
  boundaries, config file trust, and artifact/report rendering.
- **Operator UX surface:** commands that render tables, mutate state, or launch
  background work should stay consistent in selector syntax and output shape.

The intended workflow is: use metrics to find pressure points, inspect the code
for real boundaries, then split or refactor only when the resulting module names
and tests become clearer.

## How To Act On A Finding

Use the metrics as triage signals:

- **High complexity:** look for long `if`/`elif` or `match` ladders, deeply
  nested branches, and repeated parser/rendering branches. Dispatch tables,
  smaller pure helpers, and data-driven command maps are good first candidates.
- **High LOC only:** inspect before splitting. A large cohesive table or schema
  module can be acceptable.
- **High fan-out:** look for orchestration code that can hand work to a narrower
  service module.
- **High fan-in:** preserve compatibility or provide a facade before changing
  behavior.
- **High churn plus high complexity:** prioritize tests before refactoring.
- **High security hits:** review redaction, capability checks, path handling,
  subprocess boundaries, and artifact/report rendering before changing shape.
- **High doc size or headings:** check whether the page still has one reader
  goal. Split only when the split makes the first useful action easier to find.
- **High doc link coupling:** check the page as a routing point. Index pages can
  have high coupling; model or task pages should avoid becoming catch-alls.
- **High stale-term hits:** fix vocabulary drift before adding more examples.
