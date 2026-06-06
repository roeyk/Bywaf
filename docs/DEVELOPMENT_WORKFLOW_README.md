# Development Workflow README

Bywaf is developed with a structured human-plus-LLM workflow. Codex is used
less like a one-shot code generator and more like a persistent engineering
collaborator.

This workflow is intentionally iterative. The project owner and assistant
discuss design, inspect the codebase, implement narrow slices, run validation,
record decisions, and then choose the next slice. The goal is not to expect a
single large prompt to produce perfect work. The goal is to create a disciplined
loop where design decisions, implementation, validation, and handoff reinforce
each other.

## Public Repo Versus Private Support Material

The public GitHub repository contains the Bywaf source code, tests, public
documentation, plugin skeletons, and project-facing development guides.
External contributors do not need access to the private support files; public
issues, tests, documentation, plugin skeletons, and normal pull-request review
are enough to contribute.

The maintainer workflow also uses private/local support material that lives
outside the public GitHub repository. That support material includes handoff
files, the Tracker, action logs, restart notes, and lessons learned. These files
are local maintainer memory, not part of the distributed Bywaf package and not
required for normal users or plugin authors.

The public repo documents the development pattern so contributors can understand
how decisions are made. The private support files preserve detailed continuity
for ongoing maintainer and assistant sessions.

The private support files also reduce context drift, session loss, and
hallucinated continuity. A restarted assistant should re-read durable project
state instead of relying on an expired or reconstructed chat transcript.

## The Basic Loop

The common development loop is:

1. Discuss the problem and clarify intent.
2. Read the relevant docs, tracker items, tests, and source code.
3. Implement a narrow, testable slice.
4. Run focused validation first.
5. Run broader validation before closing the work.
6. Record decisions, actions, validation results, and follow-up state.
7. Review the result and choose the next slice.

This loop keeps work aligned with the existing framework instead of relying on
large speculative rewrites.

## Quality And Refactoring Loop

The collaboration includes routine engineering hygiene, not only feature
implementation.

As part of the back-and-forth coding process, Bywaf work regularly includes:

- Python source-code testing with focused tests and broader regression runs;
- coupling, cohesion, and complexity analysis through architecture metrics;
- periodic code refactoring when metrics and code review point to real
  maintenance pressure;
- documentation refactoring when public docs drift, duplicate concepts, mix
  audiences, or stop matching implementation behavior;
- plugin manifest and schema checks;
- bundled-plugin manual consistency checks;
- CI and CodeQL review after pushed changes;
- tracker and handoff updates so quality decisions persist across sessions.

Metrics are used to guide inspection rather than to force automatic rewrites.
For example, high fan-out, high fan-in, rising single-function complexity,
large modules, or weak test references identify places to review. The actual
decision to refactor still depends on whether the code is actively difficult to
change, risky to extend, weakly covered, or blocking a planned feature.

## What The Tracker Is

The Tracker is the durable issue-and-decision layer used by the maintainer.

Each tracker item is a living record for one topic, question, feature, bug,
design decision, or deferred idea. A tracker item may contain:

- the original question or request;
- status and priority;
- the relevant project area;
- a short code such as `EVENT-004` or `JOB-002`;
- scope and acceptance criteria;
- running discussion notes;
- decisions made by the project owner;
- assistant analysis and recommendations;
- actions taken;
- validation results;
- related tracker items;
- final outcome, including implemented, open, low-priority, completed, or
  wontfix decisions.

The project owner creates the agenda through conversation: questions,
corrections, priorities, and decisions. Codex maintains the tracker with the
owner's input by adding new items, updating discussion logs, recording
decisions, refreshing status and priority, and keeping the generated tracker
index current.

The Tracker is not only a TODO list. It is a shared memory of why decisions
were made, what was tried, what was accepted, and what should not be repeated.

## Handoff Files And Conventions

The private handoff files make the collaboration restartable. They tell a fresh
assistant how to get oriented, which files to read, what repository boundaries
matter, what shell/tooling notes apply, and what validation matrix is expected.

The action log records concrete work from recent sessions: what changed, what
was validated, what was committed and pushed, and what immediate follow-up state
remains.

Together, these files reduce dependency on chat transcript memory. A restarted
assistant can re-read them, inspect the repository, and continue from the actual
project state.

## Lessons Learned

The lessons-learned archive stores reusable process and design takeaways that
should outlive a single implementation slice. It is for guidance that should
shape future sessions, not for tracking the status of one feature or bug.

Lessons learned are separate from tracker items. Tracker items record specific
questions, decisions, priorities, implementation state, and validation for one
topic. Lessons learned capture broader patterns, such as workflow conventions,
refactoring judgment, documentation practices, or how to reason about a class
of design tradeoffs.

Each lesson is stored as a numbered document with a short descriptive title.
Lessons include created and updated timestamps, and the archive has an index
that lists lesson filenames and dates. When a new lesson is added or revised,
the index should be updated at the same time so fresh sessions can discover
the relevant takeaways quickly.

## Why The Workflow Is Iterative

Bywaf has many moving parts: framework behavior, plugin contracts, event
schemas, audit semantics, user-facing commands, tests, docs, and operator
workflow. A single large request is unlikely to capture all constraints
correctly.

The iterative loop lets the owner and assistant converge:

- The owner explains intent and supplies product judgment.
- Codex inspects the codebase and finds the real implementation shape.
- Codex proposes or implements a small slice.
- Tests and metrics reveal whether the change is safe.
- The owner reviews, corrects, accepts, defers, or redirects.
- The Tracker records the decision so it persists.

This is especially useful for terminology and policy decisions. When a term is
clarified or a policy is accepted, the decision is recorded rather than left as
implicit chat memory.

## What Codex Does

Codex acts as a persistent engineering agent:

- reads the handoff, tracker, docs, and relevant source code;
- inspects current repository state before editing;
- implements small, scoped changes;
- runs focused and broad validation;
- reports concrete results;
- updates tracker, action, and lesson files when appropriate;
- commits and pushes public repository changes when asked or when the workflow
  requires it;
- checks CI and records remote validation.

Codex may challenge unclear or risky design ideas when needed, but the project
owner sets priorities and makes final product decisions.

Outside AI tools may be used for critique, alternate drafts, or independent
review. Their suggestions are treated as input to the same inspection,
validation, and maintainer approval loop, not as project authority.

## What The Project Owner Does

The project owner steers the project:

- sets priorities;
- asks design questions;
- clarifies terminology;
- accepts, rejects, or revises proposals;
- decides what is low priority, on hold, implemented, or wontfix;
- reviews implementation reports;
- supplies the human judgment that tests and metrics cannot provide.

The owner does not need to pre-specify every detail. The workflow is designed so
that design details can be discovered and refined through code inspection,
tests, and discussion.

## Validation Expectations

Small changes start with focused tests. Broader changes should run the standard
local validation set:

```bash
PYTHONPATH=. pytest -q
ruff check .
pyright
PYTHONPATH=. python3 scripts/plugin_check.py --all
python3 scripts/bundled_plugin_manual_check.py
python3 scripts/architecture_metrics.py
```

Architecture metrics are treated as inspection signals, not automatic
decisions. High coupling, high complexity, large modules, or weak test
references nominate code for review; human judgment decides whether a refactor
is warranted.

## Short Explanation

Here is the concise version:

> Bywaf uses Codex as a persistent engineering collaborator, not a one-shot code
> generator. The maintainer workflow has private handoff docs, conventions, a
> tracker, action logs, and lessons learned outside the public repo so each
> session can restart from durable project memory. Work happens in small slices:
> discuss the design, inspect the code, implement, validate, update the tracker,
> and review together. The Tracker is the durable record of questions,
> decisions, actions, status, and validation for each topic. Codex maintains it
> with owner input, while the owner sets priorities and makes final product
> decisions. This keeps AI-assisted work auditable, restartable, and aligned
> with the real codebase instead of relying on one giant prompt.

## Practical Lesson

The effective pattern is:

```text
conversation -> inspection -> small implementation -> validation -> tracker update -> review -> next slice
```

That loop gives the assistant enough context to move quickly, while preserving
human control over meaning, priority, and acceptance.
