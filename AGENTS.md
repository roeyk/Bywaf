# Bywaf Assistant Restart Gate

Before editing code, committing, pushing, or running a broad coding batch in
this repository, read these files in order:

1. `/home/roey/Downloads/codex/bywaf-discussions/START_HERE.md`
2. `/home/roey/Downloads/codex/bywaf-discussions/ACTIONS.md`
3. `/home/roey/Downloads/codex/bywaf-discussions/CONVENTIONS.md`
4. `/home/roey/Downloads/codex/bywaf-discussions/index.json`
5. the active tracker items and lessons-learned files listed in
   `START_HERE.md`

Then inspect the repository state:

```bash
git status --short --branch
git diff --stat
git log --oneline -5
git log --oneline origin/main..HEAD
```

The first working update must explicitly state that the mandatory handoff,
actions, conventions, index, tracker, and lessons-learned files were read;
summarize branch/status and latest local commit; note any uncommitted or
unpushed work; name the applicable validation matrix row from `CONVENTIONS.md`;
and list the local repository files inspected before editing.

If you cannot honestly provide that read receipt, do not edit files yet.
