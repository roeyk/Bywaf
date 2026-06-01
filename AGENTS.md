# Bywaf Assistant Restart Gate

Before editing code, committing, pushing, or running a broad coding batch in
this repository, read these files in order:

1. the private discussion handoff `START_HERE.md`, if available
2. the private actions log `ACTIONS.md`, if available
3. the private conventions file `CONVENTIONS.md`, if available
4. the private tracker guide `TRACKER.md`, if available
5. the private tracker index `index.json`, if available
6. the active tracker items and lessons-learned files listed in
   `START_HERE.md`

Then inspect the repository state:

```bash
git status --short --branch
git diff --stat
git log --oneline -5
git log --oneline origin/main..HEAD
```

The first working update must explicitly state that the mandatory handoff,
actions, conventions, tracker guide, index, tracker, and lessons-learned files
were read; summarize branch/status and latest local commit; note any
uncommitted or unpushed work; name the applicable validation matrix row from
`CONVENTIONS.md`; and list the local repository files inspected before editing.

If you cannot honestly provide that read receipt, do not edit files yet.

Do not commit local machine paths, usernames, home directories, scratch
directories, secrets, tokens, keys, cookies, or other environment-specific
disclosure into this repository.
