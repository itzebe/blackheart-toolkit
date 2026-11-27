# Incremental finding baseline

A baseline turns a re-run from a wall of findings into a reviewable diff:

```bash
# commit this (it contains no evidence content, only identifying metadata)
python3 -m blackheart baseline --findings research/private/findings create --out baseline.json

# in CI: fail only when a genuinely new finding appears
python3 -m blackheart baseline --findings research/private/findings \
  compare --baseline baseline.json --fail-on-new
```

## What it compares

Each finding is reduced to its **content fingerprint** -- the same
`finding_fingerprint` the SARIF export emits. The fingerprint is built from the
fields that define the defect: component, category, root-cause file and line, and
the design mistake. When those are absent it falls back to the finding id and
title.

| Bucket | Meaning |
|---|---|
| **new** | a fingerprint the baseline has never seen |
| **resolved** | a baseline fingerprint no longer present |
| **changed** | the same fingerprint with a different verdict or severity |
| **unchanged** | everything else, including a new id or title for the same root cause |

`compare` exits 0 normally and 1 with `--fail-on-new` when the **new** bucket is
non-empty. `--json` emits the full diff; the default is Markdown.

## Why content-addressed

Row order, timestamps and titles are not identity. A finding re-recorded under a
new id, or retitled, is the same defect and stays in **unchanged**. A verdict
that moves from `UNCONFIRMED` to `CONFIRMED` is a **change**, so the move is
visible and is not mistaken for a new bug.

When two records share a fingerprint, the baseline keeps the stronger one
(`CONFIRMED` before `STRONGLY_SUPPORTED`, higher severity before lower), so a
duplicate note cannot downgrade the baseline.

## Limitations

- Identity includes the root-cause **line**. A line that moves is a new
  fingerprint, so the diff shows it as new + resolved; review it rather than
  treating it as a regression by itself.
- The baseline covers findings, not raw `ingest` candidate flags. A flag is a
  lead, and its lifecycle is the findings repository.
- The baseline carries no evidence content, so it cannot prove a finding; it only
  says what is new since the baseline.

Acceptance bar: `tests/test_baseline.py`.
