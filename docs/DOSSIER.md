# Project dossier

`blackheart dossier <path>` is one explorable view of a project. It adds no
engine: it runs the scanner, the rule engine, the interrogation pass and the
dataflow pass that already exist and renders what they already report as a single
ranked page.

Use it when you are opening an **advanced or already-audited** project and want to
start from what the code says and where it cannot be trusted, instead of a blank
editor.

```
blackheart dossier path/to/project
blackheart dossier path/to/project --json
blackheart dossier path/to/project --out work/
```

## What it reports

- **Surface** — contracts/packages, functions, externally callable, state-changing,
  dispatchables, cgo/FFI boundaries, as the active scanner recovered them.
- **Candidate leads** — every rule that matched, with `file:line` and the question
  to ask.
- **Interrogation** — the claims the code makes, split into falsified / survived /
  untestable. A falsified claim is the strongest static signal in the dossier.
- **Unprivileged data flows** (Solidity) — `msg.sender` / parameters / external
  returns reaching a sink without a recognised guard.
- **Next probes (ranked)** — the strongest of the above, severity-ordered, so the
  first thing to reproduce is the first thing you read.
- **What the scanner could not read** — unread source and unsupported constructs,
  so a thin dossier is never mistaken for a safe one.

## Discipline

Every item is a **lead**, never a finding. The dossier prints that in its own
output. A clean dossier is not a proof of safety; it names the blind spots it
could not see.

## Not in this increment

Audit-report ingestion and unaudited-surface mapping (`blackheart audit
coverage`), transaction replay (`blackheart debug tx`) and an interactive shell
(`blackheart explore`) are the next increments; this command is the composition
they build on.
