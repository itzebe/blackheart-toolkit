# Contributing to BLACKHEART

Read `AGENTS.md` first. It carries the identity, the question every mission
answers, the operational doctrine and the repository facts. This page is the
short workflow.

## Setup

```bash
python3 -m pip install -e ".[dev]"
python3 -m blackheart version
python3 -m pytest tests/ -q
```

Python 3.11 or newer. The runtime is stdlib-only; do not add a dependency
without a concrete reason and a test that needs it.

## The rules that are not negotiable

1. **Additive and tested.** Do not weaken an existing check to make a new one
   pass. A change is done only when the full suite is green.
2. **No fabricated evidence.** A finding is a record of what ran, with evidence.
   Never invent a metric, a reproduction, a reviewer, or a result.
3. **Fails closed.** Authorization, the compatibility gate and the findings
   confirmation gate refuse when they cannot prove the precondition. Keep it
   that way.
4. **A blocked run is not a clean run.** Report `BLOCKED`, `INCOMPLETE` or
   `NO_FINDINGS` honestly; never turn one into `PASS`.
5. **No secrets, no private target data.** Use the environment, not source,
   fixtures, logs or SARIF.
6. **One concern per pull request.** Match the existing architecture and style.

## Adding a capability

A new engine or class is not done when the code runs. It is done when:

- the capability statement (`blackheart/capability.py`) says what it can and
  cannot do, with evidence and a limitation;
- `docs/CAPABILITIES.md` is regenerated or updated;
- the class has an executable vulnerable/guarded pair and the coverage ledger
  names it (`blackheart coverage` must stay green);
- a test proves the vulnerable side breaks **and** the guarded twin holds;
- the new command appears in `blackheart guide` (the product test enforces it).

If a class cannot be modelled, record it as a named gap. A gap is honest; a
missing model presented as coverage is not.

## Tests

- Unit tests for logic; integration tests at the boundaries; a real end-to-end
  path where one exists.
- No mocks unless the real path cannot be exercised, and say why in the test.
- Mark slow, live and network tests with the existing markers.
- Run the relevant subset while developing, then the full suite before the PR:

```bash
python3 -m pytest tests/ -q
python3 -m blackheart differential
python3 -m blackheart coverage
python3 -m blackheart doctor
```

A skipped test is not a pass. State what was skipped and why.

## Pull requests

- Branch from `main`, keep the change reviewable, and link the issue or mission.
- Describe what changed, why, the exact commands you ran, the counts, and the
  honest limitations.
- CI must be green. Do not merge with a failing required check.
- Do not push to `main` directly and do not commit build output, caches,
  credentials or `research/private/`.

## Code style

- Standard library first; type hints on public functions.
- Small functions, clear names, comments only for non-obvious intent, an
  invariant, or a workaround with its removal condition.
- Errors are explicit: decide what is retryable, user-facing, or a bug.
- Keep the doctrine in `blackheart/doctrine.py` and the identity in
  `blackheart/mindset.py`; do not paraphrase them into a new module.

## Review

Review your own change as a senior engineer who did not write it: production
ready, no dead control, no fake success, no authorization gap, no regression
outside the touched code, every acceptance criterion evidenced.
