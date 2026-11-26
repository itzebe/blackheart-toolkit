# The authorization gate

The gate is the single choke point that decides whether **active** testing may run
against an asset. It fails closed.

## What must be true before active testing

For the asset:

- it is explicitly classified `AUTHORIZED` (never inferred).

For the program (all required):

- `program_active` — the program is currently active,
- `safe_harbor` — a safe harbor applies,
- `zero_cost` — participation needs no spend,
- `nigerian_eligible` — researcher eligibility established,
- `payout_feasible` — a practical payout path exists,
- `verified` — the record is marked verified,
- dated `evidence` attached,
- an official `scope_url` recorded.

Any missing item blocks. `AuthorizationError` is raised by `assert_authorized`.

## Asset classification

Every asset is one of:

- `AUTHORIZED` — active testing permitted under verified rules,
- `PASSIVE_ONLY` — passive analysis permitted, active testing not established,
- `UNKNOWN` — authorization unresolved (the default),
- `OUT_OF_SCOPE` — prohibited or excluded.

Only `AUTHORIZED` may enter active exploitation.

## Ownership is not permission

`reject_inferred_authorization` refuses to treat an asset as in-scope because it
was found via a public repository, a deployed application, a third-party tracker,
company ownership, or a bare assumption. Authorization must be recorded from the
official program scope.

## Recording a check

Copy `templates/authorization.json`, fill it in from the current official program
page, and store it in the registry (append-only JSONL). The registry refuses to
store a record with no evidence.

```bash
python3 -m blackheart campaign --profile p.json --authz auth.json \
    --engagement eng --asset asset-a --workdir research/private/eng
# -> prints "authorization for 'asset-a': allowed=<bool>", then blocks or proceeds
```

## Regression tests

`tests/test_authz.py` (15 tests) covers: fully-authorized allowed; every
non-authorized status blocked; each required check blocking when missing; missing
evidence/scope/verified blocking; inferred-authorization rejection for all five
sources; and ownership-is-not-permission.

```bash
python3 -m pytest tests/test_authz.py
```
