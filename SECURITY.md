# Security policy

This policy covers **BLACKHEART itself** — the Python package, CLI, scheduler,
triggers, findings repository and release artifacts. It does not grant permission
to test any third-party system. Every active test still passes BLACKHEART's own
authorization gate (`blackheart/authz/`), and you must have written permission
from the target's owner.

## Supported versions

| Version | Supported |
|---|---|
| `1.x` | yes |
| `< 1.0` | no |

## Reporting a vulnerability in BLACKHEART

Use GitHub's private vulnerability reporting:

<https://github.com/itzebe/blackheart/security/advisories/new>

Do **not** open a public issue for a suspected vulnerability. Include:

- the affected version (`blackheart version --json`) and commit;
- the module or command;
- a minimal reproduction, with the target fixture or a redacted equivalent;
- the impact you believe it has;
- any suggested fix.

Do not include credentials, private target data, or bounty-confidential material.
If a proof requires a secret, describe the shape of the secret instead.

## What to expect

- Acknowledgement within 7 days.
- Triage and a severity assessment against the project's own impact rules.
- A fix, a regression test, and credit in the changelog if you want it.
- No bug bounty is offered for BLACKHEART itself.

## Safe harbour

Good-faith research on **your own installation** is welcome. The following are
out of scope and are not covered by safe harbour:

- testing a system you do not own or have written permission to test;
- accessing, changing or exfiltrating another person's data;
- denial of service, spam, social engineering, or physical attacks;
- publishing a working exploit before a fix is available.

## Security design rules this project holds itself to

- Authorization fails closed; an unverified or empty record authorizes nothing.
- External engines run only behind a compatibility record bound to the target.
- No secret is written to source, logs, findings, SARIF, or release artifacts.
- A finding cannot become `CONFIRMED` without evidence, an independent
  verification and a named reviewer.
- A blocked run is never reported as a clean run.
