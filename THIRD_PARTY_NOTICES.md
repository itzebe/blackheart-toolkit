# Third-party notices

BLACKHEART integrates with the following external projects as **separate
programs and services**. None of their source is vendored, linked, or embedded
in BLACKHEART; BLACKHEART communicates with them over a process or network
boundary and consumes only their output. Their licenses therefore apply to those
programs, not to BLACKHEART.

| Project | Upstream | License | How BLACKHEART uses it |
|---|---|---|---|
| **Strix** | https://github.com/usestrix/strix | Apache License 2.0 | Invoked as an external CLI (`strix --target ...`). No code linked. |
| **Shannon** | https://github.com/KeygraphHQ/shannon | **GNU AGPL-3.0** | Invoked as an isolated external process (`npx @keygraph/shannon ...`). No code linked, imported, or embedded. |
| **PentAGI** | https://github.com/vxcontrol/pentagi | MIT (core) + EULA / NOTICE | Used as an isolated upstream HTTP service (REST/GraphQL). Not hosted or modified by BLACKHEART. |

## Why the boundaries matter

- **Shannon (AGPL-3.0).** AGPL-3.0 imposes strong copyleft and a network-use
  clause. BLACKHEART deliberately treats Shannon as a **separate program**: it
  runs the Shannon CLI as a child process and reads the files Shannon writes. It
  does not `import` Shannon, vendor its source, or link against it. This keeps the
  programs separate under copyright law and BLACKHEART's own license unaffected.
  If you redistribute BLACKHEART together with a copy of Shannon, the AGPL terms
  for Shannon still apply to Shannon.
- **PentAGI (MIT + EULA).** The core is MIT, but the distributed product carries a
  EULA/NOTICE. BLACKHEART treats it purely as a **network service** the operator
  installs and runs under their own agreement with the vendor. BLACKHEART ships
  none of PentAGI's code or configuration.
- **Strix (Apache-2.0).** Permissive. Still invoked as an external CLI rather than
  vendored, so its license and attribution remain with the upstream project.

## Operator responsibilities

- Install and run each engine under its own license terms and the operator's own
  agreements with the upstream projects.
- Provide the engines' model-provider credentials (Strix/Shannon) or a running
  PentAGI instance and API token. BLACKHEART reads these from the environment and
  never stores them.
- Do not enable any engine against a target that has not passed BLACKHEART's
  authorization gate. The gate is enforced in code (see `docs/ENGINES.md`).

No engine source is copied into this repository. The engine *names* and the
*interface shapes* (CLI flags, output file formats) are used to interoperate,
which is permitted; the upstream projects' own code and licenses remain theirs.
(The one adapted-code dependency, Agentic-Bug-Hunter, is documented separately
below.)

## Adapted source (code ported into BLACKHEART)

Unlike the engines above, the following project's **source was adapted into
BLACKHEART**. The port is a reimplementation of the upstream's tables and
decision logic in BLACKHEART's own model, not a verbatim copy, but it is derived
from upstream code, so the upstream MIT notice is preserved in the affected
modules and reproduced here.

| Project | Upstream | License | How BLACKHEART uses it |
|---|---|---|---|
| **Agentic-Bug-Hunter** | https://github.com/awarexone/Agentic-Bug-Hunter | MIT | Deterministic scope matcher (`blackheart/authz/scope_matcher.py`, adapted from `bughunter/tools/scope_checker.py`) and the weak-finding triage gate (`blackheart/verify/triage.py`, adapted from `skills/triage-validation/SKILL.md` and `bughunter/tools/lead_board.py`). |

```
MIT License

Copyright (c) 2026 Claude Bug Bounty Hunter Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The upstream repository is **not** vendored, cloned, or imported at runtime; only
the specific, documented algorithms above were adapted, with the MIT notice kept
in each affected module. See `docs/AGENTIC_BUG_HUNTER.md` for what was adopted,
why, and how it was modified for BLACKHEART's architecture.
