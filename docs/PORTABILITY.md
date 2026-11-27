# Portability

BLACKHEART is designed to run in any independent OpenHands sandbox. This document
states exactly what is portable, how to install, update, and recover, and what has
actually been tested.

## What makes it portable

- The engine (`blackheart/`) depends only on the Python standard library
  (`dependencies = []` in `pyproject.toml`). It runs with no network and no keys.
- The toolchain is installed by `install.sh`, which detects OS/arch, is
  idempotent, and reports per-tool status instead of failing wholesale.
- Skills (`skills/`) and agents (`agents/`) are plain Markdown with frontmatter;
  they can be copied into any OpenHands workspace's `.agents/`/`.openhands/`.
- All state (evidence, ledger, authorization registry, tool registry) is written
  to paths under the engagement workdir or `~/.blackheart`, never to tracked
  paths by default.

## Install into a fresh sandbox

```bash
git clone <repo> && cd blackheart
./install.sh --core                     # fast: engine + Foundry
python3 -m pytest tests/                # engine self-test, no network
python3 -m blackheart tools verify      # toolchain status for this host
```

## Update

```bash
git pull
./install.sh --verify                   # re-check the toolchain after a change
python3 -m pytest tests/
```

## Recover

Everything is reproducible from the repository plus `install.sh`:

- **Lost toolchain** -> `./install.sh`.
- **Lost private evidence** -> re-run `python3 -m blackheart engagement --workdir <dir>`;
  evidence is content-addressed, so identical results re-derive identical ids.
- **Stale tool registry** -> `python3 -m blackheart tools verify --out <path>`.

## Separating public code from private evidence

- Public, committed: `blackheart/`, `harnesses/`, `agents/`, `skills/`, `docs/`,
  `templates/`, `examples/`, tests.
- Private, gitignored: `research/private/**` (engagement evidence, reports,
  authorization records with target data), `.openhands/`, `.agents/`.
- Never commit secrets, private keys, API tokens, viewing keys, or
  bounty-confidential evidence.

## Tested portability claims

This section is deliberately conservative — it lists only what was actually run.

- **Tested here:** the engine, its **115-test** suite, the Foundry harness, and the
  reference engagement all run in this sandbox with the standard library plus the
  installed toolchain.
- **Tested in a second, independent workspace:** the working tree was copied to
  `/tmp/bh-portable` (excluding `.openhands/` and the vendored `forge-std`).
  `python3 -m blackheart provision` created the discovery layout; `pytest tests/`
  then reported **115 passed**, and `python3 -m blackheart agents-verify` loaded
  all **7 skills and 12 agents** from the fresh workspace. The only setup step
  needed was fetching `forge-std` for the Foundry harness (`install.sh` does this).
- **Tested in an independent container (2026-11-10).** `docker run python:3.13-slim`
  (a *different* Linux image, no Foundry, no toolchain) with the repo mounted
  read-only:

  | check | command | result |
  |---|---|---|
  | engine self-test | `python3 -m pytest tests/` | **87 passed, 3 skipped, 0 failed** (the 3 skips are forge/fork tests, skipped honestly when forge is absent) |
  | self-diagnosis | `python3 -m blackheart doctor` | **healthy** (only `forge on PATH` and the tool registry report `[!!]`, as expected on a bare host) |
  | repeatable install | `./install.sh --core` | completes; `forge --version` -> **1.9.0** |
  | stdlib-only | `pip install pytest` was the *only* install | the engine imports with no third-party runtime dependency |

  This is a real second-environment test: the engine is **portability-verified**
  for the stdlib-only path, and `install.sh --core` is **functionally verified**
  on a clean image. The remaining `[!!]` items (live-protocol tools) install on
  demand and are not required for the fork workflow.
- **Not yet tested here:** a full `./install.sh` run on a *second, independent*
  sandbox with network access to install the non-Foundry tools. Until that is
  done, the installer is "designed to be portable and syntax-verified", not
  "fully portability-verified". Treat this as an open item (see
  `docs/RESEARCH_LOG.md`).

## Portable cloud execution (InstaBox)

BLACKHEART can run work on a persistent InstaBox cloud machine, for the heavy
jobs the local sandbox cannot do. The client (`blackheart/cloud/`) is **standard
library only**, so no Node, no CLI install, and no extra dependency is needed —
the same portability property as the rest of the engine. The credential is read
from `INSTABOX_API_KEY` (an OpenHands secret) and is never committed or logged.

```bash
pip install -e .
python3 -m blackheart cloud doctor    # auth -> machine -> remote run -> artifact
```

`cloud doctor` fails closed: no credential (`exit 3`), a rejected credential
(`exit 4`), or an absent machine (`exit 5`) each abort, and there is no local
fallback — the module has no local execution path. Full detail, the verified API
contract, and the honest limits are in [CLOUD_EXECUTION.md](CLOUD_EXECUTION.md).

## Making skills and agents discoverable

OpenHands loads **project** skills from `{workspace}/.openhands/skills/` and project
agents from `{workspace}/.openhands/agents/`. BLACKHEART keeps them at `skills/`
and `agents/` (the layout its own tooling and tests use), so run:

```bash
python3 -m blackheart provision          # create the discovery layout (idempotent)
python3 -m blackheart agents-verify      # confirm the agent-server sees them all
```

`provision` creates relative symlinks (falling back to a copy on filesystems that
reject symlinks). `agents-verify` talks to the real agent-server and exits non-zero
if anything is missing or the server is unreachable — it never reports a
fabricated success. `install.sh` runs `provision` automatically at the end.

## Inheriting external intelligence in every project

The You.com external-intelligence capability (see
[INTELLIGENCE.md](INTELLIGENCE.md)) is **portable, not hardcoded to one target**.
`provision` also runs the intelligence bootstrap, so a project initialized or
provisioned through BLACKHEART receives the capability:

```bash
python3 -m blackheart provision                    # also bootstraps .openhands/ intelligence
python3 -m blackheart intel bootstrap --root <proj> # or bootstrap one project explicitly
python3 -m blackheart intel providers              # real availability (no fake success)
```

The bootstrap writes `.openhands/mcp.json` (referencing `${YDC_API_KEY}`, never the
value) and `.openhands/intelligence.env.example`. `.openhands/` is gitignored, so
no secret is committed. A project may override the provider order or disable a
provider **only with an explicit reason** in `.openhands/intelligence.json`;
a reasonless disable is ignored, so a project cannot silently drop the capability.

**Scope of the claim:** projects that are not provisioned by BLACKHEART do not
inherit this automatically — they get it via `provision`/`bootstrap` or by copying
the `.openhands/` config. The portable `install.sh` also performs the bootstrap
(`--project <path>`) and prints the intelligence verification status.
