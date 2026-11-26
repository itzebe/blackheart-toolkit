# Portable cloud execution (InstaBox)

BLACKHEART runs a persistent Linux box on [InstaBox](https://instabox.sh) and
uses it for work the local OpenHands sandbox cannot do: heavy source analysis,
corpus processing, fuzzing, and builds. This document states exactly what the
integration is, how to bootstrap it in a fresh sandbox, what was verified, and
what is not.

## What it is

- `blackheart/cloud/__init__.py` — the InstaBox API client. Standard library
  only (`urllib`); **no dependency, no Node, no CLI install required**.
- `blackheart/cloud/run.py` — engagement-scoped execution, artifact retrieval
  with SHA-256 verification, and the audit log.
- `blackheart cloud …` — the CLI (`doctor`, `connect`, `status`, `execute`,
  `artifacts`).

The API server is `https://api.instabox.sh`. The client speaks the same REST API
the InstaBox CLI and SDKs use; the request/response shapes below were read from
the official docs and **verified live** (see "Verified" below).

## Security model

| Requirement | How it is enforced |
| --- | --- |
| Credential never committed or logged | Read only from `INSTABOX_API_KEY`; never written to a file, artifact, or the audit log; `CloudConfig.to_dict()` and `repr(client)` redact it; the key travels only in the `X-API-Key` header |
| Fails closed on missing credential | `MissingCredential`; the CLI exits `3` and prints how to set the secret |
| Fails closed on rejected credential | HTTP 401/403 → `AuthError`; the CLI exits `4` |
| Fails closed when the machine is absent | `MachineNotFound`; the CLI exits `5` |
| **Never falls back to local execution** | The module has no local execution path at all; a network error aborts (`test_network_failure_never_falls_back_to_local`) |
| Reuses the existing machine | The client exposes no create/stop/suspend/delete/resize route; `resolve_machine` only reads |
| Idle-suspended machine is reused, not skipped | A persistent box that has idled into auto-suspend is the **normal** state; `resolve_machine` treats `running`, `suspended` and `paused` as usable (`WAKEABLE_STATES`) because an `exec` wakes them. Only a state an `exec` cannot wake (`stopped`, …) is refused |
| Persistent storage preserved | Work is written under `/data/home/...` (the persistent disk); the client never touches the root disk |
| Concurrent conversations do not corrupt state | Each engagement has a unique id and its own remote + local directory and audit log |
| Artifact integrity | The machine's own `sha256sum` is compared to the received bytes; a mismatch is refused, not written |

An **engagement** is one unit of remote work: a unique id
(`eng-<UTC>-<8 hex>`), a remote directory under
`/data/home/.blackheart/engagements/<id>`, a matching local directory under
`research/private/cloud/<id>` (gitignored), and an append-only `audit.jsonl`
recording each command, its exit code, and **hashes** of the output — never the
output itself.

## Bootstrap in a fresh sandbox

```bash
git clone https://github.com/itzebe/blackheart && cd blackheart
pip install -e .                      # or: ./install.sh --core
# The credential comes from the environment; in OpenHands it is a registered
# secret named INSTABOX_API_KEY and is injected automatically.
python3 -m blackheart cloud doctor    # one command: auth -> machine -> remote run -> artifact
```

`cloud doctor` performs the whole chain and prints one line per check:

```
  [ok] credential present           INSTABOX_API_KEY set
  [ok] authenticated                login=<you>
  [ok] machine discovered           <name> (m_…)
  [ok] machine ready                state=running
  [ok] resources reported           4 vCPU / 8192 MiB
  [ok] persistent storage           /data 20 GiB
  [ok] remote exec                  blackheart-remote-ok
  [ok] genuine remote (not local)   remote host <box> kernel … != local <sandbox>
  [ok] artifact round-trip verified <name> sha256=…
```

It exits `0` only when every check passes, and the credential is never printed.

## Required secret configuration

One secret, no others:

| Name | Where it comes from | Notes |
| --- | --- | --- |
| `INSTABOX_API_KEY` | InstaBox dashboard → **API keys** (`ibk_…`) | Scopes needed: `machines:read`, `machines:write` (exec and file write). `machines:delete` is **not** used. |

In OpenHands, register it as a secret named `INSTABOX_API_KEY`; the platform
injects it into the shell environment, which is exactly where the client reads
it. No other configuration is required. Optional overrides:
`BLACKHEART_CLOUD_MACHINE` (machine id or name when several are running),
`INSTABOX_SERVER` / `INSTABOX_API_URL` / `INSTABOX_API` (a non-default API base),
`BLACKHEART_CLOUD_HOME` (the local engagement root).

## Commands

```bash
blackheart cloud connect                       # authenticate + print the machine identity
blackheart cloud status                         # health, resources, /data usage
blackheart cloud doctor                         # full portability check (above)
blackheart cloud execute -- 'uname -a'          # run a command in a new engagement
blackheart cloud execute --timeout 300 -- make test
blackheart cloud execute --artifact /data/home/.blackheart/engagements/<id>/out.json \
                        --artifact-name out.json -- 'build > out.json'
blackheart cloud artifacts                      # list + re-verify retrieved artifacts
```

The connection flags `--machine`, `--server`, `--workdir` are accepted both
before and after the subcommand.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success |
| `1` | a check failed, or the remote command failed (for `execute`, the command's own exit code) |
| `3` | no `INSTABOX_API_KEY` (fails closed; never local) |
| `4` | the credential was rejected (HTTP 401/403) |
| `5` | no usable machine found (none running/suspended/paused) |

## Verified API contract

Read from the official docs (`instabox.sh/docs`) and confirmed live on
2026-11-12 against machine `m_agq45fy6ywysgwnx6yhqnybgsa` (`jonathan`):

| Operation | Method + path | Verified |
| --- | --- | --- |
| account | `GET /v1/me` | 200, `login=itzebe` |
| list machines | `GET /v1/machines` | 200, JSON array |
| one machine | `GET /v1/machines/{id}` | 200 |
| run a command | `POST /v1/machines/{id}/exec` body `{"cmd","cwd","envs","timeoutSeconds"}` | 200, `{stdout,stderr,exitCode,timedOut,truncated,oomKilled}` |
| write a file | `PUT /v1/machines/{id}/files?path=…&parents=true` (raw bytes) | 201, `{path,size,sha256,…}` |
| read a file | `GET /v1/machines/{id}/files/content?path=…` | 200, raw bytes |
| list a directory | `GET /v1/machines/{id}/files?path=…` | 200, Files shape |
| disk usage | `GET /v1/machines/{id}/disk` | 200, filesystems |

Authentication is the `X-API-Key` header (or `Authorization: Bearer`). An exec
is capped at 600 seconds; a longer job must run detached.

## Tested claims (only what was run)

- **Local, live:** `blackheart cloud doctor` passed every check against the real
  machine on 2026-11-12; `connect`, `status`, `execute`, and `artifacts` were each
  run against it and behaved as documented.
- **Genuine remote execution:** the doctor's remote self-test reports the machine's
  own hostname (`instabox-jonathan`) and kernel (`6.18.60-instabox`), which differ
  from the local sandbox's; the artifact is fetched back and its SHA-256 verified.
- **Auto-suspend wake (verified live):** a suspended machine was resolved and used
  without any lifecycle command — an `exec` woke it (`state: suspended → running`,
  stdout `HELLO_FROM_REMOTE`, host `instabox-jonathan`). This is the normal state
  for a fresh conversation, and the reason `resolve_machine` accepts wakeable
  states (regression-tested by `test_resolve_accepts_suspended_machine`).
- **Unit tests:** `tests/test_cloud.py` — 39 tests covering credential handling,
  error mapping, machine resolution (including wakeable states), engagement
  isolation, concurrent engagements, artifact verification and tamper detection,
  audit redaction, and every fail-closed path. The network is the only thing
  replaced (an injected transport); the client logic runs unchanged.
- **Full suite:** `python3 -m pytest` — **416 passed, 12 skipped**.

## Honest limits

- The unit tests use an in-process fake for the network boundary. They prove the
  client logic and the failure handling; they do **not** prove a live round trip
  — the live `doctor` run does that.
- A full fresh-sandbox portability run needs the `INSTABOX_API_KEY` secret to be
  present in that sandbox. Without it the client correctly fails closed; the
  clean-sandbox check is then limited to the credential-absent path.
- The client exposes read/exec/file routes only. It cannot create, stop, resize,
  or delete a machine — deliberately, so a bug cannot destroy the persistent box.
