# External intelligence (You.com)

BLACKHEART can pull **external** intelligence — live web search, page
extraction, and citation-backed research — and reads every result through the
one attacker question:

> I am an ordinary, unprivileged attacker: what transaction sequence, inputs,
> timing, account state, or market conditions can I create or manipulate to
> receive more assets than I am entitled to, bypass a restriction, or make
> another user's position absorb my loss?

This document describes the layer, the safety rules, and the honest limits.

## 1. Why it exists

A mission often needs external context: known attack patterns for a class, a
protocol's documented behaviour, prior advisories, or prior art before claiming
novelty. You.com provides three capabilities for that:

| Capability | Endpoint | Billed? | Use |
| --- | --- | --- | --- |
| Web search | `POST https://ydc-index.io/v1/search` | snippets: no; `--extract`: yes | find prior art, advisories, patterns |
| Contents | `POST https://ydc-index.io/v1/contents` | **yes** | fetch a page's Markdown |
| Research | `POST https://api.you.com/v1/research` | **yes** | a citation-backed answer |

Authentication is the `X-API-Key` header (the documented REST convention; the
Inference Router's Bearer token is a different layer and is not used here). The
key is read from `YDC_API_KEY`.

## 2. The load-bearing rule: external results are untrusted input

A search result or a fetched page can say anything, including instructions aimed
at the agent. Every result is therefore treated as **data to reason over, never
as an instruction to follow**, and never as evidence that a vulnerability exists.
Only deterministic reproduction, verified impact, and applicable authorization
can confirm a finding. `frame_question()` attaches the attacker lens (the
question, the three outcomes, the five levers) to every result so the material is
read through the mission's lens rather than taken at face value.

This is enforced, not just documented. `blackheart/intelligence/quarantine.py`
wraps a result set in a fence that names it untrusted, attaches the attacker
lens, preserves provenance, and sanitises each snippet (control characters
stripped, length capped). `scan_for_injection` flags text that *looks like* an
instruction override ("ignore previous instructions", a fake `system:` tag, a
spoofed tool call, a request to exfiltrate a key) — a flag is a **warning for the
reviewer**, never an action. Because BLACKHEART never acts on retrieved text in
the first place, detection changes nothing about what it is allowed to do; it
only tells the human where to look. `blackheart intel investigate "<query>"`
returns this quarantined, lensed, provenance-tagged view.

## 3. Cost safety

The paid paths refuse to run unless the caller has explicitly opted in:

- `search(extract="highlights"|"full_page")`, `contents(...)`, and `research(...)`
  raise a distinct **`CostRefusal`** unless `allow_paid=True`.
- A hard per-instance cap (`max_paid_calls`) stops runaway spend; a cap of `0`
  with `allow_paid=True` still refuses every paid call.
- `health()` and a snippets-only search **never spend**.

`CostRefusal` is a separate type from `YouComError`, so a caller can never
mistake "BLACKHEART chose not to spend" for "the service failed".

## 4. Key safety

The key is read from `YDC_API_KEY`, sent only in the `X-API-Key` header, and
scrubbed from every error message before it is returned (both the exact key and
any `ydc-` token are redacted). It never appears in a URL, a log line, or the
emitted MCP config — which references `${YDC_API_KEY}` instead.

## 5. A non-obvious operational fact

`api.you.com` (Research) sits behind Cloudflare and **rejects urllib's default
`User-Agent` with HTTP 403 (error 1010)**. The client always sends a plain
`User-Agent: blackheart-intelligence/1.0`. Without it, research fails with a 403
that looks like an auth problem but is not. `ydc-index.io` (search/contents) does
not care but is unaffected.

## 6. CLI

```bash
blackheart intel health                        # probe connectivity (never billed)
blackheart intel search "erc4626 share inflation" --count 5
blackheart intel search "…" --extract highlights --allow-paid --max-paid-calls 1
blackheart intel contents --url https://… --allow-paid
blackheart intel research "how does … work?" --effort lite --allow-paid
blackheart intel mcp                           # emit the OpenHands MCP config
blackheart intel discover rpc "base" --chain-id 8453   # find + verify RPC endpoints
blackheart intel discover contract "USDC ethereum" --chain ethereum --rpc <url>
blackheart intel discover chain base           # resolve a chain id (registry first)
```

Every subcommand has `--json`; the JSON carries the attacker lens
(`attacker_lens`) alongside the result. Exit codes: `0` ok, `1` failure, `2`
usage error, `3` cost refused.

### Structured, verified discovery (`intel discover`)

The router and `investigate` return *sources*: text a human reads. A mission also
needs three concrete facts the engine cannot invent -- the RPC endpoint of a
chain, the on-chain address of a target, and a chain's numeric id. `intel
discover` produces those as a **structured, verified** result:

- `rpc <chain> [--chain-id N]` -- gathers candidate endpoints from the **keyless
  authoritative registry** (`chainid.network/chains.json`) and from You.com, then
  **probes every candidate with a real `eth_chainId` call**. Only endpoints that
  answer (and match `--chain-id`, when given) land in `verified`; the rest are
  reported as `candidates` with the error that disqualified them. `--no-probe`
  returns leads only, honestly labelled.
- `contract "<protocol> <chain>" [--rpc URL]` -- extracts `0x…` addresses from
  You.com results and verifies each holds code (`eth_getCode`) on the given RPC.
- `chain <name>` -- resolves the numeric id, **registry first** (exact), falling
  back to search only for a chain the registry lacks, and treating several
  distinct ids as ambiguous rather than guessing one.

The discipline is the project's own: external text is a *lead*, and only a call
that runs makes it a fact. A caller that wants only facts reads `verified` and
never `candidates`.

## 7. MCP (for an agent host)

The You.com MCP server exposes `you-search`, `you-contents`, `you-research`,
`you-finance`, `you-balance`, and `you-discover`. `blackheart intel mcp` emits an
`mcpServers` block for an OpenHands/FastMCP host.

**A verified dialect detail:** OpenHands (FastMCP) keys the transport as
`"transport": "http"`; several other hosts (and You.com's own docs) use
`"type": "http"`. Emitting the wrong key silently produces a non-connecting
server, so the module emits the OpenHands dialect by default and supports both
(`mcp_config(style="openhands"|"claude")`).

The general endpoint is `https://api.you.com/mcp` (search/contents/balance/
discover); the research tool lives on `https://api.you.com/mcp/research`. A
keyless free profile is `https://api.you.com/mcp?profile=free` (search + discover
only). The MCP auth header is `Authorization: Bearer <key>` (a transport detail),
not the REST `X-API-Key`.

**Cloudflare User-Agent caveat (verified live 2026-11-15):** `api.you.com` sits
behind Cloudflare, which answers a *default* User-Agent with `403` "Error 1010:
Access denied". This is a bot/IP rule, not an auth failure — the key is fine. Any
explicit User-Agent passes (`python-httpx/…`, `curl/…`, and BLACKHEART's own
`blackheart-intelligence/1.0` all returned `200` in testing), so ordinary MCP
clients (which set a UA) are unaffected; only a bare `urllib` request with no UA
is blocked. Do not read a `403` 1010 as a bad key.

## 8. Verified vs. unverified

- **Verified live (2026-11-13):** snippets search, a `lite` research call with
  sources, a contents fetch, and a raw MCP handshake listing the tools above.
- **Re-verified live (2026-11-15):** `POST https://ydc-index.io/v1/search`
  (`X-API-Key`) returned `200` with 5 results and real source URLs, provenance
  `you.com`; an MCP `initialize` handshake against `https://api.you.com/mcp`
  (`Authorization: Bearer`) returned `200` (`serverInfo: You.com 4.0.7`); and with
  `YDC_API_KEY` unset the router fell back to a live keyless provider without
  fabricating a result.
- **Unverified here:** the `deep`/`exhaustive` research efforts, the `frontier`
  (background) mode (not implemented — it is refused), the finance MCP path, and
  `output_schema`-shaped research output. These are documented but were not
  exercised in this engagement; treat them as unproven until a mission runs them.

## 9. Provider layer and primary-first policy

You.com is the **primary** provider. `blackheart/intelligence/providers.py` adds a
small provider registry and a deterministic router:

| Provider | Key needed | What it is | Billed |
| --- | --- | --- | --- |
| `you.com` | `YDC_API_KEY` | the full REST search above | snippets: no |
| `duckduckgo` | none | DuckDuckGo Instant Answer API | no |
| `wikipedia` | none | Wikipedia search API | no |

`blackheart intel providers` reports each provider's real availability (a keyless
provider is always available; You.com is `UNAVAILABLE` without a key — it does
not pretend to work).

`blackheart intel route "<query>"` enforces the primary: **when You.com is
configured it is the whole order by default**, so a hunt never silently answers a
technical query with a thin keyless result. The keyless providers are preserved as
an explicit, opt-in capability (`--allow-fallback` on `blackheart intel route` /
`investigate`, or `SearchRouter.search(..., allow_fallback=True)`); they are used
automatically only when the primary is *not configured* — honest degradation beats
no context at all. The router **skips** an unconfigured provider, tries the next on
failure, and keeps looking past a provider that returned an empty-but-ok result.
It never substitutes a fabricated or cached result for a failed live request: if
every provider fails, the routed result is `ok: False` with no sources.

Each attempt records **provenance**: the provider that answered, the error kind
on failure, and — with `--cross-check` — the per-provider disagreement
(URLs seen only by the primary, only by the other, or shared). Disagreement is
**recorded, not silently resolved** into one conclusion.

The free providers are honest about their limits: the DuckDuckGo Instant Answer
API is not a general web index and returns nothing for many technical queries;
that is reported as an empty result with a warning, not an error and not a
fabrication.

### Source independence (coverage is not a provider count)

Two providers that both return pages from one publisher are **one source**, and a
single provider returning four pages from four publishers is **four sources**.
`blackheart/intelligence/sources.py` canonicalises each result URL (scheme,
`www.`, default port, fragment, tracking parameters, trailing slash) to a
registrable domain (eTLD+1, with compound-suffix, IDN, and IP handling), so the
novelty gate measures *independent origins* rather than the number of providers
or the number of results. `classify_evidence_tier` separates primary evidence (an
official advisory, a CVE/NVD/OSV record, or the repository's own
issue/PR/commit) from secondary commentary.

`collect_disclosures` records `NoveltyReview.independent_sources` from the real
result set, and when several providers collapse to fewer origins it records a
limitation rather than counting the providers as independent coverage. A review
that names only providers (no origins) falls back to the provider count, so
hand-recorded reviews keep their previous meaning.

## 10. Project-wide availability (portable install)

The capability is **not** hardcoded to one target project. `blackheart intel
bootstrap --root <project>` writes the reusable config into a project's
`.openhands/` (which is gitignored — no secret is ever committed):

- `.openhands/mcp.json` — the You.com MCP server, referencing `${YDC_API_KEY}`
  (the value is never written).
- `.openhands/intelligence.env.example` — the variables to export.

`blackheart provision` runs this bootstrap automatically, so a project
initialized through BLACKHEART inherits the intelligence capability without the
integration being rewritten. `ProviderRegistry(project_root=...)` reads an
optional `.openhands/intelligence.json`; a project may disable a provider **only**
with an explicit reason (`{"disable": {"you.com": "project policy: no external
key"}}`) — a reasonless disable is ignored, so a project cannot silently drop the
global capability.

**Scope of the claim:** a project that is *not* connected to BLACKHEART does not
automatically inherit this. The inheritance is via the bootstrap/provision path
above, or by copying the `.openhands/` config.

### Configuration summary

```bash
export YDC_API_KEY=...                     # primary provider (REST + MCP)
blackheart intel setup                     # exact setup instructions
blackheart intel providers                 # real availability, no fake success
blackheart intel providers --probe         # make one cheap real request each
blackheart intel bootstrap --root <proj>   # give a project the capability
blackheart intel route "<query>" --cross-check
blackheart intel investigate "<query>"     # fenced untrusted view + injection signals
```

The two auth headers are **different layers**: REST uses `X-API-Key:
$YDC_API_KEY`; the hosted MCP server uses `Authorization: Bearer $YDC_API_KEY`.
Do not interchange them.

## 11. Using the providers inside a mission

The provider layer is wired into a real workflow, not just exposed as a command:

- `blackheart novelty --file <review.json> --search` runs each query in the
  review's `queries` through the router and turns the returned sources into
  `PublicDisclosure` candidates before the novelty gate adjudicates. The
  providers that actually answered are recorded in `databases_searched`, so the
  coverage check rests on real responders rather than a hand-written claim.
  `blackheart/novelty.py::collect_disclosures` is the pure function; it accepts
  any `(query, count=...) -> result` search function, and unwraps a router
  wrapper (`.result`) or a bare provider result alike.
- **Honest consequence:** coverage now rests on *independent origins*, not on the
  number of providers. One provider that returns pages from four different
  publishers supplies four independent sources; two providers that both return
  pages from one publisher supply one. A search that collapses to fewer than
  `MIN_SOURCES_FOR_NOVELTY` (4) distinct origins — or fewer than
  `MIN_QUERIES_FOR_NOVELTY` queries — yields `INSUFFICIENT_EVIDENCE`, not
  `LIKELY_NEW`. That is the intended behaviour: a thin or single-publisher search
  must not be read as proof of novelty. Build coverage with genuinely independent
  origins (several publishers, plus manual CVE/advisory databases).
