# Multi-model research intelligence

BLACKHEART can use several language models as **different analytical roles** —
and let them disagree — without ever treating their agreement as proof. This
document describes the provider layer, the privacy gate, and the honest limits.

## 1. The load-bearing rule

> AI output is **advisory**. Agreement between models is *not* confirmation of a
> vulnerability. Only deterministic reproduction, verified impact, and applicable
> authorization can confirm a finding.

Every role output is recorded with its provider, model, and a `simulated` flag.
The router's `summarise()` reports agreement **and** disagreement, and states
plainly that neither confirms anything. No path in this layer can promote a claim
to `CONFIRMED`.

## 2. Providers

`blackheart/providers/registry.py` holds one `ProviderSpec` per provider. Each
records the base URL, the key environment variable, a default model, a
**free-tier note**, a **data-terms URL**, and the date the facts were verified.
Free tiers change; the note and date are what stop a stale "it's free" assumption
from being treated as current.

| Provider | Key env var | Notes |
| --- | --- | --- |
| OpenRouter | `OPENROUTER_API_KEY` | `:free` model variants with per-day caps |
| Groq | `GROQ_API_KEY` | free tier, per-model rate limits |
| Google Gemini | `GEMINI_API_KEY` | AI Studio free tier; OpenAI-compat endpoint is beta |
| NVIDIA NIM | `NVIDIA_API_KEY` | free evaluation credits via build.nvidia.com |
| SambaNova | `SAMBANOVA_API_KEY` | free developer tier, account-specific quotas |
| Z.ai | `ZAI_API_KEY` | free `flash` tier; broader access is paid |
| Cloudflare Workers AI | `CLOUDFLARE_API_TOKEN` | free daily neurons; **not** OpenAI-compatible |
| Mistral | `MISTRAL_API_KEY` | free availability must be re-checked |
| Cohere | `COHERE_API_KEY` | trial key; compatibility endpoint |
| LLM7 | `LLM7_API_KEY` | keyless gateway; **opt-in only** |
| Cerebras | `CEREBRAS_API_KEY` | free developer tier |
| Kilo | `KILO_API_KEY` | no confirmed inference endpoint (unverified) |
| Together | `TOGETHER_API_KEY` | primarily paid; do not assume a free tier |

A provider becomes **configured** only when its key is present in the
environment. A keyless provider (LLM7) is **opt-in** via `BLACKHEART_PROVIDERS`,
because an unauthenticated public gateway must not become the silent default.
Providers whose endpoint is not OpenAI-compatible, or that have no confirmed
model id, are **not wired** — the adapter refuses to guess a path.

## 3. Zero-provider mode

With nothing configured, the router is **local-only**: every request goes to the
offline `LocalProvider`, which makes no network call. This is a real, working
mode, not an error — `blackheart models health` exits `0` because the local
engine is always healthy, and `blackheart models benchmark` runs (and honestly
reports that a rule-based engine cannot judge semantics).

## 4. Privacy gate (data classification)

A request carries a `DataClass`:

| Class | Example | Sent off-host by default? |
| --- | --- | --- |
| `PUBLIC` | published source, docs, advisories | yes, if a provider is configured |
| `INTERNAL` | internal drafts and notes | no |
| `CONFIDENTIAL` | private vulnerability evidence, unpublished PoC | no |
| `SECRET` | credentials, keys, tokens, customer data | **never, at any ceiling** |

The router's `ceiling` (default `PUBLIC`) is the highest class allowed to leave
the host. Anything above it is routed to the local engine and **never
transmitted**. `SECRET` raises `PrivacyViolation` everywhere. `blackheart models
route --data-class CONFIDENTIAL` prints the decision, so the gate is auditable.

External provider use requires: a user-configured credential, a review of the
provider's data-handling terms (the `data_terms_url`), and explicit authorization
for that category of material. The tool never asks for secrets in chat and never
makes a paid call.

## 5. The seven roles

Each role asks a **different** question with a **different** system prompt, so the
roles can genuinely disagree (tested: their prompts are all distinct).

1. **planner** — target + threat model → bounded research plan.
2. **hypothesis** — falsifiable technical hypotheses (invariant + falsification).
3. **code_analyst** — analyses the code path for/against a hypothesis.
4. **adversarial** — tries to *disprove* the hypothesis.
5. **exploit_dev** — proposes a minimal, local-only reproduction.
6. **reproduction** — judges whether a reproduction proves the claim.
7. **report_quality** — judges whether the evidence supports a report.

`summarise()` collects the judgement verdicts and records any supports/disputes
split as a preserved disagreement.

## 6. Quota tracking

`QuotaTracker` counts calls and tokens per provider per day, persisted as JSONL
so a resumed run keeps counting. It is **advisory**: it can see what BLACKHEART
has spent, never the provider's real remaining allowance. It exists to stop a run
before an unknown cap and to make usage visible.

## 7. Honest limits

- No provider's free tier is assumed stable, unlimited, or current. The recorded
  facts are dated and must be re-checked.
- The `LocalProvider` is a rule-based summariser, **not** a language model. It
  produces structure only and cannot reason about novel semantics.
- Mock and local results are always labelled `simulated` and are never counted as
  correct in the benchmark.
- The benchmark corpus is small (five historical cases from BLACKHEART's own
  history). It measures the judgement roles; it does not prove a finding.
- Role outputs are advisory by construction; the confirmation gate lives in the
  investigation engine and the independent verifier, not here.
- **The reviewer model is optional.** No separately configured reviewer API key is
  required to run the core research or release workflow. `resolve_reviewer_model`
  distinguishes three states honestly: `configured` (a distinct provider has a
  key), `verified` (a liveness probe proved the credential authenticates), and
  `available` (configured **and** verified). A key that is present but invalid or
  expired is reported as `configured` and **not** `available` — availability is
  never inferred from a key merely existing. When no verified reviewer exists, the
  workflow performs a same-model adversarial review in a fresh context and records
  `ReviewIndependence.SAME_MODEL`. That is a real review, but it is never labelled
  an independent-model review, it does not pass gate 6 as independent verification,
  and a record carrying it is refused at `CONFIRMED` and at report submission.
- **Provenance is verified against the record, not trusted on its own.** The
  claimed provenance is checked against the two records that describe the same
  event: the reviewer label stored on a `FindingRecord` and the gate-6 detail
  stored on the `Finding`. A `same-model-adversarial-reviewer` (or
  `deterministic-verifier`) label alongside an `INDEPENDENT_MODEL` claim, or a
  gate-6 detail that says the review was same-model while the finding claims
  independence, fails closed. So does an `INDEPENDENT_MODEL` claim resting on a
  legacy free-text gate-6 detail: a detail that names no provenance cannot prove
  one. A legacy detail still passes for every other provenance, so findings
  written before this field existed are unaffected.
  `blackheart.models.evidenced_review_independence` is the single rule both the
  report layer and the findings repository apply -- neither can be the weaker
  path -- and `blackheart.models.gate6_detail` is the single definition of the
  canonical detail, so the wording can never drift between the code that writes
  the gate and the code that reads it.
- **A retired model id must not disable a valid credential.** Providers retire
  model ids (`gemini-2.0-flash` was retired), and a pinned id that no longer
  exists makes a perfectly valid key probe as unavailable. Any provider spec may
  declare `model_env_key`; `resolved_model(spec)` returns that override when set,
  else the pinned `default_model`. The override is resolved in **one** place and
  used by the health probe, the completion call and the reported model, so the
  three can never disagree. A call that omits `model` uses the same id the probe
  verified. `BLACKHEART_GEMINI_MODEL` is the Gemini override:

  ```bash
  GEMINI_API_KEY=... BLACKHEART_GEMINI_MODEL=gemini-3.5-flash \
    blackheart models reviewer          # available: true, INDEPENDENT_MODEL
  ```

  With no override, the retired pin still fails its probe and the tool reports
  `available: false` with the reason -- honestly unavailable, never silently
  broken and never fabricated as independent. The override is a *credential
  repair*, not an independence bypass: `_same_model_family` compares the resolved
  ids, so an override naming the primary's weights is rejected as `SAME_MODEL`.

## 8. Commands

```bash
blackheart models list                         # providers + verified free-tier notes
blackheart models health                        # probe configured providers
blackheart models route --data-class CONFIDENTIAL
blackheart models reviewer                      # is an independent reviewer available? (optional)
blackheart models benchmark                     # adversarial role on the historical cases
blackheart models usage                         # advisory call/token counts
```
