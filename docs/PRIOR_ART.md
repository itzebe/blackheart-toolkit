# Prior art: the free source, and what it cannot do

A novelty review only means something if the search behind it was real. The
primary route is BLACKHEART's provider router (You.com and keyless fallbacks),
but every hosted search backend costs a key or a quota, and when that quota is
gone the gate has nothing to compare against. `blackheart/prior_art.py` adds one
source that is free, documented and machine-readable: the **GitHub Advisory
database**, via the public REST API.

## The endpoint's real contract was measured, not assumed

`GET https://api.github.com/advisories` does **not** support free-text search. A
`q` parameter is accepted and ignored — `q=reentrancy`, `q=OpenZeppelin` and
`q=solidity` all return the same unfiltered global feed. Shipping a `q`-based
search would have compared a candidate against unrelated advisories (a WordPress
plugin backup bug, a Corosync heap overflow) and reported them as prior art.

Only these narrow the result set:

| Parameter | Meaning | Example that works |
| --- | --- | --- |
| `affects` | an **ecosystem package name** | `lodash` → 2+ advisories |
| `cve_id` | one exact CVE | `CVE-2021-44228` → Log4j |
| `ecosystem` | coarsener | `npm`, `pip` |
| `severity` | coarsener | `critical` |

`affects=openzeppelin` returns nothing, because that is not a published package
name in the advisory database's ecosystem index. A protocol's own contract name
will also return nothing. **A low hit count here means "nothing in the advisory
corpus", never "novel".**

## What it is honestly good for

A *package* check: does the library this candidate depends on have a published
advisory? That is a real and useful question, and it is free.

It is **not** a protocol-logic prior-art search. A bespoke reentrancy or
accounting error in a protocol is usually never assigned a GHSA, so the advisory
database is the wrong corpus for it. For that, use Solodit, Code4rena, Sherlock
and public audit reports through the provider router — all of which are the
operator's job to point at, and none of which this module pretends to replace.

## Refusals, on purpose

* **A query that is not a package name or CVE id is refused**, not sent. It
  returns `ok=False` with the reason, which `collect_disclosures` records in
  `search_limitations`. The novelty gate then sees an under-powered search and
  refuses to claim novelty — which is the correct outcome.
* **Quota exhaustion is an error, not an empty result.** A `403`/`429` becomes
  `ok=False, error="rate limited or forbidden"`. An exhausted quota must never
  read as "nothing published, therefore novel".
* **No free-text fallback.** If the API cannot honour a query, the module says so
  rather than approximating with the global feed.

## Usage

```bash
# from the CLI, alongside any other provider search
python3 -m blackheart novelty --file review.json --advisories

# or programmatically, as a search_fn for the existing gate
python3 - <<'PY'
from blackheart.novelty import collect_disclosures
from blackheart.models import NoveltyReview
from blackheart.prior_art import advisory_search_fn

review = NoveltyReview(finding_id="X-1", queries=["lodash", "CVE-2021-44228"])
collect_disclosures(review, advisory_search_fn())
PY
```

Authentication uses `$GITHUB_TOKEN`, which a sandbox already carries for git
access. Unauthenticated calls work but are rate-limited to 60/hour; a missing
token is reported in `error` rather than silently degrading the search.

## Tests

`tests/test_prior_art.py` pins the behaviour that matters — the refusal of
non-package queries, the mapping of `affects`/`cve_id`, quota-as-error — offline.
The two live tests are marked `network` and excluded from the default suite
(`pytest -m network` runs them). A public API's latency, quota or outage is not a
property of this codebase, so it must not be able to fail CI.
