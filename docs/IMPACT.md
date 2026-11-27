# IMPACT — a difference is not a vulnerability

`blackheart impact` (and `blackheart.impact.triage`) is the pre-surface gate that
stops the most expensive false positive class: a **difference** or an **off-chain
observation** reported as if it were a security finding.

It answers one question before anything is promoted or surfaced: does this claim
name an unprivileged-attacker **outcome** on an **executable** surface?

## The three refusals

| Disposition | When | Why |
|---|---|---|
| `LEAD_ONLY` | the surface has no executable model (off-chain API, HTTP response, config, docs) | the engine can only prove what it can run; an unexecutable claim is a lead |
| `INFORMATIONAL` | two identifiers are a **name collision** (`marginTable` vs `notionalMarginTable`) | they are different fields, not a contradiction |
| `INFORMATIONAL` | no attacker outcome, or no value movement / restriction bypass | the outcome is asserted, not shown |

Only `SURFACE` means the claim names one of the three outcomes on an executable
surface — and even then it is a lead until it is reproduced and independently
reviewed.

## Where it is enforced

- **Lead promotion** (`hypothesis/from_leads.py`): an off-chain or name-collision
  lead is refused at promotion with the reason, never turned into a hypothesis.
- **Surfacing** (`autohunt.bounty_grade`): a finding that fails the triage is
  `E_INFORMATIONAL` and is never surfaced for review; the official bounty gate
  only ever sees a qualifying claim.
- **Operator check** (`blackheart impact`): check any claim before writing it up.

```bash
blackheart impact --surface off-chain \
  --impact "marginTable differs from the enforced value" \
  --identifiers marginTable notionalMarginTable
# LEAD_ONLY — surface 'off-chain' has no executable model; a lead, not a finding
```

Exit `0` = the claim qualifies (still a lead until reproduced); exit `1` = it does
not.

## Honest limit

The triage is a conservative, text-and-surface classifier: it fails closed, so it
can refuse a genuine claim that is worded without an outcome or value keyword. It
reduces the false-positive class; it does not replace reproduction. A `SURFACE`
verdict is permission to *investigate*, never a finding.
