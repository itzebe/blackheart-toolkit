# Audit coverage, transaction replay, and explore

Three compositions over the existing engines for opening an **advanced or
already-audited** project. None adds a new engine; each reuses the scanner, rule
engine, interrogation, dataflow, callgraph, RPC resolver and ABI modules.

## `blackheart audit coverage <path> --audit FILE`

Parse an audit report (JSON, or Markdown as a heuristic), map each finding onto
the recovered surface, and rank the **reachable functions no finding refers to**
— the unaudited surface — by the existing rule leads.

```
blackheart audit coverage path/to/project --audit report.json
blackheart audit coverage path/to/project --audit report.md --json
```

- JSON accepts a list, or `{"findings": [...]}`, or `{"issues": [...]}`; common key
  aliases (`id`/`finding_id`, `title`/`name`, `severity`/`risk`, `location` object
  or `file:line`) are recognised.
- Markdown is parsed heuristically from headings (`## [H-01] Title`) or bold
  bullets; anything unrecognised is reported as a **parse uncertainty**, never
  guessed.
- Mapping is by function name or `file:line` (nearest preceding function). An
  ambiguous or unmatched finding is reported as **unmapped**, never forced.
- Output: coverage %, audited functions, and a ranked unaudited surface.

Coverage is not a verdict: an audited function is not proven safe, and an
unaudited one is not proven broken.

## `blackheart debug tx <hash> [--rpc URL] [--abi FILE]`

Read-only replay of one transaction: fetch tx + receipt, request a `callTracer`
trace, decode calldata against a supplied ABI, and render a call tree with gas,
value and revert reasons. **Never sends or signs a transaction.**

- `debug_traceTransaction` is not enabled on every node; when unavailable the
  result is `TRACE_UNAVAILABLE` and still shows the receipt and decoded input.
- ABI decoding is best-effort for static types (address/uint/int/bool); dynamic
  types are shown raw.
- The HTTP transport is injectable, so the logic is tested offline.

## `blackheart explore <path> [--query "..."]`

A small shell over the recovered surface:

```
help | contracts | functions [contract] | function <name> (explain <name>)
leads [severity] | claims | flows | callgraph | quit
```

`--query` runs one query and exits (scriptable); without it, `explore` reads
commands from stdin (interactive when attached to a TTY). It executes nothing.

## Limits

- `audit coverage` maps Solidity surfaces (functions carry `file:line`); other
  languages return `supported: false` rather than an unproven map.
- `debug tx` needs an RPC that serves `debug_traceTransaction` for the call tree;
  `explore` is static except for what the scanner recovered.
- Every command prints its own discipline line: a lead is not a finding.
