# SARIF export

`blackheart findings sarif` writes the findings repository as a
[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
log, so GitHub code scanning, IDE plugins and other SARIF consumers can read a
BLACKHEART finding without a bespoke adapter.

```bash
# whole repository
python3 -m blackheart findings --dir research/private/findings sarif --out findings.sarif

# one finding
python3 -m blackheart findings --dir research/private/findings \
  export --finding F-001 --format sarif
```

## What travels in the log

| SARIF field | BLACKHEART meaning |
|---|---|
| `runs[0].tool.driver.name` | `BLACKHEART` |
| `results[].ruleId` | `blackheart/<category>` |
| `results[].level` | a **presentation hint**, derived from the verdict and severity |
| `results[].message.text` | title, verdict, target and component |
| `results[].locations[]` | `root_cause_file` (or the first `source_refs` entry) and the line parsed from `root_cause_location` |
| `results[].partialFingerprints["blackheart/v1"]` | the content fingerprint shared with the baseline |
| `results[].properties.verdict` | the record's own verdict |
| `results[].properties.confirmed` | the **evidence-gated** answer, not the status flag |
| `results[].properties.record_sha256` | digest of the embedded record |
| `results[].properties.record` | the full A-J record, for a lossless round-trip |

## Honesty rules

- **`level` never upgrades a finding.** Only an evidence-gated `CONFIRMED`
  finding with `critical`/`high` severity becomes `error`. A hand-set
  `CONFIRMED` that lacks evidence is exported as `warning` with
  `confirmed: false`.
- **False positives, out-of-scope and not-reproducible findings are `none`.**
- **The record digest is checked on import.** `from_sarif` refuses a log whose
  embedded record was edited, and it re-applies the confirmation gate: a
  `CONFIRMED` claim without evidence is downgraded to `STRONGLY_SUPPORTED`,
  exactly as the repository does on save.
- **The fingerprint is identity, not integrity.** It is built from the fields
  that define the defect (component, category, root-cause file and line, design
  mistake), so the same bug re-recorded under a new id or title keeps its
  fingerprint. The record digest is what detects an edit.

## Validation

`blackheart.findings.sarif.validate` performs structural checks (version,
schema, tool driver, rule resolution, levels, messages, locations, fingerprints,
digests) and the CLI refuses to write a log that fails them. The acceptance bar
is `tests/test_sarif.py`.

## Limitations

The export describes the finding record; it does not prove the finding. A SARIF
consumer that ignores `properties.verdict` and `properties.confirmed` and reads
only `level` can over-read a result. The location is the recorded root cause,
not a compiler-derived range, and a finding with no recorded file has no
`locations` entry.
