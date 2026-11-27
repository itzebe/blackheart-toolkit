"""Benchmark for the GitHub Actions analyzer (blackheart/gha.py).

Detector improvements must be measured, not asserted. This benchmark holds a
labeled corpus of workflow files grouped by kind:

  * ``known-vulnerable``   — reachable attack chains that must be flagged.
  * ``patched``            — the same chains with the documented fix applied.
  * ``safe-lookalike``     — workflows that superficially resemble the vulnerable
                             ones (``workflow_run``, ``pull_request_target``,
                             ``write-all``) but are not exploitable.
  * ``multi-workflow``     — a chain split across two files (trigger + consumer).
  * ``known-false-positive``— patterns that a naive detector would wrongly flag;
                             the correct behaviour is *no* finding.

The runner reports true positives, false positives, false negatives, precision,
recall, a "safe not flagged" rate, and wall-clock analysis time. It is wired
into ``tests/test_gha_bench.py`` with thresholds, so a change that trades
precision for recall (or vice versa) fails CI.

Run directly: ``python -m blackheart.gha_bench``.
"""

from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import gha

# --------------------------------------------------------------------------- #
# Case corpus
# --------------------------------------------------------------------------- #

_OSS001_CHAINED = """\
name: Chained E2E
on:
  workflow_run:
    workflows: ['Trigger E2E']
    types: ['completed']
jobs:
  fetch:
    runs-on: ubuntu-latest
    outputs:
      repository: ${{ steps.ctx.outputs.REPO }}
      sha: ${{ steps.ctx.outputs.SHA }}
    steps:
      - uses: actions/download-artifact@v5
        with:
          name: repo_name
          run-id: ${{ github.event.workflow_run.id }}
      - id: ctx
        env:
          REPO: ${{ needs.fetch.outputs.repo_name || github.repository }}
          SHA: ${{ github.event.workflow_run.head_sha }}
        run: echo "REPO=$REPO" >> "$GITHUB_OUTPUT"
  test:
    needs: fetch
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ needs.fetch.outputs.repository }}
          ref: ${{ needs.fetch.outputs.sha }}
      - run: npm ci
      - env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
        run: npm run build
"""

_OSS001_TRIGGER = """\
name: Trigger E2E
on:
  pull_request:
jobs:
  save:
    runs-on: ubuntu-latest
    steps:
      - env:
          REPO_NAME: ${{ github.event.pull_request.head.repo.full_name }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          mkdir -p ./pr
          echo "$REPO_NAME" > ./pr/repo_name
          echo "$HEAD_SHA" > ./pr/head_sha
      - uses: actions/upload-artifact@v4
        with:
          name: repo_name
          path: pr/
"""

_PRT_VULN = """\
name: pwn request
on: pull_request_target
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
      - run: npm ci && npm test
"""

_INJECT_VULN = """\
name: triage
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}" >> out.txt
"""

_GUARD_LINE = "    if: github.event.workflow_run.head_repository.full_name == github.repository\n"


@dataclass
class Case:
    id: str
    kind: str
    files: dict[str, str]
    expected: tuple[str, ...]

    @property
    def expected_empty(self) -> bool:
        return not self.expected


def _chain(chained_text: str) -> dict[str, str]:
    return {"trigger_e2e.yml": _OSS001_TRIGGER, "chained_e2e.yml": chained_text}


CASES: list[Case] = [
    # --- known vulnerable ---------------------------------------------------
    Case("oss001-chain", "multi-workflow", _chain(_OSS001_CHAINED),
         (gha.RULE_WORKFLOW_RUN_ARTIFACT_CHECKOUT,)),
    Case("prt-untrusted-checkout", "known-vulnerable", {"wf.yml": _PRT_VULN},
         (gha.RULE_PR_TARGET_UNTRUSTED_CHECKOUT,)),
    Case("inject-comment-body", "known-vulnerable", {"wf.yml": _INJECT_VULN},
         (gha.RULE_UNTRUSTED_SCRIPT_INJECTION,)),

    # --- patched equivalents ------------------------------------------------
    Case("oss001-guarded", "patched",
         _chain(_OSS001_CHAINED.replace("  test:\n", "  test:\n" + _GUARD_LINE)), ()),
    Case("oss001-base-checkout", "patched",
         _chain(_OSS001_CHAINED.replace(
             "          repository: ${{ needs.fetch.outputs.repository }}",
             "          repository: ${{ github.repository }}")), ()),
    Case("prt-base-checkout", "patched",
         {"wf.yml": _PRT_VULN.replace(
             "          ref: ${{ github.event.pull_request.head.sha }}\n"
             "          repository: ${{ github.event.pull_request.head.repo.full_name }}\n",
             "          ref: ${{ github.sha }}\n")}, ()),
    Case("inject-via-env", "patched",
         {"wf.yml": _INJECT_VULN.replace(
             '      - run: echo "${{ github.event.comment.body }}" >> out.txt\n',
             "      - env:\n          BODY: ${{ github.event.comment.body }}\n"
             '        run: echo "$BODY" >> out.txt\n')}, ()),

    # --- safe lookalikes ----------------------------------------------------
    Case("workflow-run-no-artifact", "safe-lookalike",
         {"wf.yml": _OSS001_CHAINED.replace(
             "      - uses: actions/download-artifact@v5\n"
             "        with:\n"
             "          name: repo_name\n"
             "          run-id: ${{ github.event.workflow_run.id }}\n", "")}, ()),
    Case("prt-base-only", "safe-lookalike",
         {"wf.yml": "name: x\non: pull_request_target\npermissions:\n  contents: write\n"
                    "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "      - run: npm ci\n"}, ()),
    Case("write-all-benign", "safe-lookalike",
         {"wf.yml": "name: x\non:\n  push:\npermissions: write-all\n"
                    "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - uses: actions/checkout@v4\n      - run: npm test\n"}, ()),
    Case("unpinned-action-only", "known-false-positive",
         {"wf.yml": "name: x\non:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
                    "    steps:\n      - uses: some/action@main\n      - run: make\n"}, ()),
]


@dataclass
class Metrics:
    true_positives: int
    false_positives: int
    false_negatives: int
    safe_cases: int
    safe_cases_flagged: int
    seconds: float

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 1.0

    @property
    def safe_accuracy(self) -> float:
        return (self.safe_cases - self.safe_cases_flagged) / self.safe_cases if self.safe_cases else 1.0

    def to_dict(self) -> dict:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "safe_cases": self.safe_cases,
            "safe_cases_flagged": self.safe_cases_flagged,
            "safe_accuracy": round(self.safe_accuracy, 4),
            "seconds": round(self.seconds, 4),
        }


def run(corpus_root: Path | None = None) -> tuple[Metrics, list[str]]:
    """Run the benchmark. Returns (metrics, notes). If `corpus_root` is given,
    it is additionally analyzed as a whole to measure real-world false positives."""
    notes: list[str] = []
    tp = fp = fn = 0
    safe_cases = safe_flagged = 0

    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for case in CASES:
            cdir = tmp_path / case.id
            cdir.mkdir()
            found: set[str] = set()
            for name, content in case.files.items():
                p = cdir / name
                p.write_text(content)
                for c in gha.analyze_file(p):
                    found.add(c.rule_id)
            expected = set(case.expected)
            tp += len(found & expected)
            fp += len(found - expected)
            fn += len(expected - found)
            if case.expected_empty:
                safe_cases += 1
                if found:
                    safe_flagged += 1
                    notes.append(f"SAFE CASE FLAGGED: {case.id} -> {sorted(found)}")
            elif expected - found:
                notes.append(f"MISSED: {case.id} -> missing {sorted(expected - found)}")
    seconds = time.perf_counter() - t0

    if corpus_root is not None and corpus_root.is_dir():
        t1 = time.perf_counter()
        cands = gha.analyze_tree(corpus_root)
        notes.append(
            f"real corpus {corpus_root}: {len(cands)} candidates in "
            f"{time.perf_counter() - t1:.2f}s")
        for c in cands:
            notes.append(f"  corpus hit: {c.file} :: {c.job} :: {c.rule_id}")

    return Metrics(tp, fp, fn, safe_cases, safe_flagged, seconds), notes


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="GitHub Actions analyzer benchmark")
    ap.add_argument("--corpus", help="optional real repository/corpus to scan too")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    metrics, notes = run(Path(args.corpus) if args.corpus else None)
    if args.json:
        print(json.dumps(metrics.to_dict(), indent=2))
    else:
        m = metrics.to_dict()
        print("GitHub Actions analyzer benchmark")
        print("=" * 40)
        print(f"true positives : {m['true_positives']}")
        print(f"false positives: {m['false_positives']}")
        print(f"false negatives: {m['false_negatives']}")
        print(f"precision      : {m['precision']}")
        print(f"recall         : {m['recall']}")
        print(f"safe accuracy  : {m['safe_accuracy']}  ({m['safe_cases'] - m['safe_cases_flagged']}/{m['safe_cases']})")
        print(f"analysis time  : {m['seconds']}s")
        for n in notes:
            print("  -", n)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
