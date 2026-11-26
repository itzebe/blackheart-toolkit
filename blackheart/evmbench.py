"""Score a static analyser against EVMbench ground truth, without an API key.

EVMbench's own harness (``paradigmxyz/evmbench``) needs Postgres, RabbitMQ, Docker
and a paid OpenAI key, so it cannot be the thing a fresh sandbox runs to answer
"is BLACKHEART any good?". The *ground truth*, however, is free: the audit dataset
(``openai/frontier-evals``, MIT) ships, for every disclosed vulnerability, the
maintainer's own fix as a unified diff. A fix diff is an exact, machine-readable
statement of *where the bug was* -- ``Vault.sol`` line 1125, not "somewhere in the
vault".

So this module measures one honest question, and states its limits loudly:

    given the real fix location, did the analyser report anything at that line?

That is a **localization** measurement, not a detection-of-the-vulnerability
measurement. A generic detector that flags a `divide-before-multiply` near a fix
line has *not* found the audited logic bug; it has found a neighbouring smell. The
scorer therefore reports two separate numbers and never merges them:

* ``file_recall``  -- the analyser touched the file the fix changed at all.
* ``line_recall``  -- the analyser produced a finding whose line range covers a
  line the fix actually changed.

``file_recall`` is the weak, generous number. ``line_recall`` is the one that
means something, and it is still only localization: it says "pointed at the right
line", never "understood the bug". Both are reported with their denominators so a
reader can see how thin the evidence is.

Nothing here downloads, executes, or scores a model. It reads two things that are
already on disk -- the dataset's ``config.yaml``/``patch/*.diff`` and an analyser's
JSON report -- and counts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

__all__ = [
    "Hunk",
    "GroundTruth",
    "Finding",
    "AuditScore",
    "EvalReport",
    "parse_unified_diff",
    "load_ground_truth",
    "load_slither_findings",
    "score_audit",
    "evaluate",
]

#: A fix diff line like ``@@ -1120,7 +1125,7 @@``. The *old* side is the
#: vulnerable code, so its start line is what a detector should have pointed at.
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")


@dataclass(frozen=True)
class Hunk:
    """One changed region of a fix diff: a file and the line span it touched."""

    file: str
    start: int          # first line of the hunk on the vulnerable (old) side
    length: int

    @property
    def end(self) -> int:
        return self.start + max(self.length, 1) - 1

    def covers(self, line: int) -> bool:
        return self.start <= line <= self.end

    def overlaps(self, start: int, end: int) -> bool:
        return not (end < self.start or start > self.end)


@dataclass
class GroundTruth:
    """Every location a disclosed vulnerability's fix changed."""

    audit: str
    vulnerability: str
    title: str = ""
    award: float = 0.0
    hunks: list[Hunk] = field(default_factory=list)
    patch_files: list[str] = field(default_factory=list)

    @property
    def files(self) -> set[str]:
        return {h.file for h in self.hunks} or set(self.patch_files)


@dataclass(frozen=True)
class Finding:
    """A normalized analyser finding, reduced to what localization needs."""

    check: str
    file: str
    start: int
    end: int
    impact: str = ""
    confidence: str = ""


@dataclass
class AuditScore:
    audit: str
    vulnerability: str
    title: str
    #: ``True`` when at least one finding lands on a changed file.
    file_hit: bool = False
    #: ``True`` when at least one finding's line range overlaps a changed hunk.
    line_hit: bool = False
    #: ``True`` when the overlapping finding's *class* could plausibly correspond
    #: to the audited bug. This is the only number worth quoting: on a real run
    #: the naive ``line_hit`` fired 2/2 while ``class_hit`` fired 0/2, because
    #: ``reentrancy-events`` and ``naming-convention`` overlap almost any line.
    class_hit: bool = False
    #: Findings that touched a ground-truth file, for auditability.
    touching: list[Finding] = field(default_factory=list)
    #: The detector families the audited bug would plausibly map to.
    expected: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "audit": self.audit,
            "vulnerability": self.vulnerability,
            "title": self.title,
            "file_hit": self.file_hit,
            "line_hit": self.line_hit,
            "class_hit": self.class_hit,
            "expected_detectors": list(self.expected),
            "touching": [
                {"check": f.check, "file": f.file, "lines": [f.start, f.end],
                 "impact": f.impact}
                for f in self.touching
            ],
        }



#: Which Slither detector families could plausibly correspond to a bug described
#: in a title. Deliberately coarse and deliberately *narrow*: a class that is not
#: listed here is not credited, because crediting it is how a 100% number gets
#: manufactured out of noise. ``reentrancy-events``, ``naming-convention``,
#: ``unused-return`` and ``immutable-states`` are excluded on purpose -- on the
#: real pooltogether run they were the only things that overlapped the fix lines,
#: and none of them can express "a malicious user can steal deposits".
_TITLE_CLASSES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("steal", "drain", "withdraw", "deposit", "truncat", "round", "precision",
      "mint", "burn", "transfer", "balance", "share", "fee", "accounting"),
     ("divide-before-multiply", "unchecked-transfer", "incorrect-equality",
      "arbitrary-send-erc20", "arbitrary-send-eth", "controlled-delegatecall",
      "uninitialized-state", "uninitialized-local")),
    (("access", "permission", "anyone", "unauthori", "owner", "admin", "auth",
      "whitelist", "callable"),
     ("suicidal", "controlled-delegatecall", "arbitrary-send-erc20",
      "arbitrary-send-eth", "unprotected-upgrade", "delegatecall-loop")),
    (("reentran", "callback"),
     ("reentrancy-eth", "reentrancy-no-eth")),
    (("oracle", "price", "manipulat"),
     ("divide-before-multiply", "incorrect-equality", "unchecked-transfer")),
    (("overflow", "underflow", "cast", "uint96", "uint128", "truncat"),
     ("divide-before-multiply", "unchecked-transfer")),
    (("lock", "freeze", "denial", "dos", "grief", "stuck"),
     ("calls-loop", "locked-ether", "unchecked-lowlevel")),
)


def expected_classes(title: str) -> tuple[str, ...]:
    """Detector families a fix-title plausibly maps to. Empty means "unknown"."""
    low = title.lower()
    out: list[str] = []
    for keys, checks in _TITLE_CLASSES:
        if any(k in low for k in keys):
            out.extend(c for c in checks if c not in out)
    return tuple(out)


def chance_baseline(findings: Iterable[Finding], gt_file: str,
                    total_lines: int) -> Optional[float]:
    """Fraction of a file's lines any finding touches -- the no-skill hit rate.

    If 18% of a file is covered by findings, then 18% of fix lines would be "hit"
    by a detector that chose lines at random. Without this number a localization
    score is uninterpretable, which is why it is reported beside it.
    """
    if total_lines <= 0:
        return None
    covered: set[int] = set()
    for f in findings:
        if _same_file(f.file, gt_file):
            covered.update(range(f.start, f.end + 1))
    return min(len(covered), total_lines) / total_lines


@dataclass
class EvalReport:
    scores: list[AuditScore] = field(default_factory=list)
    #: Ground-truth vulnerabilities that had no fix diff at all (a title only).
    unscored: list[tuple[str, str, str]] = field(default_factory=list)
    total_findings: int = 0
    audits_seen: int = 0

    @property
    def scored(self) -> int:
        return len(self.scores)

    @property
    def file_hits(self) -> int:
        return sum(1 for s in self.scores if s.file_hit)

    @property
    def line_hits(self) -> int:
        return sum(1 for s in self.scores if s.line_hit)

    @property
    def class_hits(self) -> int:
        return sum(1 for s in self.scores if s.class_hit)

    def _rate(self, hits: int) -> Optional[float]:
        # None, never 0.0 or 1.0: a rate over an empty denominator is unknown.
        return None if not self.scores else hits / len(self.scores)

    @property
    def file_recall(self) -> Optional[float]:
        return self._rate(self.file_hits)

    @property
    def line_recall(self) -> Optional[float]:
        return self._rate(self.line_hits)

    @property
    def class_recall(self) -> Optional[float]:
        return self._rate(self.class_hits)

    def to_dict(self) -> dict:
        return {
            "audits_seen": self.audits_seen,
            "vulnerabilities_scored": self.scored,
            "unscored": [{"audit": a, "vulnerability": v, "reason": r}
                         for a, v, r in self.unscored],
            "total_findings": self.total_findings,
            "file_hits": self.file_hits,
            "line_hits": self.line_hits,
            "class_hits": self.class_hits,
            "file_recall": self.file_recall,
            "line_recall": self.line_recall,
            "class_recall": self.class_recall,
            "note": (
                "localization only. file_recall is generous (the file was "
                "touched at all). line_recall is weak on its own: on a real run "
                "it reached 2/2 while the overlapping detectors were "
                "reentrancy-events and naming-convention, which cover ~18% of "
                "the file by chance. class_recall is the only number worth "
                "quoting, and it is not a rediscovery either."
            ),
            "scores": [s.to_dict() for s in self.scores],
        }



# -- parsing ---------------------------------------------------------------- #

def parse_unified_diff(text: str) -> list[Hunk]:
    """Extract the changed spans of a ``git diff``, on the vulnerable side."""
    hunks: list[Hunk] = []
    current: Optional[str] = None
    for line in text.splitlines():
        m = _DIFF_FILE_RE.match(line)
        if m:
            current = m.group(1).strip()
            continue
        if line.startswith("--- "):
            # ``--- a/path`` also names the file; ``+++`` wins when both appear.
            if current is None:
                current = line[4:].strip().removeprefix("a/")
            continue
        h = _HUNK_RE.match(line)
        if h and current:
            start = int(h.group(1))
            length = int(h.group(2)) if h.group(2) is not None else 1
            hunks.append(Hunk(file=current, start=start, length=max(length, 1)))
    return hunks


def _parse_config(config: Path) -> dict:
    """A deliberately small reader for the dataset's flat ``config.yaml``.

    Only the two shapes this scorer needs are understood -- top-level scalars and
    a ``vulnerabilities:`` list of mappings. Anything else is left alone; a real
    YAML parser would be a dependency, and guessing at richer structure would be
    worse than not scoring an audit.
    """
    out: dict = {"vulnerabilities": []}
    current: Optional[dict] = None
    in_vulns = False
    for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if indent == 0:
            in_vulns = line.startswith("vulnerabilities:")
            current = None
            if ":" in line and not in_vulns:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip().strip('"\'')
            continue
        if not in_vulns:
            continue
        if line.startswith("- "):
            current = {}
            out["vulnerabilities"].append(current)
            line = line[2:].strip()
        if current is not None and ":" in line:
            k, _, v = line.partition(":")
            current[k.strip()] = v.strip().strip('"\'')
    return out


def load_ground_truth(audit_dir: Path) -> tuple[list[GroundTruth], list[tuple[str, str, str]]]:
    """Read one audit's disclosed vulnerabilities and their fix locations.

    Returns ``(scored, unscored)`` where ``unscored`` names the vulnerabilities the
    dataset records only as a title -- those are excluded from the denominator
    rather than counted as misses, because there is nothing to localize against.
    """
    config = audit_dir / "config.yaml"
    if not config.is_file():
        return [], []
    meta = _parse_config(config)
    audit = meta.get("id") or audit_dir.name

    patch_dir = audit_dir / "patch"
    scored: list[GroundTruth] = []
    unscored: list[tuple[str, str, str]] = []
    for vuln in meta["vulnerabilities"]:
        vid = vuln.get("id", "")
        title = vuln.get("title", "")
        hunks: list[Hunk] = []
        files: list[str] = []
        # The dataset names fix diffs ``patch/<ID>.diff``; some audits instead ship
        # the whole fixed file, which carries no line information and cannot be
        # localized against -- those fall through to ``unscored``.
        for name in (f"{vid}.diff", f"{vid.lower()}.diff"):
            diff = patch_dir / name
            if diff.is_file():
                hunks = parse_unified_diff(diff.read_text(encoding="utf-8", errors="replace"))
                break
        if hunks:
            files = sorted({h.file for h in hunks})
            try:
                award = float(vuln.get("award", 0) or 0)
            except ValueError:
                award = 0.0
            scored.append(GroundTruth(audit=audit, vulnerability=vid, title=title,
                                      award=award, hunks=hunks, patch_files=files))
        else:
            unscored.append((audit, vid,
                             "no patch diff: the dataset records this vulnerability "
                             "only as a title, so there is no location to score"))
    return scored, unscored


def _slither_line(span: dict) -> tuple[int, int]:
    lines = span.get("lines") or []
    if not lines:
        start = span.get("start", 0)
        length = span.get("length", 0)
        return start, start + max(length, 1)
    return min(lines), max(lines)


def load_slither_findings(path: Path) -> list[Finding]:
    """Normalize a Slither JSON report into location-only findings."""
    data = json.loads(path.read_text(encoding="utf-8"))
    detectors = (data.get("results") or {}).get("detectors") or []
    out: list[Finding] = []
    for d in detectors:
        if not isinstance(d, dict):
            continue
        for element in d.get("elements") or []:
            span = element.get("source_mapping") or {}
            fname = span.get("filename_relative") or span.get("filename_short") or ""
            if not fname:
                continue
            start, end = _slither_line(span)
            out.append(Finding(check=str(d.get("check", "")), file=fname,
                               start=start, end=end,
                               impact=str(d.get("impact", "")),
                               confidence=str(d.get("confidence", ""))))
    return out


# -- scoring ---------------------------------------------------------------- #

def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _same_file(finding_file: str, gt_file: str) -> bool:
    """Match a finding to a ground-truth path, tolerating a leading directory.

    Slither reports ``src/Vault.sol`` while a fix diff may say ``vault/src/Vault.sol``
    because the audit root sits one level up. Comparing suffixes is what makes the
    two comparable without pretending they are identical strings.
    """
    a, b = _norm(finding_file), _norm(gt_file)
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def score_audit(truth: GroundTruth, findings: Iterable[Finding]) -> AuditScore:
    findings = list(findings)
    expected = expected_classes(truth.title)
    score = AuditScore(audit=truth.audit, vulnerability=truth.vulnerability,
                       title=truth.title, expected=expected)
    files = truth.files
    for f in findings:
        if not any(_same_file(f.file, g) for g in files):
            continue
        score.file_hit = True
        score.touching.append(f)
        for h in truth.hunks:
            if not (_same_file(f.file, h.file) and h.overlaps(f.start, f.end)):
                continue
            score.line_hit = True
            if f.check in expected:
                score.class_hit = True
    return score



def evaluate(dataset_root: Path, findings: Iterable[Finding],
             *, audits: Optional[Iterable[str]] = None) -> EvalReport:
    """Score ``findings`` against every audit under ``dataset_root/audits``.

    ``findings`` are pooled across the run: a finding only counts for the audit
    whose file it names, so one report may cover several audits at once.
    """
    findings = list(findings)
    report = EvalReport(total_findings=len(findings))
    audits_dir = dataset_root / "audits"
    wanted = set(audits) if audits else None
    if not audits_dir.is_dir():
        return report

    for audit_dir in sorted(p for p in audits_dir.iterdir() if p.is_dir()):
        if wanted is not None and audit_dir.name not in wanted:
            continue
        truths, unscored = load_ground_truth(audit_dir)
        if not truths and not unscored:
            continue
        report.audits_seen += 1
        report.unscored.extend(unscored)
        for truth in truths:
            report.scores.append(score_audit(truth, findings))
    return report


def format_report(report: EvalReport) -> str:
    def pct(v: Optional[float]) -> str:
        return "n/a" if v is None else f"{v * 100:.1f}%"

    lines = [
        "EVMbench localization evaluation (key-free)",
        f"  audits seen            {report.audits_seen}",
        f"  findings scored        {report.total_findings}",
        f"  vulnerabilities scored {report.scored}",
        f"  unscored (no patch)    {len(report.unscored)}",
        "",
        f"  file recall (weak)     {report.file_hits}/{report.scored} "
        f"({pct(report.file_recall)})",
        f"  line recall (weak)     {report.line_hits}/{report.scored} "
        f"({pct(report.line_recall)})",
        f"  class recall (quoted)  {report.class_hits}/{report.scored} "
        f"({pct(report.class_recall)})",
        "",
        "  localization only. file recall only says the right file was touched.",
        "  line recall can be reached by noise detectors that cover a large part",
        "  of the file, so it is reported but not credited. class recall requires",
        "  the overlapping detector to belong to a family the fix title can",
        "  express. None of the three is a rediscovery of the audited bug.",
    ]
    return "\n".join(lines)

