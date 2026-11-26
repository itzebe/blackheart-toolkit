"""Web/API/recon tool adapters.

Each function drives one real tool and parses its machine-readable output into
:class:`ToolFinding` records. The parsers are written against the tool's actual
output shape, and every one degrades honestly: if the JSON is absent or malformed
the raw output is still captured in the :class:`ToolRun`, with a ``parse_notes``
entry explaining what could not be read.

Authorization is enforced by :func:`base.authorized_run` before any binary starts.
"""

from __future__ import annotations

import json
from typing import Optional

from ...models import AuthorizationRecord
from .base import ToolFinding, ToolRun, authorized_run

# --------------------------------------------------------------------------- #
# ffuf -- content discovery / fuzzing
# --------------------------------------------------------------------------- #

def run_ffuf(
    url: str,
    wordlist: str,
    *,
    record: AuthorizationRecord,
    asset: str = "",
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> ToolRun:
    """Directory/content discovery with ffuf.

    ``url`` must contain the ``FUZZ`` keyword. Only ``200``-class and ``30x``
    responses are kept by default (``-mc``), so the result is a shortlist of real
    endpoints rather than every 404.
    """
    asset = asset or url

    def build(path: str) -> list[str]:
        cmd = [path, "-u", url, "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
               "-of", "json", "-o", "/dev/stdout", "-s"]
        cmd += extra_args or []
        return cmd

    run = authorized_run(tool="ffuf", asset=asset, target=url, record=record,
                         build_cmd=build, timeout=timeout)
    if not run.available or run.returncode not in (0, 1):
        if run.returncode == 1 and not run.stdout.strip():
            run.parse_notes.append("ffuf exited 1 with no output (no matches)")
        return run
    _parse_ffuf(run)
    return run


def _parse_ffuf(run: ToolRun) -> None:
    text = run.stdout.strip()
    if not text:
        run.parse_notes.append("ffuf produced no output")
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        run.parse_notes.append("ffuf output was not JSON; raw output captured, not parsed")
        return
    for res in (data.get("results") or []):
        if not isinstance(res, dict):
            continue
        status = res.get("status")
        run.findings.append(ToolFinding(
            tool="ffuf",
            kind="endpoint",
            target=str(res.get("url") or ""),
            severity="info",
            detail=f"HTTP {status} ({res.get('length', '?')} bytes, {res.get('words', '?')} words)",
            evidence=json.dumps(res, sort_keys=True)[:500],
            raw=res,
        ))


# --------------------------------------------------------------------------- #
# gobuster -- directory/DNS brute forcing
# --------------------------------------------------------------------------- #

def run_gobuster(
    url: str,
    wordlist: str,
    *,
    record: AuthorizationRecord,
    asset: str = "",
    mode: str = "dir",
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> ToolRun:
    asset = asset or url

    def build(path: str) -> list[str]:
        cmd = [path, mode, "-u", url, "-w", wordlist, "-q", "--no-error"]
        cmd += extra_args or []
        return cmd

    run = authorized_run(tool="gobuster", asset=asset, target=url, record=record,
                         build_cmd=build, timeout=timeout)
    if not run.available:
        return run
    _parse_gobuster(run)
    return run


def _parse_gobuster(run: ToolRun) -> None:
    import re

    # gobuster lines look like: `/admin                (Status: 200) [Size: 1234]`
    line_re = re.compile(r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)(?:\s*\[Size:\s*(?P<size>\d+)\])?")
    for line in run.stdout.splitlines():
        m = line_re.search(line.strip())
        if not m:
            continue
        run.findings.append(ToolFinding(
            tool="gobuster",
            kind="endpoint",
            target=m.group("path"),
            severity="info",
            detail=f"HTTP {m.group('status')}" + (f" ({m.group('size')} bytes)" if m.group("size") else ""),
            evidence=line.strip(),
        ))
    if not run.findings:
        run.parse_notes.append("gobuster produced no parsable result lines")


# --------------------------------------------------------------------------- #
# nuclei -- template-based vulnerability scanning
# --------------------------------------------------------------------------- #

def run_nuclei(
    target: str,
    *,
    record: AuthorizationRecord,
    asset: str = "",
    severity: str = "",
    templates: Optional[list[str]] = None,
    timeout: int = 900,
    extra_args: Optional[list[str]] = None,
) -> ToolRun:
    """Run nuclei against ``target`` and parse its JSONL output."""
    asset = asset or target

    def build(path: str) -> list[str]:
        cmd = [path, "-u", target, "-jsonl", "-silent", "-no-color", "-nc"]
        if severity:
            cmd += ["-severity", severity]
        for t in templates or []:
            cmd += ["-t", t]
        cmd += extra_args or []
        return cmd

    run = authorized_run(tool="nuclei", asset=asset, target=target, record=record,
                         build_cmd=build, timeout=timeout)
    if not run.available:
        return run
    _parse_nuclei(run)
    return run


def _parse_nuclei(run: ToolRun) -> None:
    for line in run.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            run.parse_notes.append("a nuclei line was not valid JSON and was skipped")
            continue
        info = obj.get("info") or {}
        run.findings.append(ToolFinding(
            tool="nuclei",
            kind=str(obj.get("template-id") or obj.get("templateID") or "match"),
            target=str(obj.get("matched-at") or obj.get("host") or ""),
            severity=str(info.get("severity") or ""),
            detail=str(info.get("name") or ""),
            evidence=line[:500],
            raw=obj,
        ))
    if not run.findings:
        run.parse_notes.append("nuclei found no matching templates (no findings)")


# --------------------------------------------------------------------------- #
# sqlmap -- SQL injection detection
# --------------------------------------------------------------------------- #

def run_sqlmap(
    url: str,
    *,
    record: AuthorizationRecord,
    asset: str = "",
    data: str = "",
    timeout: int = 900,
    extra_args: Optional[list[str]] = None,
) -> ToolRun:
    """Run sqlmap in batch mode and parse its findings.

    Batch mode (``--batch``) is mandatory so the tool never prompts; ``--level``
    and ``--risk`` stay at sqlmap's defaults unless the caller raises them.
    """
    asset = asset or url

    def build(path: str) -> list[str]:
        cmd = [path, "-u", url, "--batch", "--output-dir=/tmp/sqlmap-bh"]
        if data:
            cmd += ["--data", data]
        cmd += extra_args or []
        return cmd

    run = authorized_run(tool="sqlmap", asset=asset, target=url, record=record,
                         build_cmd=build, timeout=timeout)
    if not run.available:
        return run
    _parse_sqlmap(run, url)
    return run


def _parse_sqlmap(run: ToolRun, url: str) -> None:
    # sqlmap's human output is the stable interface. Its *positive* finding is a
    # line that names an injectable parameter/type; the negative phrasing ("do not
    # appear to be injectable", "not injectable") must NOT be read as a finding --
    # a substring check on "injectable" alone would flag it, which is exactly the
    # kind of false positive this parser must not produce.
    negative = ("do not appear", "does not appear", "not injectable",
                "no parameter", "all tested parameters do not")
    injectable = False
    for line in run.stdout.splitlines():
        low = line.lower()
        if any(neg in low for neg in negative):
            continue
        positive = (
            "is injectable" in low
            or "is vulnerable" in low
            or "sqlmap identified the following injection point" in low
            or ("parameter" in low and "injectable" in low)
        )
        if positive:
            injectable = True
            run.findings.append(ToolFinding(
                tool="sqlmap",
                kind="sql-injection",
                target=url,
                severity="high",
                detail=line.strip(),
                evidence=line.strip(),
            ))
    if not injectable:
        run.parse_notes.append("sqlmap reported no injectable parameters")


# --------------------------------------------------------------------------- #
# dalfox -- XSS scanning
# --------------------------------------------------------------------------- #

def run_dalfox(
    url: str,
    *,
    record: AuthorizationRecord,
    asset: str = "",
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> ToolRun:
    asset = asset or url

    def build(path: str) -> list[str]:
        cmd = [path, "url", url, "--silence", "--no-color", "--format", "json"]
        cmd += extra_args or []
        return cmd

    run = authorized_run(tool="dalfox", asset=asset, target=url, record=record,
                         build_cmd=build, timeout=timeout)
    if not run.available:
        return run
    _parse_dalfox(run, url)
    return run


def _parse_dalfox(run: ToolRun, url: str) -> None:
    text = run.stdout.strip()
    if not text:
        run.parse_notes.append("dalfox produced no output (no XSS found)")
        return
    # dalfox emits one JSON object per line in --format json.
    parsed_any = False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        run.findings.append(ToolFinding(
            tool="dalfox",
            kind=str(obj.get("type") or "xss"),
            target=str(obj.get("data") or obj.get("url") or url),
            severity="high",
            detail=str(obj.get("evidence") or obj.get("message") or ""),
            evidence=line[:500],
            raw=obj,
        ))
    if not parsed_any:
        run.parse_notes.append("dalfox output was not JSONL; raw output captured")


# --------------------------------------------------------------------------- #
# gitleaks -- secret scanning
# --------------------------------------------------------------------------- #

def run_gitleaks(
    path: str,
    *,
    record: AuthorizationRecord,
    asset: str = "",
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> ToolRun:
    """Scan a local path (repo/dir) for secrets. This reads local files only."""
    asset = asset or path

    def build(exe: str) -> list[str]:
        cmd = [exe, "detect", "--source", path, "--report-format", "json",
               "--report-path", "/dev/stdout", "--no-banner"]
        cmd += extra_args or []
        return cmd

    run = authorized_run(tool="gitleaks", asset=asset, target=path, record=record,
                         build_cmd=build, timeout=timeout)
    if not run.available:
        return run
    _parse_gitleaks(run)
    return run


def _parse_gitleaks(run: ToolRun) -> None:
    text = run.stdout.strip()
    if not text:
        run.parse_notes.append("gitleaks produced no output (no secrets found)")
        return
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        run.parse_notes.append("gitleaks output was not JSON; raw output captured")
        return
    leaks = data if isinstance(data, list) else data.get("findings", [])
    for leak in leaks:
        if not isinstance(leak, dict):
            continue
        run.findings.append(ToolFinding(
            tool="gitleaks",
            kind=str(leak.get("RuleID") or "secret"),
            target=str(leak.get("File") or ""),
            severity="high",
            detail=f"{leak.get('Description', 'secret')} at line {leak.get('StartLine', '?')}",
            evidence=json.dumps(leak, sort_keys=True)[:500],
            raw=leak,
        ))
    if not run.findings:
        run.parse_notes.append("gitleaks reported no secrets")
