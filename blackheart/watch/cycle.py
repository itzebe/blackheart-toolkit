"""One monitoring cycle: observe, diff, classify, remember, report.

The cycle is deliberately sequential and bounded. Each target is independent;
a failure in one policy page, repository or contract is recorded as a gap and
never stops the rest. The only shared state is the dedupe set and the baseline,
written atomically at the end (and even when a source failed).

Order matters and is the doctrine's order: read the official policy, then the
code that may ship, then the deployed bytecode. A repository commit is never
reported as a deployment; only the on-chain fingerprint can establish that.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from ..models import utcnow
from .classify import (
    Event,
    Kind,
    Lead,
    Status,
    assess_repo_change,
    classify_event,
    make_event,
)
from .fetch import (
    ContractObservation,
    GitHubClient,
    HttpFetcher,
    RpcClient,
)
from .registry import ContractRef, Target, load_registry
from .source import SourceClient, SourceDiff, diff_bundles
from .state import WatchState

__all__ = [
    "CycleConfig",
    "TargetReport",
    "CycleReport",
    "run_cycle",
    "stabilize_text",
    "policy_diff",
    "policy_signals",
]

_ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")
_CLOCK_RE = re.compile(r"\b\d{2}:\d{2}(?::\d{2})?\b")
_EPOCH_RE = re.compile(r"\b\d{10,13}\b")
_LONG_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.I)
#: Platform counters that move on every page view. They are not policy text.
_COUNTER_RE = re.compile(
    r"\b(scope review|submissions?|hackers?|reports?|views?|watchers?|stars?|forks?)"
    r"\s*:?\s*[\d,]+",
    re.I,
)


def stabilize_text(text: str) -> str:
    """Remove clock/build/counter noise while keeping dates and policy words."""
    text = _ISO_RE.sub("<timestamp>", text)
    text = _CLOCK_RE.sub("<clock>", text)
    text = _EPOCH_RE.sub("<epoch>", text)
    text = _LONG_HEX_RE.sub("<hex>", text)
    text = _COUNTER_RE.sub(r"\1 <counter>", text)
    return re.sub(r"\s+", " ", text).strip()


_SIGNAL_PATTERNS = {
    "ai_agent": re.compile(
        r"(ai agent|automated (?:tool|scanner|agent)|artificial intelligence|llm|"
        r"large language model|bot(?:s)? (?:are|is)|machine learning)",
        re.I,
    ),
    "kyc": re.compile(r"\b(kyc|know your customer|identity verification)\b", re.I),
    "testnet": re.compile(r"\b(testnet|test net|test-network)\b", re.I),
    "mainnet": re.compile(r"\b(mainnet|main net)\b", re.I),
    "nigeria": re.compile(r"\bnigeria\b", re.I),
    "out_of_scope": re.compile(r"\b(out[- ]of[- ]scope|not in scope|excluded)\b", re.I),
    "paused": re.compile(r"\b(paused|suspended|closed|not accepting)\b", re.I),
    "reward": re.compile(r"\b(reward|bounty|payout|up to \$)\b", re.I),
    "safe_harbor": re.compile(r"\bsafe harbor\b", re.I),
    "poc_required": re.compile(r"\b(proof of concept|poc|exploit script)\b", re.I),
}


def policy_signals(text: str, *, limit: int = 4) -> dict:
    """Extract reviewable policy signals with short verbatim snippets.

    A signal is a *pointer for a human*, never an automatic permission change.
    The registry is the only place that can set ``ai_agent_allowed``.
    """
    out: dict[str, dict] = {}
    for name, pattern in _SIGNAL_PATTERNS.items():
        matches = list(pattern.finditer(text))
        snippets = []
        for m in matches[:limit]:
            start = max(0, m.start() - 90)
            end = min(len(text), m.end() + 90)
            snippets.append(text[start:end].strip())
        out[name] = {"found": bool(matches), "count": len(matches), "snippets": snippets}
    return out


def policy_diff(
    old_text: str, new_text: str, *, limit: int = 20
) -> tuple[str, list[str], bool]:
    """A short, human-reviewable diff of two normalized policy texts.

    Returns ``(summary, changed_lines, material)``. ``material`` is false when the
    only difference is a number (a view counter, a submission count), which is not
    a policy change. The diff is sentence-level because the normaliser collapses a
    page to one line; a word diff would be unreadable.
    """
    def sentences(t: str) -> list[str]:
        parts = re.split(r"(?<=[.!?])\s+|\s{2,}", t)
        return [p.strip() for p in parts if p.strip()]

    def numbers_neutral(t: str) -> str:
        t = re.sub(r"<(counter|timestamp|clock|epoch|hex)>", "#", t)
        # Decimals and currency amounts move every hour on live program pages
        # (``Vault TVL $79,950.72`` -> ``$79,952``); they are metrics, not policy.
        t = re.sub(r"\d[\d,]*(?:\.\d+)?", "#", t)
        # ``Submissions: 190`` and the stabilised ``Submissions <counter>`` are
        # the same fact; the colon is punctuation, not a policy change.
        return re.sub(r":\s*#", " #", t)

    old_s, new_s = sentences(old_text), sentences(new_text)
    if numbers_neutral(" ".join(old_s)) == numbers_neutral(" ".join(new_s)):
        return "metric/counter change only (no policy text changed)", [], False

    diff = list(
        difflib.unified_diff(old_s, new_s, fromfile="previous", tofile="current", lineterm="", n=0)
    )
    changed = [line for line in diff if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
    security = [line for line in changed if re.search(
        r"scope|eligib|reward|payout|kyc|ai |agent|testnet|mainnet|exclude|out of scope|"
        r"paused|closed|safe harbor|severity|duplicate",
        line, re.I,
    )]
    chosen = (security or changed)[:limit]
    summary = f"{len(changed)} changed line(s)"
    if security:
        summary += f", {len(security)} mention scope/eligibility/reward terms"
    return summary, chosen[:limit], True


def ai_agent_review(signals: dict) -> dict:
    """Flag AI-agent language for human review; never changes a permission."""
    ai = signals.get("ai_agent") or {}
    snippets = [str(s) for s in (ai.get("snippets") or [])]
    joined = " ".join(snippets).lower()
    prohibited = any(
        phrase in joined
        for phrase in (
            "not allowed", "prohibited", "do not", "don't", "must not",
            "automated scanners", "no automated", "not permitted",
        )
    )
    return {
        "detected": bool(ai.get("found")),
        "prohibited_language": prohibited,
        "snippets": snippets[:4],
        "note": (
            "Policy text mentions AI agents or automation. This is a signal for "
            "manual review only; the registry permission is unchanged."
        ),
    }


@dataclass
class CycleConfig:
    state_dir: str = "research/bounty-monitor/state"
    out_dir: str = "research/bounty-monitor"
    registry_path: Optional[str] = None
    targets: tuple[str, ...] = ()
    skip_policy: bool = False
    skip_repos: bool = False
    skip_contracts: bool = False
    max_repos: Optional[int] = None
    max_policy: Optional[int] = None
    max_contracts: Optional[int] = None
    timeout: int = 25
    dry_run: bool = False
    email: bool = False
    email_to: str = ""
    quiet: bool = False
    #: Fetch and diff verified source when a deployment changes (Sourcify).
    source_diff: bool = True


@dataclass
class TargetReport:
    target: Target
    policy: list[dict] = field(default_factory=list)
    repos: list[dict] = field(default_factory=list)
    contracts: list[dict] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    deduped: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.events)

    def to_dict(self) -> dict:
        return {
            "target": self.target.to_dict(),
            "policy": self.policy,
            "repos": self.repos,
            "contracts": self.contracts,
            "events": [e.to_dict() for e in self.events],
            "leads": [l.to_dict() for l in self.leads],
            "failures": list(self.failures),
            "gaps": list(self.gaps),
            "deduped": self.deduped,
        }


@dataclass
class CycleReport:
    cycle_id: str
    started_at: str
    finished_at: str = ""
    duration_s: float = 0.0
    state_dir: str = ""
    out_dir: str = ""
    registry_count: int = 0
    targets: list[TargetReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notifications: dict = field(default_factory=dict)
    exit_code: int = 0

    @property
    def events(self) -> list[Event]:
        return [e for t in self.targets for e in t.events]

    @property
    def leads(self) -> list[Lead]:
        return [l for t in self.targets for l in t.leads]

    @property
    def failures(self) -> list[tuple[str, str]]:
        return [(t.target.slug, f) for t in self.targets for f in t.failures]

    def counts(self) -> dict[str, int]:
        counts = {s: 0 for s in (
            Status.NEW_ACTIONABLE_CHANGE,
            Status.INVESTIGATE,
            Status.WATCH,
            Status.NO_CHANGE,
            Status.POLICY_BLOCKED,
            Status.KNOWN_DUPLICATE,
            Status.SOURCE_INACCESSIBLE,
        )}
        for lead in self.leads:
            counts[lead.status] = counts.get(lead.status, 0) + 1
        # A deduplicated source failure is still a failure, not a clean check.
        inaccessible_targets = sum(1 for t in self.targets if t.failures)
        counts[Status.SOURCE_INACCESSIBLE] = max(
            counts.get(Status.SOURCE_INACCESSIBLE, 0), inaccessible_targets
        )
        counts[Status.NO_CHANGE] = sum(
            1 for t in self.targets if not t.events and not t.failures
        )
        counts["targets"] = len(self.targets)
        counts["events"] = len(self.events)
        counts["failures"] = len(self.failures)
        counts["deduped"] = sum(t.deduped for t in self.targets)
        return counts

    def to_dict(self) -> dict:
        return {
            "cycle_id": self.cycle_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 3),
            "state_dir": self.state_dir,
            "out_dir": self.out_dir,
            "registry_count": self.registry_count,
            "counts": self.counts(),
            "warnings": list(self.warnings),
            "notifications": self.notifications,
            "exit_code": self.exit_code,
            "targets": [t.to_dict() for t in self.targets],
        }


# --------------------------------------------------------------------------- #
# Cycle
# --------------------------------------------------------------------------- #

def run_cycle(
    config: CycleConfig,
    *,
    registry: Optional[tuple[Target, ...]] = None,
    fetcher: Optional[HttpFetcher] = None,
    github: Optional[GitHubClient] = None,
    rpc: Optional[RpcClient] = None,
    source: Optional[SourceClient] = None,
) -> CycleReport:
    """Run one monitoring cycle and return an honest report."""
    started = time.monotonic()
    cycle_id = utcnow().replace(":", "").replace("-", "").replace(".", "")[:15] + "Z"
    report = CycleReport(
        cycle_id=cycle_id,
        started_at=utcnow(),
        state_dir=config.state_dir,
        out_dir=config.out_dir,
    )
    targets = registry if registry is not None else load_registry(config.registry_path)
    if config.targets:
        wanted = set(config.targets)
        targets = tuple(t for t in targets if t.slug in wanted)
        missing = wanted - {t.slug for t in targets}
        if missing:
            raise SystemExit(f"unknown target(s): {', '.join(sorted(missing))}")
    report.registry_count = len(targets)

    fetcher = fetcher or HttpFetcher(timeout=config.timeout)
    github = github or GitHubClient(timeout=config.timeout)
    rpc = rpc or RpcClient(timeout=config.timeout)
    if source is None and config.source_diff:
        source = SourceClient(timeout=config.timeout)

    state = WatchState.load(config.state_dir)
    if state.warning:
        report.warnings.append(state.warning)
    if not config.dry_run:
        state.begin_cycle()

    with state.lock():
        for target in targets:
            tr = TargetReport(target=target)
            report.targets.append(tr)
            try:
                if not config.skip_policy:
                    _check_policy(target, tr, state, fetcher, config)
                if not config.skip_repos:
                    _check_repos(target, tr, state, github, config)
                if not config.skip_contracts:
                    _check_contracts(target, tr, state, rpc, config, source, cycle_id)
            except Exception as exc:  # noqa: BLE001 -- one target cannot kill the cycle
                tr.failures.append(f"{target.slug}: cycle error {type(exc).__name__}: {exc}")
                state.record_failure(f"{target.slug}:cycle", str(exc))

            for event in tr.events:
                if state.seen(event.id):
                    tr.deduped += 1
                    continue
                lead = classify_event(
                    event,
                    target,
                    sensitive_files=event.detail.get("security_files", []),
                    sensitive_messages=event.detail.get("security_messages", []),
                )
                tr.leads.append(lead)
                state.remember(event.id)
            state.mark_cycle(target.slug)
            if not target.contracts:
                tr.gaps.append("no verified contract address recorded")
            if not target.policy_urls:
                tr.gaps.append("no official policy URL recorded")
            if not target.repos:
                tr.gaps.append("no verified repository recorded")

        if not config.dry_run:
            state.save()

    report.finished_at = utcnow()
    report.duration_s = time.monotonic() - started
    report.exit_code = _exit_code(report)
    if not config.dry_run:
        from .report import write_report

        write_report(report, config.out_dir)
        if config.email:
            from .notify import email_cycle_report

            report.notifications = email_cycle_report(report, to=config.email_to)
    return report


def _exit_code(report: CycleReport) -> int:
    if report.failures:
        return 2  # incomplete must never read as clean
    if report.events:
        return 1
    return 0


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #

def _check_policy(
    target: Target,
    tr: TargetReport,
    state: WatchState,
    fetcher: HttpFetcher,
    config: CycleConfig,
) -> None:
    refs = target.policy_urls[: config.max_policy] if config.max_policy else target.policy_urls
    for ref in refs:
        prev = state.policy(target.slug, ref.url)
        result = fetcher.fetch(
            ref.url,
            etag=str(prev.get("etag", "")),
            last_modified=str(prev.get("last_modified", "")),
        )
        entry = result.to_dict()
        entry["kind"] = ref.kind
        entry["official"] = ref.official
        tr.policy.append(entry)

        if not result.ok:
            error = f"policy {ref.url}: {result.error or result.error_kind}"
            tr.failures.append(error)
            state.record_failure(f"policy:{target.slug}:{ref.url}", error)
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.SOURCE_FAILED,
                    component=ref.url,
                    summary=f"policy source unreadable: {result.error or result.error_kind}",
                    evidence_urls=(ref.url,),
                    detail={"error_kind": result.error_kind, "status": result.status},
                )
            )
            continue

        state.clear_failure(f"policy:{target.slug}:{ref.url}")
        if result.not_modified:
            state.set_policy(
                target.slug,
                ref.url,
                {
                    **prev,
                    "retrieved_at": result.retrieved_at,
                    "status": result.status,
                    "not_modified": True,
                },
            )
            continue

        text = stabilize_text(result.text)
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        prev_sha = str(prev.get("text_sha256", ""))
        signals = policy_signals(text)
        changed = bool(prev_sha and prev_sha != text_sha)
        snapshot = _write_policy_snapshot(
            Path(config.state_dir), target.slug, ref.url, text,
            changed=changed, old_sha=prev_sha,
        )
        old_text = (
            _read_policy_archive(Path(config.state_dir), target.slug, ref.url)
            if changed
            else ""
        )

        if not prev_sha:
            summary = "first observation of the official policy"
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.POLICY_NEW,
                    component=ref.url,
                    summary=summary,
                    new=text_sha,
                    evidence_urls=(ref.url,),
                    detail={
                        "title": result.title,
                        "signals": signals,
                        "ai_agent_review": ai_agent_review(signals),
                    },
                )
            )
        elif prev_sha != text_sha:
            if old_text:
                diff_summary, changed, material = policy_diff(old_text, text)
            else:
                diff_summary, changed, material = (
                    "content changed; previous text unavailable for a line diff",
                    [],
                    True,
                )
            if material:
                tr.events.append(
                    make_event(
                        target=target.slug,
                        kind=Kind.POLICY_CHANGED,
                        component=ref.url,
                        summary=f"official policy changed: {diff_summary}",
                        old=prev_sha,
                        new=text_sha,
                        evidence_urls=(ref.url,),
                        security_relevant=True,
                        detail={
                            "title": result.title,
                            "changed_lines": changed,
                            "signals": signals,
                            "ai_agent_review": ai_agent_review(signals),
                            "previous_text_available": bool(old_text),
                        },
                    )
                )
            else:
                entry["metric_only"] = True

        state.set_policy(
            target.slug,
            ref.url,
            {
                "url": ref.url,
                "kind": ref.kind,
                "official": ref.official,
                "title": result.title,
                "status": result.status,
                "text_sha256": text_sha,
                "raw_sha256": result.raw_sha256,
                "etag": result.etag,
                "last_modified": result.last_modified,
                "retrieved_at": result.retrieved_at,
                "snapshot": str(snapshot),
                "signals": signals,
            },
        )


def _url_token(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _policy_dir(root: Path, slug: str, url: str) -> Path:
    return root / "snapshots" / "policy" / slug / _url_token(url)


def _write_policy_snapshot(
    root: Path, slug: str, url: str, text: str, *, changed: bool, old_sha: str
) -> Path:
    """Write the current policy text and archive the previous one on a change.

    The archive decision comes from the *state hash*, not from re-hashing the
    stored text: re-stabilising an already-stabilised page is not a reliable way
    to recover the old content, and losing it would silently downgrade a real
    diff to "previous text unavailable".
    """
    d = _policy_dir(root, slug, url)
    d.mkdir(parents=True, exist_ok=True)
    latest = d / "latest.txt"
    if changed and latest.is_file():
        old = latest.read_text(encoding="utf-8", errors="replace")
        stamp = utcnow().replace(":", "").replace(".", "")
        archive = d / f"{stamp}-{old_sha[:12] or 'previous'}.txt"
        archive.write_text(old, encoding="utf-8")
    latest.write_text(text, encoding="utf-8")
    return latest


def _read_policy_archive(root: Path, slug: str, url: str) -> str:
    """The most recently archived (pre-change) policy text, if one exists."""
    d = _policy_dir(root, slug, url)
    archives = sorted(p for p in d.glob("*.txt") if p.name != "latest.txt")
    if not archives:
        return ""
    return archives[-1].read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Repositories
# --------------------------------------------------------------------------- #

def _check_repos(
    target: Target,
    tr: TargetReport,
    state: WatchState,
    github: GitHubClient,
    config: CycleConfig,
) -> None:
    def repo_failure(component: str, summary: str, detail: dict) -> None:
        error = f"repo {component}: {summary}"
        tr.failures.append(error)
        state.record_failure(f"repo:{target.slug}:{component}", error)
        tr.events.append(
            make_event(
                target=target.slug,
                kind=Kind.SOURCE_FAILED,
                component=component,
                summary=f"repository unreadable: {summary}",
                evidence_urls=(f"https://github.com/{component}",),
                detail=detail,
            )
        )

    refs = target.repos[: config.max_repos] if config.max_repos else target.repos
    for ref in refs:
        prev = state.repo(target.slug, ref.repo)
        repo_res = github.repo(ref.repo, etag=str(prev.get("etag_repo", "")))
        if not repo_res.ok:
            repo_failure(ref.repo, str(repo_res.error or repo_res.error_kind),
                         {"error_kind": repo_res.error_kind, "status": repo_res.status})
            continue
        state.clear_failure(f"repo:{target.slug}:{ref.repo}")
        if repo_res.not_modified and prev:
            meta = {
                "default_branch": prev.get("branch", ""),
                "archived": prev.get("archived", False),
                "pushed_at": prev.get("pushed_at", ""),
            }
        else:
            meta = repo_res.data if isinstance(repo_res.data, dict) else {}
        branch = str(meta.get("default_branch") or "")
        if not branch:
            # Never guess "main": that turns a metadata gap into a false HEAD move.
            repo_failure(ref.repo, "metadata has no default_branch",
                         {"status": repo_res.status, "not_modified": repo_res.not_modified})
            continue
        archived = bool(meta.get("archived", False))
        if archived:
            tr.gaps.append(f"repository {ref.repo} is archived")

        head_res = github.head_commit(ref.repo, branch, etag=str(prev.get("etag_head", "")))
        head = str(prev.get("head", "")) if head_res.not_modified else ""
        head_message = str(prev.get("head_message", "")) if head_res.not_modified else ""
        head_date = str(prev.get("head_date", "")) if head_res.not_modified else ""
        empty = head_res.status == 409
        if empty:
            # A newly created, still-empty repository is a watch item, not a failure.
            tr.gaps.append(f"repository {ref.repo} is empty (no commits)")
        elif not head_res.ok:
            repo_failure(ref.repo, f"head unreadable: {head_res.error or head_res.error_kind}",
                         {"error_kind": head_res.error_kind, "status": head_res.status})
            continue
        elif not head_res.not_modified:
            if not (isinstance(head_res.data, list) and head_res.data):
                repo_failure(ref.repo, "head response contained no commit",
                             {"status": head_res.status})
                continue
            commit = head_res.data[0]
            head = str(commit.get("sha", ""))
            head_message = str((commit.get("commit") or {}).get("message", "")).splitlines()[0][:300]
            head_date = str(((commit.get("commit") or {}).get("author") or {}).get("date", ""))

        rel_res = github.latest_release(ref.repo, etag=str(prev.get("etag_release", "")))
        release_tag = str(prev.get("release", "")) if rel_res.not_modified else ""
        release_name = str(prev.get("release_name", "")) if rel_res.not_modified else ""
        release_at = str(prev.get("release_at", "")) if rel_res.not_modified else ""
        release_body = ""
        if rel_res.ok and not rel_res.not_modified and isinstance(rel_res.data, dict):
            release_tag = str(rel_res.data.get("tag_name", ""))
            release_name = str(rel_res.data.get("name", ""))
            release_at = str(rel_res.data.get("published_at", ""))
            release_body = str(rel_res.data.get("body", "") or "")[:4000]

        tags_res = github.tags(ref.repo, limit=5)
        if tags_res.not_modified:
            tags = list(prev.get("tags") or [])
        else:
            tags = [str(t.get("name", "")) for t in tags_res.data] if (
                tags_res.ok and isinstance(tags_res.data, list)
            ) else []

        tr.repos.append(
            {
                "repo": ref.repo,
                "role": ref.role,
                "branch": branch,
                "archived": archived,
                "empty": empty,
                "pushed_at": meta.get("pushed_at", ""),
                "head": head,
                "head_date": head_date,
                "head_message": head_message,
                "release": release_tag,
                "tags": tags,
                "observed_at": utcnow(),
            }
        )

        prev_head = str(prev.get("head", ""))
        if head and prev_head and head != prev_head:
            files: list[str] = []
            messages: list[str] = []
            compare_ok = False
            compare = github.compare(ref.repo, prev_head, head)
            if compare.ok and isinstance(compare.data, dict):
                compare_ok = True
                files = [str(f.get("filename", "")) for f in (compare.data.get("files") or [])]
                messages = [
                    str((c.get("commit") or {}).get("message", "")).splitlines()[0]
                    for c in (compare.data.get("commits") or [])
                ]
            relevant, sec_files, sec_msgs = assess_repo_change(files, messages)
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.REPO_HEAD,
                    component=ref.repo,
                    summary=(
                        f"HEAD moved {prev_head[:10]} -> {head[:10]}; "
                        f"{len(files)} file(s), {len(messages)} commit(s)"
                    ),
                    old=prev_head,
                    new=head,
                    evidence_urls=(f"https://github.com/{ref.repo}/compare/{prev_head}...{head}",),
                    security_relevant=relevant or not compare_ok,
                    detail={
                        "branch": branch,
                        "head_message": head_message,
                        "files": files[:200],
                        "messages": messages[:50],
                        "security_files": sec_files,
                        "security_messages": sec_msgs,
                        "compare_ok": compare_ok,
                        "deployment_evidence": False,
                        "note": "a commit is not a deployment",
                    },
                )
            )
        elif head and prev and not prev_head:
            # The repository was observed empty before; its first commit is new code.
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.REPO_HEAD,
                    component=ref.repo,
                    summary=f"repository gained its first commit {head[:10]}",
                    new=head,
                    evidence_urls=(f"https://github.com/{ref.repo}/commit/{head}",),
                    security_relevant=True,
                    detail={
                        "branch": branch,
                        "head_message": head_message,
                        "files": [],
                        "messages": [head_message] if head_message else [],
                        "compare_ok": False,
                        "deployment_evidence": False,
                        "note": "new repository content; a commit is not a deployment",
                    },
                )
            )

        prev_release = str(prev.get("release", ""))
        if release_tag and prev_release and release_tag != prev_release:
            relevant, _, sec_msgs = assess_repo_change([], [release_body])
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.REPO_RELEASE,
                    component=ref.repo,
                    summary=f"release {prev_release} -> {release_tag} ({release_name})",
                    old=prev_release,
                    new=release_tag,
                    evidence_urls=(f"https://github.com/{ref.repo}/releases/tag/{release_tag}",),
                    security_relevant=relevant,
                    detail={
                        "release_name": release_name,
                        "published_at": release_at,
                        "security_messages": sec_msgs,
                        "deployment_evidence": False,
                    },
                )
            )

        prev_tags = set(prev.get("tags") or [])
        new_tags = [t for t in tags if t and t not in prev_tags]
        if prev_tags and new_tags:
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.REPO_TAG,
                    component=ref.repo,
                    summary=f"new tag(s): {', '.join(new_tags[:5])}",
                    new=",".join(new_tags[:5]),
                    evidence_urls=(f"https://github.com/{ref.repo}/tags",),
                    security_relevant=False,
                    detail={"tags": new_tags[:10], "deployment_evidence": False},
                )
            )

        state.set_repo(
            target.slug,
            ref.repo,
            {
                "repo": ref.repo,
                "branch": branch,
                "archived": archived,
                "empty": empty,
                "pushed_at": meta.get("pushed_at", ""),
                "head": head,
                "head_date": head_date,
                "head_message": head_message,
                "release": release_tag,
                "release_name": release_name,
                "release_at": release_at,
                "tags": tags,
                "observed_at": utcnow(),
                "etag_repo": repo_res.etag or prev.get("etag_repo", ""),
                "etag_head": head_res.etag or prev.get("etag_head", ""),
                "etag_release": rel_res.etag or prev.get("etag_release", ""),
            },
        )


# --------------------------------------------------------------------------- #
# Contracts
# --------------------------------------------------------------------------- #

def _older_than(iso: object, *, days: int) -> bool:
    if not isinstance(iso, str) or not iso:
        return False
    try:
        then = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return True
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then) >= timedelta(days=days)


def _write_source_diff(
    out_dir: str, cycle_id: str, slug: str, key: str, diff: SourceDiff
) -> str:
    root = Path(out_dir) / "source-diffs"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{cycle_id or 'cycle'}-{slug}-{key}.diff"
    body = diff.unified or "(manifest-only delta: previous source text is unavailable)\n"
    path.write_text(body, encoding="utf-8")
    return str(path)


def _refresh_source(
    target: Target,
    ref: ContractRef,
    obs: ContractObservation,
    previous: dict,
    deployment_moved: bool,
    source: Optional[SourceClient],
    config: CycleConfig,
    cycle_id: str,
) -> tuple[dict, Optional[SourceDiff], str]:
    """Fetch verified source only when the deployment moved; diff it if so."""
    if source is None:
        return previous, None, ""
    address = (obs.implementation if obs.proxy and obs.implementation else ref.address).lower()
    previous_address = str(previous.get("address", "")).lower()
    # A contract Sourcify does not verify is retried weekly, not every hour; a
    # transient fetch error is retried on the next cycle.
    stale_gap = (
        previous.get("status") == "not_verified"
        and _older_than(previous.get("last_attempt_at"), days=7)
    )
    retry = previous.get("status") == "error" or stale_gap
    if previous and previous_address == address and not deployment_moved and not retry:
        return previous, None, ""

    chain_id = obs.chain_id or ref.chain_id
    bundle = source.fetch(chain_id, address)
    if not bundle.ok:
        return (
            {
                **previous,
                "address": address,
                "status": bundle.status,
                "error": bundle.error,
                "url": bundle.url,
                "last_attempt_at": utcnow(),
            },
            None,
            "",
        )

    delta: Optional[SourceDiff] = None
    diff_path = ""
    if previous.get("manifest") and (
        previous_address != address or previous.get("manifest") != bundle.manifest()
    ):
        old_bundle = source.fetch(chain_id, previous_address) if previous_address != address else None
        candidate = diff_bundles(
            old_bundle if old_bundle is not None and old_bundle.ok else None,
            bundle,
            old_manifest=previous.get("manifest") or {},
        )
        if not candidate.empty:
            delta = candidate
            if not config.dry_run:
                diff_path = _write_source_diff(
                    config.out_dir, cycle_id, target.slug, ref.key, candidate
                )
    record = bundle.record()
    record["last_attempt_at"] = utcnow()
    return record, delta, diff_path


def _check_contracts(
    target: Target,
    tr: TargetReport,
    state: WatchState,
    rpc: RpcClient,
    config: CycleConfig,
    source: Optional[SourceClient] = None,
    cycle_id: str = "",
) -> None:
    refs = target.contracts[: config.max_contracts] if config.max_contracts else target.contracts
    for ref in refs:
        obs = rpc.observe(ref)
        if not obs.ok:
            tr.contracts.append(obs.to_dict())
            error = f"contract {ref.key}: {obs.error or obs.error_kind}"
            tr.failures.append(error)
            state.record_failure(f"contract:{target.slug}:{ref.key}", error)
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.SOURCE_FAILED,
                    component=ref.key,
                    summary=f"contract unreadable: {obs.error or obs.error_kind}",
                    evidence_urls=(ref.provenance,) if ref.provenance else (),
                    detail={
                        "chain_id": ref.chain_id,
                        "address": ref.address,
                        "error_kind": obs.error_kind,
                    },
                )
            )
            continue
        state.clear_failure(f"contract:{target.slug}:{ref.key}")
        prev = state.contract(target.slug, ref.key)
        old_fp = str(prev.get("fingerprint", ""))
        old_impl = str(prev.get("implementation", ""))
        old_admin = str(prev.get("admin", ""))
        old_owner = str(prev.get("owner", ""))
        evidence = (ref.provenance,) if ref.provenance else ()

        source_record, source_diff, diff_path = _refresh_source(
            target,
            ref,
            obs,
            prev.get("source") or {},
            bool(old_fp) and obs.fingerprint != old_fp,
            source,
            config,
            cycle_id,
        )
        extra: dict = {}
        if source_diff is not None:
            delta = source_diff.to_dict()
            delta["diff_path"] = diff_path
            extra["source_diff"] = delta
        elif source_record.get("status") == "error" and not any(
            gap.startswith("verified source unavailable") for gap in tr.gaps
        ):
            tr.gaps.append(
                f"verified source unavailable for {ref.key}: "
                f"{source_record.get('error', '')[:160]}"
            )

        if old_fp and obs.fingerprint != old_fp:
            kind = Kind.CONTRACT_IMPL if (
                obs.proxy and old_impl and obs.implementation.lower() != old_impl.lower()
            ) else Kind.CONTRACT_CODE
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=kind,
                    component=ref.key,
                    summary=(
                        f"deployed {'implementation' if kind == Kind.CONTRACT_IMPL else 'bytecode'} "
                        f"changed for {ref.name}"
                    ),
                    old=old_fp,
                    new=obs.fingerprint,
                    evidence_urls=evidence,
                    security_relevant=True,
                    detail={
                        "chain_id": obs.chain_id,
                        "address": ref.address,
                        "block_number": obs.block_number,
                        "proxy": obs.proxy,
                        "implementation_old": old_impl,
                        "implementation_new": obs.implementation,
                        "deployment_evidence": True,
                        "note": "on-chain runtime fingerprint moved; this is a deployment change",
                        **extra,
                    },
                )
            )
        if old_impl and obs.implementation and obs.implementation.lower() != old_impl.lower() and old_fp == obs.fingerprint:
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.CONTRACT_IMPL,
                    component=ref.key,
                    summary=f"proxy implementation re-pointed for {ref.name}",
                    old=old_impl,
                    new=obs.implementation,
                    evidence_urls=evidence,
                    security_relevant=True,
                    detail={
                        "chain_id": obs.chain_id,
                        "address": ref.address,
                        "block_number": obs.block_number,
                        "deployment_evidence": True,
                        **extra,
                    },
                )
            )
        if old_admin and obs.admin and obs.admin.lower() != old_admin.lower():
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.CONTRACT_ADMIN,
                    component=ref.key,
                    summary=f"proxy admin changed for {ref.name}",
                    old=old_admin,
                    new=obs.admin,
                    evidence_urls=evidence,
                    security_relevant=True,
                    detail={
                        "chain_id": obs.chain_id,
                        "address": ref.address,
                        "block_number": obs.block_number,
                        "deployment_evidence": True,
                    },
                )
            )
        if old_owner and obs.owner and obs.owner.lower() != old_owner.lower():
            tr.events.append(
                make_event(
                    target=target.slug,
                    kind=Kind.CONTRACT_OWNER,
                    component=ref.key,
                    summary=f"owner() changed for {ref.name}",
                    old=old_owner,
                    new=obs.owner,
                    evidence_urls=evidence,
                    security_relevant=True,
                    detail={
                        "chain_id": obs.chain_id,
                        "address": ref.address,
                        "block_number": obs.block_number,
                        "deployment_evidence": True,
                    },
                )
            )

        observation = obs.to_dict()
        observation["source"] = source_record
        tr.contracts.append(observation)
        state.set_contract(target.slug, ref.key, observation)
