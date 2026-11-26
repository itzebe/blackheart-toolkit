"""Honest, human-reviewable reports for the bounty watchtower.

A cycle report answers four questions without decoration: what changed, whether
it is actually deployed, whether the program permits action, and what evidence
would be needed next. Every lead carries the mission's seventeen fields; a field
that could not be established says so instead of guessing.

Nothing here calls a lead a vulnerability. The strongest status is
``NEW ACTIONABLE CHANGE``, which means "a credible investigation opportunity
under a program that permits participation" -- still a hypothesis.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .classify import (
    CONTRACT_KINDS,
    Kind,
    Lead,
    SCORE_WEIGHTS,
    Status,
)
from .cycle import CycleReport

__all__ = [
    "render_cycle",
    "render_issue",
    "render_investigation",
    "render_status",
    "write_report",
    "lagos_time",
]

_LAGOS = timezone(timedelta(hours=1), name="Africa/Lagos")


def lagos_time(iso: str) -> str:
    """Render an ISO-8601 UTC timestamp in Africa/Lagos (UTC+1, no DST)."""
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_LAGOS).strftime("%Y-%m-%d %H:%M:%S") + " Africa/Lagos"


def _cell(value: object, limit: int = 120) -> str:
    text = str(value or "").replace("|", "\\|").replace("\n", " ")
    return text[:limit]


def render_status(report: CycleReport) -> str:
    c = report.counts()
    return (
        f"{report.cycle_id}: {c['targets']} targets, {c['events']} event(s), "
        f"{c['NEW ACTIONABLE CHANGE']} actionable, {c['INVESTIGATE']} investigate, "
        f"{c['POLICY BLOCKED']} policy-blocked, {c['SOURCE INACCESSIBLE']} inaccessible, "
        f"{c['NO CHANGE']} no-change, {c['deduped']} deduped"
    )


def render_cycle(report: CycleReport) -> str:
    c = report.counts()
    lines: list[str] = [
        f"# Bounty watch cycle {report.cycle_id}",
        "",
        f"- **Started (UTC):** {report.started_at}",
        f"- **Started (Africa/Lagos):** {lagos_time(report.started_at)}",
        f"- **Duration:** {report.duration_s:.1f}s",
        f"- **Targets monitored:** {c['targets']} (registry: {report.registry_count})",
        f"- **Exit code:** {report.exit_code} "
        "(0 = no change, 1 = change, 2 = source failure/incomplete)",
        "",
        "## Summary",
        "",
        "| status | count |",
        "| --- | ---: |",
    ]
    for status in (
        Status.NEW_ACTIONABLE_CHANGE,
        Status.INVESTIGATE,
        Status.WATCH,
        Status.POLICY_BLOCKED,
        Status.KNOWN_DUPLICATE,
        Status.SOURCE_INACCESSIBLE,
        Status.NO_CHANGE,
    ):
        lines.append(f"| {status} | {c.get(status, 0)} |")
    lines += [
        f"| events | {c['events']} |",
        f"| deduplicated repeats | {c['deduped']} |",
        f"| source failures | {c['failures']} |",
        "",
    ]
    if report.warnings:
        lines += ["## State warnings", ""]
        lines += [f"- {w}" for w in report.warnings]
        lines.append("")

    actionable = [l for l in report.leads if l.status in (Status.NEW_ACTIONABLE_CHANGE, Status.INVESTIGATE)]
    blocked = [l for l in report.leads if l.status == Status.POLICY_BLOCKED]
    known = [l for l in report.leads if l.status == Status.KNOWN_DUPLICATE]
    failed = [l for l in report.leads if l.status == Status.SOURCE_INACCESSIBLE]
    watch = [l for l in report.leads if l.status == Status.WATCH]

    if actionable:
        lines += ["## Recommended leads", ""]
        for lead in actionable:
            lines.append(_lead_summary(lead))
            lines.append("")
    if blocked:
        lines += ["## Credible leads blocked by participation policy", ""]
        lines.append(
            "These are security-relevant changes, but the program's participation "
            "gates are not satisfied. They are **not** actionable and must not be "
            "tested or submitted until the operator records authorization."
        )
        lines.append("")
        for lead in blocked:
            lines.append(_lead_summary(lead))
            lines.append("")
    if known:
        lines += ["## Known / duplicate (suppressed)", ""]
        for lead in known:
            ki = lead.known_issue
            lines.append(
                f"- `{lead.target.slug}` / `{lead.event.component}`: "
                f"{lead.event.summary} — matched **{ki.id if ki else '?'}** "
                f"({ki.status if ki else '?'}); not reported."
            )
        lines.append("")
    if failed:
        lines += ["## Source failures (gaps, not clean results)", ""]
        for lead in failed:
            lines.append(
                f"- `{lead.target.slug}` / `{lead.event.component}`: {lead.event.summary}"
            )
        lines.append("")
    if watch:
        lines += ["## Watch (relevant, not yet a credible path)", ""]
        for lead in watch:
            lines.append(
                f"- `{lead.target.slug}` / `{lead.event.component}`: "
                f"{lead.event.summary} (score {lead.score}/100)"
            )
        lines.append("")

    lines += ["## Per-target status", ""]
    lines += [
        "| target | group | program | policy | repos | contracts | events | status |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for tr in report.targets:
        t = tr.target
        statuses = sorted({l.status for l in tr.leads}) or [Status.NO_CHANGE]
        lines.append(
            f"| `{t.slug}` | {t.group} | {t.program_status} | {len(tr.policy)} | "
            f"{len(tr.repos)} | {len(tr.contracts)} | {len(tr.events)} | "
            f"{_cell(', '.join(statuses), 60)} |"
        )
    lines.append("")

    lines += ["## Target records", ""]
    for tr in report.targets:
        t = tr.target
        lines.append(f"### {t.name} (`{t.slug}`)")
        lines.append("")
        lines.append(f"- Group: {t.group}; value class: {t.value_class}; program: **{t.program_status}**")
        if t.focus:
            lines.append(f"- Focus: {', '.join(t.focus)}")
        if t.policy_urls:
            lines.append("- Official policy:")
            for p in t.policy_urls:
                lines.append(f"  - [{p.kind}] {p.url}")
        if t.repos:
            lines.append("- Repositories: " + ", ".join(f"`{r.repo}`" for r in t.repos))
        if t.contracts:
            lines.append(
                "- Contracts: "
                + ", ".join(f"`{c.key}` ({c.chain_id})" for c in t.contracts)
            )
        if t.restrictions:
            lines.append("- Restrictions: " + "; ".join(t.restrictions))
        if t.eligibility.notes:
            lines.append("- Eligibility notes: " + "; ".join(t.eligibility.notes))
        if tr.gaps:
            lines.append("- Gaps: " + "; ".join(tr.gaps))
        if tr.failures:
            lines.append("- Failures: " + "; ".join(tr.failures))
        lines.append("")

    lines += [
        "## Honesty notes",
        "",
        "- A repository commit, tag or release is **not** deployment evidence. Only the "
        "on-chain runtime fingerprint establishes that deployed code changed.",
        "- A detected change is a **lead**, not a vulnerability. No finding is confirmed "
        "by this report; confirmation requires a reproduction and independent review.",
        "- A source failure is a **gap**. It is never reported as \"no change\".",
        "- Participation gates are recorded per program; no target is authorized for "
        "testing or submission unless its registry record says so explicitly.",
        "",
    ]
    return "\n".join(lines)


def _lead_summary(lead: Lead) -> str:
    ev = lead.event
    return (
        f"- **{lead.status}** — `{lead.target.slug}` / `{ev.component}` "
        f"(score **{lead.score}/100**): {ev.summary}"
        + (f" — blocked: {lead.block_reason}" if lead.policy_blocked else "")
    )


def render_issue(report: CycleReport) -> str:
    """A concise GitHub-issue body: only what a human must look at now."""
    c = report.counts()
    lines = [
        f"Bounty watch cycle `{report.cycle_id}` ({lagos_time(report.started_at)}).",
        "",
        f"Targets: {c['targets']} · events: {c['events']} · actionable: "
        f"{c['NEW ACTIONABLE CHANGE']} · investigate: {c['INVESTIGATE']} · "
        f"policy-blocked: {c['POLICY BLOCKED']} · inaccessible: {c['SOURCE INACCESSIBLE']} · "
        f"deduped: {c['deduped']}.",
        "",
    ]
    interesting = [
        l for l in report.leads
        if l.status in (Status.NEW_ACTIONABLE_CHANGE, Status.INVESTIGATE, Status.POLICY_BLOCKED)
    ]
    if interesting:
        lines += ["| target | component | status | score | change |", "| --- | --- | --- | ---: | --- |"]
        for lead in interesting:
            lines.append(
                f"| `{lead.target.slug}` | `{_cell(lead.event.component, 50)}` | "
                f"{lead.status} | {lead.score} | {_cell(lead.event.summary, 140)} |"
            )
        lines.append("")
    failures = report.failures
    if failures:
        lines += ["**Source failures (gaps):**", ""]
        for slug, failure in failures[:30]:
            lines.append(f"- `{slug}`: {_cell(failure, 220)}")
        lines.append("")
    lines += [
        "Full report: `research/bounty-monitor/reports/` in the repository (workflow artifact).",
        "",
        "_Posted automatically by the bounty-watch workflow (an AI agent, OpenHands). "
        "A change is a lead, not a confirmed vulnerability._",
    ]
    return "\n".join(lines)


def render_investigation(lead: Lead) -> str:
    """The mission's seventeen-field investigation record for one lead."""
    ev, t = lead.event, lead.target
    deployed = bool(ev.detail.get("deployment_evidence"))
    files = ev.detail.get("files") or []
    messages = ev.detail.get("messages") or []
    delta = ev.detail.get("source_diff") or {}
    lines = [
        f"# Investigation lead: {t.name} / {ev.component}",
        "",
        f"**Status:** {lead.status}  ",
        f"**Score:** {lead.score}/100  ",
        f"**Detected:** {ev.detected_at} (UTC) / {lagos_time(ev.detected_at)}  ",
        f"**Event id:** `{ev.id}`",
        "",
        "## 1. Target and bounty program",
        f"- Target: **{t.name}** (`{t.slug}`), group {t.group}, value class {t.value_class}.",
        f"- Program status: **{t.program_status}**; platforms: {', '.join(t.platforms) or 'not recorded'}.",
        "",
        "## 2. Date and time discovered",
        f"- {ev.detected_at} UTC ({lagos_time(ev.detected_at)}).",
        "",
        "## 3. Official source links",
    ]
    sources = list(ev.evidence_urls) + [p.url for p in t.policy_urls]
    for key in ("url_old", "url_new"):
        if delta.get(key):
            sources.append(delta[key])
    if sources:
        lines += [f"- {u}" for u in dict.fromkeys(sources)]
    else:
        lines.append("- Not established: no official source URL is recorded for this component.")
    lines += [
        "",
        "## 4. Exact changed contract, repository or component",
        f"- Component: `{ev.component}`.",
        f"- Change kind: `{ev.kind}`.",
        "",
        "## 5. Previous and current versions or addresses",
        f"- Previous: `{ev.old or 'not recorded'}`",
        f"- Current: `{ev.new or 'not recorded'}`",
    ]
    if ev.detail.get("implementation_old") or ev.detail.get("implementation_new"):
        lines.append(
            f"- Implementation: `{ev.detail.get('implementation_old') or '-'}` -> "
            f"`{ev.detail.get('implementation_new') or '-'}`"
        )
    lines += [
        "",
        "## 6. Exact code or deployment delta",
    ]
    if delta:
        lines.append(
            f"- **Verified source delta** (Sourcify): `{delta.get('address_old') or 'previous'}` "
            f"-> `{delta.get('address_new')}`"
        )
        for label, key in (
            ("modified", "files_modified"),
            ("added", "files_added"),
            ("removed", "files_removed"),
        ):
            paths = delta.get(key) or []
            if paths:
                lines.append(f"- {len(paths)} {label} file(s):")
                lines += [f"  - `{p}`" for p in paths[:40]]
        if delta.get("sensitive_functions"):
            lines.append(
                "- Security-sensitive changed functions: "
                + ", ".join(f"`{n}`" for n in delta["sensitive_functions"][:20])
            )
        elif delta.get("functions"):
            lines.append(
                "- Changed functions: "
                + ", ".join(f"`{n}`" for n in delta["functions"][:20])
            )
        if delta.get("external_calls"):
            lines.append("- Added external-call lines (review, not a finding):")
            lines += [f"  - `{s}`" for s in delta["external_calls"][:8]]
        if delta.get("diff_path"):
            lines.append(f"- Full diff archived at `{delta['diff_path']}`"
                         + (" (truncated)" if delta.get("truncated") else ""))
    elif files:
        lines.append(f"- {len(files)} changed file(s) in the compare API:")
        lines += [f"  - `{f}`" for f in files[:40]]
    elif messages:
        lines.append("- Commit messages:")
        lines += [f"  - {m}" for m in messages[:20]]
    elif ev.kind == Kind.POLICY_CHANGED:
        lines.append("- Policy text diff:")
        lines += [f"  - {line}" for line in (ev.detail.get("changed_lines") or [])[:20]]
    elif ev.kind in CONTRACT_KINDS:
        lines.append(
            "- On-chain runtime fingerprint moved; verified source for the old or new "
            "implementation is not published (Sourcify), so no source diff is claimed."
        )
    else:
        lines.append("- Not established from the observed record.")
    lines += [
        "",
        "## 7. Whether the change is actually deployed",
        (
            "- **Yes — on-chain evidence.** The runtime fingerprint was read from the "
            f"chain at block {ev.detail.get('block_number', 'unknown')}."
            if deployed
            else "- **No deployment evidence.** A repository or policy change does not prove "
            "a production deployment. Verify the deployed bytecode separately."
        ),
        "",
        "## 8. Relevant security invariant",
        f"- {_invariant(ev.kind)}",
        "",
        "## 9. Plausible attacker capability and attack sequence",
        "- Capability: an ordinary unprivileged external actor. No role, key, trusted-peer "
        "position, or privileged transaction is assumed.",
        "- Sequence (hypothesis only, not established):",
        "  1. Fetch the new deployed source or diff the changed commit.",
        "  2. Identify the changed security-sensitive function and its callers.",
        "  3. Check authorization, signature/replay, accounting and external-call assumptions.",
        "  4. Reproduce on a local mainnet fork with a guarded control.",
        "  5. Prove value movement or a bypass; otherwise discard the lead.",
        "",
        "## 10. Potential impact",
        "- Unknown until reproduced. Candidate classes only: unauthorized value movement, "
        "bypassed restriction, or another user's position absorbing a loss. Do not assign a "
        "severity before a reproduction.",
        "",
        "## 11. Official scope eligibility",
        f"- Program status: {t.program_status}. Submission permitted by the recorded gates: "
        f"**{'yes' if t.submission_permitted else 'no'}**.",
    ]
    if not t.submission_permitted:
        lines.append(f"- Blocking gates: {lead.block_reason or 'not established'}.")
    lines += [
        "",
        "## 12. AI-agent participation restrictions",
        f"- Recorded value: **{t.eligibility.ai_agent_allowed}**. This is a registry fact, "
        "not an inference from policy prose; a policy change that appears to permit agents "
        "must be reviewed by the operator before it is recorded.",
    ]
    review = ev.detail.get("ai_agent_review") or {}
    if review.get("detected"):
        lines.append(
            f"- Policy text mentions AI agents or automation "
            f"(prohibited-language signal: **{review.get('prohibited_language')}**). "
            "Manual review is required before any participation."
        )
        for snippet in (review.get("snippets") or [])[:3]:
            lines.append(f"  - \"{snippet[:240]}\"")
    lines += [
        "",
        "## 13. Nigeria eligibility and payout restrictions",
        f"- Recorded Nigeria eligibility: **{t.eligibility.nigeria_eligible}**; "
        f"KYC required: **{t.eligibility.kyc_required}**. If either is unknown, it is not "
        "safe to assume a payout is available.",
        "",
        "## 14. Known-issue and duplicate checks",
    ]
    if lead.known_issue:
        ki = lead.known_issue
        lines.append(f"- Matched **{ki.id}** ({ki.status}): {ki.summary}. Suppressed.")
    elif t.known_issues:
        lines += [
            f"- {k.id} ({k.status}): {k.summary}" for k in t.known_issues
        ]
        lines.append("- No exclusion keyword matched this event; a public-search novelty check "
                     "is still required before any submission.")
    else:
        lines.append("- No known-issue exclusion is recorded for this target. A public-search "
                     "novelty check is still required before any submission.")
    lines += [
        "",
        "## 15. Safe validation strategy",
        "- Local fork or local harness only. No mainnet transaction, no user funds, no DoS, "
        "no production testing, no program contact. Stop if the test would reach an "
        "out-of-scope system.",
        "",
        "## 16. Evidence required for a reproducible PoC",
        "- Fork block number and chain id.",
        "- Before/after deployed bytecode fingerprint and the fetched verified source.",
        "- A failing test that moves value or bypasses the restriction, plus a guarded "
        "control that does not.",
        "- Exact value delta and the attacker's starting position (unprivileged).",
        "- Independent verification by a reviewer who did not write the PoC.",
        "",
        "## 17. Research priority and estimated effort",
        f"- Score: **{lead.score}/100** (threshold for active investigation: 80).",
        f"- Estimated effort: {_effort(ev.kind)}.",
        "",
        "### Score breakdown",
        "",
        "| component | score | max |",
        "| --- | ---: | ---: |",
    ]
    for name, maximum in SCORE_WEIGHTS.items():
        lines.append(f"| {name} | {lead.components.get(name, 0)} | {maximum} |")
    lines += ["", "### Rationale", ""]
    lines += [f"- {r}" for r in lead.rationale]
    lines += [
        "",
        "---",
        "",
        "_This is a lead, not a confirmed vulnerability. No submission or program contact "
        "is authorized by this record._",
        "",
    ]
    return "\n".join(lines)


def _invariant(kind: str) -> str:
    if kind in (Kind.CONTRACT_IMPL, Kind.CONTRACT_CODE):
        return (
            "The deployed implementation must preserve the audited authorization, "
            "accounting, withdrawal and signature invariants. A post-audit bytecode change "
            "invalidates the audit's assumptions until the delta is reviewed."
        )
    if kind == Kind.CONTRACT_ADMIN:
        return "Only the intended governance address may hold proxy admin authority."
    if kind == Kind.CONTRACT_OWNER:
        return "Only the intended governance address may hold owner authority."
    if kind == Kind.REPO_HEAD:
        return (
            "Code merged to the default branch must not introduce an unauthorized value path; "
            "the commit must still be shown to be deployed before it matters on-chain."
        )
    if kind in (Kind.REPO_RELEASE, Kind.REPO_TAG):
        return "A release or tag must not silently change a security-relevant default."
    if kind == Kind.POLICY_CHANGED:
        return "Scope, exclusions, severity and participation rules must be re-read before action."
    return "Not established."


def _effort(kind: str) -> str:
    if kind in CONTRACT_KINDS:
        return "low-to-medium (fetch source, diff one contract, fork-test one path)"
    if kind in (Kind.REPO_HEAD, Kind.REPO_RELEASE):
        return "medium (diff the commit, confirm deployment, fork-test the changed path)"
    return "low (policy review; no code path yet)"


def write_report(report: CycleReport, out_dir: str | Path) -> dict[str, str]:
    """Write the cycle markdown, machine JSON and index. Returns the paths."""
    root = Path(out_dir)
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    md_path = reports / f"{report.cycle_id}.md"
    json_path = reports / f"{report.cycle_id}.json"
    md_path.write_text(render_cycle(report), encoding="utf-8")
    json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / "latest.md").write_text(render_cycle(report), encoding="utf-8")

    # One detailed record per interesting lead, so a reviewer can act without
    # re-running the cycle.
    leads_dir = root / "investigation-leads"
    for lead in report.leads:
        if lead.status in (
            Status.NEW_ACTIONABLE_CHANGE,
            Status.INVESTIGATE,
            Status.POLICY_BLOCKED,
        ):
            name = f"{report.cycle_id}-{lead.target.slug}-{lead.event.id[:8]}.md"
            (leads_dir).mkdir(parents=True, exist_ok=True)
            (leads_dir / name).write_text(render_investigation(lead), encoding="utf-8")

    index = reports / "INDEX.md"
    header = "# Bounty watch reports\n\n| cycle (UTC) | targets | events | actionable | investigate | blocked | inaccessible | report |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n"
    if not index.is_file():
        index.write_text(header, encoding="utf-8")
    c = report.counts()
    row = (
        f"| {report.cycle_id} | {c['targets']} | {c['events']} | "
        f"{c['NEW ACTIONABLE CHANGE']} | {c['INVESTIGATE']} | {c['POLICY BLOCKED']} | "
        f"{c['SOURCE INACCESSIBLE']} | [{report.cycle_id}.md]({report.cycle_id}.md) |\n"
    )
    with index.open("a", encoding="utf-8") as fh:
        fh.write(row)
    return {"markdown": str(md_path), "json": str(json_path), "index": str(index)}
