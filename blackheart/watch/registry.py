"""The watchlist registry: one independent record per bounty target.

Every target is monitored separately. Scope, eligibility, participation
permission and known-issue exclusions are never shared between programs, because
combining them is how a researcher ends up testing something they were never
authorized to test.

The registry is data (``targets.json`` next to this module), loaded into frozen
dataclasses so a caller cannot mutate a target mid-cycle. A fact that was not
verified is stored as ``"unknown"`` -- never as a guess. In particular
``Eligibility.submission_permitted`` is false unless *all* of the following are
explicitly true:

  * the program is active,
  * the program permits AI-agent participation,
  * the operator authorized participation, and
  * the operator permits participating through the program's platform.

The last two are operator decisions, not facts about the program, and they
default to false. Monitoring is always allowed; testing and submission are not.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "GROUPS",
    "PROGRAM_STATUSES",
    "KNOWN_ISSUE_STATUSES",
    "PolicyRef",
    "RepoRef",
    "ContractRef",
    "KnownIssue",
    "Eligibility",
    "Target",
    "RegistryError",
    "load_registry",
    "validate_targets",
    "write_target_records",
]

GROUPS = ("A", "B", "C", "D")

#: What the official program is currently doing. ``UNVERIFIED`` means no official
#: program page could be confirmed; it is not "inactive" and not "active".
PROGRAM_STATUSES = (
    "ACTIVE",
    "CLOSED",
    "TESTNET_ONLY",
    "AUDIT_COMPETITION",
    "UNVERIFIED",
    "NO_PUBLIC_PROGRAM_FOUND",
)

KNOWN_ISSUE_STATUSES = (
    "PUBLIC_FIXED",
    "EXCLUDED",
    "PREVIOUSLY_REPORTED",
    "PREVIOUSLY_INVESTIGATED",
    "FALSE_POSITIVE",
)

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class RegistryError(ValueError):
    """The registry is not fit to run."""


@dataclass(frozen=True)
class PolicyRef:
    """One official page that states a program's rules or scope."""

    url: str
    kind: str = "program"  # program | scope | security-policy | advisory | platform
    official: bool = True
    note: str = ""


@dataclass(frozen=True)
class RepoRef:
    """A repository whose commits may ship in-scope code."""

    repo: str
    role: str = ""
    provenance: str = ""


@dataclass(frozen=True)
class ContractRef:
    """A deployed contract to fingerprint. ``provenance`` names the official page."""

    key: str
    chain_id: int
    address: str
    name: str
    proxy: bool = False
    provenance: str = ""


@dataclass(frozen=True)
class KnownIssue:
    """A previously disclosed, excluded, fixed or already-investigated issue.

    ``keywords`` are matched case-insensitively against an event's summary and
    changed paths. ``monitor=True`` keeps watching the area (for a remediation or
    a materially new change) without ever re-reporting the known issue itself.
    """

    id: str
    summary: str
    status: str
    keywords: tuple[str, ...] = ()
    do_not_report: bool = True
    monitor: bool = False
    evidence: str = ""


@dataclass(frozen=True)
class Eligibility:
    """Program-level participation facts and operator decisions.

    ``ai_agent_allowed``, ``nigeria_eligible`` and ``kyc_required`` are
    ``"true"``/``"false"``/``"unknown"`` strings, never booleans, so "not checked"
    cannot be confused with "not allowed".
    """

    ai_agent_allowed: str = "unknown"
    participation_authorized: bool = False
    platform_participation_allowed: bool = False
    nigeria_eligible: str = "unknown"
    kyc_required: str = "unknown"
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "ai_agent_allowed": self.ai_agent_allowed,
            "participation_authorized": self.participation_authorized,
            "platform_participation_allowed": self.platform_participation_allowed,
            "nigeria_eligible": self.nigeria_eligible,
            "kyc_required": self.kyc_required,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class Target:
    """One bounty program and everything known about monitoring it."""

    slug: str
    name: str
    group: str
    program_status: str
    platforms: tuple[str, ...] = ()
    policy_urls: tuple[PolicyRef, ...] = ()
    repos: tuple[RepoRef, ...] = ()
    contracts: tuple[ContractRef, ...] = ()
    eligibility: Eligibility = field(default_factory=Eligibility)
    restrictions: tuple[str, ...] = ()
    known_issues: tuple[KnownIssue, ...] = ()
    focus: tuple[str, ...] = ()
    value_class: str = "medium"  # high | medium | low
    notes: str = ""

    @property
    def submission_permitted(self) -> bool:
        """True only when every participation gate is explicitly satisfied."""
        return (
            self.program_status == "ACTIVE"
            and self.eligibility.ai_agent_allowed == "true"
            and self.eligibility.participation_authorized
            and self.eligibility.platform_participation_allowed
        )

    @property
    def research_only(self) -> bool:
        """Monitoring/research is fine; testing or submitting is not."""
        return not self.submission_permitted

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "name": self.name,
            "group": self.group,
            "program_status": self.program_status,
            "platforms": list(self.platforms),
            "policy_urls": [
                {"url": p.url, "kind": p.kind, "official": p.official, "note": p.note}
                for p in self.policy_urls
            ],
            "repos": [
                {"repo": r.repo, "role": r.role, "provenance": r.provenance}
                for r in self.repos
            ],
            "contracts": [
                {
                    "key": c.key,
                    "chain_id": c.chain_id,
                    "address": c.address,
                    "name": c.name,
                    "proxy": c.proxy,
                    "provenance": c.provenance,
                }
                for c in self.contracts
            ],
            "eligibility": self.eligibility.to_dict(),
            "restrictions": list(self.restrictions),
            "known_issues": [
                {
                    "id": k.id,
                    "summary": k.summary,
                    "status": k.status,
                    "keywords": list(k.keywords),
                    "do_not_report": k.do_not_report,
                    "monitor": k.monitor,
                    "evidence": k.evidence,
                }
                for k in self.known_issues
            ],
            "focus": list(self.focus),
            "value_class": self.value_class,
            "notes": self.notes,
            "submission_permitted": self.submission_permitted,
        }


def _tup(value: Any) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def target_from_dict(data: dict) -> Target:
    """Build a :class:`Target` from one JSON record, rejecting malformed facts."""
    elig = data.get("eligibility") or {}
    return Target(
        slug=str(data["slug"]),
        name=str(data["name"]),
        group=str(data.get("group", "")),
        program_status=str(data.get("program_status", "UNVERIFIED")),
        platforms=tuple(str(x) for x in _tup(data.get("platforms"))),
        policy_urls=tuple(
            PolicyRef(
                url=str(p["url"]),
                kind=str(p.get("kind", "program")),
                official=bool(p.get("official", True)),
                note=str(p.get("note", "")),
            )
            for p in _tup(data.get("policy_urls"))
        ),
        repos=tuple(
            RepoRef(
                repo=str(r["repo"]),
                role=str(r.get("role", "")),
                provenance=str(r.get("provenance", "")),
            )
            for r in _tup(data.get("repos"))
        ),
        contracts=tuple(
            ContractRef(
                key=str(c["key"]),
                chain_id=int(c["chain_id"]),
                address=str(c["address"]),
                name=str(c.get("name", c["key"])),
                proxy=bool(c.get("proxy", False)),
                provenance=str(c.get("provenance", "")),
            )
            for c in _tup(data.get("contracts"))
        ),
        eligibility=Eligibility(
            ai_agent_allowed=str(elig.get("ai_agent_allowed", "unknown")),
            participation_authorized=bool(elig.get("participation_authorized", False)),
            platform_participation_allowed=bool(
                elig.get("platform_participation_allowed", False)
            ),
            nigeria_eligible=str(elig.get("nigeria_eligible", "unknown")),
            kyc_required=str(elig.get("kyc_required", "unknown")),
            notes=tuple(str(x) for x in _tup(elig.get("notes"))),
        ),
        restrictions=tuple(str(x) for x in _tup(data.get("restrictions"))),
        known_issues=tuple(
            KnownIssue(
                id=str(k["id"]),
                summary=str(k.get("summary", "")),
                status=str(k.get("status", "")),
                keywords=tuple(str(x) for x in _tup(k.get("keywords"))),
                do_not_report=bool(k.get("do_not_report", True)),
                monitor=bool(k.get("monitor", False)),
                evidence=str(k.get("evidence", "")),
            )
            for k in _tup(data.get("known_issues"))
        ),
        focus=tuple(str(x) for x in _tup(data.get("focus"))),
        value_class=str(data.get("value_class", "medium")),
        notes=str(data.get("notes", "")),
    )


def validate_targets(targets: tuple[Target, ...]) -> list[str]:
    """Return a list of problems. An empty list means the registry is runnable."""
    problems: list[str] = []
    seen_slugs: set[str] = set()
    seen_contracts: set[tuple[int, str]] = set()
    for t in targets:
        if not _SLUG_RE.match(t.slug):
            problems.append(f"{t.slug!r}: slug must be lowercase [a-z0-9-]")
        if t.slug in seen_slugs:
            problems.append(f"duplicate target slug: {t.slug}")
        seen_slugs.add(t.slug)
        if t.group not in GROUPS:
            problems.append(f"{t.slug}: unknown group {t.group!r}")
        if t.program_status not in PROGRAM_STATUSES:
            problems.append(f"{t.slug}: unknown program_status {t.program_status!r}")
        if t.value_class not in ("high", "medium", "low"):
            problems.append(f"{t.slug}: unknown value_class {t.value_class!r}")
        for p in t.policy_urls:
            if not p.url.startswith("https://"):
                problems.append(f"{t.slug}: policy URL is not https: {p.url}")
        for r in t.repos:
            if not _REPO_RE.match(r.repo):
                problems.append(f"{t.slug}: bad repo {r.repo!r} (owner/name)")
        for c in t.contracts:
            if not _ADDRESS_RE.match(c.address):
                problems.append(f"{t.slug}/{c.key}: bad address {c.address!r}")
            ident = (c.chain_id, c.address.lower())
            if ident in seen_contracts:
                problems.append(f"{t.slug}/{c.key}: duplicate contract {c.address}")
            seen_contracts.add(ident)
            if c.provenance and not c.provenance.startswith("https://"):
                problems.append(f"{t.slug}/{c.key}: provenance is not https")
        for k in t.known_issues:
            if k.status not in KNOWN_ISSUE_STATUSES:
                problems.append(f"{t.slug}/{k.id}: unknown known-issue status {k.status!r}")
        if t.eligibility.ai_agent_allowed not in ("true", "false", "unknown"):
            problems.append(
                f"{t.slug}: ai_agent_allowed must be true/false/unknown"
            )
    return problems


def load_registry(path: Optional[str | Path] = None) -> tuple[Target, ...]:
    """Load and validate ``targets.json``. Raises :class:`RegistryError` on drift."""
    p = Path(path) if path is not None else Path(__file__).with_name("targets.json")
    if not p.is_file():
        raise RegistryError(f"registry not found: {p}")
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RegistryError(f"registry unreadable: {exc}") from exc
    records = raw.get("targets") if isinstance(raw, dict) else raw
    if not isinstance(records, list) or not records:
        raise RegistryError("registry has no targets")
    try:
        targets = tuple(target_from_dict(d) for d in records)
    except (KeyError, TypeError, ValueError) as exc:
        raise RegistryError(f"registry record malformed: {exc}") from exc
    problems = validate_targets(targets)
    if problems:
        raise RegistryError("registry invalid:\n  " + "\n  ".join(problems))
    return targets


def write_target_records(
    targets: tuple[Target, ...], directory: str | Path
) -> dict[str, str]:
    """Write one independent JSON record per target plus an index.

    Returns ``{relative path: slug}``. The per-target files are the durable,
    reviewable form of the watchlist; no two programs share a record.
    """
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    index: list[dict] = []
    for t in targets:
        rel = f"{t.group}/{t.slug}.json"
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(t.to_dict(), indent=2) + "\n", encoding="utf-8")
        written[rel] = t.slug
        index.append(
            {
                "slug": t.slug,
                "name": t.name,
                "group": t.group,
                "program_status": t.program_status,
                "submission_permitted": t.submission_permitted,
                "policy_urls": len(t.policy_urls),
                "repos": len(t.repos),
                "contracts": len(t.contracts),
                "record": rel,
            }
        )
    (out / "index.json").write_text(
        json.dumps({"count": len(targets), "targets": index}, indent=2) + "\n",
        encoding="utf-8",
    )
    written["index.json"] = "(index)"
    return written
