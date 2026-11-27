"""Cross-engine orchestration: real coordination, not three reports concatenated.

This module turns a set of engine executions into a single BLACKHEART judgement.
It performs, in order:

  1. **Ingestion + normalisation** -- every engine's raw records become
     :class:`~blackheart.engines.schema.NormalizedFinding` candidates, keeping
     provenance.
  2. **Deduplication** -- candidates that share a root-cause fingerprint collapse
     into one cluster, whether they came from the same engine twice or from two
     different engines.
  3. **Corroboration** -- a cluster found by more than one engine is marked
     corroborated. This *raises confidence*, it does **not** confirm: two AI
     engines agreeing is not proof (see the class docstring of
     :class:`FindingCluster`).
  4. **Contradiction detection** -- when one engine reports a defect and another
     explicitly failed to reproduce it, the disagreement is preserved and the
     cluster is flagged for independent verification rather than resolved by
     majority.
  5. **Attack-chain correlation** -- clusters are linked only when evidence
     establishes that one weakness enables the next (an authorization bypass that
     precedes a privilege escalation on the same component). Proximity alone
     never creates a chain.
  6. **Historical / prior-art check** -- a fingerprint already in the engagement
     ledger is marked ``DUPLICATE_OR_KNOWN``.

The output is an :class:`OrchestrationResult`. Nothing here can move a finding to
``CONFIRMED``: that requires BLACKHEART's own verification gate (``blackheart.verify``)
and a named reviewer, exactly as for a native finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..models import Classification, sha256_of, utcnow
from ..toolchain.enforce import ExecutionTarget, guarded
from .contract import EngineAdapter, EngineState, ExecutionResult
from .schema import NormalizedFinding, SEVERITY_ORDER

#: Attack-chain edges: (enabling category) -> (enabled category). A chain is only
#: proposed when the first weakness plausibly *enables* the second, by category.
_CHAIN_EDGES = [
    ("authentication", "authorization"),
    ("authorization", "privilege_escalation"),
    ("authorization", "idor"),
    ("idor", "data_exposure"),
    ("ssrf", "credential_access"),
    ("injection", "rce"),
    ("injection", "data_exposure"),
    ("privilege_escalation", "sensitive_state_manipulation"),
    ("access_control", "privilege_escalation"),
    ("reentrancy", "accounting_error"),
    ("oracle_manipulation", "price_manipulation"),
    ("price_manipulation", "insolvency"),
    ("flash_loan", "price_manipulation"),
]

#: Words that indicate an engine could not reproduce what it (or another) claims.
_CONTRADICTION_MARKERS = (
    "false_positive", "not reproduced", "failed_to_reproduce", "cannot reproduce",
    "unreproducible", "no exploit", "not exploitable", "invalid", "rejected",
)


#: Fuzzer categories that name the same class of defect. A property falsified
#: by Echidna and the same property falsified by Medusa are one defect seen by
#: two engines, so they must corroborate rather than count twice.
_DEFECT_CLASS_ALIASES = {
    "sequence-violation": "property-violation",
    "assertion-violation": "property-violation",
}


def _location_identity(location: str) -> str:
    """The location, keeping its line number.

    ``schema._normalize_location`` drops line numbers, which is right for the exact
    fingerprint but wrong here: two reentrancy bugs on different lines of one
    file are two defects, and merging them would hide one. A range collapses to
    its first line so ``Vault.sol:35-40`` and ``Vault.sol:35`` are one site.
    """
    if not location:
        return ""
    text = location.strip().lower()
    text = re.sub(r":\s*(\d+)\s*[-\u2013]\s*\d+", r":\1", text)
    return text.strip()


def _defect_class(finding: NormalizedFinding) -> str:
    category = (finding.category or "").strip().lower()
    return _DEFECT_CLASS_ALIASES.get(category, category)


def _structural_key(finding: NormalizedFinding) -> str:
    """The identity of a defect, independent of how an engine words it.

    Two findings collide here only when they name the same *defect*: the same
    target, the same component, the same source location, and the same class of
    weakness. Location alone is not enough -- one line can carry an unchecked
    transfer and a reentrancy, which are different bugs -- and class alone is not
    enough either, since one class recurs across many locations.

    A property fuzzer reports no location; its identity is the falsified
    property, which the title carries. Returns "" when neither a location nor a
    property name is available, so an unidentified observation is never merged
    into an unrelated one.
    """
    defect_class = _defect_class(finding)
    if not defect_class:
        return ""
    location = _location_identity(finding.source_location)
    if location:
        identity = location
    else:
        # "falsified property: NAME (2 call(s))" -> "name". Engines decorate the
        # property name with their own counters, so only the identifier is kept.
        title = (finding.title or "").strip()
        _, sep, name = title.partition(":")
        name = name.split("(")[0].strip().lower() if sep else ""
        identity = name if re.fullmatch(r"[a-z_][a-z0-9_]*", name or "") else ""
    if not identity:
        return ""
    return "|".join((finding.target_id.strip().lower(),
                     finding.component.strip().lower(),
                     defect_class, identity))


def _canonical_category(text: str) -> str:
    t = (text or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "authn": "authentication", "auth": "authentication",
        "authz": "authorization", "access_control": "authorization",
        "privesc": "privilege_escalation", "priv_esc": "privilege_escalation",
        "sqli": "injection", "sql_injection": "injection", "nosql": "injection",
        "command_injection": "injection", "ssti": "injection", "xxe": "injection",
        "xss": "xss", "csrf": "csrf",
        "info_disclosure": "data_exposure", "information_disclosure": "data_exposure",
    }
    return aliases.get(t, t)


@dataclass
class FindingCluster:
    """One defect, possibly reported by several engines.

    ``disposition`` is BLACKHEART's verdict. Corroboration and severity raise the
    *confidence* of the cluster but never set ``CONFIRMED`` on their own: only the
    independent verification gate does that.
    """

    fingerprint: str
    cluster_id: str
    representative: NormalizedFinding
    members: list[NormalizedFinding] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    corroborated: bool = False
    contradiction: bool = False
    contradiction_detail: str = ""
    known_prior_art: bool = False
    chain_ids: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return min((m.severity for m in self.members),
                   key=lambda s: SEVERITY_ORDER.get(s, 5), default="info")

    @property
    def disposition(self) -> str:
        if self.known_prior_art:
            return Classification.DUPLICATE_OR_KNOWN.value
        if self.contradiction:
            # Unresolved disagreement -> more evidence, never a silent confirmation.
            return Classification.NEEDS_MORE_EVIDENCE.value
        if any(m.disposition == Classification.CONFIRMED.value for m in self.members):
            return Classification.CONFIRMED.value
        return Classification.NEEDS_MORE_EVIDENCE.value

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "fingerprint": self.fingerprint,
            "sources": list(self.sources),
            "corroborated": self.corroborated,
            "contradiction": self.contradiction,
            "contradiction_detail": self.contradiction_detail,
            "known_prior_art": self.known_prior_art,
            "chain_ids": list(self.chain_ids),
            "severity": self.severity,
            "disposition": self.disposition,
            "attacker_lens": self.attacker_lens(),
            "member_ids": [m.finding_id for m in self.members],
            "representative": self.representative.to_dict(),
        }

    def attacker_lens(self) -> dict:
        """Frame this cluster against the canonical attacker question.

        Names the outcome the defect produces and the attacker-controlled levers
        it exercises, so every engine finding is read through the same lens as a
        native one. A cluster that names no lever is reported with that gap.
        """
        from ..mindset import apply_lens

        r = self.representative
        app = apply_lens(r.category, texts=(r.description, r.impact, r.title))
        return {"outcome": app.outcome, "levers": list(app.levers), "gaps": list(app.gaps)}


@dataclass
class AttackChain:
    """A sequence of clusters where evidence links one weakness to the next."""

    chain_id: str
    steps: list[str]            # cluster ids, in order
    edges: list[tuple[str, str]]
    rationale: str

    def to_dict(self) -> dict:
        return {"chain_id": self.chain_id, "steps": list(self.steps),
                "edges": [list(e) for e in self.edges], "rationale": self.rationale}


@dataclass
class EngineRunSummary:
    engine: str
    state: str
    version: str = ""
    findings: int = 0
    detail: str = ""
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        return {"engine": self.engine, "state": self.state, "version": self.version,
                "findings": self.findings, "detail": self.detail,
                "metadata": self.metadata}


@dataclass
class OrchestrationResult:
    target: str
    engines: list[EngineRunSummary] = field(default_factory=list)
    candidates: list[NormalizedFinding] = field(default_factory=list)
    clusters: list[FindingCluster] = field(default_factory=list)
    chains: list[AttackChain] = field(default_factory=list)
    missing_engines: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> list[FindingCluster]:
        return [c for c in self.clusters if c.disposition == Classification.CONFIRMED.value]

    @property
    def pending(self) -> list[FindingCluster]:
        return [c for c in self.clusters
                if c.disposition == Classification.NEEDS_MORE_EVIDENCE.value]

    @property
    def duplicates(self) -> list[FindingCluster]:
        return [c for c in self.clusters
                if c.disposition == Classification.DUPLICATE_OR_KNOWN.value]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "engines": [e.to_dict() for e in self.engines],
            "missing_engines": list(self.missing_engines),
            "candidate_count": len(self.candidates),
            "clusters": [c.to_dict() for c in self.clusters],
            "chains": [c.to_dict() for c in self.chains],
            "notes": list(self.notes),
        }


class EngineOrchestrator:
    """Drive a set of engine adapters and coordinate their findings.

    The orchestrator owns *coordination*; it does not own authorization. It is
    designed to be called only after BLACKHEART's authorization gate has admitted
    the target (the CLI enforces this); it never contacts an engine for a target
    that has not passed the gate.
    """

    def __init__(self, workspace: str | Path, adapters: list[EngineAdapter] | None = None,
                 *, ledger_fingerprints: Optional[set[str]] = None):
        self.workspace = Path(workspace)
        self.adapters = adapters or []
        self.ledger_fingerprints = set(ledger_fingerprints or set())

    # -- run --------------------------------------------------------------- #
    def run(self, target: str, *, engine_options: Optional[dict] = None,
            cancel_event: Any = None,
            compatibility: object = None) -> OrchestrationResult:
        """Dispatch every adapter at ``target``, behind the compatibility gate.

        The gate is checked once here, for the whole dispatch, and again inside
        every adapter's ``execute_scan``, so a target that is not covered by a
        validated record never reaches an engine process.
        """
        with guarded(compatibility, ExecutionTarget(name=str(target)),
                     "Orchestrator.run"):
            return self._run(target, engine_options=engine_options,
                             cancel_event=cancel_event)

    def _run(self, target: str, *, engine_options: Optional[dict] = None,
             cancel_event: Any = None) -> OrchestrationResult:
        engine_options = engine_options or {}
        result = OrchestrationResult(target=target)
        for adapter in self.adapters:
            options = dict(engine_options.get(adapter.name, {}))
            if cancel_event is not None:
                options.setdefault("cancel_event", cancel_event)
            summary, findings = self._run_one(adapter, target, options, result)
            result.engines.append(summary)
            result.candidates.extend(findings)
        result.finished_at = utcnow()
        self._coordinate(result)
        return result

    def _run_one(self, adapter: EngineAdapter, target: str, options: dict,
                 result: OrchestrationResult) -> tuple[EngineRunSummary, list[NormalizedFinding]]:
        try:
            health = adapter.verify_health()
        except Exception as e:  # noqa: BLE001 - an adapter bug must not crash the run
            return EngineRunSummary(adapter.name, EngineState.FAILED.value,
                                    detail=f"health check raised {type(e).__name__}"), []
        if health.state in (EngineState.MISSING, EngineState.UNSUPPORTED):
            result.missing_engines.append(adapter.name)
            return EngineRunSummary(adapter.name, health.state.value, health.version,
                                    detail=health.detail), []
        if health.state == EngineState.CONFIGURATION_ERROR:
            result.notes.append(f"{adapter.name}: {health.detail}")
            return EngineRunSummary(adapter.name, health.state.value, health.version,
                                    detail=health.detail), []
        try:
            execution: ExecutionResult = adapter.execute_scan(target, **options)
        except Exception as e:  # noqa: BLE001
            return EngineRunSummary(adapter.name, EngineState.FAILED.value, health.version,
                                    detail=f"execution raised {type(e).__name__}: {e}"), []
        try:
            findings = adapter.normalize_findings(execution)
        except Exception as e:  # noqa: BLE001
            result.notes.append(f"{adapter.name}: normalization raised {type(e).__name__}")
            findings = []
        # Re-stamp the target id so a finding is always bound to the requested target.
        for f in findings:
            if not f.target_id:
                f.target_id = target
        summary = EngineRunSummary(
            adapter.name, execution.state.value, execution.metadata.version,
            findings=len(findings), detail=execution.metadata.note,
            metadata=execution.to_dict()["metadata"],
        )
        if execution.state in (EngineState.FAILED, EngineState.PARTIAL, EngineState.CANCELLED):
            result.notes.append(f"{adapter.name}: {execution.state.value} ({execution.metadata.note})")
        return summary, findings

    # -- coordination ------------------------------------------------------ #
    def _coordinate(self, result: OrchestrationResult) -> None:
        # SECURITY: an engine's self-declared disposition is untrusted. Reset every
        # ingested candidate to the honest "not yet proven" value before clustering,
        # preserving the engine's claim under `raw` for provenance. This is the
        # enforcement point that stops an engine from confirming its own finding.
        for finding in result.candidates:
            claim = finding.disposition
            if claim and claim != Classification.NEEDS_MORE_EVIDENCE.value:
                finding.raw.setdefault("engine_disposition_claim", claim)
            finding.disposition = Classification.NEEDS_MORE_EVIDENCE.value

        clusters: dict[str, FindingCluster] = {}
        # Two engines rarely word the same defect identically, and the exact
        # fingerprint includes the description text, so a wording difference
        # would split one defect into two "independent" discoveries. This index
        # merges on the *structural* identity -- target, component, location and
        # defect class -- which is the same bug regardless of prose. Severity,
        # CWE and the engine are deliberately not part of it: a High and a Medium
        # report of the same site are one defect, and `cluster.severity` keeps
        # the worst.
        structural: dict[str, str] = {}
        for finding in result.candidates:
            key = finding.fingerprint or finding.finalize().fingerprint
            shape = _structural_key(finding)
            existing = clusters.get(key) or (
                clusters.get(structural[shape]) if shape in structural else None)
            if existing is None:
                cluster = FindingCluster(
                    fingerprint=key,
                    cluster_id="CL-" + key[:10].upper(),
                    representative=finding,
                    members=[finding],
                    sources=[finding.source_engine],
                )
                clusters[key] = cluster
                if shape:
                    structural[shape] = key
                continue
            existing.members.append(finding)
            if finding.source_engine not in existing.sources:
                existing.sources.append(finding.source_engine)
            # Record the merge so a duplicate is visible, not silently absorbed.
            if finding.fingerprint and finding.fingerprint != existing.fingerprint:
                finding.duplicate_of = existing.representative.finding_id
            if shape:
                structural.setdefault(shape, existing.fingerprint)
        result.clusters = list(clusters.values())

        for cluster in result.clusters:
            self._mark_corroboration(cluster)
            self._detect_contradiction(cluster)
            self._check_prior_art(cluster)
        self._correlate_chains(result)

    @staticmethod
    def _mark_corroboration(cluster: FindingCluster) -> None:
        # Corroboration = the same root cause independently reported by >1 engine.
        cluster.corroborated = len(set(cluster.sources)) > 1

    @staticmethod
    def _detect_contradiction(cluster: FindingCluster) -> None:
        """Flag a cluster when one member claims a defect and another denies it.

        The disagreement is preserved (never resolved by majority); a contradiction
        forces the cluster to NEEDS_MORE_EVIDENCE regardless of how many engines
        agree.
        """
        claimed = [m for m in cluster.members if not _denies(m)]
        denied = [m for m in cluster.members if _denies(m)]
        if claimed and denied:
            cluster.contradiction = True
            denier = denied[0]
            cluster.contradiction_detail = (
                f"{denier.source_engine} did not reproduce the defect that "
                f"{', '.join(sorted({m.source_engine for m in claimed}))} reported"
            )

    def _check_prior_art(self, cluster: FindingCluster) -> None:
        if cluster.fingerprint in self.ledger_fingerprints:
            cluster.known_prior_art = True

    @staticmethod
    def _correlate_chains(result: OrchestrationResult) -> None:
        """Link clusters only when a category edge establishes enablement.

        Two clusters form an edge only when their canonical categories match a
        known enabling relationship *and* they share a component or target. This
        avoids inventing chains from mere co-occurrence.
        """
        by_component: dict[str, list[FindingCluster]] = {}
        for c in result.clusters:
            comp = (c.representative.component or c.representative.target_id or "").strip().lower()
            by_component.setdefault(comp, []).append(c)
        chains: list[AttackChain] = []
        seen: set[tuple[str, str]] = set()
        for comp, group in by_component.items():
            if len(group) < 2:
                continue
            cats = {_canonical_category(c.representative.category): c for c in group}
            for enabler_cat, enabled_cat in _CHAIN_EDGES:
                a = cats.get(enabler_cat)
                b = cats.get(enabled_cat)
                if a is None or b is None or a.cluster_id == b.cluster_id:
                    continue
                key = (a.cluster_id, b.cluster_id)
                if key in seen:
                    continue
                seen.add(key)
                chain_id = "CH-" + sha256_of({"c": comp, "a": a.cluster_id, "b": b.cluster_id})[:8].upper()
                a.chain_ids.append(chain_id)
                b.chain_ids.append(chain_id)
                chains.append(AttackChain(
                    chain_id=chain_id,
                    steps=[a.cluster_id, b.cluster_id],
                    edges=[(enabler_cat, enabled_cat)],
                    rationale=(f"on component {comp or a.representative.target_id!r}: "
                               f"{enabler_cat} enables {enabled_cat}"),
                ))
        result.chains = chains


def _denies(finding: NormalizedFinding) -> bool:
    """True when a finding explicitly denies exploitability/reproduction."""
    status = (finding.reproduction_status or "").lower()
    disposition = (finding.disposition or "").lower()
    text = f"{status} {disposition} {finding.confidence}".lower()
    return any(marker in text for marker in _CONTRADICTION_MARKERS)
