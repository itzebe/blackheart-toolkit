"""P3 -- Investigation workflow engine.

P2 turns a validated threat model into ranked, falsifiable hypotheses. P3 is the
lifecycle that takes one hypothesis and drives it to an evidence-backed verdict,
refusing to skip steps:

    HYPOTHESIS -> TRIAGE -> SOURCE ANALYSIS -> TEST DESIGN
              -> REPRODUCTION -> INDEPENDENT CHALLENGE -> VERDICT

Every transition has explicit **entry criteria** (what must already be true) and
**evidence requirements** (what the transition itself must produce). A transition
that does not meet its criteria is refused -- the engine fails closed, exactly as
the authorization and verification gates do.

The properties the mission requires, enforced in code:

  * **Persistent and resumable.** State is an append-only JSONL log; the current
    investigation is rebuilt by replay, so an interrupted investigation resumes
    with nothing lost -- including after the sandbox that started it is gone.
  * **Authorization before execution.** No test runs until the authorization gate
    classifies the asset AUTHORIZED against a live record. An out-of-scope or
    unverifiable asset cannot enter REPRODUCTION at all.
  * **Independent challenge before confirmation.** A verdict may not be CONFIRMED
    unless an independent challenge has actually reproduced the result. The
    engine refuses to confirm otherwise (mirrors ``ResearchRecord.promote``).
  * **Honest outcome classification.** Malformed-input rejection, self-DoS,
    environmental failure, false positive, out-of-scope, and a genuine violation
    are distinct outcomes with distinct memory statuses; an environmental failure
    is INCOMPLETE (retryable), never "disproven".
  * **Negative results are kept.** A rejected or disproven hypothesis, with its
    reason, is a first-class result -- it stops the next cycle re-deriving a dead
    end.

The engine orchestrates; it does not itself decide whether a bug is real. The
independent verifier (``blackheart.verify``) and the novelty gate
(``blackheart.novelty``) remain the authorities, and this module calls them
rather than reimplementing them.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional, Protocol

from ..authz import authorize_active_testing
from ..exploit.toolselect import select_tools
from ..integrity import (
    GENESIS,
    Checkpoint,
    IntegrityKey,
    VerificationResult,
    chain_hash,
    content_hash,
    record_mac,
    verify_chain,
)
from ..models import (
    AuthorizationRecord,
    InvestigationStatus,
    ResearchRecord,
    utcnow,
)
from ..research import ResearchMemory
from ..hypothesis.generation import GeneratedHypothesis


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #

class Stage:
    HYPOTHESIS = "HYPOTHESIS"
    TRIAGE = "TRIAGE"
    SOURCE_ANALYSIS = "SOURCE_ANALYSIS"
    TEST_DESIGN = "TEST_DESIGN"
    REPRODUCTION = "REPRODUCTION"
    INDEPENDENT_CHALLENGE = "INDEPENDENT_CHALLENGE"
    VERDICT = "VERDICT"


STAGE_ORDER = [
    Stage.HYPOTHESIS,
    Stage.TRIAGE,
    Stage.SOURCE_ANALYSIS,
    Stage.TEST_DESIGN,
    Stage.REPRODUCTION,
    Stage.INDEPENDENT_CHALLENGE,
    Stage.VERDICT,
]

# Terminal investigation statuses. A terminal investigation is not advanced
# further; a non-terminal one (TRIAGE/DEFER, INCOMPLETE) can be resumed.
TERMINAL = frozenset({"CONFIRMED", "DISPROVEN", "REJECTED_TRIAGE", "ABANDONED"})


class Triage:
    PURSUE = "PURSUE"
    DEFER = "DEFER"
    REJECT = "REJECT"


class Outcome:
    """How an investigation ended, kept deliberately distinct.

    The mission insists these are not conflated: a target that *rejects* malformed
    input is behaving correctly (not a bug); a self-DoS harms only the attacker;
    an environmental failure is not a statement about the target at all.
    """

    GENUINE_VIOLATION = "GENUINE_VIOLATION"
    MALFORMED_INPUT_REJECTED = "MALFORMED_INPUT_REJECTED"
    SELF_DOS = "SELF_DOS"
    ENVIRONMENTAL_FAILURE = "ENVIRONMENTAL_FAILURE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    INCONCLUSIVE = "INCONCLUSIVE"


# Outcome -> persistent memory status. The mapping is the honesty guarantee:
# only a genuine, independently-verified violation can be CONFIRMED.
_OUTCOME_TO_STATUS = {
    Outcome.GENUINE_VIOLATION: InvestigationStatus.CONFIRMED.value,
    Outcome.MALFORMED_INPUT_REJECTED: InvestigationStatus.DISPROVEN.value,
    Outcome.SELF_DOS: InvestigationStatus.DISPROVEN.value,
    Outcome.FALSE_POSITIVE: InvestigationStatus.DISPROVEN.value,
    Outcome.OUT_OF_SCOPE: InvestigationStatus.DISPROVEN.value,
    Outcome.ENVIRONMENTAL_FAILURE: InvestigationStatus.INCOMPLETE.value,
    Outcome.INCONCLUSIVE: InvestigationStatus.INCOMPLETE.value,
}


class InvalidTransition(RuntimeError):
    """Raised when a transition is not allowed, or its entry criteria are unmet."""


class AuthorizationRequired(RuntimeError):
    """Raised when a step needs active testing but the asset is not authorized."""


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

@dataclass
class SourceArtifact:
    """One piece of source evidence gathered during SOURCE ANALYSIS."""

    path: str
    function: str = ""
    code_path: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TestPlan:
    """A reproducible plan to test the hypothesis.

    ``command`` is the exact command to run; ``expected`` and ``falsify`` are the
    observable results that would, respectively, demonstrate and refute the
    hypothesis. A plan with no command is not a plan.
    """

    method: str                      # foundry | echidna | medusa | halmos | slither | dvdf | ...
    command: str
    expected: str = ""
    falsify: str = ""
    tools: list[str] = field(default_factory=list)
    secure_control: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# The name starts with "Test", which pytest would otherwise try to collect as a
# test class; it is a data record, not a test suite.
TestPlan.__test__ = False


@dataclass
class RunOutput:
    command: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class CommandRunner(Protocol):
    """Anything that can run a shell command and capture its output."""

    def run(self, command: str, *, cwd: str = "", timeout: int = 600) -> RunOutput: ...


class SubprocessRunner:
    """The default runner: a real subprocess with captured output."""

    def run(self, command: str, *, cwd: str = "", timeout: int = 600) -> RunOutput:
        try:
            proc = subprocess.run(
                command, shell=True, cwd=cwd or None, capture_output=True,
                text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return RunOutput(command, -1, exc.stdout or "", exc.stderr or "", timed_out=True)
        return RunOutput(command, proc.returncode, proc.stdout or "", proc.stderr or "")


@dataclass
class InvestigationState:
    """The replayed state of one investigation."""

    investigation_id: str
    hypothesis_id: str
    target: str
    asset: str
    stage: str = Stage.HYPOTHESIS
    status: str = "OPEN"             # OPEN | <terminal> | INCOMPLETE
    scope_reference: str = ""
    hypothesis: dict = field(default_factory=dict)
    triage_decision: str = ""
    triage_reason: str = ""
    sources: list[SourceArtifact] = field(default_factory=list)
    test_plan: dict = field(default_factory=dict)
    reproduction: dict = field(default_factory=dict)
    challenge: dict = field(default_factory=dict)
    verdict: dict = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def is_terminal(self) -> bool:
        return self.status in TERMINAL

    def next_stage(self) -> Optional[str]:
        idx = STAGE_ORDER.index(self.stage)
        return STAGE_ORDER[idx + 1] if idx + 1 < len(STAGE_ORDER) else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = [s.to_dict() if isinstance(s, SourceArtifact) else s for s in self.sources]
        return d


# --------------------------------------------------------------------------- #
# Persistent store
# --------------------------------------------------------------------------- #

class InvestigationStore:
    """Append-only, replayable store of investigation events.

    Persisted states are *hash-chained*: each carries its sequence number, the
    previous record's chain hash, its own content hash, and its chain hash, plus
    an HMAC-SHA256 signature when a signing key is configured. The chain is what
    makes deletion, reordering, insertion, and truncation detectable -- a bare
    per-record hash (the earlier design) detects only a careless edit.

    The key is supplied by the caller and never stored in the log; without one the
    log is still hash-chained (tamper-*evident* against an attacker who edits but
    does not recompute the chain) and ``verify_integrity`` reports the signature
    layer as unavailable rather than silently passing it. See
    ``blackheart.integrity`` and ``docs/INTEGRITY.md``.
    """

    def __init__(
        self, root: str | os.PathLike, name: str = "investigations",
        *, key: Optional[IntegrityKey] = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{name}.jsonl"
        self.key = key

    def _append(self, event: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": utcnow(), **event}, default=str) + "\n")

    def _events(self) -> list[dict]:
        if not self.path.exists():
            return []
        events: list[dict] = []
        skipped = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                # A process killed mid-write can leave a truncated final line. Skip
                # it rather than losing the whole log, but count it so the loss is
                # reported by ``corruption_report`` instead of hidden.
                skipped += 1
        self._last_skipped = skipped
        return events

    def corruption_report(self) -> dict:
        """Report how many log lines could not be parsed (crash-truncated log)."""
        self._events()
        return {"skipped_lines": getattr(self, "_last_skipped", 0),
                "ok": getattr(self, "_last_skipped", 0) == 0}

    def verify_integrity(
        self, *, key: Optional[IntegrityKey] = None,
        require_signatures: bool = False,
        checkpoint: Optional[Checkpoint] = None,
    ) -> dict:
        """Verify the whole hash chain and report the honest outcome.

        Returns a dict whose ``status`` is one of VERIFIED / FAILED / LEGACY /
        UNAVAILABLE and whose ``ok`` is true only for VERIFIED. Detection is
        additive: replay (``all``/``get``) still returns the (now suspect) state,
        so resumption is never blocked by a failed check -- but a caller that
        trusts a *security verdict* must consult this result first.
        """
        result = verify_chain(self.path, key=key or self.key,
                              require_signatures=require_signatures,
                              checkpoint=checkpoint)
        return result.to_dict()

    def head(self) -> tuple[int, str]:
        """Return the current ``(head_seq, head_chain)`` for a checkpoint."""
        seq, prev = self._head()
        return seq - 1, prev

    def save_state(self, state: InvestigationState) -> None:
        """Append a state snapshot, hash-chained to the previous one.

        The record carries ``seq`` (position), ``prev`` (previous chain hash),
        ``content_sha256``, ``chain_sha256`` (commits to position + prev +
        content), and ``hmac`` (HMAC-SHA256 over the same tuple) when a signing
        key is configured. The chain is what lets ``verify_integrity`` detect a
        deleted, reordered, inserted, or truncated record -- a bare per-record
        hash beside its payload cannot.
        """
        payload = state.to_dict()
        seq, prev = self._head()
        ch = content_hash(payload)
        chain = chain_hash(seq, prev, ch)
        event = {
            "type": "state", "id": state.investigation_id, "content": payload,
            "seq": seq, "prev": prev, "content_sha256": ch, "chain_sha256": chain,
        }
        if self.key is not None:
            event["hmac"] = record_mac(self.key, seq, prev, ch)
            event["key_id"] = self.key.key_id
        self._append(event)

    def _head(self) -> tuple[int, str]:
        """Return ``(next_seq, prev_chain_hash)`` for the next state record."""
        seq = 0
        prev = GENESIS
        for ev in self._events():
            if ev.get("type") == "state" and ev.get("content"):
                prev = ev.get("chain_sha256") or chain_hash(
                    ev.get("seq", seq), prev, content_hash(ev["content"])
                )
                seq = ev.get("seq", seq) + 1
        return seq, prev

    def append_history(self, investigation_id: str, line: str) -> None:
        self._append({"type": "history", "id": investigation_id, "line": line})

    def all(self) -> list[InvestigationState]:
        """Replay into the current state of every investigation."""
        state: dict[str, InvestigationState] = {}
        for ev in self._events():
            if ev.get("type") == "state" and ev.get("content"):
                st = self._from_dict(ev["content"])
                state[st.investigation_id] = st
            elif ev.get("type") == "history" and ev.get("id") in state:
                state[ev["id"]].history.append(ev["line"])
        return list(state.values())

    def get(self, investigation_id: str) -> Optional[InvestigationState]:
        return next((s for s in self.all() if s.investigation_id == investigation_id), None)

    def open(self) -> list[InvestigationState]:
        return [s for s in self.all() if not s.is_terminal()]

    @staticmethod
    def _from_dict(d: dict) -> InvestigationState:
        known = {f for f in InvestigationState.__dataclass_fields__}
        data = {k: v for k, v in d.items() if k in known}
        data["sources"] = [SourceArtifact(**s) for s in d.get("sources", [])]
        return InvestigationState(**data)


# --------------------------------------------------------------------------- #
# Outcome classification
# --------------------------------------------------------------------------- #

@dataclass
class Observation:
    """The facts an investigator established, to be classified honestly."""

    reproduced: bool = False
    impact_demonstrated: bool = False
    in_scope: bool = True
    # The distinguishing signals.
    malformed_input_rejected: bool = False   # target correctly refused bad input
    self_harm_only: bool = False             # only the attacker can be harmed
    environmental_error: bool = False        # tool/infra failed; not the target
    control_reproduces: bool = False         # the secure control also "reproduces"
    benign_explanation: bool = False         # a non-security account of the result
    note: str = ""


def classify_outcome(obs: Observation) -> str:
    """Map an observation to exactly one outcome, with a documented precedence.

    Order matters and is deliberate: an environmental failure or a correct
    rejection of malformed input must never be mistaken for a genuine violation,
    so those are checked before the positive path.
    """
    if obs.environmental_error:
        return Outcome.ENVIRONMENTAL_FAILURE
    if obs.malformed_input_rejected:
        return Outcome.MALFORMED_INPUT_REJECTED
    if obs.self_harm_only:
        return Outcome.SELF_DOS
    if obs.control_reproduces or obs.benign_explanation:
        return Outcome.FALSE_POSITIVE
    if not obs.in_scope:
        return Outcome.OUT_OF_SCOPE
    if obs.reproduced and obs.impact_demonstrated:
        return Outcome.GENUINE_VIOLATION
    return Outcome.INCONCLUSIVE


def _integrity_blocks_confirmation(integrity: dict) -> tuple[bool, str]:
    """Decide whether a log-integrity result forbids recording CONFIRMED.

    Only ``VERIFIED`` is trustworthy enough to carry a CONFIRMED verdict. The
    other three states are each blocking, and are reported distinctly so the
    reason is honest:

      * ``FAILED``      -- a concrete check failed (edit, deletion, bad HMAC).
      * ``UNAVAILABLE`` -- verification could not run. ``docs/INTEGRITY.md``
        states plainly that this must never be treated as success, so a
        deployment that demands signatures but holds no key must not confirm.
      * ``LEGACY``      -- records predate integrity protection. A verdict in an
        unstamped log cannot be shown to be untampered.
    """
    status = integrity.get("status", "")
    if status == "FAILED":
        return True, ("not confirmed: the investigation log failed integrity "
                      "verification (" + "; ".join(integrity.get("reasons", [])) + ")")
    if status == "UNAVAILABLE":
        return True, ("not confirmed: the investigation log could not be integrity-"
                      "verified (" + (integrity.get("unavailable_reason")
                                      or "verification unavailable") + ")")
    if status == "LEGACY":
        return True, ("not confirmed: the investigation log contains legacy records "
                      "that predate integrity protection, so tampering cannot be "
                      "excluded (" + "; ".join(integrity.get("unstamped", [])) + ")")
    return False, ""


# --------------------------------------------------------------------------- #
# Test-plan construction from the tool selector
# --------------------------------------------------------------------------- #

def plan_from_tools(
    hypothesis: GeneratedHypothesis, *, tools_available: Optional[set[str]] = None,
) -> TestPlan:
    """Build a TestPlan from the class-aware tool selector for a hypothesis.

    The plan names the tools the class needs and a concrete command for the
    engine method it selects. It is a *plan*, not a run: nothing executes here.
    """
    plan = select_tools(hypothesis.category, available=tools_available)
    method = plan.engine_methods[0] if plan.engine_methods else "forge"
    command = _command_for(method, hypothesis)
    return TestPlan(
        method=method,
        command=command,
        expected=hypothesis.reproduction_criteria,
        falsify=hypothesis.falsification_criteria,
        tools=plan.primary,
        secure_control=plan.control,
    )


def _command_for(method: str, hyp: GeneratedHypothesis) -> str:
    """A reproducible command skeleton for an engine method.

    These are the exact engine invocations the module supports; a caller with a
    project harness substitutes the concrete test path. The command is stated so
    a reviewer can run it, not so it always succeeds unedited.
    """
    slug = hyp.component.replace(" ", "") or "Target"
    if method == "stateful-fuzz":
        return f"python3 -m blackheart fuzz --target <target>   # invariant {hyp.invariant_id or hyp.invariant}"
    if method == "fork-harness":
        return "python3 -m blackheart fork run --target <target>"
    if method == "differential-pair":
        return "python3 -m blackheart differential --target <target>"
    if method == "malformed-input":
        return f"forge test --match-contract {slug}Malformed -vv"
    if method == "memory-safety":
        return f"forge test --match-contract {slug}Memory -vv   # under ASAN"
    if method == "workflow-reachability":
        return "python3 -m blackheart gha-analyze --repo <owner/repo>"
    return f"forge test --match-contract {slug} -vv"


# --------------------------------------------------------------------------- #
# The engine
# --------------------------------------------------------------------------- #

class InvestigationEngine:
    """Drive one hypothesis through the lifecycle, persistently and safely.

    ``authorization`` is the dated record proving the asset is testable; without
    it (or when it does not classify the asset AUTHORIZED) the engine refuses to
    enter REPRODUCTION. ``runner`` executes reproduction commands; it is
    injectable so a caller can supply a project-specific harness.
    """

    def __init__(
        self,
        store: InvestigationStore,
        *,
        authorization: Optional[AuthorizationRecord] = None,
        memory: Optional[ResearchMemory] = None,
        evidence=None,
        runner: Optional[CommandRunner] = None,
        novelty_gate=None,
        verify: Optional[Callable[[InvestigationState], tuple[bool, str]]] = None,
        cwd: str = "",
        require_signatures: bool = False,
    ) -> None:
        self.store = store
        self.authorization = authorization
        self.memory = memory
        self.evidence = evidence
        self.runner = runner or SubprocessRunner()
        self.novelty_gate = novelty_gate
        self.verify = verify
        self.cwd = cwd
        # When true, a CONFIRMED verdict additionally requires that the log's
        # HMAC chain verifies. Off by default so a keyless deployment still works,
        # but a deployment that holds a signing key should turn it on.
        self.require_signatures = require_signatures

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(
        self, hypothesis: GeneratedHypothesis, *, scope_reference: str = "",
        investigation_id: str = "",
    ) -> InvestigationState:
        """Create an investigation for a complete hypothesis.

        A hypothesis missing required fields cannot start an investigation: the
        mission forbids generating executable research tasks from an incomplete
        model, and the same discipline applies to an incomplete hypothesis.
        """
        gaps = hypothesis.missing_fields()
        if gaps:
            raise InvalidTransition(
                "cannot start an investigation from an incomplete hypothesis; "
                "missing: " + ", ".join(gaps)
            )
        iid = investigation_id or f"INV-{hypothesis.hyp_id}"
        existing = self.store.get(iid)
        if existing is not None:
            return existing
        state = InvestigationState(
            investigation_id=iid,
            hypothesis_id=hypothesis.hyp_id,
            target=hypothesis.hyp_id.split(":")[0] if ":" in hypothesis.hyp_id else "",
            asset=hypothesis.critical_asset,
            stage=Stage.HYPOTHESIS,
            status="OPEN",
            scope_reference=scope_reference,
            hypothesis=hypothesis.to_dict(),
        )
        state.history.append(f"created at {state.created_at}")
        self.store.save_state(state)
        return state

    def resume(self, investigation_id: str) -> InvestigationState:
        """Load an investigation from the store (resume after interruption)."""
        state = self.store.get(investigation_id)
        if state is None:
            raise InvalidTransition(f"no investigation {investigation_id!r} in the store")
        return state

    # ------------------------------------------------------------------ #
    # Entry criteria
    # ------------------------------------------------------------------ #
    def entry_criteria(self, state: InvestigationState, stage: str) -> list[str]:
        """Return the unmet entry criteria for advancing *into* ``stage``.

        An empty list means the transition is allowed. Each message names the
        concrete missing artefact, so a refusal is actionable.
        """
        gaps: list[str] = []
        if stage == Stage.TRIAGE:
            if not state.hypothesis:
                gaps.append("no hypothesis recorded")
        elif stage == Stage.SOURCE_ANALYSIS:
            if state.triage_decision != Triage.PURSUE:
                gaps.append(
                    "triage decision is not PURSUE "
                    f"(is {state.triage_decision or 'unset'})"
                )
        elif stage == Stage.TEST_DESIGN:
            if not state.sources:
                gaps.append("no source artefacts recorded (SOURCE ANALYSIS produced nothing)")
        elif stage == Stage.REPRODUCTION:
            if not state.test_plan.get("command"):
                gaps.append("no test plan with a runnable command")
            allowed, reason = self._authorization_ok(state)
            if not allowed:
                gaps.append(reason)
        elif stage == Stage.INDEPENDENT_CHALLENGE:
            if not state.reproduction.get("ran"):
                gaps.append("reproduction has not been run")
            elif not state.reproduction.get("evidence_id"):
                gaps.append("reproduction has no evidence reference")
        elif stage == Stage.VERDICT:
            if not state.challenge.get("ran"):
                gaps.append("independent challenge has not been recorded")
        return gaps

    def _authorization_ok(self, state: InvestigationState) -> tuple[bool, str]:
        if self.authorization is None:
            return False, (
                "no authorization record supplied; active testing is refused "
                "(provide a dated AuthorizationRecord for this asset)"
            )
        decision = authorize_active_testing(self.authorization, state.asset)
        if not decision.allowed:
            return False, "authorization gate blocked: " + "; ".join(decision.blockers)
        return True, ""

    # ------------------------------------------------------------------ #
    # Transitions
    # ------------------------------------------------------------------ #
    def _advance(self, state: InvestigationState, stage: str) -> InvestigationState:
        if state.is_terminal():
            raise InvalidTransition(
                f"investigation {state.investigation_id} is terminal ({state.status})"
            )
        expected = state.next_stage()
        if stage != expected:
            raise InvalidTransition(
                f"illegal transition {state.stage} -> {stage}; the next allowed stage "
                f"is {expected}"
            )
        gaps = self.entry_criteria(state, stage)
        if gaps:
            raise InvalidTransition(
                f"entry criteria unmet for {stage}: " + "; ".join(gaps)
            )
        state.stage = stage
        state.updated_at = utcnow()
        state.history.append(f"-> {stage} at {state.updated_at}")
        self.store.save_state(state)
        return state

    def triage(
        self, state: InvestigationState, decision: str, *, reason: str = "",
    ) -> InvestigationState:
        """Record the triage decision and advance to SOURCE ANALYSIS (or reject)."""
        # Validate *before* any state mutation: a refused transition must leave the
        # investigation exactly as it was, so a corrected retry is possible.
        if decision not in (Triage.PURSUE, Triage.DEFER, Triage.REJECT):
            raise InvalidTransition(f"unknown triage decision {decision!r}")
        if decision == Triage.REJECT and not reason.strip():
            raise InvalidTransition("rejecting a hypothesis requires a documented reason")
        self._advance(state, Stage.TRIAGE)
        state.triage_decision = decision
        state.triage_reason = reason
        state.updated_at = utcnow()
        if decision == Triage.REJECT:
            state.status = "REJECTED_TRIAGE"
            state.lessons.append(f"triage rejected: {reason}")
            state.history.append(f"rejected at triage: {reason}")
            self.store.save_state(state)
            self._record_memory(state, InvestigationStatus.DISPROVEN,
                                reason=f"triage rejected: {reason}")
            return state
        state.history.append(f"triage: {decision} {reason}".strip())
        self.store.save_state(state)
        if decision == Triage.PURSUE:
            return self._advance(state, Stage.SOURCE_ANALYSIS)
        return state  # DEFER: stays at TRIAGE, resumable

    def add_source(
        self, state: InvestigationState, path: str, *, function: str = "",
        code_path: str = "", note: str = "",
    ) -> InvestigationState:
        if state.stage != Stage.SOURCE_ANALYSIS:
            raise InvalidTransition(
                f"source analysis may only be recorded at SOURCE_ANALYSIS "
                f"(currently {state.stage})"
            )
        state.sources.append(SourceArtifact(path=path, function=function,
                                            code_path=code_path, note=note))
        state.updated_at = utcnow()
        self.store.save_state(state)
        return state

    def design_test(self, state: InvestigationState, plan: TestPlan) -> InvestigationState:
        if not plan.command.strip():
            raise InvalidTransition("a test plan must include a runnable command")
        self._advance(state, Stage.TEST_DESIGN)
        state.test_plan = plan.to_dict()
        state.updated_at = utcnow()
        state.history.append(f"test design: {plan.method} :: {plan.command}")
        self.store.save_state(state)
        return state

    def reproduce(
        self, state: InvestigationState, *, command: str = "",
        reproduce: Optional[Callable[[], tuple[bool, str]]] = None,
        evidence=None, timeout: int = 600,
    ) -> InvestigationState:
        """Enter REPRODUCTION (authorization-gated) and run the test.

        The authorization gate is re-checked here, immediately before execution --
        a scope that closed since TEST DESIGN must stop the run. Every run is
        captured in the evidence store (the engine's own by default): a reproduction
        with no evidence reference is not evidence, and INDEPENDENT_CHALLENGE
        requires one.
        """
        store = evidence if evidence is not None else self.evidence
        # Check the stage entry criteria (test plan + authorization) *first*, so an
        # authorization failure is reported as such; then require an evidence store;
        # only then mutate state. No failure path leaves the stage advanced.
        gaps = self.entry_criteria(state, Stage.REPRODUCTION)
        if gaps:
            raise InvalidTransition(
                "entry criteria unmet for REPRODUCTION: " + "; ".join(gaps)
            )
        if store is None:
            raise InvalidTransition(
                "no evidence store configured; a reproduction must be captured as "
                "evidence (pass evidence= to the engine or to reproduce())"
            )
        self._advance(state, Stage.REPRODUCTION)
        cmd = command or state.test_plan.get("command", "")
        if reproduce is not None:
            reproduced, output = reproduce()
            run = RunOutput(cmd or "<callable>", 0 if reproduced else 1, output)
        else:
            run = self.runner.run(cmd, cwd=self.cwd, timeout=timeout)
        ev = store.put_text(
            (run.stdout or "") + (run.stderr or ""), kind="reproduction",
            description=f"reproduction for {state.investigation_id}",
            command=cmd, metadata={"returncode": run.returncode,
                                   "timed_out": run.timed_out},
        )
        ev_id = ev.evidence_id
        state.evidence_ids.append(ev_id)
        state.reproduction = {
            "ran": True,
            "command": cmd,
            "returncode": run.returncode,
            "timed_out": run.timed_out,
            "reproduced": run.ok,
            "evidence_id": ev_id,
            "tail": (run.stdout or "")[-2000:],
        }
        state.updated_at = utcnow()
        state.history.append(f"reproduction ran: rc={run.returncode} evidence={ev_id}")
        self.store.save_state(state)
        return state

    def challenge(
        self, state: InvestigationState, *, independent: bool, reproduced: bool,
        evidence_id: str = "", note: str = "",
    ) -> InvestigationState:
        """Record the independent challenge (the required pre-confirmation step)."""
        self._advance(state, Stage.INDEPENDENT_CHALLENGE)
        state.challenge = {
            "ran": True,
            "independent": bool(independent),
            "reproduced": bool(reproduced),
            "evidence_id": evidence_id,
            "note": note,
        }
        state.updated_at = utcnow()
        state.history.append(
            f"independent challenge: independent={independent} reproduced={reproduced}"
        )
        self.store.save_state(state)
        return state

    def verdict(self, state: InvestigationState, obs: Observation) -> InvestigationState:
        """Advance to VERDICT and classify the outcome honestly.

        Confirmation is gated: a GENUINE_VIOLATION is only recorded as CONFIRMED
        when the independent challenge actually reproduced it. Otherwise it is
        held as UNCONFIRMED (a lead), never promoted.
        """
        self._advance(state, Stage.VERDICT)
        classification = classify_outcome(obs)
        status = _OUTCOME_TO_STATUS[classification]

        gated_reason = ""
        if classification == Outcome.GENUINE_VIOLATION:
            challenged = bool(state.challenge.get("ran"))
            reproduced_independently = bool(state.challenge.get("reproduced"))
            if not challenged:
                status = InvestigationStatus.UNCONFIRMED.value
                gated_reason = (
                    "not confirmed: no independent challenge was recorded "
                    "(mission requires independent verification before confirmation)"
                )
            elif not reproduced_independently:
                status = InvestigationStatus.UNCONFIRMED.value
                gated_reason = (
                    "not confirmed: the independent challenge did NOT reproduce the "
                    "result, so the finding is a lead, not a confirmed violation"
                )
            else:
                # The log itself must be intact before any verdict in it is
                # trusted: a CONFIRMED recorded in a tampered log is exactly the
                # fabrication the "no fabricated evidence" gate forbids.
                integrity = self.store.verify_integrity(
                    require_signatures=self.require_signatures,
                )
                # Optional independent verifier (blackheart.verify): when supplied,
                # it must also confirm the finding before CONFIRMED is recorded.
                verified, why = (True, "")
                if self.verify is not None:
                    verified, why = self.verify(state)
                blocked, integrity_reason = _integrity_blocks_confirmation(integrity)
                if blocked:
                    status = InvestigationStatus.UNCONFIRMED.value
                    gated_reason = integrity_reason
                elif not verified:
                    status = InvestigationStatus.UNCONFIRMED.value
                    gated_reason = f"not confirmed: independent verifier did not confirm: {why}"
                # Novelty gate (PR #26): a confirmed, in-scope finding may still be
                # a duplicate. If a gate is supplied and blocks, hold as UNCONFIRMED.
                elif self.novelty_gate is not None:
                    allowed, why = self.novelty_gate.allows_submission(
                        state.hypothesis.get("hyp_id", state.investigation_id)
                    )
                    if not allowed:
                        status = InvestigationStatus.UNCONFIRMED.value
                        gated_reason = f"not confirmed: novelty gate blocked submission: {why}"

        state.verdict = {
            "classification": classification,
            "status": status,
            "reason": obs.note or gated_reason,
            "gated_reason": gated_reason,
            "observation": asdict(obs),
        }
        state.status = status
        state.updated_at = utcnow()
        state.history.append(f"verdict: {classification} -> {status}")
        if gated_reason:
            state.lessons.append(gated_reason)
        self.store.save_state(state)
        self._record_memory(state, InvestigationStatus(status),
                            reason=obs.note or classification)
        return state

    # ------------------------------------------------------------------ #
    def _record_memory(
        self, state: InvestigationState, status: InvestigationStatus, *, reason: str = "",
    ) -> None:
        """Persist the investigation outcome as a ResearchRecord (mission Part 2)."""
        if self.memory is None:
            return
        hyp = state.hypothesis or {}
        record = ResearchRecord(
            record_id=state.investigation_id,
            target=hyp.get("component", "") or state.target,
            vulnerability_class=hyp.get("category", ""),
            hypothesis=hyp.get("title", ""),
            attack_strategy=hyp.get("strategy", ""),
            tools=hyp.get("required_tools", []),
            commands=[state.reproduction.get("command", "")] if state.reproduction else [],
            expected_outcome=state.test_plan.get("expected", ""),
            actual_outcome=state.verdict.get("classification", ""),
            evidence_hashes=[state.reproduction.get("evidence_id", "")] if state.reproduction else [],
            impact=hyp.get("expected_impact", ""),
            false_positive_reason=reason if status != InvestigationStatus.CONFIRMED else "",
            lessons=list(state.lessons),
            independently_verified=bool(state.challenge.get("reproduced")),
            verification_ref=state.challenge.get("evidence_id", ""),
            status=status.value,
            scope_reference=state.scope_reference,
        )
        # ``promote`` enforces the confirmation gate on the record itself too.
        record.promote(status)
        self.memory.save(record)

    # ------------------------------------------------------------------ #
    def run_to_verdict(
        self,
        hypothesis: GeneratedHypothesis,
        *,
        sources: list[SourceArtifact],
        plan: TestPlan,
        reproduce: Optional[Callable[[], tuple[bool, str]]] = None,
        challenge: tuple[bool, bool, str] = (True, False, ""),
        observation: Optional[Observation] = None,
        scope_reference: str = "",
        evidence=None,
        timeout: int = 600,
    ) -> InvestigationState:
        """Drive a hypothesis through the whole lifecycle in one call.

        This is a convenience for the common case; every step is the same guarded
        transition the individual methods enforce, so nothing is bypassed.
        """
        state = self.start(hypothesis, scope_reference=scope_reference)
        state = self.triage(state, Triage.PURSUE, reason="selected for investigation")
        for src in sources:
            state = self.add_source(state, src.path, function=src.function,
                                    code_path=src.code_path, note=src.note)
        state = self.design_test(state, plan)
        state = self.reproduce(state, reproduce=reproduce, evidence=evidence, timeout=timeout)
        independent, reproduced, ev_id = challenge
        state = self.challenge(state, independent=independent, reproduced=reproduced,
                               evidence_id=ev_id)
        obs = observation or Observation()
        return self.verdict(state, obs)


__all__ = [
    "Stage",
    "STAGE_ORDER",
    "TERMINAL",
    "Triage",
    "Outcome",
    "InvalidTransition",
    "AuthorizationRequired",
    "SourceArtifact",
    "TestPlan",
    "RunOutput",
    "SubprocessRunner",
    "InvestigationState",
    "InvestigationStore",
    "InvestigationEngine",
    "Observation",
    "classify_outcome",
    "plan_from_tools",
]
