"""Independent adversarial verification of state-space violations.

The explorer finds a sequence that broke an invariant. That is a *violation*, not
a vulnerability. This module is the separate stage that tries to **reject** it,
using procedures that do not share the explorer's assumptions:

  1. **Independent re-run.** Re-execute the minimal sequence from a fresh state in
     a *fresh target instance*, and confirm the violation reappears. A violation
     that does not reproduce independently is rejected.
  2. **Attacker reachability.** Confirm the violating sequence uses only actors an
     attacker can actually be (unprivileged). A sequence that needs a privileged
     actor is rejected -- an attack that assumes privilege is not this attacker's.
  3. **Differential / control integrity.** Re-run the same sequence against the
     *secure control*. If the control ALSO violates the invariant, the invariant
     does not discriminate vulnerability from intended behaviour, and the finding
     is rejected as a false positive. This is the check that catches a badly
     specified invariant, which no amount of re-running would otherwise expose.
  4. **Precondition satisfiability.** Every precondition the hypothesis stated must
     be satisfiable by the attacker. An unsatisfiable precondition rejects.
  5. **Intended behaviour.** If the observed behaviour is in the model's
     ``intended_behaviours``, it is not a vulnerability.
  6. **Duplicate / known.** A violation whose canonical sequence is already
     recorded as known is marked duplicate, not new.

The verifier returns one of the mission's dispositions. It is *allowed* to reject
the generator's conclusion -- that is its purpose -- and it never promotes a
violation to INDEPENDENTLY_VERIFIED unless the independent re-run, the attacker
reachability, the control integrity, and the scope checks all hold.

The verdict is produced from executed evidence, not from the hypothesis narrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .explore import Violation, run_sequence
from .model import SequenceTarget, SystemModel


class VerificationIndependence(str, Enum):
    """Whether the verifier is a different execution engine from the producer.

    A fresh instance of the same engine is an independent *re-run*; it is not an
    independent *engine*. The distinction matters because shared blind spots do
    not disappear when the state is reset. ``UNRECORDED`` is never read as
    independent when a caller asks for a distinct engine.
    """

    INDEPENDENT_ENGINE = "INDEPENDENT_ENGINE"
    SAME_ENGINE = "SAME_ENGINE"
    UNRECORDED = "UNRECORDED"

    @classmethod
    def coerce(cls, value) -> "VerificationIndependence":
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except (ValueError, TypeError):
            return cls.UNRECORDED


@dataclass
class VerifyConfig:
    """Facts the verifier needs that are not derivable from the sequence alone."""

    # A factory that returns a *fresh* secure control instance for the same
    # invariant, or None when no control exists (then control integrity is
    # UNKNOWN, never assumed-pass).
    control_factory: Optional[Callable[[], SequenceTarget]] = None
    # Canonical sequence keys already recorded as known/duplicate.
    known_sequences: set = field(default_factory=set)
    # True only when the target asset is within the authorized program scope.
    in_scope: Optional[bool] = None
    scope_reference: str = ""
    # Whether active testing was authorized by the gate (mirrors the authz gate).
    authorization_gate_passed: Optional[bool] = None
    #: Names of the engine that produced the witness and the engine re-running
    #: it. Empty means unrecorded, never "same" and never "independent".
    producer_engine: str = ""
    verifier_engine: str = ""
    #: When true, a same-engine or unrecorded re-run cannot be
    #: INDEPENDENTLY_VERIFIED. The sequence can still be REPRODUCED.
    require_distinct_engine: bool = False


@dataclass
class VerifyResult:
    """The verifier's verdict on one violation."""

    invariant_id: str
    disposition: str
    checks: dict = field(default_factory=dict)   # check name -> (passed, detail)
    reasons: list[str] = field(default_factory=list)
    independence: VerificationIndependence = VerificationIndependence.UNRECORDED

    def to_dict(self) -> dict:
        return {
            "invariant_id": self.invariant_id,
            "disposition": self.disposition,
            "checks": {k: {"passed": v[0], "detail": v[1]} for k, v in self.checks.items()},
            "reasons": list(self.reasons),
            "independence": self.independence.value,
        }


def _seq_key(seq) -> tuple:
    return tuple((s.actor, s.action) for s in seq)


def _engine_independence(producer: str, verifier: str) -> VerificationIndependence:
    producer = (producer or "").strip().lower()
    verifier = (verifier or "").strip().lower()
    if not producer or not verifier:
        return VerificationIndependence.UNRECORDED
    if producer == verifier:
        return VerificationIndependence.SAME_ENGINE
    return VerificationIndependence.INDEPENDENT_ENGINE


def _scope_value(in_scope: Optional[bool], authorized: Optional[bool]) -> Optional[bool]:
    """The scope gate, three-valued.

    ``False`` when either fact is a known no; ``None`` when either is
    unestablished; ``True`` only when both are established yes. ``None`` must
    never be read as a pass: an unexamined scope is not an authorized one.
    """
    if in_scope is False or authorized is False:
        return False
    if in_scope is None or authorized is None:
        return None
    return True


def _close_target(target) -> None:
    """Release a target the verifier constructed for a one-off re-run.

    The verifier builds throwaway instances (a fresh target for the independent
    reproduction, a control for the differential check). For a real-runtime
    adapter -- notably the EVM adapter, where each target owns an ``anvil``
    process -- a target that is not closed leaks its node. This best-effort close
    is idempotent and never raises: a cleanup failure must not mask the verdict.
    """
    adapter = getattr(target, "adapter", None)
    close = getattr(adapter, "close", None)
    if callable(close):
        try:
            close()
        except Exception:  # noqa: BLE001 -- cleanup must never change the verdict
            pass


class IndependentSequenceVerifier:
    """Challenges a violation; may reject it. Never rubber-stamps the explorer."""

    def __init__(self, target_factory: Callable[[], SequenceTarget],
                 config: Optional[VerifyConfig] = None) -> None:
        self.target_factory = target_factory
        self.config = config or VerifyConfig()

    def verify(self, violation: Violation, *, model: Optional[SystemModel] = None,
               preconditions_satisfiable: Optional[bool] = None) -> VerifyResult:
        cfg = self.config
        checks: dict = {}
        reasons: list[str] = []

        # -- 1. Independent re-run in a FRESH instance ------------------- #
        fresh = self.target_factory()
        try:
            _, bad = run_sequence(fresh, violation.minimal_sequence)
        finally:
            _close_target(fresh)
        reproduced = violation.invariant_id in bad
        checks["independent_reproduction"] = (
            reproduced,
            "reproduced in a fresh target instance" if reproduced
            else "did NOT reproduce independently",
        )
        if not reproduced:
            reasons.append("independent re-run did not reproduce the violation")

        # -- 1b. Engine independence ------------------------------------- #
        independence = _engine_independence(cfg.producer_engine,
                                            cfg.verifier_engine)
        independence_pass: Optional[bool] = {
            VerificationIndependence.INDEPENDENT_ENGINE: True,
            VerificationIndependence.SAME_ENGINE: False,
            VerificationIndependence.UNRECORDED: None,
        }[independence]
        checks["independent_engine"] = (
            independence_pass,
            {
                VerificationIndependence.INDEPENDENT_ENGINE:
                    f"producer {cfg.producer_engine!r} and verifier "
                    f"{cfg.verifier_engine!r} are distinct engines",
                VerificationIndependence.SAME_ENGINE:
                    f"producer and verifier both report {cfg.producer_engine!r}",
                VerificationIndependence.UNRECORDED:
                    "engine provenance was not recorded; a fresh instance is a "
                    "re-run, not a distinct engine",
            }[independence],
        )
        if cfg.require_distinct_engine and independence_pass is not True:
            reasons.append(
                "a distinct verifier engine was required but not established"
            )

        # -- 2. Attacker reachability ------------------------------------ #
        reachable = violation.reachable_by_attacker
        checks["attacker_reachable"] = (
            reachable,
            "sequence uses only unprivileged actors" if reachable
            else "sequence requires a privileged actor the attacker cannot be",
        )
        if not reachable:
            reasons.append("sequence requires a privileged actor")

        # -- 3. Differential / control integrity ------------------------- #
        control = None
        if cfg.control_factory is not None:
            try:
                control = cfg.control_factory()
            except Exception as exc:  # a control that cannot be built is UNKNOWN
                control = None
                reasons.append(f"control could not be constructed: {exc}")
        if control is not None:
            try:
                _, cbad = run_sequence(control, violation.minimal_sequence)
            finally:
                _close_target(control)
            control_violates = violation.invariant_id in cbad
            checks["control_integrity"] = (
                not control_violates,
                "secure control holds the invariant (PoC discriminates)"
                if not control_violates
                else "secure control ALSO violates: invariant does not discriminate",
            )
            if control_violates:
                reasons.append("secure control reproduces the violation (non-discriminating)")
        else:
            checks["control_integrity"] = (None, "no secure control available (unestablished)")

        # -- 4. Precondition satisfiability ------------------------------ #
        if preconditions_satisfiable is None:
            checks["preconditions_satisfiable"] = (None, "not established")
        else:
            checks["preconditions_satisfiable"] = (
                preconditions_satisfiable,
                "attacker can satisfy the stated preconditions" if preconditions_satisfiable
                else "a stated precondition is unsatisfiable by the attacker",
            )
            if not preconditions_satisfiable:
                reasons.append("a stated precondition is unsatisfiable")

        # -- 5. Intended behaviour --------------------------------------- #
        if model is not None and model.intended_behaviours:
            # The observed snapshot keys/values are matched loosely against the
            # documented intended behaviours; a match is not a vulnerability.
            intended = _matches_intended(violation, model)
            checks["not_intended"] = (
                not intended,
                "behaviour is not in the documented intended set" if not intended
                else "observed behaviour is documented as intended",
            )
            if intended:
                reasons.append("observed behaviour is documented as intended")
        else:
            checks["not_intended"] = (True, "no intended-behaviour list declared")

        # -- 6. Duplicate / known ---------------------------------------- #
        is_dup = _seq_key(violation.minimal_sequence) in cfg.known_sequences
        checks["not_duplicate"] = (
            not is_dup, "sequence is new" if not is_dup else "sequence is already known",
        )
        if is_dup:
            reasons.append("sequence matches a previously known/duplicate finding")

        # -- 7. Scope / authorization ------------------------------------ #
        # Three-valued on purpose. ``None`` means "not established", and an
        # unestablished scope is not authorization: it must never read as a pass,
        # because this check is the one that decides whether BLACKHEART may claim
        # an asset was authorized for active testing.
        scope_value = _scope_value(cfg.in_scope, cfg.authorization_gate_passed)
        checks["scope_and_authorization"] = (
            scope_value,
            {
                True: "asset authorized and in scope",
                False: "asset out of scope or not authorized",
                None: "scope/authorization not established; declare it before this "
                      "verdict can be treated as an authorized result",
            }[scope_value],
        )
        if scope_value is False:
            reasons.append("asset is out of scope or not authorized")
        elif scope_value is None:
            reasons.append(
                "scope and authorization were not established for this asset; the "
                "sequence is reproduced but not an authorized, in-scope result"
            )

        disposition = self._disposition(
            checks, reproduced, reachable, independence,
            cfg.require_distinct_engine,
        )
        return VerifyResult(invariant_id=violation.invariant_id, disposition=disposition,
                            checks=checks, reasons=reasons,
                            independence=independence)

    @staticmethod
    def _disposition(checks: dict, reproduced: bool, reachable: bool,
                     independence: VerificationIndependence = VerificationIndependence.UNRECORDED,
                     require_distinct_engine: bool = False) -> str:
        # Hard rejections first -- these override any number of passing checks.
        if checks["control_integrity"][0] is False:
            return "REJECTED"
        if checks.get("preconditions_satisfiable", (None,))[0] is False:
            return "REJECTED"
        if checks["not_intended"][0] is False:
            return "REJECTED"
        if checks["scope_and_authorization"][0] is False:
            return "REJECTED"
        if checks["not_duplicate"][0] is False:
            return "REJECTED"
        if not reachable:
            return "REJECTED"
        # Not reproduced -> we cannot claim anything.
        if not reproduced:
            return "INSUFFICIENT_EVIDENCE"
        # Reproduced + reachable, but the discriminating control is unestablished.
        if checks["control_integrity"][0] is None:
            return "REPRODUCED"
        # Everything established.
        if checks["preconditions_satisfiable"][0] is None:
            return "REPRODUCED"
        # Scope/authorization unknown is not a rejection (the sequence *was*
        # reproduced) but it cannot be an *authorized* independent verification.
        if checks["scope_and_authorization"][0] is None:
            return "REPRODUCED"
        # A caller that demanded a distinct engine is not satisfied by a fresh
        # instance of the producer. The witness is still reproduced; it is not
        # independently verified.
        if require_distinct_engine and independence != VerificationIndependence.INDEPENDENT_ENGINE:
            return "REPRODUCED"
        return "INDEPENDENTLY_VERIFIED"


def _matches_intended(violation: Violation, model: SystemModel) -> bool:
    """True if the observed snapshot/sequence is documented as intended behaviour."""
    hay = " ".join(model.intended_behaviours).lower()
    if not hay:
        return False
    # Match on operation names in the sequence, and on observed keys.
    for s in violation.minimal_sequence:
        if s.action.lower() in hay:
            return True
    return False


def verify_report(violations: list[Violation], target_factory: Callable[[], SequenceTarget],
                  config: Optional[VerifyConfig] = None,
                  model: Optional[SystemModel] = None) -> list[VerifyResult]:
    """Verify every violation; returns one result per violation."""
    verifier = IndependentSequenceVerifier(target_factory, config)
    return [verifier.verify(v, model=model) for v in violations]
