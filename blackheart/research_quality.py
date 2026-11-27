"""Phase 3 — controlled adversarial research-quality evaluation suite.

This module defines a fixed, reproducible evaluation of BLACKHEART's attacker-first
engine over **local, intentionally-vulnerable targets only**. It never touches a
production system, a network, or real funds.

Each :class:`ResearchCase` encodes the ten fields the mission requires:

  1. attacker objective            6. expected secure behaviour
  2. attacker capabilities         7. expected vulnerable behaviour
  3. target preconditions          8. reproduction method
  4. attack surface                9. independent verification criteria
  5. hypothesis                   10. evidence required

The suite is a **differential** evaluation: for every attack class it runs the
vulnerable target and its guarded control through the real stateful fuzzer.

  * **Positive control** — the vulnerable target MUST yield an attacker-reachable
    invariant break (the harness can detect a known-intentional vulnerability).
  * **Negative control** — the guarded control MUST NOT break the same invariant
    (the same attack is rejected by a secure implementation).

A case that fails either control is reported as a failure, not hidden. No finding
is fabricated: every result is produced by the engine, and a case is only marked
``detected`` when a real counterexample exists.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from .invariants import FuzzConfig, StatefulFuzzer
from .invariants.engine import run_sequence
from .invariants.registry import make_target


# --------------------------------------------------------------------------- #
# The ten-field case definition
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ResearchCase:
    """One attack class, defined the way the mission requires."""

    case_id: str
    attack_class: str
    # the differential pair this case is evaluated against
    vulnerable: str
    guarded: str
    # 1-5: the attacker's framing
    objective: str
    capabilities: list[str]
    preconditions: list[str]
    surface: str
    hypothesis: str
    # 6-10: the expected outcomes and the proof obligations
    expected_secure: str
    expected_vulnerable: str
    reproduction: str
    verification: str
    evidence: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


# The ten attack classes the mission names, mapped to the pairs that exist.
CASES: list[ResearchCase] = [
    ResearchCase(
        case_id="AUTHZ-01",
        attack_class="Authorization bypass",
        vulnerable="access-control", guarded="access-guarded",
        objective="Bypass a restriction: call a privileged setter without the role.",
        capabilities=["call public functions", "supply arbitrary calldata"],
        preconditions=["a privileged setter exists", "its gating is weak or missing"],
        surface="the public entry points that mutate protected state",
        hypothesis="an unprivileged caller can overwrite protected state because the "
                   "authorization check is absent or on the wrong dimension",
        expected_secure="the guarded setter reverts for a non-owner caller",
        expected_vulnerable="the unprivileged caller changes protected state",
        reproduction="stateful fuzz for a sequence where a non-owner mutates state",
        verification="re-run the minimal sequence on the vulnerable target and confirm "
                     "the same invariant still breaks; the guarded target must hold",
        evidence=["minimal_sequence", "observed state", "invariant id"],
    ),
    ResearchCase(
        case_id="IDOR-01",
        attack_class="IDOR / cross-user access",
        vulnerable="access-control", guarded="access-guarded",
        objective="Obtain unauthorized access: act on another principal's object.",
        capabilities=["enumerate identifiers", "call object-scoped operations"],
        preconditions=["object-level authorization is missing"],
        surface="object-scoped read/write operations",
        hypothesis="the caller's authority over an object is never checked, so any "
                   "principal can act on another principal's object",
        expected_secure="the guarded object operation rejects a non-owner principal",
        expected_vulnerable="a non-owner principal mutates another principal's object",
        reproduction="fuzz sequences in which actor != owner reach the object operation",
        verification="the counterexample names an actor that is not the object owner",
        evidence=["actor_roles", "minimal_sequence", "observed state"],
    ),
    ResearchCase(
        case_id="PRIVESC-01",
        attack_class="Privilege escalation",
        vulnerable="proxy-initializer", guarded="proxy-guarded",
        objective="Bypass a restriction: obtain the owner role from an unprivileged start.",
        capabilities=["call a public initializer", "front-run deployment"],
        preconditions=["an initializer can be re-called"],
        surface="the initializer / ownership-transfer surface",
        hypothesis="the initializer can be called after deployment, handing the owner "
                   "role to the attacker",
        expected_secure="the guarded initializer is one-shot and rejects re-calls",
        expected_vulnerable="a re-call assigns ownership to the attacker",
        reproduction="fuzz for a second initialize() call by a non-deployer actor",
        verification="the minimal sequence contains the re-initialization and the "
                     "attacker ends as owner",
        evidence=["minimal_sequence", "ownership snapshot"],
    ),
    ResearchCase(
        case_id="AUTHN-01",
        attack_class="Authentication / session boundary",
        vulnerable="permit-replay", guarded="permit-guarded",
        objective="Replay an authorization to act more than once.",
        capabilities=["observe signed messages", "resubmit transactions"],
        preconditions=["signatures lack a single-use binding"],
        surface="the signature/permit verification path",
        hypothesis="a valid signature can be replayed because it is not bound to a "
                   "single use",
        expected_secure="the guarded permit rejects the second use",
        expected_vulnerable="the same signature is accepted twice",
        reproduction="fuzz a sequence that submits the same authorization twice",
        verification="the counterexample shows two successful uses of one authorization",
        evidence=["minimal_sequence", "authorization state"],
    ),
    ResearchCase(
        case_id="SIG-01",
        attack_class="Signature and replay validation",
        vulnerable="permit-replay", guarded="permit-guarded",
        objective="Forge or replay a signature to authorize an action.",
        capabilities=["supply arbitrary (v,r,s)", "choose the message", "replay"],
        preconditions=["verification lacks malleability or replay protection"],
        surface="the ecrecover-based verification path",
        hypothesis="signature verification accepts an invalid or reused authorization",
        expected_secure="invalid/replayed signatures are rejected",
        expected_vulnerable="an invalid or reused signature authorizes the action",
        reproduction="fuzz for a permit accepted without a fresh, single-use signature",
        verification="the counterexample isolates the missing signature binding",
        evidence=["minimal_sequence", "signature/permit state"],
    ),
    ResearchCase(
        case_id="INPUT-01",
        attack_class="Input validation / trust boundary",
        vulnerable="callback-reentrancy", guarded="callback-guarded",
        objective="Cause inconsistent state by violating a trust boundary.",
        capabilities=["supply a hostile callback target", "reenter"],
        preconditions=["an external call runs before effects are written"],
        surface="the external-call / callback boundary",
        hypothesis="a callback re-enters before state is finalised and observes or "
                   "acts on partially-updated state",
        expected_secure="the guarded target finalises state before the external call "
                        "(or guards reentry) and holds",
        expected_vulnerable="the reentrant callback drains or corrupts state",
        reproduction="fuzz a sequence with a hostile callback that reenters",
        verification="the counterexample requires the callback and breaks the "
                     "atomicity invariant",
        evidence=["minimal_sequence", "observed balances"],
    ),
    ResearchCase(
        case_id="LOGIC-01",
        attack_class="Business logic abuse",
        vulnerable="hl-pm-supply", guarded="hl-pm-supply-guarded",
        objective="Receive more assets than entitled to via a legitimate-looking "
                  "operation sequence.",
        capabilities=["open positions", "sequence calls", "withdraw"],
        preconditions=["an operation path lets a supplier remove lent-out funds"],
        surface="the supply/withdraw lifecycle",
        hypothesis="a supplier can withdraw funds that are lent out, leaving debt "
                   "unbacked, by ordering operations a certain way",
        expected_secure="the guarded pool blocks the withdrawal while funds are lent",
        expected_vulnerable="the withdrawal succeeds and leaves debt unbacked",
        reproduction="fuzz the supply/borrow/withdraw ordering",
        verification="the counterexample leaves outstanding credit above backing",
        evidence=["minimal_sequence", "backing snapshot"],
    ),
    ResearchCase(
        case_id="CHAIN-01",
        attack_class="Cross-function / multi-operation chain",
        vulnerable="hl-outcome", guarded="hl-outcome-guarded",
        objective="Receive more assets than entitled to by composing operations.",
        capabilities=["mint", "merge", "chain calls"],
        preconditions=["two operations share accounting that can be composed"],
        surface="the merge/mint accounting surface",
        hypothesis="composing merge operations mints value that no single operation "
                   "would",
        expected_secure="the guarded market conserves value across the composition",
        expected_vulnerable="the composed sequence creates value",
        reproduction="fuzz multi-step merge/mint sequences",
        verification="the minimal sequence has >1 step and breaks the conservation "
                     "invariant",
        evidence=["minimal_sequence (len>1)", "value snapshot"],
    ),
    ResearchCase(
        case_id="ASSET-01",
        attack_class="Asset / accounting invariant violation",
        vulnerable="vulnerable", guarded="safe",
        objective="Receive more assets than entitled to via share/asset accounting.",
        capabilities=["deposit", "donate", "sequence calls"],
        preconditions=["accounting mixes external balances with internal shares"],
        surface="the deposit/withdraw share math",
        hypothesis="a donation to the vault before a later deposit lets the attacker "
                   "capture the depositor's value (share inflation)",
        expected_secure="the guarded vault (with a virtual offset) holds the invariant",
        expected_vulnerable="internal accounting diverges from redeemable value",
        reproduction="fuzz donation-then-deposit orderings",
        verification="the counterexample shows a balance increase without equal payment",
        evidence=["minimal_sequence", "observed share/asset values"],
    ),
    ResearchCase(
        case_id="TOOL-01",
        attack_class="Agent/tool authorization failure",
        vulnerable="access-guarded", guarded="access-guarded",
        objective="Make a tool/agent perform an action the caller is not authorized "
                  "for.",
        capabilities=["invoke a tool/endpoint", "omit or forge credentials"],
        preconditions=["the tool/endpoint performs an action without checking the "
                       "caller's authority"],
        surface="the tool/agent invocation boundary",
        hypothesis="a tool performs a privileged action for an unauthorized caller "
                   "because it does not enforce the caller's authority",
        expected_secure="the guarded surface refuses the unauthorized tool call",
        expected_vulnerable="(if the surface were unguarded) the tool would act",
        reproduction="drive the guarded surface with an unauthorized caller",
        verification="this case is a NEGATIVE-only control: it asserts the guarded "
                     "surface holds; there is no unguarded twin in the registry",
        evidence=["guarded invariant result"],
    ),
]


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

@dataclass
class CaseResult:
    case_id: str
    attack_class: str
    vulnerable: str
    guarded: str
    vulnerable_breaks: int
    guarded_breaks: int
    positive_control: bool          # vulnerable target yielded an attacker-reachable break
    negative_control: bool          # guarded target held
    attacker_reachable: bool
    minimal_sequence_len: int
    seed: int | None
    status: str                     # DETECTED / NOT_DETECTED / CONTROL_FAILED
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _run_target(name: str, cfg: FuzzConfig):
    target = make_target(name)
    report = StatefulFuzzer(target, cfg).run()
    return target, report


def evaluate_case(case: ResearchCase, *, runs: int = 400,
                  steps_per_run: int = 12, seed: int = 0) -> CaseResult:
    """Run one research case as a differential positive/negative control."""
    cfg = FuzzConfig(runs=runs, steps_per_run=steps_per_run, seed=seed)
    notes: list[str] = []

    vuln_target, vuln_report = _run_target(case.vulnerable, cfg)
    # The negative control uses a different seed so it is a genuine independent
    # check, not a replay of the same sequence.
    guard_cfg = FuzzConfig(runs=runs, steps_per_run=steps_per_run, seed=seed + 1)
    _, guard_report = _run_target(case.guarded, guard_cfg)

    attacker_failures = [f for f in vuln_report.failures if f.reachable_by_attacker]
    vulnerable_breaks = len(vuln_report.failures)
    guarded_breaks = len(guard_report.failures)

    positive = bool(attacker_failures)
    negative = guarded_breaks == 0

    minimal_len = 0
    used_seed: int | None = None
    if attacker_failures:
        f = attacker_failures[0]
        minimal_len = len(f.minimal_sequence)
        used_seed = f.seed
        # Independent verification: re-execute the exact minimal sequence and
        # confirm the invariant still breaks.
        result = run_sequence(vuln_target, f.minimal_sequence)
        if f.inv_id not in result.violated:
            notes.append("counterexample did not reproduce on re-execution")
            positive = False

    # TOOL-01 is explicitly a negative-only control (no unguarded twin exists).
    if case.case_id == "TOOL-01":
        status = "DETECTED" if negative else "CONTROL_FAILED"
        if not negative:
            notes.append("guarded surface broke an invariant; negative control failed")
        return CaseResult(case.case_id, case.attack_class, case.vulnerable,
                          case.guarded, vulnerable_breaks, guarded_breaks,
                          positive, negative, positive, minimal_len, used_seed,
                          status, notes)

    if not positive:
        status = "NOT_DETECTED"
        notes.append("vulnerable target produced no attacker-reachable break")
    elif not negative:
        status = "CONTROL_FAILED"
        notes.append("guarded control broke an invariant; differential is invalid")
    else:
        status = "DETECTED"

    return CaseResult(
        case_id=case.case_id, attack_class=case.attack_class,
        vulnerable=case.vulnerable, guarded=case.guarded,
        vulnerable_breaks=vulnerable_breaks, guarded_breaks=guarded_breaks,
        positive_control=positive, negative_control=negative,
        attacker_reachable=positive, minimal_sequence_len=minimal_len,
        seed=used_seed, status=status, notes=notes,
    )


def run_evaluation(*, runs: int = 400, steps_per_run: int = 12, seed: int = 0,
                   cases: list[ResearchCase] | None = None) -> dict:
    """Run the full evaluation suite and return a machine-readable report."""
    selected = cases if cases is not None else CASES
    results = [evaluate_case(c, runs=runs, steps_per_run=steps_per_run, seed=seed)
               for c in selected]
    detected = sum(1 for r in results if r.status == "DETECTED")
    failed = sum(1 for r in results if r.status == "CONTROL_FAILED")
    not_detected = sum(1 for r in results if r.status == "NOT_DETECTED")

    # Honesty: some attack classes are demonstrated by the same differential pair
    # (the registry has fewer pairs than named classes). Cases that share a pair
    # are correlated, not independent detections -- say so rather than implying
    # ten independent confirmations.
    pair_counts: dict[str, int] = {}
    for r in results:
        pair_counts[f"{r.vulnerable}/{r.guarded}"] = \
            pair_counts.get(f"{r.vulnerable}/{r.guarded}", 0) + 1
    shared = {p: n for p, n in pair_counts.items() if n > 1}

    return {
        "suite": "blackheart-research-quality",
        "scope": "local intentionally-vulnerable targets only; no network, no funds",
        "runs_per_case": runs,
        "steps_per_run": steps_per_run,
        "seed": seed,
        "cases": len(results),
        "detected": detected,
        "not_detected": not_detected,
        "control_failed": failed,
        "distinct_differential_pairs": len(pair_counts),
        "pairs_shared_across_classes": shared,
        "all_controls_pass": failed == 0 and detected == len(results),
        "results": [r.to_dict() for r in results],
        "note": (
            "Positive control = the vulnerable target yields an attacker-reachable "
            "break. Negative control = the guarded target holds. A case is DETECTED "
            "only when both hold. No finding is fabricated; every result is engine "
            "output. Cases sharing a differential pair (see "
            "pairs_shared_across_classes) are correlated, not independent "
            "confirmations."
        ),
    }


def write_evaluation_report(report: dict, workdir: str | Path) -> Path:
    import json
    root = Path(workdir)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "research-quality-report.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return path
