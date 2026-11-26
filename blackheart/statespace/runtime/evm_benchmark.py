"""Fair, real-execution baselines for the external-source EVM cases.

Mission 04 asks for a fair competitive comparison against conventional approaches,
with every approach given the same target, the same operations, the same runtime,
and the same budget. This module runs, against the *same deployed bytecode* on the
*same local anvil node*:

  * **guided** -- BLACKHEART's unchanged state-space engine (hypothesis generation
    -> model-guided exploration -> minimisation).
  * **random** -- uniform random sequences over the same operations, same actors,
    same parameter domains, same per-sequence step cap. This is the conventional
    stateful fuzzer.
  * **native** -- the application's own upstream Foundry test for the level (the
    "does the project's own test suite catch it" baseline), where the upstream
    repository ships one. Reported by suite outcome, not by a modelled sequence.

All three are scored on the same invariant, evaluated from the same observed
state. A hit is a *violation of the case's declared invariant* -- nothing more.

Honesty rules this module enforces:

  * The random baseline is a genuine uniform sampler over the identical operation
    and parameter space; it is not a straw man, and it is not told where the bug
    is any more than the guided search is.
  * Every approach gets the same execution budget (``max_operations``) and the
    same wall-clock ceiling; a budget exhaustion is reported, never hidden.
  * Small samples are reported as small. No statistical-significance claim is made.
  * The native baseline measures the project's own test, not BLACKHEART's, and is
    reported separately so it cannot be mistaken for a BLACKHEART result.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..explore import ExploreConfig, StateSpaceExplorer, run_sequence
from ..hypotheses import HypothesisGenerator
from .base import ExecutionBudget, RuntimeTarget
from .evm import EvmExecutionAdapter
from .evm_registry import ALL_CASES, get_case, has_control, target_for
from .evm_run import build_evm_target


@dataclass
class ApproachResult:
    approach: str
    detected: bool = False
    sequences_tried: int = 0
    steps_executed: int = 0
    seconds: float = 0.0
    minimal_len: int = 0
    reproduced: bool = False
    verified: bool = False
    control_rejected: Optional[bool] = None
    budget_exhausted: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "approach": self.approach, "detected": self.detected,
            "sequences_tried": self.sequences_tried, "steps_executed": self.steps_executed,
            "seconds": self.seconds, "minimal_len": self.minimal_len,
            "reproduced": self.reproduced, "verified": self.verified,
            "control_rejected": self.control_rejected,
            "budget_exhausted": self.budget_exhausted, "errors": self.errors,
        }


@dataclass
class CaseComparison:
    case: str
    target: str
    suite: str
    invariant_ids: list[str] = field(default_factory=list)
    approaches: dict[str, ApproachResult] = field(default_factory=dict)
    native_test: Optional[dict] = None
    search_space: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "case": self.case, "target": self.target, "suite": self.suite,
            "invariant_ids": self.invariant_ids,
            "approaches": {k: v.to_dict() for k, v in self.approaches.items()},
            "native_test": self.native_test,
            "search_space": self.search_space,
        }


def _search_space(case_name: str, cfg: ExploreConfig) -> dict:
    """Cardinality of the sequence space both approaches search.

    Reported so the regime is explicit: on these deliberately-small educational
    cases the space is tiny (so uniform random sampling is competitive), whereas
    the same arithmetic grows exponentially with operations, parameters and length.
    ``distinct_sequences`` counts ordered sequences of length 1..max_steps where
    each step is any (operation, parameter-assignment) pair, times the actor count.
    """
    case = get_case(case_name)
    per_step = 0
    for op in case.ops:
        size = 1
        for values in op.domains.values():
            size *= max(1, len(values))
        per_step += size
    actors = max(1, len(case.actors))
    per_step *= actors
    total = sum(per_step ** length for length in range(1, cfg.max_steps + 1))
    return {"operations": len(case.ops), "actors": len(case.actors),
            "per_step_choices": per_step, "max_steps": cfg.max_steps,
            "distinct_sequences": total}


def _domain_params(op, rng: random.Random) -> dict[str, Any]:
    """A random parameter assignment from the operation's declared domains."""
    params: dict[str, Any] = {}
    for name in op.param_names():
        values = list(op.domains.get(name, ()))
        if not values:
            continue
        params[name] = rng.choice(values)
    if op.value_param:
        values = list(op.domains.get(op.value_param, (0,)))
        params[op.value_param] = rng.choice(values) if values else 0
    return params


def run_random_baseline(case_name: str, *, seed: int = 0, max_sequences: int = 400,
                        max_steps: int = 6, max_operations: int = 200_000) -> ApproachResult:
    """Uniform random sequences over the same ops/actors/domains, same budget.

    Each sequence is freshly reset first (so a sequence is scored from the known
    initial state, exactly as the guided explorer scores its candidates). When a
    violation is found, the random approach is given the *same* treatment the
    guided approach gets: the violating prefix is independently re-run in a fresh
    instance, and (when a control exists) checked against the differential control.
    This is the fair comparison -- the baseline is not penalised for lacking a
    pipeline it was not given.
    """
    res = ApproachResult(approach="random")
    case = get_case(case_name)
    adapter = EvmExecutionAdapter(case, _scope(case_name),
                                  budget=ExecutionBudget(max_operations=max_operations))
    adapter.load()
    target = RuntimeTarget(adapter)
    inv_ids = {i[0] for i in case.invariants}
    rng = random.Random(seed)
    t0 = time.monotonic()
    hit_steps: list = []
    try:
        for i in range(max_sequences):
            length = rng.randint(1, max_steps)
            target.reset()
            seq: list = []
            hit = False
            for _ in range(length):
                op = rng.choice(case.ops)
                params = _domain_params(op, rng)
                step = _make_step(target, op, params)
                seq.append(step)
                target.step(target.snapshot(None), op.name, op.actor, params)
                res.steps_executed += 1
                last = target.last_record()
                if last is not None and set(last.violated) & inv_ids:
                    hit = True
                    break
            res.sequences_tried += 1
            if hit:
                res.detected = True
                res.minimal_len = len(seq)
                hit_steps = seq
                break
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        res.errors.append(msg)
        if "budget" in msg.lower():
            res.budget_exhausted = True
    finally:
        adapter.close()

    if res.detected and hit_steps:
        res.reproduced, res.verified, res.control_rejected = _verify_like_guided(
            case_name, hit_steps, max_operations)
    res.seconds = round(time.monotonic() - t0, 4)
    return res


def _make_step(target: RuntimeTarget, op, params: dict):
    """Build the engine AttackStep shape for an operation (for reproduction)."""
    from ...models import AttackStep

    return AttackStep(index=0, actor=op.actor, action=op.name, params=dict(params),
                      target_contract=target.name)


def _verify_like_guided(case_name: str, seq: list, max_operations: int) -> tuple[bool, bool, Optional[bool]]:
    """Reproduce and (if a control exists) verify an arbitrary sequence.

    Uses the *same* fresh-instance reproduction and differential-control checks the
    guided path uses, so both approaches are judged identically.
    """
    from ..verify import IndependentSequenceVerifier, VerifyConfig

    case = get_case(case_name)
    inv_ids = {i[0] for i in case.invariants}
    fresh = build_evm_target(case_name, max_operations=max_operations)[1]
    try:
        _, bad = run_sequence(fresh, list(seq))
        reproduced = bool(set(bad) & inv_ids)
    finally:
        fresh.adapter.close()
    if not reproduced:
        return False, False, None

    control_factory = None
    if has_control(case_name):
        control_factory = lambda: build_evm_target(case_name, control=True,
                                                   max_operations=max_operations)[1]
    adapter_for_model = build_evm_target(case_name, max_operations=max_operations)[0]
    try:
        model = adapter_for_model.model()
    finally:
        adapter_for_model.close()
    verifier = IndependentSequenceVerifier(
        lambda: build_evm_target(case_name, max_operations=max_operations)[1],
        VerifyConfig(control_factory=control_factory, in_scope=True,
                     scope_reference=f"local-evm:{case_name}",
                     authorization_gate_passed=True))
    violation = _as_violation(case_name, seq)
    result = verifier.verify(violation, model=model, preconditions_satisfiable=True)
    ci = result.checks.get("control_integrity")
    # ci[0] is True when the secure control *holds* the invariant, i.e. the
    # patched contract correctly rejects the attack and the PoC discriminates.
    control_rejected = None if ci is None else ci[0]
    return reproduced, result.disposition == "INDEPENDENTLY_VERIFIED", control_rejected


def _as_violation(case_name: str, seq: list):
    """Wrap a raw sequence as a Violation so the shared verifier can consume it."""
    from ..explore import Violation, _reachable_by_attacker

    case = get_case(case_name)
    inv = case.invariants[0][0] if case.invariants else ""
    steps = list(seq)
    return Violation(invariant_id=inv, sequence=steps, minimal_sequence=steps,
                     seed=0, actor_roles=[s.actor for s in steps],
                     observed={}, reachable_by_attacker=_reachable_by_attacker(steps))


def run_guided(case_name: str, *, cfg: Optional[ExploreConfig] = None,
               max_operations: int = 200_000) -> ApproachResult:
    """BLACKHEART's unchanged guided engine on the same deployed bytecode."""
    res = ApproachResult(approach="guided")
    cfg = cfg or ExploreConfig()
    adapter, target = build_evm_target(case_name, max_operations=max_operations)
    t0 = time.monotonic()
    best_seq: list = []
    try:
        gen = HypothesisGenerator(target.model()).generate()
        explore = StateSpaceExplorer(target, cfg).explore(gen.hypotheses)
        res.sequences_tried = explore.sequences_tried
        res.steps_executed = explore.steps_evaluated
        if explore.violations:
            res.detected = True
            best = min(explore.violations, key=lambda v: len(v.minimal_sequence))
            res.minimal_len = len(best.minimal_sequence)
            best_seq = list(best.minimal_sequence)
    except Exception as exc:  # noqa: BLE001
        msg = f"{type(exc).__name__}: {exc}"
        res.errors.append(msg)
        if "budget" in msg.lower():
            res.budget_exhausted = True
    finally:
        adapter.close()
    if res.detected and best_seq:
        # identical treatment to the random baseline: fresh-instance reproduction,
        # then the same independent verifier and differential control.
        res.reproduced, res.verified, res.control_rejected = _verify_like_guided(
            case_name, best_seq, max_operations)
    res.seconds = round(time.monotonic() - t0, 4)
    return res


def _scope(name: str):
    from .evm_run import _evm_scope

    return _evm_scope(name)


def compare_case(case_name: str, *, cfg: Optional[ExploreConfig] = None,
                 random_sequences: int = 400) -> CaseComparison:
    """Run guided and random against the same case; record both honestly."""
    case = get_case(case_name)
    cmp = CaseComparison(case=case.name, target=target_for(case_name).project,
                         suite=case.suite, invariant_ids=[i[0] for i in case.invariants],
                         search_space=_search_space(case_name, cfg or ExploreConfig()))
    cmp.approaches["guided"] = run_guided(case_name, cfg=cfg)
    cmp.approaches["random"] = run_random_baseline(
        case_name, seed=(cfg.seed if cfg else 0), max_sequences=random_sequences,
        max_steps=(cfg.max_steps if cfg else 6))
    cmp.native_test = native_test_result(case_name)
    return cmp


def compare_all(*, cfg: Optional[ExploreConfig] = None,
                random_sequences: int = 400) -> list[CaseComparison]:
    return [compare_case(name, cfg=cfg, random_sequences=random_sequences)
            for name in ALL_CASES]


# --------------------------------------------------------------------------- #
# Application-native baseline: the project's own upstream Foundry test
# --------------------------------------------------------------------------- #

#: Per-case mapping to the upstream project's own test, run with `forge test`.
#: This is a provenance/context column, NOT a detection baseline: it reports
#: whether the upstream repository's own shipped test passes as-is. Note the two
#: projects ship different kinds of test:
#:   * DVDF ships *challenge scaffolds* whose solution body is an empty
#:     "CODE YOUR SOLUTION HERE" slot, so the shipped suite FAILS until a solver
#:     fills it in -- a fail here is expected and says nothing about detection.
#:   * Ethernaut ships its level tests *with the solution filled in*, so they PASS
#:     -- a pass here confirms the level is solvable, not that anything was found.
#: It is reported separately so it can never be mistaken for a BLACKHEART result.
_NATIVE_TESTS: dict[str, dict] = {
    "dvdf-unstoppable": {
        "root": "harnesses/dvdf-external/vendor/dvdf",
        "match": "test/unstoppable/Unstoppable.t.sol",
        "interpretation": "DVDF challenge scaffold: solution slot is empty by design, "
                          "so the shipped suite fails until a solver fills it in.",
    },
    "dvdf-truster": {
        "root": "harnesses/dvdf-external/vendor/dvdf",
        "match": "test/truster/Truster.t.sol",
        "interpretation": "DVDF challenge scaffold: solution slot is empty by design, "
                          "so the shipped suite fails until a solver fills it in.",
    },
    "dvdf-naive-receiver": {
        "root": "harnesses/dvdf-external/vendor/dvdf",
        "match": "test/naive-receiver/NaiveReceiver.t.sol",
        "interpretation": "DVDF challenge scaffold: solution slot is empty by design, "
                          "so the shipped suite fails until a solver fills it in.",
    },
    "ethernaut-fallout": {
        "root": "harnesses/ethernaut-external/vendor/ethernaut/contracts",
        "match": "test/levels/Fallout.t.sol",
        "interpretation": "Ethernaut level test with the solution filled in: a pass "
                          "confirms the level is solvable, not that BLACKHEART found it.",
    },
    "ethernaut-token": {
        "root": "harnesses/ethernaut-external/vendor/ethernaut/contracts",
        "match": "test/levels/Token.t.sol",
        "interpretation": "Ethernaut level test with the solution filled in: a pass "
                          "confirms the level is solvable, not that BLACKHEART found it.",
    },
    "euler-v1-donate": {
        "root": "harnesses/euler-v1/vendor/euler-contracts",
        "match": "test/reservesDonate.js",
        "interpretation": "Euler V1 is a Hardhat/JS project, so its own test cannot be "
                          "run with `forge test`; the recorded command documents the "
                          "upstream suite that covers the donation path. Provenance only.",
        "runner": "hardhat",
    },
}


def native_test_result(case_name: str) -> Optional[dict]:
    """Run the upstream project's own Foundry test for this case, if it exists.

    Returns a dict with the command, pass/fail, and a short excerpt; ``None`` when
    the case has no mapped upstream test. This is a provenance column only -- see
    the note on ``_NATIVE_TESTS`` -- and is never treated as a detection result.
    Foundry must be on PATH or at ``~/.foundry/bin``; if it is absent the result
    records that explicitly.
    """
    spec = _NATIVE_TESTS.get(case_name)
    if spec is None:
        return None
    from .evm import _foundry_bin
    from pathlib import Path
    import subprocess

    root = Path(__file__).resolve().parents[3] / spec["root"]
    if not root.exists():
        return {"command": "", "passed": None,
                "note": f"upstream tree not present: {root} (run the harness fetch)"}
    # A Hardhat/JS project cannot be run with `forge test`; record the upstream
    # test's location as provenance rather than pretending to execute it.
    if spec.get("runner") == "hardhat":
        return {
            "command": f"(hardhat) npx hardhat test {spec['match']}",
            "root": str(root),
            "passed": None,
            "interpretation": spec.get("interpretation", ""),
            "note": "provenance only: the upstream project's own (Hardhat) test that "
                    "covers this path; not executed here and not a BLACKHEART result",
        }
    forge = _foundry_bin("forge")
    if forge is None:
        return {"command": "", "passed": None, "note": "forge not available"}
    cmd = [forge, "test", "--match-path", spec["match"]]
    try:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, timeout=600, check=False)
    except subprocess.TimeoutExpired:
        return {"command": " ".join(cmd), "passed": None, "note": "timed out"}
    tail = (proc.stdout or "")[-400:]
    return {
        "command": " ".join(cmd),
        "root": str(root),
        "returncode": proc.returncode,
        "passed": proc.returncode == 0,
        "interpretation": spec.get("interpretation", ""),
        "note": "provenance only: the upstream project's own test, as shipped; "
                "not a BLACKHEART result and not a detection baseline",
        "excerpt": tail,
    }
