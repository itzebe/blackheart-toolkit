"""Benchmark the executed (runtime) path against the in-memory baseline.

This extends the existing benchmark interpretation rather than replacing it. The
mission retains the earlier finding (equal detection and false-positive rates,
fewer sequences guided, a large sequence-count reduction on the decoy-heavy case,
baseline better on the small held-out pair) and adds the runtime axes the new
capability must be judged on:

  * **Detection rate** -- did execution against the running app find the flaw?
  * **False-positive rate** -- did it wrongly report the secure control?
  * **Executed vs generated sequences** -- how many sequences were actually run
    against the app, versus generated as candidates?
  * **Runtime and resource cost** -- wall-clock and executed operations.
  * **Reproduction success rate** -- did the minimised sequence re-execute and
    still violate from a clean state?
  * **Independent-verification success rate** -- how many reached
    INDEPENDENTLY_VERIFIED.
  * **Secure-control behaviour** -- the differential result.
  * **Held-out performance** -- the target the adapter was not tuned against.
  * **Failures / unsupported operation types** -- reported, not hidden.

Configuration is disclosed and deterministic: each case uses a fixed seed and a
fixed exploration config. Small samples are reported as small; no statistical
significance is claimed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from ..explore import ExploreConfig
from .execute import run_runtime_discovery
from .harness_apps import APP_PAIRS, DEVELOPMENT_APPS, make_app


@dataclass
class RuntimeCase:
    app: str
    suite: str                       # "development" | "heldout" | "control"
    invariant: str
    description: str
    executed: bool = False
    detected: bool = False
    false_positive: bool = False     # only meaningful for a control row
    sequences_executed: int = 0
    steps_executed: int = 0
    seconds: float = 0.0
    minimal_len: int = 0
    reproduced: bool = False
    independently_verified: bool = False
    verdict: str = ""
    # in-memory random baseline on the same app (fair ablation; the baseline
    # cannot execute over HTTP, so it runs the same operations against an
    # in-memory instance of the same app)
    baseline_detected: bool = False
    baseline_false_positive: bool = False
    baseline_seqs_to_detect: int = 0
    guided_seqs_to_detect: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "app": self.app,
            "suite": self.suite,
            "invariant": self.invariant,
            "description": self.description,
            "executed": self.executed,
            "detected": self.detected,
            "false_positive": self.false_positive,
            "sequences_executed": self.sequences_executed,
            "steps_executed": self.steps_executed,
            "seconds": self.seconds,
            "minimal_len": self.minimal_len,
            "reproduced": self.reproduced,
            "independently_verified": self.independently_verified,
            "verdict": self.verdict,
            "baseline_detected": self.baseline_detected,
            "baseline_false_positive": self.baseline_false_positive,
            "baseline_seqs_to_detect": self.baseline_seqs_to_detect,
            "guided_seqs_to_detect": self.guided_seqs_to_detect,
            "errors": list(self.errors),
        }


@dataclass
class RuntimeBenchmark:
    seed: int = 0
    guided_runs: int = 200
    cases: list[RuntimeCase] = field(default_factory=list)

    def summary(self) -> dict:
        vuln = [c for c in self.cases if c.suite in ("development", "heldout")]
        control = [c for c in self.cases if c.suite == "control"]
        heldout = [c for c in self.cases if c.suite == "heldout"]
        dev = [c for c in self.cases if c.suite == "development"]

        def rate(cases, attr):
            return round(sum(1 for c in cases if getattr(c, attr)) / len(cases), 4) if cases else 0.0

        return {
            "config": {"seed": self.seed, "guided_runs": self.guided_runs,
                       "note": "deterministic; small sample (one app per class)"},
            "detection_rate": rate(vuln, "detected"),
            "false_positive_rate": rate(control, "false_positive"),
            "development_detection_rate": rate(dev, "detected"),
            "heldout_detection_rate": rate(heldout, "detected"),
            "reproduction_success_rate": rate(vuln, "reproduced"),
            "independent_verification_rate": rate(vuln, "independently_verified"),
            "secure_control_held": all(not c.false_positive for c in control),
            "sequences_executed_total": sum(c.sequences_executed for c in self.cases),
            "steps_executed_total": sum(c.steps_executed for c in self.cases),
            "seconds_total": round(sum(c.seconds for c in self.cases), 3),
            # in-memory random baseline on the *same* apps (fair ablation)
            "baseline_detection_rate": rate(vuln, "baseline_detected"),
            "baseline_false_positive_rate": rate(control, "baseline_false_positive"),
            "baseline_seqs_to_detect_total": sum(c.baseline_seqs_to_detect for c in vuln),
            "guided_seqs_to_detect_total": sum(c.guided_seqs_to_detect for c in vuln),
            "cases": len(self.cases),
        }

    def to_dict(self) -> dict:
        return {**self.summary(), "case_detail": [c.to_dict() for c in self.cases]}


def run_runtime_benchmark(*, seed: int = 0, guided_runs: int = 200) -> RuntimeBenchmark:
    """Run every evaluation pair (development + held-out) against real apps."""
    bench = RuntimeBenchmark(seed=seed, guided_runs=guided_runs)
    cfg = ExploreConfig(seed=seed)
    for vuln, guard, inv, desc in APP_PAIRS:
        suite = "development" if vuln in DEVELOPMENT_APPS else "heldout"
        bench.cases.append(_run_app(vuln, inv, desc, suite, cfg))
        bench.cases.append(_run_app(guard, inv, desc, "control", cfg))
    return bench


def _run_app(app: str, inv: str, desc: str, suite: str, cfg: ExploreConfig) -> RuntimeCase:
    case = RuntimeCase(app=app, suite=suite, invariant=inv, description=desc)
    t0 = time.monotonic()
    try:
        report = run_runtime_discovery(app, cfg=cfg).to_dict()
    except Exception as exc:  # noqa: BLE001 -- a failed run is data, not a crash
        case.errors.append(f"{type(exc).__name__}: {exc}")
        case.seconds = round(time.monotonic() - t0, 4)
        return case
    case.seconds = round(time.monotonic() - t0, 4)
    case.executed = report.get("executed", False)
    case.sequences_executed = report.get("sequences_executed", 0)
    case.steps_executed = report.get("steps_executed", 0)
    hits = [v for v in report.get("violations", []) if v["invariant_id"] == inv]
    if suite == "control":
        case.false_positive = bool(hits)
    else:
        case.detected = bool(hits)
        if hits:
            case.minimal_len = min(len(v["minimal_sequence"]) for v in hits)
    verdicts = [v for v in report.get("verdicts", []) if v["invariant_id"] == inv]
    if verdicts:
        case.verdict = verdicts[0]["disposition"]
        case.reproduced = any(
            v["checks"].get("independent_reproduction", {}).get("passed") for v in verdicts)
        case.independently_verified = any(v["disposition"] == "INDEPENDENTLY_VERIFIED"
                                          for v in verdicts)
    _run_baseline(app, inv, case, cfg)
    return case


def _run_baseline(app: str, inv: str, case: RuntimeCase, cfg: ExploreConfig) -> None:
    """In-memory random baseline + guided candidates-to-first-hit, on the same app.

    The baseline fuzzer cannot drive HTTP, so it runs the *same* app's operations
    in memory. This is the fair comparison the mission asks for: same target
    semantics, same invariant, same seed -- measuring only the search.
    """
    from ..hypotheses import HypothesisGenerator
    from ...invariants.engine import FuzzConfig, StatefulFuzzer

    try:
        target = _in_memory_target(app)
    except Exception as exc:  # noqa: BLE001
        case.errors.append(f"baseline: {type(exc).__name__}: {exc}")
        return
    fcfg = FuzzConfig(runs=cfg.variants_per_hypothesis * 8, steps_per_run=cfg.max_steps,
                      seed=cfg.seed)
    freport = StatefulFuzzer(target, fcfg).run()
    case.baseline_detected = any(f.inv_id == inv for f in freport.failures)
    case.baseline_seqs_to_detect = _seqs_to_detect_baseline(target, fcfg, inv)
    hyps = HypothesisGenerator(target.model()).generate().hypotheses
    case.guided_seqs_to_detect = _seqs_to_detect_guided(target, hyps, cfg, inv)


def _in_memory_target(app_name: str):
    """An in-memory SequenceTarget backed by a harness app's real handlers."""
    from ...invariants.engine import InvariantSpec, OpSpec
    from ..model import SequenceTarget

    app = make_app(app_name)
    invs = [InvariantSpec(i.inv_id, i.title, i.predicate) for i in app.invariants()]

    class _InMemoryApp(SequenceTarget):
        name = app_name

        def __init__(self) -> None:
            self._state = app.initial_state()
            self._ops = {op.name: op for op in app.ops()}
            self._roles = app.roles()

        def model(self):
            return app.model()

        def reset(self):
            self._state = app.initial_state()
            return self._state

        def ops(self):
            return [OpSpec(op.name, [a for a, r in self._roles.items()
                                     if not op.roles or (set(op.roles) & set(r))],
                           {"amount": [10, 100, 1000]})
                    for op in app.ops()]

        def invariants(self):
            return invs

        def step(self, state, op_name, actor, params):
            spec = self._ops.get(op_name)
            if spec is None:
                return
            if spec.roles and not (set(spec.roles) & set(self._roles.get(actor, ()))):
                return
            status, _body = spec.handler(self._state, actor, params)

        def snapshot(self, state):
            return app.snapshot(self._state)

    return _InMemoryApp()


def _seqs_to_detect_guided(target, hypotheses, cfg: ExploreConfig, invariant: str) -> int:
    from ..explore import enumerate_candidates, attack_steps_for, run_sequence

    for i, cand in enumerate(enumerate_candidates(target, hypotheses, cfg), start=1):
        _, bad = run_sequence(target, attack_steps_for(target, cand))
        if invariant in bad:
            return i
    return 0


def _seqs_to_detect_baseline(target, fcfg, invariant: str) -> int:
    import random

    from ...invariants.engine import _generate_sequence, run_sequence as engine_run

    for i in range(fcfg.runs):
        rng = random.Random(fcfg.seed + i)
        seq = _generate_sequence(target, rng, fcfg.steps_per_run)
        if invariant in engine_run(target, seq).violated:
            return i + 1
    return 0
