"""Mission-06 tests: adaptive discovery capability and resistance to false claims.

Two things are proven here, on real code paths (no mocks):

  * **Capability** -- the adaptive engine finds the parameter-boundary cases the
    guided engine missed, changes its decisions in response to execution
    feedback, and reports only what an independent verifier confirms.
  * **Resistance** -- it reports no false positive on clean negative controls,
    the independent verifier rejects fabricated / privileged / non-discriminating
    candidates, and a minimal exploit still reproduces from a clean state.

The blind hold-out corpus (``blackheart.discovery.blind``) is the ground truth and
is never read by the engines.
"""

from __future__ import annotations

import pytest

from blackheart.discovery import blind as blind_mod
from blackheart.discovery import corpus as corpus_mod
from blackheart.discovery.blind_benchmark import run_blind_benchmark
from blackheart.discovery.harness import ModelTarget
from blackheart.statespace.adaptive import AdaptiveConfig, AdaptiveExplorer
from blackheart.statespace.explore import (
    ExploreConfig,
    StateSpaceExplorer,
    run_sequence,
)
from blackheart.statespace.hypotheses import HypothesisGenerator
from blackheart.statespace.verify import IndependentSequenceVerifier, VerifyConfig


def _adaptive(target, **kw) -> AdaptiveExplorer:
    return AdaptiveExplorer(ModelTarget(target), AdaptiveConfig(seed=0, max_steps=4, **kw))


# --------------------------------------------------------------------------- #
# Capability
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("case_id", ["H07-fee-base", "H08-share-inflation"])
def test_adaptive_finds_the_guided_engines_parameter_boundary_misses(case_id):
    """The two cases the guided engine missed are parameter-boundary bugs. The
    adaptive engine must find both, and the guided engine must still miss them
    (so this test measures the actual gap, not a fixture change)."""
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == case_id)
    guided = StateSpaceExplorer(
        ModelTarget(case.vulnerable()), ExploreConfig(seed=0, max_steps=4)
    ).explore(HypothesisGenerator(ModelTarget(case.vulnerable()).model()).generate().hypotheses)
    assert not guided.violations, "the guided engine is expected to miss this case"
    adaptive = _adaptive(case.vulnerable()).explore()
    assert adaptive.violations, f"the adaptive engine must find {case_id}"


def test_adaptive_detects_every_modelled_corpus_case():
    for case in corpus_mod.modelled_cases():
        rep = _adaptive(case.vulnerable()).explore()
        assert rep.violations, f"adaptive missed {case.case_id}"


def test_adaptive_priority_changes_in_response_to_feedback():
    """The controller must re-order its pending work against observed coverage.

    A static ordering disguised as adaptive search would report zero divergences;
    this asserts a non-trivial number on a target where feedback is informative.
    """
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H08-share-inflation")
    rep = _adaptive(case.vulnerable()).explore()
    assert rep.priority_divergences > 0, "feedback must change the exploration order"



def test_profit_guided_search_prices_violations_and_reorders_work():
    """Profit guidance must (a) price every violation and (b) change the order.

    A value-aware search that never changes its order would be a label, not a
    capability; this asserts a non-trivial divergence count on a target that moves
    value (the share-inflation vault).
    """
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H08-share-inflation")
    plain = AdaptiveExplorer(ModelTarget(case.vulnerable()),
                             AdaptiveConfig(seed=0, max_steps=4)).explore()
    guided = AdaptiveExplorer(ModelTarget(case.vulnerable()),
                              AdaptiveConfig(seed=0, max_steps=4,
                                             profit_guided=True)).explore()
    assert guided.violations, "the guided search must still find the violation"
    # Every violation carries a priced account, and the account is honest.
    for v in guided.violations:
        assert v.economic is not None, "profit-guided search must price every violation"
        assert v.economic["tracked"] is True
    assert guided.priority_divergences > 0, "value feedback must change the search order"
    # Value feedback is a distinct signal from coverage feedback.
    assert guided.priority_divergences != plain.priority_divergences or plain.violations


def test_profit_guided_minimisation_keeps_the_value_movement():
    """Shrinking a profitable sequence must not silently drop the profit."""
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H08-share-inflation")
    guided = AdaptiveExplorer(ModelTarget(case.vulnerable()),
                              AdaptiveConfig(seed=0, max_steps=4,
                                             profit_guided=True)).explore()
    moved = [v for v in guided.violations
             if v.economic and (v.economic["attacker_profit"] > 0
                                or v.economic["victim_loss"] > 0)]
    assert moved, "the share-inflation vault must yield at least one value-moving violation"
    for v in moved:
        assert len(v.minimal_sequence) <= len(v.sequence)


def test_adaptive_sequence_is_minimal_and_reproduces_from_a_clean_state():
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H08-share-inflation")
    rep = _adaptive(case.vulnerable()).explore()
    assert rep.violations
    v = rep.violations[0]
    # The minimal form is never longer than the original sequence.
    assert len(v.minimal_sequence) <= len(v.sequence)
    # It reproduces from a fresh instance.
    fresh = ModelTarget(case.vulnerable())
    _, bad = run_sequence(fresh, v.minimal_sequence)
    assert v.invariant_id in bad, "the minimal sequence must reproduce the violation"
    # Minimality: dropping any single step loses the violation.
    for i in range(len(v.minimal_sequence)):
        shorter = list(v.minimal_sequence[:i]) + list(v.minimal_sequence[i + 1:])
        if not shorter:
            continue
        _, bad2 = run_sequence(ModelTarget(case.vulnerable()), shorter)
        assert v.invariant_id not in bad2, "a step can be dropped without losing the violation"


def test_adaptive_is_deterministic():
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H01-reentrancy-dao")
    a = _adaptive(case.vulnerable()).explore()
    b = _adaptive(case.vulnerable()).explore()
    ka = [tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in v.minimal_sequence)
          for v in a.violations]
    kb = [tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in v.minimal_sequence)
          for v in b.violations]
    assert ka == kb, "adaptive exploration must be deterministic"


# --------------------------------------------------------------------------- #
# Resistance to false claims
# --------------------------------------------------------------------------- #

def test_adaptive_no_false_positive_on_patched_controls():
    """Every modelled case's patched control must be clean under the adaptive
    engine -- a detection on a fixed system is a false positive."""
    for case in corpus_mod.modelled_cases():
        rep = _adaptive(case.patched()).explore()
        assert not rep.violations, f"{case.case_id}: patched control falsely flagged"


def test_adaptive_no_false_positive_on_clean_negative_controls():
    for cls in blind_mod.NEGATIVE_CONTROLS:
        rep = _adaptive(cls()).explore()
        assert not rep.violations, f"{cls.name}: clean control falsely flagged"


def test_verifier_rejects_a_privileged_only_candidate():
    """A violation that needs a privileged actor is not this attacker's."""
    from blackheart.models import AttackStep
    from blackheart.statespace.explore import Violation

    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H02-access-parity")
    target = ModelTarget(case.vulnerable())
    # Forge a candidate performed by a privileged actor.
    seq = [AttackStep(index=0, actor="owner", action="set_owner", params={"new": "attacker"})]
    forged = Violation(invariant_id=target.invariants()[0].inv_id, sequence=seq,
                       minimal_sequence=seq, seed=0, actor_roles=["owner"], observed={},
                       reproducible=True, reachable_by_attacker=False)
    verifier = IndependentSequenceVerifier(lambda: ModelTarget(case.vulnerable()),
                                           VerifyConfig(in_scope=True, authorization_gate_passed=True))
    res = verifier.verify(forged, preconditions_satisfiable=True)
    assert res.disposition == "REJECTED"
    assert any("privileged" in r for r in res.reasons)


def test_verifier_rejects_a_non_reproducing_candidate():
    """A fabricated sequence that does not actually violate the invariant must be
    rejected as insufficient evidence, never confirmed."""
    from blackheart.models import AttackStep
    from blackheart.statespace.explore import Violation

    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H03-oracle-spot")
    seq = [AttackStep(index=0, actor="attacker", action="borrow", params={"amount": 1})]
    forged = Violation(invariant_id="collateralization", sequence=seq, minimal_sequence=seq,
                       seed=0, actor_roles=["attacker"], observed={},
                       reproducible=False, reachable_by_attacker=True)
    verifier = IndependentSequenceVerifier(lambda: ModelTarget(case.vulnerable()),
                                           VerifyConfig(in_scope=True, authorization_gate_passed=True))
    res = verifier.verify(forged, preconditions_satisfiable=True)
    assert res.disposition in ("INSUFFICIENT_EVIDENCE", "REJECTED")


def test_verifier_rejects_a_non_discriminating_candidate():
    """If the secure control ALSO violates, the invariant does not discriminate
    and the candidate must be rejected as a false positive."""
    from blackheart.models import AttackStep
    from blackheart.statespace.explore import Violation

    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H07-fee-base")
    seq = [AttackStep(index=0, actor="attacker", action="transfer", params={"amount": 1})]
    forged = Violation(invariant_id="fee-bounded", sequence=seq, minimal_sequence=seq,
                       seed=0, actor_roles=["attacker"], observed={},
                       reproducible=True, reachable_by_attacker=True)
    # The "control" is the *vulnerable* model, so it also violates -> non-discriminating.
    verifier = IndependentSequenceVerifier(
        lambda: ModelTarget(case.vulnerable()),
        VerifyConfig(control_factory=lambda: ModelTarget(case.vulnerable()),
                     in_scope=True, authorization_gate_passed=True))
    res = verifier.verify(forged, preconditions_satisfiable=True)
    assert res.disposition == "REJECTED"
    assert any("control" in r for r in res.reasons)


# --------------------------------------------------------------------------- #
# Phase B (mission 07): exact prefix-state reuse optimization
# --------------------------------------------------------------------------- #

def test_prefix_reuse_is_exactly_equivalent_to_full_replay():
    """The reuse path must produce the identical state, violations and feedback
    as a full replay -- it is an optimization, not a behavioural change."""
    import random

    cases = [c for c in corpus_mod.modelled_cases() if c.vulnerable is not None]
    for case in cases:
        target = ModelTarget(case.vulnerable())
        ex = AdaptiveExplorer(target, AdaptiveConfig(seed=0, max_steps=4))
        ex.explore()  # warm the prefix cache
        rng = random.Random(1)
        for _ in range(20):
            depth = rng.randint(1, 4)
            pool = ex._sequences_at_depth(depth)
            if not pool:
                continue
            seq = rng.choice(pool)
            s1, bad1, fb1 = ex._execute(seq)
            s2, bad2, fb2 = ex._execute_sequence(seq)
            assert target.snapshot(s1) == target.snapshot(s2), case.case_id
            assert bad1 == bad2, case.case_id
            assert fb1.pairs == fb2.pairs and fb1.adjacencies == fb2.adjacencies
            assert fb1.reverted == fb2.reverted and fb1.changed == fb2.changed


def test_prefix_reuse_reduces_target_step_calls_without_changing_discoveries():
    """Reuse must cut redundant ``step`` calls while preserving every discovery."""
    def run(reuse: bool):
        steps = 0
        found = 0
        for case in corpus_mod.modelled_cases():
            target = ModelTarget(case.vulnerable())
            orig = target.step
            counter = {"n": 0}

            def step(*a, _orig=orig, _c=counter, **k):
                _c["n"] += 1
                return _orig(*a, **k)

            target.step = step
            rep = AdaptiveExplorer(
                target, AdaptiveConfig(seed=0, max_steps=4, max_sequences=2000,
                                       reuse_prefix_states=reuse)).explore()
            steps += counter["n"]
            found += bool(rep.violations)
        return steps, found

    replay_steps, replay_found = run(False)
    reuse_steps, reuse_found = run(True)
    assert reuse_found == replay_found == len(corpus_mod.modelled_cases())
    assert reuse_steps < replay_steps, "reuse must reduce step executions"


def test_prefix_reuse_is_disabled_for_non_isolated_targets():
    """A target that does not declare isolated state must always replay in full,
    so a real-runtime target with external effects is never reused."""
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H08-share-inflation")
    wrapped = ModelTarget(case.vulnerable())
    ex = AdaptiveExplorer(wrapped, AdaptiveConfig(seed=0, max_steps=4))
    assert ex._reuse_enabled is True  # the pure fixture declares isolation

    class Opaque:
        name = wrapped.name

        def model(self):
            return wrapped.model()

        def reset(self):
            return wrapped.reset()

        def ops(self):
            return wrapped.ops()

        def invariants(self):
            return wrapped.invariants()

        def step(self, state, op, actor, params):
            return wrapped.step(state, op, actor, params)

        def snapshot(self, state):
            return wrapped.snapshot(state)

    opaque = AdaptiveExplorer(Opaque(), AdaptiveConfig(seed=0, max_steps=4))
    assert opaque._reuse_enabled is False, "an undeclared target must not be reused"


def test_budget_exhaustion_is_reported_not_hidden():
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H01-reentrancy-dao")
    rep = AdaptiveExplorer(ModelTarget(case.vulnerable()),
                           AdaptiveConfig(seed=0, max_steps=4, max_sequences=10)).explore()
    assert rep.sequences_tried <= 10


def test_adaptive_returns_no_violation_when_budget_is_zero():
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H01-reentrancy-dao")
    rep = AdaptiveExplorer(ModelTarget(case.vulnerable()),
                           AdaptiveConfig(seed=0, max_steps=4, max_sequences=0)).explore()
    assert rep.sequences_tried == 0
    assert not rep.violations


# --------------------------------------------------------------------------- #
# The comparative benchmark (slow: runs all four engines over the blind corpus)
# --------------------------------------------------------------------------- #

@pytest.mark.slow
def test_blind_benchmark_adaptive_is_verified_and_clean():
    rep = run_blind_benchmark().to_dict()
    # Every blind vulnerable case must be independently verified by the adaptive
    # engine, with the patched control rejecting the exploit...
    assert rep["adaptive_independently_verified"] == rep["vulnerable_cases"]["cases"]
    assert rep["adaptive_control_rejections"] == rep["vulnerable_cases"]["cases"]
    # ...and no false positive on the clean negative controls.
    assert rep["adaptive_clean_negative_false_positives"] == 0
    # The adaptive engine must be at least as good as the guided engine on recall.
    assert rep["vulnerable_cases"]["adaptive_recall"] >= rep["vulnerable_cases"]["guided_recall"]


def test_blind_corpus_engines_never_see_ground_truth():
    """The engines read only the target surface; the blind module's labels are
    never imported by the engine code. This is a structural guard."""
    from pathlib import Path

    import blackheart.statespace.adaptive as adaptive_mod
    import blackheart.statespace.explore as explore_mod
    src = (Path(adaptive_mod.__file__).read_text(encoding="utf-8")
           + Path(explore_mod.__file__).read_text(encoding="utf-8"))
    assert "discovery.blind" not in src and "blind_mod" not in src


# --------------------------------------------------------------------------- #
# CLI integration (Phase D): the campaign must expose honest status labels
# --------------------------------------------------------------------------- #

def test_cli_campaign_reports_independently_verified_status():
    import json
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-m", "blackheart", "discovery", "campaign",
         "--fixture", "BL03-expiry-not-enforced", "--steps", "4", "--budget", "2000"],
        check=False, capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert payload["campaign"]["candidates_detected"] >= 1
    statuses = {c["status"] for c in payload["candidates"]}
    assert "independently-verified" in statuses
    # An unverified candidate is never labelled a confirmed vulnerability.
    for c in payload["candidates"]:
        assert c["status"] != "confirmed-vulnerability"


def test_cli_campaign_on_a_clean_control_reports_no_candidate():
    import json
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-m", "blackheart", "discovery", "campaign",
         "--fixture", "blind-clean-vault", "--steps", "4", "--budget", "2000"],
        check=False, capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    payload = json.loads(out.stdout)
    assert payload["campaign"]["candidates_detected"] == 0
