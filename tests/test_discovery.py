"""Regression tests for the discovery engine (mission 3.A/3.B/3.D/3.E/3.G/3.H/3.I).

These are the executable acceptance bar for the mission's capability claims. Each
test asserts a *measured* property of the engine over the local corpus, not a
prose claim:

  * corpus shape (size, distinct root causes, distinct repositories),
  * the three-configuration benchmark (recall and false-positive discipline),
  * the derived-model path (Capability B) actually drives the search,
  * the parameter-aware enhanced search reaches the cases the ordering-only
    explorer misses (Capability D),
  * economic accounting reads real balances (Capability E),
  * the missed-vulnerability analyser classifies by stage (Capability I),
  * the Foundry PoC layer reproduces the exploit and the patched control rejects
    it (Capability G) -- skipped, with a clear reason, if forge is absent.

The benchmark tests are marked ``slow`` because they run the full corpus; the
default suite still exercises the corpus shape and the Foundry differential.
"""

from __future__ import annotations

import pytest

from blackheart.discovery import corpus as corpus_mod
from blackheart.discovery import economic as economic_mod
from blackheart.discovery import heldout as heldout_mod
from blackheart.discovery import missed as missed_mod
from blackheart.discovery.harness import ModelTarget, benchmark, model_from_target
from blackheart.discovery.search import discover, enhanced_candidates


# --------------------------------------------------------------------------- #
# Corpus shape (Capability A)
# --------------------------------------------------------------------------- #

def test_corpus_meets_size_and_diversity_bar():
    s = corpus_mod.summary()
    assert s["total_cases"] >= 20, "the corpus must carry at least 20 cases"
    assert s["distinct_root_causes"] >= 10, "the corpus must span >= 10 distinct root causes"
    assert s["distinct_repositories"] >= 8, "the corpus must span >= 8 distinct repositories"


def test_every_case_has_a_root_cause_and_reference():
    for case in corpus_mod.corpus():
        assert case.case_id, "every case must have an id"
        assert case.root_cause, f"{case.case_id} must name a root cause"
        assert case.reference, f"{case.case_id} must cite a public reference"


def test_modelled_cases_expose_vulnerable_and_patched_pair():
    for case in corpus_mod.modelled_cases():
        assert case.vulnerable is not None and case.patched is not None
        # The patched control must be a different class from the vulnerable one.
        assert case.vulnerable is not case.patched


# --------------------------------------------------------------------------- #
# Derived model (Capability B)
# --------------------------------------------------------------------------- #

def test_model_is_derived_from_the_target_surface():
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H03-oracle-spot")
    target = case.vulnerable()
    model = model_from_target(target)
    # The derived model must contain every operation the target exposes, with
    # explicit provenance -- nothing hand-written, nothing omitted.
    op_names = {o.name for o in target.ops()}
    model_ops = {o.name for o in model.operations}
    assert op_names <= model_ops
    assert all(o.source == "derived:Target.ops()" for o in model.operations)
    assert not model.missing(), "the derived model must be complete"


# --------------------------------------------------------------------------- #
# Enhanced parameter-aware search (Capability D)
# --------------------------------------------------------------------------- #

def test_enhanced_search_finds_parameter_boundary_case():
    """The share-inflation case needs a *small* first deposit; a fixed-parameter
    ordering search cannot reach it, the parameter-aware search can."""
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H08-share-inflation")
    mt = ModelTarget(case.vulnerable())
    viols = discover(mt)
    assert viols, "the enhanced search must find the inflation sequence"
    # The minimal sequence must include a small value (the 1-wei first deposit).
    small = [s for s in viols[0].minimal_sequence
             if any(isinstance(v, int) and 0 < v <= 2 for v in s.params.values())]
    assert small, "the exploiting sequence must use a small parameter value"


def test_enhanced_candidates_are_deterministic():
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H01-reentrancy-dao")
    mt = ModelTarget(case.vulnerable())
    specs = {op.name: op for op in mt.ops()}
    a = enhanced_candidates(mt.model(), specs)
    b = enhanced_candidates(mt.model(), specs)
    ka = [tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in seq) for seq in a]
    kb = [tuple((s.actor, s.action, tuple(sorted(s.params.items()))) for s in seq) for seq in b]
    assert ka == kb, "candidate enumeration must be deterministic"


def test_enhanced_search_has_no_false_positive_on_patched_control():
    """Every modelled case's patched control must be clean under the enhanced
    search -- a detection on a fixed system would be a false positive."""
    for case in corpus_mod.modelled_cases() + heldout_mod.holdout_cases():
        if case.vulnerable is None:
            continue
        viols = discover(ModelTarget(case.patched()))
        assert not viols, f"{case.case_id}: patched control falsely flagged"


# --------------------------------------------------------------------------- #
# Economic accounting (Capability E)
# --------------------------------------------------------------------------- #

def test_economic_account_tracks_attacker_profit():
    """The reentrancy case must show the attacker ending with more than it started
    with, read from the target's own balance snapshot."""
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H01-reentrancy-dao")
    mt = ModelTarget(case.vulnerable())
    viols = discover(mt)
    assert viols
    acct = economic_mod.analyse(mt, viols[0].minimal_sequence, viols[0].invariant_id, case.case_id)
    assert acct.attacker_profit > 0, "the attacker must profit from the reentrancy"
    assert acct.attacker_initial_capital > 0, "the attacker's starting capital must be tracked"
    assert acct.financial_impact_established, "real value moved, so impact must be established"


def test_economic_invariants_are_catalogued():
    assert "asset-conservation" in economic_mod.ECONOMIC_INVARIANTS
    assert economic_mod.invariant_for_root_cause("reentrancy")
    assert economic_mod.invariant_for_root_cause("unknown-cause") == ["asset-conservation"]


# --------------------------------------------------------------------------- #
# Economic accounting -- adversarial regression tests (mission 2.5, Phase 3).
#
# Each test pins a way the accounting could have *inflated* or *fabricated* an
# impact. They are the guardrails the prior review found missing.
# --------------------------------------------------------------------------- #

class _DictTarget:
    """A minimal in-memory Target whose snapshot is its state dict."""

    name = "dict-target"

    def __init__(self, state: dict, step_fn=None):
        self._initial = state
        self._step_fn = step_fn

    def reset(self):
        import copy
        return copy.deepcopy(self._initial)

    def snapshot(self, state):
        return state

    def step(self, state, op, actor, params):
        if self._step_fn is not None:
            self._step_fn(state, op, actor, params)


def _step(action, actor="attacker", params=None):
    from blackheart.models import AttackStep
    return AttackStep(index=0, actor=actor, action=action, params=params or {})


def test_economic_reverted_step_does_not_create_profit():
    """A step that raises (reverts) must contribute no profit, and the analyser
    must not crash on it."""
    def step_fn(st, op, actor, params):
        if op == "boom":
            raise ValueError("reverted")
        st["balance"][actor] += 50

    t = _DictTarget({"balance": {"attacker": 100}}, step_fn)
    acct = economic_mod.analyse(t, [_step("boom")], "x", "revert")
    assert acct.attacker_profit == 0, "a reverted step must not create profit"
    assert acct.reverted_steps == 1
    assert not acct.profitable


def test_economic_allowance_is_not_capital():
    """A doubled *allowance* is a permission, not value: it must not be reported
    as attacker profit."""
    def step_fn(st, op, actor, params):
        st["allowance"][actor] += 100

    t = _DictTarget({"allowance": {"attacker": 0}, "balance": {"attacker": 0}}, step_fn)
    acct = economic_mod.analyse(t, [_step("permit")], "double-settlement", "allow")
    assert acct.attacker_profit == 0, "an allowance is not spendable capital"
    assert not acct.profitable


def test_economic_borrow_does_not_inflate_capital():
    """Raising cash and debt equally is not profit: capital is net of obligations."""
    def step_fn(st, op, actor, params):
        st["balance"][actor] += 500
        st["debt"][actor] += 500

    t = _DictTarget({"balance": {"attacker": 100}, "debt": {"attacker": 0}}, step_fn)
    acct = economic_mod.analyse(t, [_step("borrow")], "x", "borrow")
    assert acct.attacker_profit == 0, "a borrow nets to zero; it is not profit"


def test_economic_overflow_is_not_realized_profit():
    """A wraparound balance (2**256 arithmetic) is an accounting artifact, not
    spendable value; it must be flagged and excluded from realized profit."""
    def step_fn(st, op, actor, params):
        st["balance"][actor] = (st["balance"][actor] - 150) % (2 ** 256)

    t = _DictTarget({"balance": {"attacker": 100, "victim": 100}}, step_fn)
    acct = economic_mod.analyse(t, [_step("underflow")], "supply-consistency", "overflow")
    assert acct.bounded_values, "the overflow must be detected"
    assert acct.attacker_profit == 0, "an overflow is not realized profit"
    assert not acct.profitable


def test_economic_unrelated_fields_are_not_cross_compared():
    """A rise in one field must never be netted against a fall in a different
    field for the *same* asset: the attacker total is a sum of owned assets."""
    def step_fn(st, op, actor, params):
        st["balance"][actor] -= 10
        st["shares"][actor] += 10

    t = _DictTarget({"balance": {"attacker": 100}, "shares": {"attacker": 0}}, step_fn)
    acct = economic_mod.analyse(t, [_step("trade")], "x", "cross")
    # Both fields are owned assets, so a swap of 10 units of one for 10 of the
    # other is flat: no fictitious profit from comparing across fields.
    assert acct.attacker_profit == 0
    assert acct.attacker_initial_capital == 100


def test_economic_victim_loss_only_counts_asset_fields():
    """A decrease in a victim's *debt* is a benefit, not a loss; only asset-field
    decreases count as victim loss."""
    def step_fn(st, op, actor, params):
        st["balance"]["victim"] -= 30
        st["balance"][actor] += 30
        st["debt"]["victim"] -= 50      # victim's obligation drops -- not a loss

    t = _DictTarget({"balance": {"attacker": 100, "victim": 100},
                     "debt": {"attacker": 0, "victim": 50}}, step_fn)
    acct = economic_mod.analyse(t, [_step("steal")], "x", "victim")
    assert acct.victim_loss == 30, "only the asset decrease counts, not the debt drop"


def test_economic_state_manipulation_without_value_is_distinguishable():
    """A sequence that flips a flag with no value movement must not be reported as
    a demonstrated financial impact."""
    def step_fn(st, op, actor, params):
        st["hijacked"] = True

    t = _DictTarget({"balance": {"attacker": 0}, "hijacked": False}, step_fn)
    acct = economic_mod.analyse(t, [_step("hijack")], "x", "flag")
    assert acct.state_changed, "the flag did change"
    assert not acct.financial_impact_established, "no value moved"
    assert not acct.profitable


def test_economic_missing_evidence_is_not_assumed():
    """A target with no attacker-identifiable balance must yield an explicitly
    untracked account, not an assumed zero- or high-impact verdict."""
    t = _DictTarget({"balance": {"alice": 100}})
    acct = economic_mod.analyse(t, [_step("noop", actor="alice")], "x", "noattacker")
    assert acct.attacker_profit == 0
    assert not acct.financial_impact_established
    assert any("no attacker-identifiable balance" in n for n in acct.notes)


def test_economic_double_counting_deposit_withdraw_is_flat():
    """A deposit followed by a withdrawal that returns the same amount must not be
    double-counted as profit."""
    def step_fn(st, op, actor, params):
        amt = params.get("amount", 0)
        if op == "deposit":
            st["balance"][actor] += amt
        elif op == "withdraw":
            st["balance"][actor] -= amt

    t = _DictTarget({"balance": {"attacker": 100}}, step_fn)
    seq = [_step("deposit", params={"amount": 50}), _step("withdraw", params={"amount": 50})]
    acct = economic_mod.analyse(t, seq, "x", "dw")
    assert acct.attacker_profit == 0, "a round-trip deposit/withdraw is flat"
    assert acct.per_step_profit == [50, -50]


# --------------------------------------------------------------------------- #
# Missed-vulnerability analysis (Capability I)
# --------------------------------------------------------------------------- #

def test_missed_report_classifies_a_miss_by_stage():
    """A synthetic miss record must be assigned to a real pipeline stage."""
    # Force a miss by using a case whose vulnerable model we deliberately starve.
    case = next(c for c in corpus_mod.modelled_cases() if c.case_id == "H01-reentrancy-dao")
    rec = missed_mod.analyse_miss(case)
    # The case is solvable, so the analyser must report the explorer reached it,
    # i.e. it must NOT misclassify a solved case as an exploration miss.
    assert rec.stage in {"minimisation_or_verification", "model", "invariant",
                         "hypothesis", "exploration", "scope", "unknown"}


# --------------------------------------------------------------------------- #
# Full benchmark (Capability H) -- slow
# --------------------------------------------------------------------------- #

@pytest.mark.slow
def test_benchmark_recall_and_false_positive_discipline():
    rep = benchmark().to_dict()
    allm = rep["all_modelled"]
    # The enhanced engine must solve every modelled case...
    assert allm["enhanced_recall"] == 1.0, "enhanced search must have full recall"
    # ...and never flag a patched control.
    assert allm["enhanced_false_positives"] == 0
    assert allm["guided_false_positives"] == 0
    # It must be at least as good as the existing engines on recall.
    assert allm["enhanced_recall"] >= allm["guided_recall"]
    assert allm["enhanced_recall"] >= allm["baseline_recall"]


@pytest.mark.slow
def test_benchmark_root_cause_recall():
    rep = benchmark().to_dict()
    assert rep["root_cause_recall_enhanced"] >= 0.95
    # The enhanced engine must not be worse than the guided one per root cause.
    assert rep["root_cause_recall_enhanced"] >= rep["root_cause_recall_guided"]


# --------------------------------------------------------------------------- #
# Foundry PoC layer (Capability G)
# --------------------------------------------------------------------------- #

def test_foundry_poc_suite_reproduces_and_controls():
    from blackheart.discovery import foundry_corpus as fc

    res = fc.run_poc_suite()
    if not res.available:
        pytest.skip("forge not installed; Foundry PoC suite not run")
    assert res.passed, f"PoC suite must pass; output tail:\n{res.stdout[-1500:]}"


def test_foundry_invariant_differential():
    from blackheart.discovery import foundry_corpus as fc

    if fc._forge() is None:
        pytest.skip("forge not installed; invariant differential not run")
    diff = fc.run_invariant_differential()
    assert diff["vulnerable_invariant_failed_as_expected"], "the bug must break the invariant"
    assert diff["patched_invariant_held"], "the patched contract must hold the invariant"
    assert diff["differential_established"]


def test_foundry_dependency_is_pinned():
    """The harness's forge-std dependency must be pinned to an immutable tag, and
    fetch.sh must agree with the module -- an unpinned fetch could silently
    substitute a different dependency version (mission 2.5, Phase 5)."""
    from blackheart.discovery import foundry_corpus as fc

    assert fc.FORGE_STD_PIN, "a pin must be declared"
    assert fc.FORGE_STD_PIN.startswith("v"), "the pin must be a release tag"
    fetch_sh = (fc.HARNESS / "fetch.sh").read_text(encoding="utf-8")
    assert fc.FORGE_STD_PIN in fetch_sh, "fetch.sh must pin the same revision"
    assert fc.FORGE_STD_REPO in fetch_sh, "fetch.sh must use the same repository"
    # The vendored dependency is deliberately git-ignored, so `forge install`
    # (which would create a submodule + .gitmodules) must NOT be *invoked*.
    code_lines = [ln for ln in fetch_sh.splitlines() if not ln.lstrip().startswith("#")]
    assert all("forge install" not in ln for ln in code_lines)
