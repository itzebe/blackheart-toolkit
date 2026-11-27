"""Tests for the second wave of attack-class models and the coverage gate.

The eight classes here (cross-chain replay, AMM slippage, silent transfer
failure, flash-loan governance, griefing DoS, reward manipulation, storage
collision, decimals mismatch) were previously described only as prose in the
objectives catalogue. These tests assert each new model behaves with the same
non-vacuity discipline as every other pair -- the vulnerable model breaks with an
*attacker-reachable* violation, the guarded control holds -- and that the coverage
ledger and the doctor/CI gate treat an unmodelled category as a hard failure.
"""

from __future__ import annotations

import json

import pytest

from blackheart.cli import main
from blackheart.invariants import FuzzConfig, StatefulFuzzer
from blackheart.invariants.coverage import (
    CATEGORY_KIND,
    PROSE_ONLY,
    Coverage,
    coverage_report,
    coverage_summary,
    modelled_categories,
)
from blackheart.invariants.defi_targets import (
    CrossDomainBridge,
    DecimalVault,
    Governor,
    GuardedCrossDomainBridge,
    GuardedDecimalVault,
    GuardedGovernor,
    GuardedLiquidator,
    GuardedProxyStorage,
    GuardedRewardPool,
    GuardedSilentFailBridge,
    GuardedSlippageAmm,
    Liquidator,
    ProxyStorage,
    RewardPool,
    SilentFailBridge,
    SlippageAmm,
)
from blackheart.invariants.registry import DIFFERENTIAL_PAIRS, TARGET_SPECS, make_target
from blackheart.objectives import available_categories

# (vulnerable, guarded, invariant that must break) for each new class.
NEW_CLASSES = [
    (CrossDomainBridge, GuardedCrossDomainBridge, "message-executed-at-most-once"),
    (SlippageAmm, GuardedSlippageAmm, "constant-product-non-decreasing"),
    (SilentFailBridge, GuardedSilentFailBridge, "credit-matches-real-transfer"),
    (Governor, GuardedGovernor, "no-pass-without-snapshot-power"),
    (Liquidator, GuardedLiquidator, "liquidation-never-blocked"),
    (RewardPool, GuardedRewardPool, "no-over-distribution"),
    (ProxyStorage, GuardedProxyStorage, "admin-slot-unwritable-by-logic"),
    (DecimalVault, GuardedDecimalVault, "credit-never-exceeds-deposited-value"),
]


def _run(cls, runs=500, steps=12):
    return StatefulFuzzer(cls(), FuzzConfig(runs=runs, steps_per_run=steps, seed=0)).run()


# --------------------------------------------------------------------------- #
# Per-class contrast: the vulnerable model breaks, the guarded one holds
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("vuln,guard,inv_id", NEW_CLASSES,
                         ids=[c[0].__name__ for c in NEW_CLASSES])
def test_class_breaks_when_vulnerable_and_holds_when_guarded(vuln, guard, inv_id):
    v = _run(vuln)
    g = _run(guard)
    assert v.failures, f"{vuln.__name__}: the modelled attack must be findable"
    # Every violation must be attributable to the attacker, not a victim-only path.
    assert all(f.reachable_by_attacker for f in v.failures), \
        f"{vuln.__name__}: a violation was not attacker-reachable"
    assert any(f.inv_id == inv_id for f in v.failures), \
        f"{vuln.__name__}: expected invariant {inv_id!r} to break"
    assert g.failures == [], f"{guard.__name__}: the guarded control must hold"


@pytest.mark.parametrize("vuln,guard,inv_id", NEW_CLASSES,
                         ids=[c[0].__name__ for c in NEW_CLASSES])
def test_each_pair_is_registered_and_contrasts_through_the_registry(vuln, guard, inv_id):
    vuln_name = vuln.name
    guard_name = guard.name
    cfg = FuzzConfig(runs=400, steps_per_run=12, seed=0)
    vr = StatefulFuzzer(make_target(vuln_name), cfg).run()
    gr = StatefulFuzzer(make_target(guard_name), cfg).run()
    assert [f for f in vr.failures if f.reachable_by_attacker], \
        f"{vuln_name}: no attacker-reachable violation"
    assert not gr.failures, f"{guard_name}: must not violate any invariant"


def test_guarded_controls_differ_from_vulnerable_in_one_method():
    """The contrast must isolate the defect, not be a redesign."""
    # AMM: only the swap formula differs.
    a = SlippageAmm(); ga = GuardedSlippageAmm()
    assert a._out_a_for_b(50, a.reset()) != ga._out_a_for_b(50, ga.reset())
    # Cross-chain: only the allowed-gate differs. m1 is on this domain (allowed
    # either way); m2 declares another domain, so the guarded bridge refuses it.
    b = CrossDomainBridge(); gb = GuardedCrossDomainBridge()
    st, gst = b.reset(), gb.reset()
    assert b._allowed(st, "m1") is True and gb._allowed(gst, "m1") is True
    assert b._allowed(st, "m2") is True and gb._allowed(gst, "m2") is False
    # Governance: only the vote-power source differs.
    v = Governor(); gv = GuardedGovernor()
    vs, gvs = v.reset(), gv.reset()
    vs.balance["attacker"] = gvs.balance["attacker"] = 100
    vs.snapshot["attacker"] = gvs.snapshot["attacker"] = 0
    assert v._vote_power(vs, "attacker") == 100
    assert gv._vote_power(gvs, "attacker") == 0
    # Griefing: only the liquidation gate differs.
    l = Liquidator(); gl = GuardedLiquidator()
    ls, gls = l.reset(), gl.reset()
    ls.frozen["attacker"] = gls.frozen["attacker"] = True
    assert l._can_liquidate(ls) is False and gl._can_liquidate(gls) is True
    # Storage: only the reserved-slot check differs.
    p = ProxyStorage(); gp = GuardedProxyStorage()
    assert p._write_allowed(0) is True and gp._write_allowed(0) is False
    # Decimals: only the credit formula differs.
    d = DecimalVault(); gd = GuardedDecimalVault()
    assert d._credit_for("eighteen", 1, d.reset()) != gd._credit_for("eighteen", 1, gd.reset())
    # Reward: only the stake checkpoint differs.
    r = RewardPool(); gr = GuardedRewardPool()
    rs, grs = r.reset(), gr.reset()
    rs.stake["attacker"] = grs.stake["attacker"] = 100
    rs.reward_index = grs.reward_index = 5_000_000
    r._checkpoint(rs, "attacker"); gr._checkpoint(grs, "attacker")
    assert rs.reward_debt["attacker"] == 0          # vulnerable: no checkpoint
    assert grs.reward_debt["attacker"] == 500        # guarded: 100 * 5e6 / 1e6


def test_silent_transfer_failure_guarded_drops_failed_credit():
    """The guarded bridge credits only what the transfer actually moved."""
    b = GuardedSilentFailBridge()
    st = b.reset()
    b.step(st, "deposit", "attacker", {"amount": 1000})   # above the token cap -> moved 0
    assert st.credited["attacker"] == 0
    assert st.false_credits == 1
    b.step(st, "deposit", "attacker", {"amount": 100})    # within the cap -> moved 100
    assert st.credited["attacker"] == 100
    assert st.vault == 100


def test_new_classes_reach_a_confirmed_finding_end_to_end(tmp_path):
    from blackheart.demonstrations import run_class_demonstration

    for vuln, guard, _ in NEW_CLASSES:
        summary = run_class_demonstration(
            tmp_path / vuln.name, pair=f"{vuln.name}/{guard.name}",
            runs=300, steps_per_run=12,
        )
        assert summary["status"] == "CONFIRMED", f"{vuln.name} did not confirm"
        assert summary["guarded_failures"] == 0
        assert summary["report_path"]


# --------------------------------------------------------------------------- #
# The coverage ledger and the eight new objective categories
# --------------------------------------------------------------------------- #

NEW_CATEGORIES = [
    "cross-chain-replay", "slippage-manipulation", "silent-transfer-failure",
    "governance-manipulation", "denial-of-service", "reward-manipulation",
    "storage-collision", "decimals-mismatch",
]


def test_the_eight_new_categories_are_declared_and_modelled():
    declared = set(available_categories())
    modelled = set(modelled_categories())
    for cat in NEW_CATEGORIES:
        assert cat in declared, f"{cat} is not a declared objective category"
        assert cat in modelled, f"{cat} has no executable model"


def test_every_declared_category_still_resolves_to_a_real_pair():
    kinds = {s.kind for s in TARGET_SPECS}
    for cov in coverage_report():
        if cov.coverage is not Coverage.MODELLED:
            continue
        specs = [s for s in TARGET_SPECS if s.kind == cov.kind]
        assert any(not s.guarded for s in specs), f"{cov.category}: no vulnerable model"
        assert any(s.guarded for s in specs), f"{cov.category}: no guarded control"


def test_coverage_is_full_and_category_kinds_all_exist():
    summary = coverage_summary()
    assert summary["unmodelled"] == 0
    # Every category is either executed or *explicitly* recorded as prose-only.
    # A prose-only class is a named, reasoned gap -- never silent, and never
    # counted as coverage.
    assert summary["modelled"] + summary["prose_only"] == summary["categories"]
    assert summary["prose_only"] == len(PROSE_ONLY)
    kinds = {s.kind for s in TARGET_SPECS}
    for cat, kind in CATEGORY_KIND.items():
        assert kind in kinds, f"{cat} maps to unknown kind {kind!r}"


def test_every_new_pair_is_in_the_differential_catalogue():
    named = {(v, g) for v, g, _ in DIFFERENTIAL_PAIRS}
    for vuln, guard, _ in NEW_CLASSES:
        assert (vuln.name, guard.name) in named, \
            f"{vuln.name}/{guard.name} is registered but not in DIFFERENTIAL_PAIRS"


# --------------------------------------------------------------------------- #
# The gate: doctor and CI must fail on an unmodelled category
# --------------------------------------------------------------------------- #

def test_doctor_reports_attack_class_coverage(capsys):
    main(["doctor"])
    text = capsys.readouterr().out
    assert "attack-class coverage" in text
    assert f"{coverage_summary()['modelled']}/{coverage_summary()['categories']}" in text


def test_doctor_fails_on_an_unmodelled_category(monkeypatch, capsys):
    """A category with no model is a hard doctor failure, not a warning.

    Simulated by removing a pair from the registry the ledger resolves against --
    the ledger must notice the kind no longer has both members and fail closed.
    """
    from blackheart.invariants import registry

    # Drop the guarded half of the 'rounding' kind: the pair is no longer complete.
    trimmed = [s for s in registry.TARGET_SPECS if s.name != "rounding-guarded"]
    monkeypatch.setattr(registry, "TARGET_SPECS", trimmed)
    import blackheart.invariants.coverage as cov_mod
    monkeypatch.setattr(cov_mod, "TARGET_SPECS", trimmed)

    rc = main(["doctor"])
    text = capsys.readouterr().out
    assert "attack-class coverage" in text
    assert "rounding-precision" in text          # the named gap is surfaced
    assert rc == 1                                # hard failure, not a warning


def test_cli_coverage_exits_nonzero_on_a_gap(monkeypatch, capsys):
    from blackheart.invariants import registry

    trimmed = [s for s in registry.TARGET_SPECS if s.name != "rounding-guarded"]
    monkeypatch.setattr(registry, "TARGET_SPECS", trimmed)
    import blackheart.invariants.coverage as cov_mod
    monkeypatch.setattr(cov_mod, "TARGET_SPECS", trimmed)

    rc = main(["coverage"])
    text = capsys.readouterr().out
    assert "rounding-precision" in text
    assert rc != 0


def test_cli_coverage_json_payload_is_complete(capsys, tmp_path):
    out = tmp_path / "cov.json"
    assert main(["coverage", "--out", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert payload["summary"]["unmodelled"] == 0
    cats = {c["category"] for c in payload["categories"]}
    assert set(NEW_CATEGORIES) <= cats
