"""Regression tests for the universal value & profitability engine.

The engine (`blackheart.value`) is the single accounting layer the discovery
benchmark, the state-space search, the campaign loop, and the CLI all share. These
tests pin the properties that make it *universal* -- it classifies value by
structure, not by a hand-maintained name list -- and the honesty rules that stop it
fabricating a financial impact.
"""

from __future__ import annotations

from blackheart.value import (
    FieldKind,
    ValueModel,
    analyse,
    classify_field,
    profit_of,
    victim_loss,
)


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


# --------------------------------------------------------------------------- #
# Classification is structural, not a name allow-list
# --------------------------------------------------------------------------- #

def test_plural_balances_is_an_asset_map():
    # The flagship ERC4626 vault uses ``balances``; the old allow-list had only
    # the singular ``balance`` and silently read the vault as having no value.
    assert classify_field("balances", {"attacker": 0, "victim": 0}) is FieldKind.ASSET
    assert classify_field("supplied", {"attacker": 0}) is FieldKind.ASSET


def test_liabilities_and_permissions_require_per_actor_structure():
    assert classify_field("debt", {"attacker": 0}) is FieldKind.LIABILITY
    assert classify_field("borrowed", {"attacker": 0}) is FieldKind.LIABILITY
    assert classify_field("allowance", {"attacker": {"victim": 5}}) is FieldKind.PERMISSION


def test_a_scalar_counter_is_not_a_permission():
    # ``total_authorized`` contains the "authoriz" token but is a counter, not a
    # grant; treating it as a permission would misread the permit target.
    assert classify_field("total_authorized", 100) is FieldKind.OTHER


def test_unknown_map_of_actors_is_read_as_an_asset():
    # A field the name-list has never seen, whose shape is a per-actor map, is
    # still value: that is what makes the engine universal.
    assert classify_field("magic_pool", {"alice": 3, "bob": 0}) is FieldKind.ASSET


def test_protocol_scalar_is_not_attacker_capital():
    # A scalar that names a value-bearing concept (``vault``) but is not a
    # per-actor map is protocol-held value: it is classified, but it is not the
    # attacker's capital.
    model = ValueModel({"vault": 500, "balances": {"attacker": 0, "victim": 0}})
    assert model.kinds["vault"] is FieldKind.PROTOCOL
    assert model.net_capital("attacker") == 0


# --------------------------------------------------------------------------- #
# Profit and victim loss
# --------------------------------------------------------------------------- #

def test_profit_of_reads_real_movement():
    def steal(state, op, actor, params):
        state["balances"]["attacker"] += 50
        state["balances"]["victim"] -= 50

    t = _DictTarget({"balances": {"attacker": 0, "victim": 50}}, steal)
    assert profit_of(t, [_step("steal")]) == 50


def test_profit_of_is_zero_without_an_attacker_actor():
    t = _DictTarget({"total_shares": 10})
    assert profit_of(t, [_step("noop")]) == 0


def test_victim_loss_counts_only_asset_fields():
    start = ValueModel({"balances": {"attacker": 0, "victim": 100},
                        "debt": {"attacker": 0, "victim": 40}})
    end = ValueModel({"balances": {"attacker": 30, "victim": 70},
                      "debt": {"attacker": 0, "victim": 0}})
    # The victim's asset drop (30) counts; the debt drop (40) is not an asset loss.
    assert victim_loss(start, end, "attacker") == 30


def test_analyse_reports_a_fabrication_free_account():
    def noop(state, op, actor, params):
        pass

    t = _DictTarget({"balances": {"attacker": 0, "victim": 0}}, noop)
    acct = analyse(t, [_step("noop")], "x", "noop")
    assert acct.attacker_profit == 0
    assert acct.victim_loss == 0
    assert not acct.financial_impact_established


# --------------------------------------------------------------------------- #
# Universality across the real executable targets (regression guard)
# --------------------------------------------------------------------------- #

def test_value_model_never_crashes_on_any_executable_target():
    """The engine must classify *every* target's reset snapshot without raising.

    The original allow-list crashed on some targets and silently read the
    flagship ERC4626 vault (which uses ``balances``, plural) as having no value.
    This pins the structural classification as the fix.
    """
    from blackheart.invariants.registry import available_targets, make_target

    for name in available_targets():
        target = make_target(name)
        ValueModel(target.snapshot(target.reset()))  # must not raise


def test_the_flagship_vault_reports_trackable_value():
    from blackheart.invariants.registry import make_target

    target = make_target("vulnerable")
    model = ValueModel(target.snapshot(target.reset()))
    assert model.attacker_actor() == "attacker"
    # The plural ``balances`` map is the attacker's capital, not an unknown field.
    assert model.kinds["balances"] is FieldKind.ASSET

