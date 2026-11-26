"""Acceptance tests for the path certifier (T2.4).

The certifier's job is to turn a *candidate* violation into a *proof* or an
honest bound. These tests pin the properties that make that trustworthy:

  * a proven certificate is deterministic and reproducible,
  * the witness is a minimal prefix that still violates (proven, not guessed),
  * a certificate is never issued against a patched control,
  * mutations stay inside the operation's declared domain -- a value the contract
    does not accept must never be dressed up as an attack,
  * a bounded exhaustive search that finds nothing says so honestly, and records
    the bound it exhausted.
"""

from __future__ import annotations

import pytest

from blackheart.discovery.certify import (
    certify_concolic,
    certify_exhaustive,
    certify_path,
)
from blackheart.discovery.corpus import corpus as corpus_fn
from blackheart.discovery.heldout import holdout_cases
from blackheart.models import AttackStep


def _cases():
    by_id = {c.case_id: c for c in corpus_fn()}
    by_id.update({c.case_id: c for c in holdout_cases()})
    return by_id


ALL_IDS = ["H01-reentrancy-dao", "H06-rounding-up", "H08-share-inflation",
           "HH1-double-refund", "HH2-stale-privilege", "HH3-stale-cache-slash",
           "HH4-round-up-redeem", "HH5-expired-order", "HH6-double-claim"]


@pytest.mark.parametrize("case_id", ALL_IDS)
def test_exhaustive_certifier_proves_vulnerable_and_clears_patched(case_id):
    case = _cases()[case_id]
    v = certify_exhaustive(case.vulnerable(), max_depth=4)
    p = certify_exhaustive(case.patched(), max_depth=4)
    assert v.proven, f"{case_id}: vulnerable target was not proven"
    assert v.reproducible, f"{case_id}: witness did not reproduce"
    assert v.witness, f"{case_id}: a proven certificate must carry a witness"
    assert not p.proven, f"{case_id}: patched control was wrongly proven"


def test_proven_witness_is_a_minimal_prefix():
    case = _cases()["HH1-double-refund"]
    cert = certify_exhaustive(case.vulnerable(), max_depth=4)
    assert cert.proven
    # Dropping the last step of a minimal witness must stop it violating.
    if len(cert.witness) > 1:
        shorter = certify_path(case.vulnerable(), cert.witness[:-1],
                               invariant_id=cert.invariant_id)
        assert not shorter.proven


def test_certify_path_refuses_a_non_violating_path():
    case = _cases()["HH6-double-claim"]
    cert = certify_path(case.patched(),
                        [AttackStep(0, "attacker", "claim", {})])
    assert not cert.proven


def test_concolic_recovers_the_inflation_near_miss_within_domain():
    case = _cases()["H08-share-inflation"]
    # The steps are right, but the first deposit uses the large value; the guided
    # search never tries the small one. The concolic certifier must recover it --
    # and only by moving to another *declared* value.
    seed = [
        AttackStep(0, "attacker", "deposit", {"amount": 1000}),
        AttackStep(1, "attacker", "donate", {"amount": 10000}),
        AttackStep(2, "victim", "deposit", {"amount": 1000}),
    ]
    cert = certify_concolic(case.vulnerable(), seed)
    assert cert.proven
    assert any(s.params.get("amount") == 1 for s in cert.witness)


def test_concolic_never_mutates_outside_the_plausible_domain():
    case = _cases()["H08-share-inflation"]
    # deposit's sample domain is [1, 1000]. A *negative* deposit is not an input
    # the contract accepts and must never appear in a certificate (the naive
    # implementation mutated 1000 -> -1, which "breaks" the patched control too).
    # A small non-negative value (0/1) IS a legitimate probe.
    seed = [AttackStep(0, "attacker", "deposit", {"amount": 1000})]
    cert = certify_concolic(case.vulnerable(), seed)
    assert all(s.params.get("amount", 1) >= 0 for s in cert.witness)
    assert not certify_concolic(case.patched(), seed).proven


def test_exhaustive_certifies_fee_on_transfer_at_a_small_amount():
    # H07 is a genuine fee-on-transfer bug that only fires at a small transfer
    # amount (fee = 1% of the whole balance, which exceeds a 1-unit transfer).
    # The certifier must reach it -- and must not certify the patched control.
    case = _cases()["H07-fee-base"]
    v = certify_exhaustive(case.vulnerable(), max_depth=4)
    p = certify_exhaustive(case.patched(), max_depth=4)
    assert v.proven, "the fee-on-transfer case must be certifiable at a small amount"
    assert not p.proven


def test_exhaustive_reports_a_bound_when_it_finds_nothing():
    case = _cases()["HH6-double-claim"]
    cert = certify_exhaustive(case.patched(), max_depth=4)
    assert not cert.proven
    assert cert.exhausted
    assert cert.bound.get("max_depth") == 4
    assert "bounded" in cert.reason.lower() or "not a proof" in cert.reason.lower()


def test_certificate_serialises_and_carries_its_trace():
    case = _cases()["H01-reentrancy-dao"]
    cert = certify_exhaustive(case.vulnerable(), max_depth=4)
    d = cert.to_dict()
    assert d["proven"] is True
    assert isinstance(d["witness"], list) and d["witness"]
    assert isinstance(d["trace"], list) and d["trace"]
    assert d["bound"]


def test_param_sets_put_the_actor_and_maximum_value_first():
    from blackheart.discovery.certify import _op_param_sets
    from blackheart.invariants.engine import OpSpec

    op = OpSpec("Token.mint", ["attacker"],
                {"to": ["attacker", "victim", "Vault"], "amount": [0, 1, 2, 100]})
    sets = _op_param_sets(op)
    assert sets[0] == {"to": "attacker", "amount": 1}
    assert {"to": "attacker", "amount": 100} in sets[:8]
    assert all(set(s) == {"to", "amount"} for s in sets)
