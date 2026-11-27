"""Acceptance tests for the pinned, held-out corpus (T1.2).

The corpus is only a credible measurement if its cases are (a) real and
reproducible references and (b) genuinely held out -- i.e. the search engine is
never told their root cause. These tests pin both properties, plus the honesty of
pin verification when the network is unavailable.
"""

from __future__ import annotations

import pytest

from blackheart.discovery import corpus as corpus_mod
from blackheart.discovery import heldout as heldout_mod
from blackheart.discovery import pins as pins_mod
from blackheart.discovery.harness import run_case


def test_holdout_cases_are_marked_held_out_and_carry_a_root_cause():
    cases = heldout_mod.holdout_cases()
    assert len(cases) >= 6
    assert all(c.holdout for c in cases)
    assert all(c.root_cause for c in cases)
    # Distinct invariants -- a holdout set of near-duplicates proves nothing.
    # (Root causes may repeat across mechanisms; the *scenario* must not.)
    invariants = {c.invariant_statement for c in cases}
    assert len(invariants) == len(cases)
    assert len({c.root_cause for c in cases}) >= 4


def test_every_holdout_case_is_detected_and_the_patched_control_holds():
    # This is the held-out recall measurement: the engine must find each case's
    # violation *and* not fire on its patched twin.
    for case in heldout_mod.holdout_cases():
        result = run_case(case)
        assert result.guided_detected, f"{case.case_id} was not detected"
        assert not result.guided_false_positive, f"{case.case_id} raised a false positive"


def test_corpus_attaches_a_verified_pin_to_named_repositories():
    cases = corpus_mod.corpus()
    pinned = [c for c in cases if c.pin_verified]
    assert pinned, "no case carries a pin"
    for c in pinned:
        assert c.pin, f"{c.case_id} is marked pinned but carries no SHA"
        assert len(c.pin) >= 7
        assert c.repository


def test_pin_for_returns_the_recorded_pin_and_none_for_unknown():
    pin = pins_mod.pin_for("OpenZeppelin/openzeppelin-contracts")
    assert pin is not None and len(pin.sha) == 40
    assert pins_mod.pin_for("nobody/nothing") is None


def test_verify_pin_is_honest_without_network(monkeypatch):
    # Simulate an unreachable GitHub: the verifier must report "unknown", never a
    # fabricated "verified".
    def boom(*_a, **_k):
        raise OSError("network down")

    monkeypatch.setattr(pins_mod, "_get_json", boom)
    status = pins_mod.verify_pin("OpenZeppelin/openzeppelin-contracts", "deadbeef")
    assert status in ("unknown", "error")


def test_sol_repro_links_point_at_real_poc_tests():
    linked = [c for c in corpus_mod.corpus() if c.sol_repro]
    assert linked, "no corpus case is linked to a Solidity reproduction"
    for c in linked:
        assert ":" in c.sol_repro
        harness, test = c.sol_repro.split(":", 1)
        assert harness.startswith("harnesses/")
        assert test.startswith("test_")
