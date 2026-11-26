"""Tests for the bounty-program eligibility gate (mission sections 5 and 7).

These are the regression tests for the *authorization gate itself* the mission
asks for: an unverifiable fact must block entry, and a viable program must flow
into the active-testing gate only when its scope was captured verbatim.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackheart.eligibility import (
    ProgramEligibility,
    evaluate,
    load_programs,
    rank_programs,
    to_authorization_record,
)
from blackheart.authz import authorize_active_testing
from blackheart.scope import ScopeError, record_authorization

SCOPE_TEXT = "In scope: the target contract at 0xabc. Testing only on a local fork."


def _program(**over) -> ProgramEligibility:
    base = dict(
        program="Example",
        platform="bugcrowd",
        brief_url="https://example.test/brief",
        scope_url="https://example.test/brief",
        brief_retrieved_at="2026-11-10T00:00:00Z",
        brief_sha256="a" * 64,
        scope_sha256="b" * 64,
        scope_text=SCOPE_TEXT,
        program_active=True,
        safe_harbor=True,
        zero_cost=True,
        nigerian_eligible=True,
        payout_feasible=True,
        poc_required=True,
        assets={"0xabc": "AUTHORIZED"},
        max_reward="$10k-$100k",
        # payout_feasible=True must cite evidence, so a fully-eligible program
        # carries a dated record for it.
        evidence=["research/private/payout-eligibility-2026-11-10.md#bugcrowd-support-response"],
    )
    base.update(over)
    return ProgramEligibility(**base)


def test_all_true_program_is_viable():
    verdict = evaluate(_program())
    assert verdict.viable is True
    assert verdict.blockers == []
    assert verdict.authorized_assets == ["0xabc"]
    assert all(verdict.checks.values())


@pytest.mark.parametrize(
    "fact", ["program_active", "safe_harbor", "zero_cost", "nigerian_eligible", "payout_feasible"]
)
def test_unknown_fact_blocks_entry(fact):
    verdict = evaluate(_program(**{fact: "unknown"}))
    assert verdict.viable is False
    assert any(fact in b for b in verdict.blockers)


@pytest.mark.parametrize("fact", ["nigerian_eligible", "payout_feasible"])
def test_false_fact_blocks_entry(fact):
    verdict = evaluate(_program(**{fact: False}))
    assert verdict.viable is False
    assert any(f"{fact}=False" in b for b in verdict.blockers)


def test_missing_scope_text_fails_scope_verified():
    verdict = evaluate(_program(scope_text="", scope_sha256=""))
    assert verdict.viable is False
    assert any("scope_verified" in b for b in verdict.blockers)


def test_no_authorized_asset_blocks_entry():
    verdict = evaluate(_program(assets={"0xabc": "OUT_OF_SCOPE"}))
    assert verdict.viable is False
    assert any("AUTHORIZED" in b for b in verdict.blockers)


def test_payout_feasible_true_without_evidence_blocks_entry():
    # The gate must not trust an asserted payout fact that carries no dated
    # evidence -- this is the exact fact that gates entry for a Nigerian
    # researcher and that no brief publishes.
    verdict = evaluate(_program(evidence=[]))
    assert verdict.viable is False
    assert verdict.checks["payout_feasible"] is False
    assert any("payout_feasible" in b and "evidence" in b for b in verdict.blockers)


def test_payout_feasible_true_with_evidence_is_viable():
    verdict = evaluate(_program(evidence=["support-ticket-12345-response.txt"]))
    assert verdict.viable is True
    assert verdict.checks["payout_feasible"] is True


def test_rank_prefers_viable_over_larger_reward():
    viable = _program(program="Viable", max_reward="$1k-$10k")
    blocked = _program(program="Blocked", payout_feasible="unknown", max_reward=">$100k")
    order = [v.program for v in rank_programs([blocked, viable])]
    assert order == ["Viable", "Blocked"]


def test_rank_orders_viable_by_reward():
    small = _program(program="Small", max_reward="$1k-$10k")
    big = _program(program="Big", max_reward=">$100k")
    order = [v.program for v in rank_programs([small, big])]
    assert order == ["Big", "Small"]


def test_to_authorization_record_feeds_the_active_testing_gate(tmp_path):
    rec = to_authorization_record(_program())
    assert rec.verified is True
    # Evidence ids are attached when the record is persisted through the real path.
    record_authorization(
        rec,
        registry_path=tmp_path / "registry.jsonl",
        evidence_root=tmp_path / "evidence",
    )
    decision = authorize_active_testing(rec, "0xabc")
    assert decision.allowed is True


def test_to_authorization_record_of_blocked_program_is_not_verified():
    rec = to_authorization_record(_program(payout_feasible="unknown"))
    assert rec.verified is False
    decision = authorize_active_testing(rec, "0xabc")
    assert decision.allowed is False
    assert any("payout_feasible" in b for b in decision.blockers)


def test_record_authorization_refuses_uncaptured_scope(tmp_path):
    # A viable-looking program with no captured scope text must not be recordable
    # as VERIFIED evidence.
    rec = to_authorization_record(_program(scope_text="", scope_sha256=""))
    rec.verified = True  # force the claim; the store must still refuse it
    with pytest.raises(ScopeError):
        record_authorization(
            rec,
            registry_path=tmp_path / "registry.jsonl",
            evidence_root=tmp_path / "evidence",
        )


def test_load_programs_accepts_wrapper_and_single(tmp_path):
    one = _program(program="Solo")
    single = tmp_path / "single.json"
    single.write_text(json.dumps(one.to_dict()), encoding="utf-8")
    assert [p.program for p in load_programs(single)] == ["Solo"]

    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"programs": [one.to_dict()]}), encoding="utf-8")
    assert [p.program for p in load_programs(wrapped)] == ["Solo"]


def test_cli_evaluate_exit_codes(tmp_path, capsys):
    from blackheart.cli import main

    viable = tmp_path / "viable.json"
    viable.write_text(json.dumps({"programs": [_program().to_dict()]}), encoding="utf-8")
    assert main(["eligibility", "evaluate", "--file", str(viable)]) == 0

    blocked = tmp_path / "blocked.json"
    blocked.write_text(
        json.dumps({"programs": [_program(nigerian_eligible="unknown").to_dict()]}),
        encoding="utf-8",
    )
    assert main(["eligibility", "evaluate", "--file", str(blocked)]) == 2


def test_cli_to_scope_writes_record_and_refuses_blocked(tmp_path):
    from blackheart.cli import main

    src = tmp_path / "programs.json"
    src.write_text(json.dumps({"programs": [_program().to_dict()]}), encoding="utf-8")
    out = tmp_path / "record.json"
    assert main(["eligibility", "to-scope", "--file", str(src), "--out", str(out)]) == 0
    rec = json.loads(out.read_text(encoding="utf-8"))
    assert rec["verified"] is True
    assert rec["asset_classes"] == {"0xabc": "AUTHORIZED"}

    blocked = tmp_path / "blocked.json"
    blocked.write_text(
        json.dumps({"programs": [_program(payout_feasible="unknown").to_dict()]}),
        encoding="utf-8",
    )
    assert (
        main(["eligibility", "to-scope", "--file", str(blocked), "--out", str(tmp_path / "x.json")])
        == 2
    )
