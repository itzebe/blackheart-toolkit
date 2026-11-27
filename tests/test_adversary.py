"""Adversary emulation: capability gates the campaign, authorization gates execution."""

import json

import pytest

from blackheart.adversary import (
    PROFILES,
    STAGE_ORDER,
    AdversaryProfile,
    Capability,
    Tier,
    plan_campaign,
    profile,
    scanner_contrast,
)
from blackheart.cli import main
from blackheart.mindset import OUTCOMES
from blackheart.models import AssetStatus, AuthorizationRecord

MORE_ASSETS = next(o for o in OUTCOMES if "more assets" in o)
BYPASS = next(o for o in OUTCOMES if "bypass a restriction" in o)
ABSORB = next(o for o in OUTCOMES if "absorb my loss" in o)

#: Engines a stage may name. Each is a CLI subcommand; a new stage engine must be
#: added here *and* registered in the CLI, which is what this test enforces.
REGISTERED_ENGINES = {
    "discovery", "hunt", "assure portfolio", "statespace", "value", "novelty",
}


def _record(asset: str = "flex-market", status: str = AssetStatus.AUTHORIZED.value):
    return AuthorizationRecord(
        program="Flex",
        platform="Mantis",
        target_url="https://mantis.inverse.finance/bounties/flex/flex",
        scope_url="https://mantis.inverse.finance/bounties/flex/flex",
        program_active=True,
        safe_harbor=True,
        zero_cost=True,
        nigerian_eligible=True,
        payout_feasible=True,
        assets={asset: status},
        evidence=["EV-2026-11-21"],
        verified=True,
    )


def test_objective_must_be_one_of_the_three_outcomes():
    with pytest.raises(ValueError, match="three outcomes"):
        plan_campaign(profile("opportunist"), "make money somehow", "asset")


def test_thinking_is_free_but_execution_is_gated():
    plan = plan_campaign(profile("opportunist"), MORE_ASSETS, "flex-market")
    assert plan.feasible is True          # the profile can afford the campaign
    assert plan.authorized is False       # but nothing may run
    assert plan.executable_stages() == []
    assert any("no authorization record" in b for b in plan.blocked)


def test_authorized_asset_makes_the_unprivileged_stages_executable():
    plan = plan_campaign(profile("opportunist"), MORE_ASSETS, "flex-market",
                         record=_record())
    assert plan.authorized is True
    assert [s.role for s in plan.executable_stages()] == [
        "recon", "position", "accumulate", "extract",
    ]


def test_out_of_scope_asset_is_refused_by_the_gate():
    plan = plan_campaign(profile("opportunist"), MORE_ASSETS, "flex-market",
                         record=_record(status=AssetStatus.OUT_OF_SCOPE.value))
    assert plan.authorized is False
    assert plan.executable_stages() == []
    assert any("scope gate refused" in b for b in plan.blocked)


def test_a_profile_without_capital_cannot_plan_a_theft_campaign():
    broke = AdversaryProfile(
        name="observer", tier=Tier.OPPORTUNIST, capabilities=frozenset(),
        dwell_days=0, capital_units=0, opsec="low", summary="no capital at all",
    )
    plan = plan_campaign(broke, MORE_ASSETS, "flex-market", record=_record())
    assert plan.feasible is False
    # recon is read-only, so it may still run; nothing that moves value may.
    assert not {"position", "accumulate", "extract"} & {s.role for s in plan.executable_stages()}
    assert any("needs flash-capital" in b for b in plan.blocked)
    # A restriction bypass needs no capital, so the same profile can still plan it.
    assert plan_campaign(broke, BYPASS, "flex-market").feasible is True


def test_state_grade_adds_patience_and_model_only_reach():
    plan = plan_campaign(profile("state-grade"), ABSORB, "flex-market", record=_record())
    roles = [s.role for s in plan.stages]
    assert "trigger" in roles and "persist" in roles
    trigger = next(s for s in plan.stages if s.role == "trigger")
    assert "180 days" in trigger.wait_condition

    modelled = [s for s in plan.stages if s.role.startswith("model:")]
    assert {s.role for s in modelled} == {
        "model:insider-access", "model:social-engineering",
        "model:supply-chain", "model:validator-control",
    }
    for stage in modelled:
        assert stage.executable is False
        assert stage.engine == ""


def test_a_one_transaction_profile_has_no_trigger_or_persist_stage():
    plan = plan_campaign(profile("opportunist"), MORE_ASSETS, "flex-market")
    roles = [s.role for s in plan.stages]
    assert "trigger" not in roles and "persist" not in roles
    assert any("no trigger stage" in n for n in plan.notes)
    assert any("no persist stage" in n for n in plan.notes)


def test_every_executable_stage_names_a_registered_engine():
    for name in PROFILES:
        plan = plan_campaign(profile(name), MORE_ASSETS, "asset", record=_record("asset"))
        for stage in plan.stages:
            if stage.executable:
                assert stage.engine in REGISTERED_ENGINES, (name, stage)


def test_every_stage_role_has_a_scanner_contrast():
    rows = {row["stage"] for row in scanner_contrast()}
    assert set(STAGE_ORDER) <= rows
    assert all(row["scanner_cannot"] for row in scanner_contrast())


def test_plan_is_deterministic():
    a = plan_campaign(profile("organized"), MORE_ASSETS, "asset", record=_record("asset"))
    b = plan_campaign(profile("organized"), MORE_ASSETS, "asset", record=_record("asset"))
    assert json.dumps(a.to_dict(), sort_keys=True) == json.dumps(b.to_dict(), sort_keys=True)


def test_cli_plan_and_profiles(tmp_path, capsys):
    assert main(["adversary", "profiles", "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert {p["name"] for p in listed["profiles"]} == set(PROFILES)

    authz = tmp_path / "authz.json"
    authz.write_text(json.dumps(_record().to_dict()), encoding="utf-8")
    assert main(["adversary", "plan", "--profile", "opportunist",
                 "--objective", MORE_ASSETS, "--asset", "flex-market",
                 "--authz", str(authz), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["authorized"] is True
    assert payload["stages"][0]["role"] == "recon"
    assert payload["scanner_contrast"]


def test_cli_refuses_an_unknown_profile():
    with pytest.raises(SystemExit):
        main(["adversary", "plan", "--profile", "nonexistent",
              "--objective", MORE_ASSETS, "--asset", "a"])
