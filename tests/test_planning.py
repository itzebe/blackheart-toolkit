"""Policy-aware planning keeps exclusions and unknowns separate."""

from __future__ import annotations

from blackheart.objectives import TargetProfile, generate_objectives
from blackheart.planning import plan_from_policy
from blackheart.program_intel.policy import Band, ClassRule, NormalizedPolicy

PROFILE = TargetProfile(
    name="vault", kind="smart-contract", assets=["funds"],
    entry_points=["deposit", "withdraw"], external_deps=["oracle"],
)


def _policy(rule: ClassRule | None = None, *, verified: bool = True) -> NormalizedPolicy:
    return NormalizedPolicy(
        program="example",
        source_url="https://example.invalid/policy" if verified else "",
        source_text="scope: vault" if verified else "",
        class_rules=[rule] if rule else [],
    )


def test_an_explicit_exclusion_blocks_that_class():
    category = generate_objectives(PROFILE)[0].category
    plan = plan_from_policy(
        _policy(ClassRule(category, eligible=False, band=Band.MEDIUM)), PROFILE)
    assert plan.status == "PLANNED"
    assert [o.category for o in plan.blocked] == [category]
    assert all(o.category != category for o in plan.allowed)


def test_a_class_with_no_rule_is_unknown_not_allowed():
    plan = plan_from_policy(_policy(), PROFILE)
    assert plan.allowed == []
    assert plan.unknown
    assert not plan.blocked


def test_an_unverified_policy_is_advisory_only():
    plan = plan_from_policy(_policy(verified=False), PROFILE)
    assert plan.status == "UNVERIFIED_POLICY"
    assert not plan.policy_verified
    assert any("not verified" in u for u in plan.uncertainties)
