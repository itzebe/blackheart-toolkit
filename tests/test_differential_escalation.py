"""The differential's escalation tier: a random walk is not a proof of absence.

Measured on this corpus before the tier existed (2026-11-21): a 1 run x 2 step
budget found 9/27 ground-truth pairs, 12x8 found 23/27 and 60x14 found 26/27.
Every miss was reachable within a handful of steps -- the search was the weak
link, not the model. These tests pin the escalation that closes it, and pin the
contrast (the guarded twin stays clean under the *same* exhaustive bound).
"""

import json

from blackheart.assurance import CertifyConfig, certify
from blackheart.cli import main
from blackheart.invariants.registry import make_target


def _run(tmp_path, *args):
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "diff.json"
    rc = main(["differential", *args, "--out", str(out)])
    return rc, json.loads(out.read_text(encoding="utf-8"))


def test_tiny_budget_escalation_strictly_increases_recall(tmp_path):
    """At a budget too small to sample the space, the certifier finds the rest."""
    _, plain = _run(tmp_path / "a", "--runs", "1", "--steps", "2", "--seed", "3",
                    "--depth", "0")
    _, escalated = _run(tmp_path / "b", "--runs", "1", "--steps", "2", "--seed", "3",
                        "--depth", "4")

    plain_hits = sum(r["passed"] for r in plain)
    escalated_hits = sum(r["passed"] for r in escalated)
    assert plain_hits < escalated_hits, (plain_hits, escalated_hits)
    assert escalated_hits >= 26, escalated_hits

    found_only_by_certifier = [r for r in escalated if r["detected_by"] == "certify"]
    assert found_only_by_certifier
    for record in found_only_by_certifier:
        assert record["invariants_broken"]
        assert record["witness"], "an escalated detection must carry its witness"


def test_certifier_establishes_contrast_for_the_depth_limited_pairs():
    """The two pairs a shallow bound leaves open are found at their real depth."""
    # hl-pm-liquidation: borrow past the borrow LTV, stay under the liquidation
    # threshold, then liquidate -- four steps.
    for vuln, guard, depth in (
        ("hl-pm-liquidation", "hl-pm-liquidation-guarded", 4),
        ("permit-replay", "permit-guarded", 6),
    ):
        cfg = CertifyConfig(max_depth=depth, price_findings=False)
        broken = certify(make_target(vuln), cfg)
        clean = certify(make_target(guard), cfg)
        assert broken.violations, vuln
        assert all(v["reachable_by_attacker"] for v in broken.violations), vuln
        assert not clean.violations, guard


def test_escalation_never_launders_a_guarded_break(tmp_path):
    """An escalation is only accepted when the guarded twin is certified clean.

    The guarded targets are the control: if the exhaustive search broke one too,
    the pair would prove nothing, so the differential must not pass it.
    """
    _, records = _run(tmp_path, "--runs", "1", "--steps", "2", "--seed", "3",
                      "--depth", "4")
    for record in records:
        if record["detected_by"] == "certify":
            assert record["guarded_failures"] == 0
            assert record["passed"]
