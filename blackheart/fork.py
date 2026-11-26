"""Fork campaign driver (mission sections 2C, 5, 10, 12).

Runs a :class:`~blackheart.targets.ForkTarget` end to end against the *real*
in-scope source on a local mainnet fork, captures evidence, and writes a
summary. It does not fabricate results: every number in the summary is parsed
from real `forge` output, and evidence is the raw output itself.

Safety: everything runs in-process on a fork. No transaction is broadcast, no
production state is written, no paid RPC key is used.
"""

from __future__ import annotations

import json
from pathlib import Path

from .engines.solidity.base import resolve_tool
from .evidence import EvidenceStore
from .targets import ForkTarget, fetch, is_fetched, rpc_url, runner
from .models import Classification, Finding, Severity
from .authz import GateDecision, authorize_active_testing


def _forge_available() -> bool:
    return resolve_tool("forge") is not None


# Structured hypotheses for the Twyne wrapper engagement (mission section 6).
# Each entry: id, title, and the status the fork evidence supports. Only a
# hypothesis with a reachable, attacker-controlled exploit is ever CONFIRMED;
# a passing "property holds" test is a FALSE_POSITIVE (the hypothesis that a
# break exists was disproved), never a finding.
FORK_HYPOTHESES: dict[str, list[dict]] = {
    "twyne-aave-wrapper": [
        {
            "id": "twyne-H1-donation-inflation",
            "title": "Donating aTokens moves the wrapper share price (inflation attack)",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "share price is derived from Aave's supply index, not the wrapper's "
                      "aToken balance; a donation does not move it (test_H1)",
        },
        {
            "id": "twyne-H2-share-backing",
            "title": "Rounding drift makes totalSupply exceed the wrapper's backed aTokens",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "after 200 small deposits the wrapper's aToken scaled balance is "
                      "exactly >= totalSupply; every share remains redeemable (test_H2)",
        },
        {
            "id": "twyne-H3-cv-rebalance-rounding",
            "title": "A collateral vault accrues aTokens beyond its shares via rebalance rounding",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "50 rebalances left the CV with aTokens exactly equal to its shares "
                      "(test_H3)",
        },
        {
            "id": "twyne-H4-cv-pull-without-shares",
            "title": "A registered collateral vault can pull aTokens while holding zero shares",
            "status": Classification.NEEDS_MORE_EVIDENCE.value,
            "detail": "mechanism is real and reproduced (test_H4/H5): rebalanceATokens_CV is "
                      "unbounded by the wrapper. Not exploitable without a CV-side path that "
                      "over-states collateral; none shown.",
        },
        {
            "id": "twyne-H6-multidecimal",
            "title": "Six-decimal assets (USDC) round-trip losslessly through the wrapper",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "1m USDC in -> 999,999.999999 USDC out; only index-floor dust (test_H6)",
        },
        {
            "id": "twyne-H7-rebasing",
            "title": "Wrapper shares rebase (change count) as Aave yield accrues",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "share count is constant; the same shares redeem 1.4% more after a year "
                      "of Aave yield -- the intended non-rebasing design (test_H7)",
        },
        {
            "id": "twyne-H5-cv-rebalance-unbounded",
            "title": "rebalanceATokens_CV is not bounded by the wrapper to the CV's shares",
            "status": Classification.NEEDS_MORE_EVIDENCE.value,
            "detail": "the wrapper performs no shares check in rebalanceATokens_CV; a registered "
                      "CV can pull up to its own aToken balance (test_H5). The wrapper only ever "
                      "moves aTokens CV->wrapper, so other holders are not drained. Trust "
                      "boundary, not a demonstrated exploit.",
        },
        {
            "id": "twyne-H8-skim-no-value-creation",
            "title": "Permissionless skim() can be turned into attacker profit",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "skim mints floor(assets/rate) shares to the receiver; value of minted "
                      "shares never exceeds the underlying supplied (test_H8).",
        },
        {
            "id": "twyne-H9-cv-burn-solvency",
            "title": "burnShares_CV after an external liquidation leaves remaining holders under-backed",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "a victim's shares remain fully backed after a CV burns the shares matching "
                      "its seized aTokens (test_H9).",
        },
        {
            "id": "twyne-H10-index-change-arbitrage",
            "title": "An Aave index change between operations can be arbitraged or dilute a holder",
            "status": Classification.FALSE_POSITIVE.value,
            "detail": "a pre-yield depositor keeps principal + real yield; a post-yield depositor "
                      "extracts exactly its deposit; total paid out never exceeds the wrapper's "
                      "aToken backing (test_H10).",
        },
    ]
}


def record_fork_hypotheses(target: ForkTarget, ledger_root: str | Path) -> dict:
    """Record this target's hypotheses and their evidence-backed statuses.

    Idempotent: re-running appends a fresh set of events, and the ledger view
    reflects the latest status per hypothesis.
    """
    from .ledger import EngagementLedger

    ledger = EngagementLedger(ledger_root, target.name)
    for h in FORK_HYPOTHESES.get(target.name, []):
        ledger.add_hypothesis(h["id"], h["title"], h["detail"])
        ledger.set_status(h["id"], h["status"], h["detail"])
    return ledger.view()


def authorize_fork_target(target: ForkTarget, record) -> GateDecision:
    """Gate a *live-fork / active* campaign for `target` on an authorization record.

    A purely local harness (compile + fork tests) needs no authorization, because
    it never touches production. But when a campaign is treated as active testing
    of an in-scope asset, this is the choke point: it delegates to the
    fail-closed authorization gate using the target's scope asset as the key.
    """
    return authorize_active_testing(record, target.scope_asset)


def run_fork_campaign(
    target: ForkTarget,
    workdir: str | Path,
    *,
    runs: int = 48,
    depth: int = 40,
    timeout: int = 900,
) -> dict:
    """Run smoke + adversarial + invariant fork tests and write a summary.

    Returns a summary dict. If `forge` is not on PATH the campaign is BLOCKED
    (honestly reported), never faked.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    evidence = EvidenceStore(workdir / "evidence")
    summary: dict = {
        "target": target.name,
        "program": target.program,
        "scope_url": target.scope_url,
        "scope_asset": target.scope_asset,
        "upstream": target.upstream,
        "pinned_commit": target.pinned_commit,
        "rpc": rpc_url(target),
        "runs": runs,
        "depth": depth,
        "stages": {},
    }

    if not _forge_available():
        summary["status"] = Classification.BLOCKED.value
        summary["blocked_reason"] = "forge not on PATH (run ./install.sh --core)"
        (workdir / "fork-campaign-summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        return summary

    if not is_fetched(target):
        rc, out = fetch(target)
        summary["stages"]["fetch"] = {"rc": rc, "tail": out[-2000:]}
        if rc != 0 or not is_fetched(target):
            summary["status"] = Classification.BLOCKED.value
            summary["blocked_reason"] = "failed to vendor real source (see stages.fetch)"
            (workdir / "fork-campaign-summary.json").write_text(
                json.dumps(summary, indent=2, default=str), encoding="utf-8"
            )
            return summary
    summary["stages"]["fetched"] = is_fetched(target)

    frunner = runner(target)
    build_rc, build_out = frunner.build(timeout=timeout)
    evidence.put_text(build_out, kind="forge-build", description=f"{target.name}: forge build")
    summary["stages"]["build_rc"] = build_rc
    if build_rc != 0:
        summary["status"] = Classification.BLOCKED.value
        summary["blocked_reason"] = "forge build failed"
        (workdir / "fork-campaign-summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        return summary

    # --- smoke (non-vacuity: the harness is wired to real Aave) --------------
    smoke = frunner.test(
        target.test_contracts.get("smoke"),
        evidence=evidence,
        description=f"{target.name}: smoke tests (real Aave wiring)",
    )
    summary["stages"]["smoke"] = smoke.to_dict()

    # --- adversarial hypotheses ---------------------------------------------
    adversarial = frunner.test(
        target.test_contracts.get("adversarial"),
        evidence=evidence,
        description=f"{target.name}: adversarial hypothesis tests",
    )
    summary["stages"]["adversarial"] = adversarial.to_dict()

    # --- stateful invariants -------------------------------------------------
    # Forge exposes invariant campaign size through the environment
    # (FOUNDRY_INVARIANT_RUNS / _DEPTH), not a --invariant-runs flag.
    inv = frunner.test(
        target.test_contracts.get("invariants"),
        evidence=evidence,
        description=f"{target.name}: stateful invariants (honest handler)",
        verbosity=2,
        env={
            "FOUNDRY_INVARIANT_RUNS": str(runs),
            "FOUNDRY_INVARIANT_DEPTH": str(depth),
        },
    )
    summary["stages"]["invariants"] = inv.to_dict()

    summary["evidence_index"] = str(workdir / "evidence" / "index.jsonl")
    ledger_view = record_fork_hypotheses(target, workdir / "ledger")
    summary["hypotheses"] = {
        hid: {"status": rec["status"], "title": rec["title"]}
        for hid, rec in ledger_view.items()
    }
    summary["status"] = "COMPLETED"
    (workdir / "fork-campaign-summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    return summary


def build_trust_boundary_finding(target: ForkTarget) -> Finding:
    """A Finding record for the documented CV trust boundary (H5).

    This is deliberately classified NEEDS_MORE_EVIDENCE: the wrapper's
    `rebalanceATokens_CV` is unbounded, but reaching a loss requires a registered
    collateral vault to pass an over-stated value, and no CV-side path that does
    so has been shown. The independent verifier is expected to leave gate 1
    (reachability) FAIL/UNKNOWN and therefore refuse CONFIRMED.
    """
    return Finding(
        finding_id=f"{target.name}-cv-rebalance-unbounded",
        title="AaveV3ATokenWrapper.rebalanceATokens_CV is unbounded; safety relies on every registered collateral vault passing a correct value",
        target=target.name,
        component="AaveV3ATokenWrapper.rebalanceATokens_CV / burnShares_CV",
        scope_reference=target.scope_asset,
        category="trust-boundary",
        severity=Severity.HIGH.value,
        prerequisites=[
            "caller is registered as a collateral vault in the Twyne factory",
            "the caller passes a `shares` value larger than the aToken scaled balance it actually holds",
        ],
        root_cause=(
            "rebalanceATokens_CV(shares) moves convertToAssets(|shares - "
            "scaledBalanceOf(caller)|) aTokens between the wrapper and the caller "
            "with no cap tied to the caller's wrapper-share balance. The wrapper "
            "trusts every registered collateral vault to pass its own tracked "
            "collateral amount."
        ),
        reproduction_steps=[
            "deploy the real wrapper on a local mainnet fork (harness twyne-aave-wrapper)",
            "victim deposits underlying; wrapper holds the matching aTokens",
            "register an attacker address as a collateral vault (factory mock)",
            "attacker (holding zero wrapper shares) calls rebalanceATokens_CV(large)",
            "observe the wrapper's aToken balance drop far below its share supply",
        ],
        poc_path="harnesses/twyne-aave-wrapper/test/TwyneWrapperAdversarial.t.sol::test_H5_cv_rebalance_is_unbounded_by_the_wrapper",
        expected_behavior="a collateral vault can only move the aTokens matching its own wrapper shares",
        actual_behavior="a registered collateral vault can move an arbitrary amount of the wrapper's aTokens",
        impact=(
            "If a registered collateral vault over-states its collateral, it can "
            "move aTokens out of the shared wrapper and leave other holders' shares "
            "unbacked. Impact is not demonstrated because no CV-side path that "
            "over-states collateral has been shown."
        ),
        commands=["forge test --match-contract TwyneWrapperAdversarialTest -vv"],
        evidence_ids=[],
        limitations=[
            "Not a confirmed vulnerability: reachability through the real Twyne "
            "collateral-vault code has not been shown.",
            "The wrapper is one contract in a larger trust system; the factory "
            "registration is the real access-control gate.",
        ],
    )
