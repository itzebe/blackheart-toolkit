"""Temporal and staged scope must survive normalization and reach the gate.

QoreChain's policy opens a second scope window and withholds components that are
still under active remediation. A parser that drops those lines turns a
"not yet in scope" component into an eligible one. These tests pin the
preservation and the gate's refusal.
"""

from __future__ import annotations

from blackheart.bounty.gate import CandidateRecord, Disposition, gate, sha256_text
from blackheart.program_intel import PolicyNormalizer

POLICY = """Break QoreChain
Rewards
Critical 5,000 USDT
High 2,000 USDT
Medium 750 USDT
Low 250 USDT
Insight 100 USDT
In scope from 1 September
- Consensus and block production, including staking, slashing and distribution
- Bank module, locked-coin accounting and escrow
- ML-DSA-87 signing path and PQ key registration, Go implementation
- EVM execution lane, chain 9801
- Public RPC and API endpoints
- QoreX wallet
Components under active remediation are not in scope at opening. Each one is added, with an announcement, as its remediation lands: the CosmWasm lane, the bridge module, the dashboard application, the C and Python bindings in qorechain-pqc, and qorechain-lightnode.
Out of scope
- Volumetric and denial of service testing against production
- Social engineering of the team or the community
- Third party dependencies without a demonstrated impact on QoreChain
- Any testing on mainnet that affects real users or real funds
- Automated mass submissions
Proof of concept required
Every submission, at every severity, must include a working proof of concept against a local devnet or the public testnet. No proof of concept, no reward.
Reporting and disclosure
1 Report privately
Write to security@qore.network with a description, reproduction steps, affected commit or version, and your assessment of impact. Do not open a public GitHub issue for security reports.
"""


def _policy():
    return PolicyNormalizer().normalize(
        POLICY, program="Break QoreChain", source_url="https://qorechain.io/security"
    )


def test_second_scope_window_and_staged_components_are_preserved():
    p = _policy()
    assert p.scope_effective_from == "from 1 September"
    assert any(e.effective_from == "from 1 September" for e in p.scope)
    assert "CosmWasm lane" in p.staged_components
    assert "bridge module" in p.staged_components
    assert any("remediation" in c for c in p.special_conditions)
    assert p.uncertainties == []


def test_qorechain_payout_table_and_poc_requirement_are_parsed():
    p = _policy()
    assert p.payouts["critical"] == "Critical 5,000 USDT"
    assert p.payouts["info"] == "Insight 100 USDT"
    assert "working proof of concept" in p.poc_standard
    assert p.minimum_severity.value == "unknown" or p.minimum_severity


def _candidate(**overrides) -> CandidateRecord:
    text = "official policy text"
    values = dict(
        candidate_id="c-1",
        target="qorechain",
        component="cosmwasm",
        program="Break QoreChain",
        policy_url="https://qorechain.io/security",
        policy_verified_at="2026-11-22",
        policy_sha256=sha256_text(text),
        policy_text=text,
        reproduction_status="CONFIRMED",
        evidence_refs=["evidence-1"],
        asset_scope="in_scope",
        deployment_verified=True,
        deployment_truth={
            "status": "SOURCE_VERIFIED", "address": "0x" + "1" * 40,
            "chain_id": 9801, "source_status": "verified", "source_bound": True,
            "runtime_binding": {"status": "EXACT", "bound": True},
        },
        program_severity="high",
        reward_available=True,
        policy_sections=["In scope"],
        vulnerability_class="accounting-manipulation",
    )
    values.update(overrides)
    return CandidateRecord(**values)


def test_staged_component_is_not_payable_even_when_technically_valid():
    out = gate(_candidate(component_status="staged"))
    assert out.disposition == Disposition.VALID_NOT_PAYABLE
    assert any("staged" in b for b in out.blockers)


def test_unverified_second_scope_window_is_not_submission_ready():
    out = gate(_candidate(scope_effective_from="from 1 September",
                          scope_effective_verified=None))
    assert out.disposition == Disposition.POTENTIALLY_PAYABLE
    assert any("scope effective" in b for b in out.blockers)


def test_verified_second_scope_window_reaches_submission_ready():
    out = gate(_candidate(scope_effective_from="from 1 September",
                          scope_effective_verified=True))
    assert out.disposition == Disposition.SUBMISSION_READY
