"""Real-source Hyperliquid Arbitrum bridge harness (opt-in).

Runs ``forge test`` against the *actual* in-scope Hyperliquid bridge source
(``Bridge2.sol``) fetched by ``harnesses/hyperliquid-bridge/fetch.sh``. Opt-in
because it needs Foundry and a one-time fetch (the vendored source and its
dependencies are git-ignored). When those are absent the test skips with an
actionable message rather than failing — a skip is not a pass.

The assertions encode the *falsification* of the bridge attack hypotheses: forged
signatures, signature reordering/duplication, withdrawal replay/double-payout,
premature finalization, role confusion, cross-action replay and permit replay are
all blocked, and the stateful solvency invariants hold. A future source revision
that regressed any of these would fail this test.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent.parent / "harnesses" / "hyperliquid-bridge"
FORGE = shutil.which("forge")
DEPS_PRESENT = (HARNESS / "vendor" / "src" / "Bridge2.sol").exists()


@pytest.mark.skipif(FORGE is None, reason="forge not on PATH; install Foundry to run this")
@pytest.mark.skipif(
    not DEPS_PRESENT,
    reason="bridge source/deps not fetched; run harnesses/hyperliquid-bridge/fetch.sh",
)
def test_real_bridge_resists_attack_suite_and_holds_invariants():
    proc = subprocess.run(
        [FORGE, "test", "-vv"],
        cwd=HARNESS,
        capture_output=True,
        text=True,
        timeout=900,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"forge test failed:\n{out}"
    # The adversarial suite and the stateful invariants must both be present and green.
    assert "Bridge2Test" in out
    assert "Bridge2Invariants" in out
    assert "Bridge2LifecycleInvariants" in out
    assert "0 failed" in out, out
    assert "15 passed" in out, out  # the adversarial Bridge2Test suite
    # The fork-mapping test skips offline; a skip is not a pass, so require the
    # offline suite to have run its 15 adversarial tests.
    # Withdrawal invariants (Bridge2Invariants) + lifecycle invariants
    # (Bridge2LifecycleInvariants) must all be present and green.
    for inv in (
        "invariant_funds_conserved",
        "invariant_broken_quorum_never_registered",
        "invariant_no_double_payout",
        "invariant_invalidated_never_finalized",
        "invariant_epoch_matches_expected",
        "invariant_pending_epoch_ahead",
        "invariant_attacker_never_set_pending",
    ):
        assert inv in out, f"missing invariant in forge output: {inv}"
