"""Real-source Twyne Aave aToken wrapper harness (opt-in).

Runs ``forge test`` against the *actual* wrapper source, if it has been fetched.
This is opt-in because it needs Foundry and a one-time ``fetch-deps.sh`` (the
target source is BUSL-1.1 and is not committed). When those are absent the test
skips with an actionable message rather than failing — a skip is not a pass.

The point of this test is the priority research question: can wrapper-share
accounting be converted into unauthorized value extraction? The assertions below
encode the *falsification*: the real wrapper blocks the inflation attack, and the
two stateful invariants hold. If a future source revision regressed, this test
would fail.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent.parent / "harnesses" / "aave-wrapper"
FORGE = shutil.which("forge")
DEPS_PRESENT = (HARNESS / "src" / "AaveV3ATokenWrapper.sol").exists() and (
    HARNESS / "lib" / "aave-v3-origin"
).exists()


@pytest.mark.skipif(FORGE is None, reason="forge not on PATH; install Foundry to run this")
@pytest.mark.skipif(
    not DEPS_PRESENT,
    reason="wrapper source/deps not fetched; run harnesses/aave-wrapper/fetch-deps.sh",
)
def test_real_wrapper_blocks_inflation_and_holds_invariants():
    proc = subprocess.run(
        [FORGE, "test", "-vv"],
        cwd=HARNESS,
        capture_output=True,
        text=True,
        timeout=900,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"forge test failed:\n{out}"
    # Both suites must pass: the accounting attack is blocked and the stateful
    # invariants hold against the real source.
    assert "AaveWrapperAccountingAttack" in out
    assert "AaveWrapperInvariants" in out
    assert "0 failed" in out, out
    assert "4 tests passed" in out or "4 passed" in out, out
