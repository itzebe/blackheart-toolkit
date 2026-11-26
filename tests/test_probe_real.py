"""End-to-end: the probe runs REAL compiled mainnet bytecode (WETH9) offline.

The runtime bytecode is committed as a fixture (tests/fixtures/weth9_runtime.hex) so this
test needs no network. WETH9 is a small, stable, open-source mainnet contract; if evmworld
can execute it, the probe is not limited to hand-assembled fixtures.
"""

import pathlib

from blackheart.probe import probe

_HEX = pathlib.Path(__file__).parent / "fixtures" / "weth9_runtime.hex"


def test_probe_executes_real_weth9_runtime_bytecode():
    code = bytes.fromhex(_HEX.read_text().strip())
    assert len(code) > 2000
    res = {r.selector: r for r in probe(code, ["0xd0e30db0", "0x2e1a7d4d"])}
    # deposit() and withdraw(0) reach a non-reverting terminal state on real compiled code.
    assert res["0xd0e30db0"].outcome == "SUCCESS"
    assert res["0x2e1a7d4d"].outcome == "SUCCESS"
    # is_lead = non-reverting reach (the design signal); writes = actually changed state.
    assert res["0xd0e30db0"].is_lead is True
    assert res["0xd0e30db0"].writes is False  # deposit(0) changes nothing -> not a stateful lead


def test_representative_args_and_the_writes_signal():
    code = bytes.fromhex(_HEX.read_text().strip())
    zero = probe(code, ["0x2e1a7d4d"])[0]                                # withdraw(0)
    real = probe(code, ["0x2e1a7d4d"], args=(1).to_bytes(32, "big"))[0]  # withdraw(1), zero balance
    assert zero.outcome == "SUCCESS" and zero.writes is False            # reach, but no state change
    assert real.outcome != "SUCCESS" and real.writes is False            # correctly gated by the arg
