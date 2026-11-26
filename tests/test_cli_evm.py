"""The EVM commands are wired to the tested engines, not to new logic."""

from __future__ import annotations

import json

from blackheart.cli import main


def _window() -> bytes:
    return bytes([
        0x60, 0x00, 0x35, 0x61, 0x02, 0xEE, 0x10,
        0x60, 0x00, 0x35, 0x61, 0x03, 0x20, 0x10, 0x15, 0x16,
        0x60, 0x14, 0x57, 0x00, 0x5B,
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


def _guarded() -> bytes:
    return bytes([
        0x60, 0x00, 0x35, 0x61, 0x03, 0x20, 0x10,
        0x60, 0x0B, 0x57, 0x00, 0x5B,
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])


_BRANCH = bytes([0x60, 0x00, 0x35, 0x60, 0x07, 0x57, 0x00, 0x5B, 0x00])


def _write(tmp_path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def test_symbolic_evm_reports_a_reverted_path(tmp_path, capsys):
    code = _write(tmp_path, "window.hex", _window().hex())
    rc = main(["symbolic-evm", code, "--input", "cd0=0..1000"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["reverted"] >= 1
    assert payload["paths_detail"]


def test_evm_diff_reports_the_window_divergence(tmp_path, capsys):
    vulnerable = _write(tmp_path, "v.hex", _window().hex())
    guarded = _write(tmp_path, "g.hex", _guarded().hex())
    rc = main(["evm-diff", vulnerable, guarded, "--words", "751"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["divergences"]


def test_evm_fuzz_covers_both_sides_of_a_branch(tmp_path, capsys):
    code = _write(tmp_path, "branch.hex", _BRANCH.hex())
    rc = main(["evm-fuzz", code, "--iterations", "100", "--seed", "1"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert 6 in payload["covered"]
    assert 7 in payload["covered"]


def test_verified_model_models_a_decompiled_surface(tmp_path, capsys):
    text = _write(tmp_path, "decompiled.txt",
                  "function transfer(address,uint256) external\n")
    rc = main(["verified-model", "1", "0x0000000000000000000000000000000000000000",
               "--decompiled", text])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["status"] == "UNMODELLED"
    assert payload["binding"]["source"] == "decompiled"


def test_symbolic_evm_writes_a_runnable_poc_from_the_witness(tmp_path, capsys):
    code = _write(tmp_path, "window.hex", _window().hex())
    out = tmp_path / "Witness.t.sol"
    rc = main(["symbolic-evm", code, "--input", "cd0=0..1000",
               "--poc-out", str(out)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["poc"] and payload["poc"]["calldata"].startswith("0x")
    text = out.read_text()
    assert "vm.etch" in text and "assertFalse" in text


def test_symbolic_evm_wrap_flag_reaches_an_overflow_witness(tmp_path, capsys):
    from blackheart.symbolic.evm import MASK

    code = bytes([0x7F]) + MASK.to_bytes(32, "big") + bytes([
        0x60, 0x00, 0x35, 0x01, 0x60, 0x00, 0x14,
        0x60, 0x2C, 0x57, 0x00, 0x5B,
        0x60, 0x00, 0x60, 0x00, 0xFD,
    ])
    path = _write(tmp_path, "overflow.hex", code.hex())
    out = tmp_path / "Overflow.t.sol"
    rc = main(["symbolic-evm", path, "--input", "cd0=0..10", "--wrap",
               "--poc-out", str(out)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["poc"] is not None
    assert payload["poc"]["calldata"].endswith("01")


def test_layout_diff_accepts_an_append_and_rejects_an_insert(tmp_path, capsys):
    before = _write(tmp_path, "before.json", json.dumps({
        "storage": [
            {"label": "a", "slot": 0, "offset": 0, "type": "uint256"},
            {"label": "b", "slot": 1, "offset": 0, "type": "uint256"},
        ]}))
    appended = _write(tmp_path, "appended.json", json.dumps({
        "storage": [
            {"label": "a", "slot": 0, "offset": 0, "type": "uint256"},
            {"label": "b", "slot": 1, "offset": 0, "type": "uint256"},
            {"label": "c", "slot": 2, "offset": 0, "type": "uint256"},
        ]}))
    inserted = _write(tmp_path, "inserted.json", json.dumps({
        "storage": [
            {"label": "c", "slot": 0, "offset": 0, "type": "uint256"},
            {"label": "a", "slot": 1, "offset": 0, "type": "uint256"},
            {"label": "b", "slot": 2, "offset": 0, "type": "uint256"},
        ]}))
    assert main(["layout", "diff", before, appended]) == 0
    assert json.loads(capsys.readouterr().out)["compatible"] is True
    assert main(["layout", "diff", before, inserted]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["compatible"] is False
    assert payload["counts"]["moved"] == 2


def test_evm_diff_writes_a_poc_from_the_first_divergence(tmp_path, capsys):
    vulnerable = _write(tmp_path, "v.hex", _window().hex())
    guarded = _write(tmp_path, "g.hex", _guarded().hex())
    out = tmp_path / "Divergence.t.sol"
    rc = main(["evm-diff", vulnerable, guarded, "--words", "751",
               "--poc-out", str(out)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["poc"] is not None
    text = out.read_text()
    assert text.count("vm.etch") == 2
    assert "the guarded twin did not diverge" in text


def test_layout_extract_pulls_a_contract_from_build_info_for_diffing(tmp_path, capsys):
    def build_info(*labels):
        return {"output": {"contracts": {"src/C.sol": {"C": {"storageLayout": {
            "storage": [{"label": label, "slot": slot, "offset": 0, "type": "uint256"}
                        for slot, label in enumerate(labels)]}}}}}}

    before = _write(tmp_path, "before-build.json", json.dumps(build_info("a", "b")))
    after = _write(tmp_path, "after-build.json", json.dumps(build_info("c", "a", "b")))
    old_layout, new_layout = str(tmp_path / "old.json"), str(tmp_path / "new.json")
    assert main(["layout", "extract", before, "--contract", "C", "-o", old_layout]) == 0
    assert main(["layout", "extract", after, "--contract", "C", "-o", new_layout]) == 0
    capsys.readouterr()
    assert main(["layout", "diff", old_layout, new_layout]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["moved"] == 2


def test_evm_diff_minimizes_the_divergent_calldata_and_the_poc(tmp_path, capsys):
    vulnerable = _write(tmp_path, "v.hex", _window().hex())
    guarded = _write(tmp_path, "g.hex", _guarded().hex())
    out = tmp_path / "Divergence.t.sol"
    rc = main(["evm-diff", vulnerable, guarded, "--words", "751,0,0",
               "--minimize", "--poc-out", str(out)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    minimized = payload["minimization"]["minimized"]
    value = int(minimized, 16)
    assert len(bytes.fromhex(minimized[2:])) == 32
    assert 750 <= value <= 751
    assert payload["poc"]["calldata"] == minimized


def test_symbolic_evm_minimizes_the_witness_and_uses_it_in_the_poc(tmp_path, capsys):
    code = _write(tmp_path, "window.hex", _window().hex())
    out = tmp_path / "Witness.t.sol"
    rc = main(["symbolic-evm", code, "--input", "cd0=0..1000",
               "--minimize", "--poc-out", str(out)])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["minimization"]["minimized"] == payload["minimized_calldata"]
    assert payload["poc"]["calldata"] == payload["minimized_calldata"]


def test_poc_run_without_a_record_is_blocked(tmp_path, capsys):
    poc = _write(tmp_path, "Poc.t.sol",
                 "contract BlackheartWitnessTest { function test_witness() public {} }")
    rc = main(["poc", "run", poc, "--target-component", "t", "--repository", "r"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert payload["status"] == "BLOCKED"
