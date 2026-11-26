"""The agent sees every stack, hunts modelled ones, and never calls blind 'clean'."""

from __future__ import annotations

from blackheart.agent import classify_stack, run_agent
from blackheart.cli import main


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_solidity_is_modelled(tmp_path):
    _write(tmp_path, "A.sol", "pragma solidity ^0.8.0; contract A {}")
    verdicts, blind = classify_stack(str(tmp_path))
    assert any(v.language == "Solidity" and v.modelled for v in verdicts)
    assert blind == []


def test_ton_is_blind(tmp_path):
    _write(tmp_path, "a.tact", "contract A {}")
    _, blind = classify_stack(str(tmp_path))
    assert "TON FunC/Tact" in blind


def test_agent_blind_on_ton(tmp_path):
    _write(tmp_path, "a.tact", "contract A {}")
    res = run_agent(str(tmp_path))
    assert res.status == "BLIND" and "TON FunC/Tact" in res.blind


def test_agent_empty(tmp_path):
    assert run_agent(str(tmp_path)).status == "EMPTY"


def test_agent_blocks_modelled_without_record(tmp_path):
    _write(tmp_path, "A.sol", "pragma solidity ^0.8.0; contract A {}")
    assert run_agent(str(tmp_path)).status == "BLOCKED"


def test_agent_routes_to_hunt_when_record_and_runner(tmp_path):
    _write(tmp_path, "A.sol", "pragma solidity ^0.8.0; contract A {}")
    runner = lambda t: {"status": "COMPLETED", "detail": "",
                        "findings": [{"reproduced": True, "outcome": "bypass a restriction",
                                      "surface": "contract"}]}
    grader = lambda f, t: {"disposition": "A_SUBMISSION_READY", "payable": True,
                           "awaiting_review": True, "reason": "ok"}
    res = run_agent(str(tmp_path), compatibility="rec.json", runner=runner, grader=grader)
    assert res.status == "PAYABLE_FOUND" and res.hunt["needs_human_review"] is True


def test_cli_agent_blind_exits_1(tmp_path, capsys):
    _write(tmp_path, "a.tact", "contract A {}")
    assert main(["agent", str(tmp_path)]) == 1
    assert "BLIND" in capsys.readouterr().out


def test_agent_surfaces_tact_handlers(tmp_path):
    (tmp_path / "jetton.tact").write_text(
        "message Mint { amount: Int; }\n"
        "contract Jetton {\n"
        "    owner: Address;\n"
        "    receive(msg: Mint) { self.total += msg.amount; }\n"
        "}\n", encoding="utf-8")
    res = run_agent(str(tmp_path))
    assert res.status == "SURFACE"
    assert res.surface and res.surface["handlers"]
    assert any(not h["guarded"] for h in res.surface["handlers"])


def test_agent_surfaces_func_handlers(tmp_path):
    (tmp_path / "jetton.fc").write_text(
        "() recv_internal(int a, int b, cell c, slice d) impure {\n"
        "  int op = d~load_uint(32);\n"
        "  if (op == op::mint()) { set_data(begin_cell().end_cell()); }\n"
        "}\n", encoding="utf-8")
    res = run_agent(str(tmp_path))
    assert res.status == "SURFACE"
    assert res.surface and any(h["name"] == "mint" for h in res.surface["handlers"])
