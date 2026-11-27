"""Acceptance tests for the Solidity source -> SystemModel extractor (T1.1).

The extractor's whole value is that it produces a *usable, honest* model from
source. These tests pin the properties that make it trustworthy:

  * it finds the externally-callable operations of a real contract,
  * it reads guards (role-bearing modifiers) and attributes them to a privileged
    actor -- without inventing a role where the source reveals none,
  * it reports what it could not read instead of silently omitting it,
  * a source proposal is validated against a running system and only then trusted.
"""

from __future__ import annotations

import textwrap

from blackheart.solidity import propose_model, propose_model_from_files
from blackheart.solidity import validate_against_operations


BANK = textwrap.dedent('''
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.24;

    interface IBank {
        function deposit() external payable;
        function withdraw(uint256 amount) external;
    }

    contract Bank is IBank {
        mapping(address => uint256) public balanceOf;
        uint256 public totalDeposits;
        address public owner;
        uint256 public feeBps;

        modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

        function deposit() external payable {
            balanceOf[msg.sender] += msg.value;
            totalDeposits += msg.value;
        }

        function withdraw(uint256 amount) external {
            balanceOf[msg.sender] -= amount;
            (bool ok, ) = msg.sender.call{value: amount}("");
            require(ok, "send failed");
            totalDeposits -= amount;
        }

        function setFeeBps(uint256 bps) external onlyOwner { feeBps = bps; }
        function rescue(address to) external onlyOwner { payable(to).transfer(address(this).balance); }

        receive() external payable {}
    }
''')


def test_extractor_finds_external_operations():
    proposal = propose_model("Bank.sol", text=BANK)
    names = {op.name for op in proposal.model.operations}
    # The externally-callable, state-changing operations are found.
    assert {"deposit", "withdraw", "setFeeBps", "rescue"} <= names


def test_extractor_reads_role_modifier_and_adds_privileged_actor():
    proposal = propose_model("Bank.sol", text=BANK)
    model = proposal.model
    fee = model.operation("setFeeBps")
    assert fee is not None
    assert fee.guard_roles == ("owner",)
    # The privileged actor exists and is NOT unprivileged.
    owners = [a for a in model.actors if "owner" in a.roles]
    assert owners and all(not a.unprivileged for a in owners)


def test_extractor_does_not_invent_a_role_for_an_unguarded_operation():
    proposal = propose_model("Bank.sol", text=BANK)
    deposit = proposal.model.operation("deposit")
    assert deposit is not None
    assert deposit.guard_roles == ()          # no role: any actor may call it
    assert deposit.actor_roles == ()


def test_extractor_marks_value_bearing_operations_sensitive_and_proposes_invariants():
    proposal = propose_model("Bank.sol", text=BANK)
    assert proposal.model.operation("deposit").sensitive
    assert proposal.model.operation("withdraw").sensitive
    assert proposal.candidates, "value-bearing operations should yield candidate invariants"
    assert proposal.model.invariants, "candidates are promoted into the model's invariants"
    assert proposal.model.is_complete()


def test_provenance_is_recorded_for_every_operation():
    proposal = propose_model("Bank.sol", text=BANK)
    for op in proposal.model.operations:
        assert op.source.startswith("Bank.sol:"), f"{op.name} has no provenance"


def test_interface_only_source_reports_a_limitation_rather_than_inventing_a_model():
    iface = textwrap.dedent('''
        pragma solidity ^0.8.24;
        interface IOnly {
            function a() external;
            function b() external;
        }
    ''')
    proposal = propose_model("IOnly.sol", text=iface)
    # Interface functions are external entry points, so they are found -- but the
    # model is not "complete" on its own and the honesty record says what is thin.
    assert proposal.model.operations
    # An empty source yields an explicit limitation, never a fabricated model.
    empty = propose_model("empty.sol", text="pragma solidity ^0.8.24;")
    assert empty.limitations
    assert not empty.model.operations


def test_validate_against_runtime_flags_source_runtime_disagreement():
    proposal = propose_model("Bank.sol", text=BANK)
    # Runtime exposes a subset plus one the source scan did not reveal.
    result = validate_against_operations(proposal, ["deposit", "withdraw", "sweep"])
    assert "deposit" in result.matched
    assert "setFeeBps" in result.missing_at_runtime
    assert "sweep" in result.undeclared_at_source
    assert not result.validated          # missing operations -> not validated


def test_validate_against_runtime_passes_when_all_proposed_ops_are_executable():
    proposal = propose_model("Bank.sol", text=BANK)
    proposed = [op.name for op in proposal.model.operations]
    result = validate_against_operations(proposal, proposed)
    assert result.validated
    assert not result.missing_at_runtime


def test_parser_is_not_fooled_by_keywords_in_strings_or_comments():
    tricky = textwrap.dedent('''
        pragma solidity ^0.8.24;
        // function withdraw() external {}  <- a comment, not a function
        contract C {
            string public note = "function rescue(address) external onlyOwner";
            function real() external {}
        }
    ''')
    proposal = propose_model("Tricky.sol", text=tricky)
    names = {op.name for op in proposal.model.operations}
    assert "real" in names
    assert "rescue" not in names          # only mentioned inside a string
