"""Explicit cross-contract outcomes: return, revert, or a named gap.

A model that treats an unmodelled call as success can invent a witness for a
call that never happened. These tests pin the opposite: the path aborts and the
reason is recorded, while a modelled call still executes atomically.
"""

from __future__ import annotations

from blackheart.ingest.protocol import Link, build_protocol
from blackheart.ingest.semantics import REVERTED, UNMODELLED
from blackheart.ingest.solidity import scan_source


def _protocol(source: str, *, links=()):
    surfaces = {c.name: c for c in scan_source(source, "Protocol.sol")}
    return build_protocol(surfaces, links=tuple(links))[0]


def test_an_unmodelled_callee_aborts_the_path_and_names_the_gap():
    source = """
    contract Callee {
        uint256 public x;
        function weird(uint256 a) external { assembly { mstore(0, a) } }
    }
    contract Caller {
        uint256 public touched;
        Callee public callee;
        function go() external { touched = 1; callee.weird(2); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {})
    assert protocol.last_outcome == UNMODELLED
    assert state["Caller"]["touched"] == 0
    assert any("weird" in gap for gap in protocol.unmodelled_calls)


def test_a_reverting_callee_restores_the_whole_protocol_state():
    source = """
    contract Callee {
        uint256 public x;
        function bump(uint256 a) external { require(a > 0); x += a; }
    }
    contract Caller {
        uint256 public touched;
        Callee public callee;
        function go(uint256 a) external { touched = 1; callee.bump(a); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {"a": 0})
    assert protocol.last_outcome == REVERTED
    assert state["Caller"]["touched"] == 0
    assert state["Callee"]["x"] == 0


def test_a_nested_external_call_propagates_through_two_contracts():
    source = """
    contract Leaf {
        uint256 public x;
        function ping() external { x += 1; }
    }
    contract Middle {
        Leaf public leaf;
        function mid() external { leaf.ping(); }
    }
    contract Top {
        Middle public middle;
        function top() external { middle.mid(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Top.top", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Leaf"]["x"] == 1


def test_an_explicit_parameter_map_can_rename_a_caller_argument():
    source = """
    contract Callee {
        uint256 public y;
        function bump(uint256 a) external { y += a; }
    }
    contract Caller {
        function go(uint256 b) external { }
    }
    """
    protocol = _protocol(
        source,
        links=(Link("Caller", "go", "Callee", "bump", param_map=(("b", "a"),)),),
    )
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {"b": 7})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Callee"]["y"] == 7


def test_a_missing_link_parameter_is_refused_not_fabricated_as_zero():
    source = """
    contract Callee {
        uint256 public y;
        function bump(uint256 a) external { y += a; }
    }
    contract Caller {
        function go(uint256 b) external { }
    }
    """
    protocol = _protocol(
        source, links=(Link("Caller", "go", "Callee", "bump"),))
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {"b": 7})
    assert protocol.last_outcome == UNMODELLED
    assert state["Callee"]["y"] == 0
    assert any("parameter map" in gap for gap in protocol.unmodelled_calls)


def test_a_link_can_assign_a_callee_return_value_to_the_caller():
    source = """
    contract Oracle {
        uint256 public answer;
        function get() external view returns (uint256) { return answer + 7; }
    }
    contract Consumer {
        uint256 public seen;
        function read() external { }
    }
    """
    protocol = _protocol(
        source,
        links=(Link("Consumer", "read", "Oracle", "get",
                     return_map=(("seen", "answer"),)),),
    )
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["seen"] == 7


def test_a_nonreentrant_guard_refuses_a_recursive_entry():
    source = """
    contract Victim {
        uint256 public x;
        Callback public cb;
        function withdraw() external nonReentrant { x += 1; cb.ping(); x += 1; }
    }
    contract Callback {
        Victim public victim;
        function ping() external { victim.withdraw(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Victim.withdraw", "attacker", {})
    assert protocol.last_outcome == REVERTED
    assert state["Victim"]["x"] == 0


def test_an_unguarded_reentrant_call_stops_at_a_named_depth_limit():
    source = """
    contract Victim {
        uint256 public x;
        Callback public cb;
        function withdraw() external { x += 1; cb.ping(); x += 1; }
    }
    contract Callback {
        Victim public victim;
        function ping() external { victim.withdraw(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Victim.withdraw", "attacker", {})
    assert protocol.last_outcome == UNMODELLED
    assert state["Victim"]["x"] == 0
    assert any("reentrancy depth limit" in gap for gap in protocol.unmodelled_calls)


# --------------------------------------------------------------------------- #
# Interface/base-typed receivers and local external-call results
# --------------------------------------------------------------------------- #

def test_an_interface_typed_receiver_resolves_to_the_single_implementation():
    source = """
    interface IOracle {
        function get() external view returns (uint256);
    }
    contract Oracle is IOracle {
        uint256 public answer;
        function get() external view returns (uint256) { return answer + 7; }
    }
    contract Consumer {
        IOracle public oracle;
        uint256 public seen;
        function read() external {
            uint256 value = oracle.get();
            seen = value;
        }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["seen"] == 7


def test_an_ambiguous_interface_receiver_is_refused_not_guessed():
    source = """
    interface IOracle {
        function get() external view returns (uint256);
    }
    contract A is IOracle {
        function get() external view returns (uint256) { return 1; }
    }
    contract B is IOracle {
        function get() external view returns (uint256) { return 2; }
    }
    contract Consumer {
        IOracle public oracle;
        uint256 public seen;
        function read() external {
            uint256 value = oracle.get();
            seen = value;
        }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == UNMODELLED
    assert state["Consumer"]["seen"] == 0
    assert any("ambiguous view receiver" in gap and "A, B" in gap
               for gap in protocol.unmodelled_calls)


def test_an_interface_typed_state_changing_call_resolves_to_its_implementation():
    source = """
    interface ICounter {
        function bump() external;
    }
    contract Counter is ICounter {
        uint256 public x;
        function bump() external { x += 1; }
    }
    contract Caller {
        ICounter public counter;
        function go() external { counter.bump(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Counter"]["x"] == 1


def test_an_external_call_return_assigned_to_a_local_stays_local():
    source = """
    contract Oracle {
        uint256 public answer;
        function get() external view returns (uint256) { return answer + 7; }
    }
    contract Consumer {
        Oracle public oracle;
        uint256 public seen;
        function read() external {
            uint256 value = 0;
            value = oracle.get();
            seen = value;
        }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["seen"] == 7
    assert "value" not in state["Consumer"]


def test_an_external_call_return_assigned_to_state_is_written_once():
    source = """
    contract Oracle {
        uint256 public answer;
        function get() external view returns (uint256) { return answer + 7; }
    }
    contract Consumer {
        Oracle public oracle;
        uint256 public seen;
        function read() external { seen = oracle.get(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["seen"] == 7


def test_a_base_typed_receiver_with_two_concrete_types_is_ambiguous():
    source = """
    contract Base {
        uint256 public x;
        function bump() public virtual { x += 1; }
    }
    contract Derived is Base {
        function bump() public override { x += 2; }
    }
    contract Caller {
        Base public base;
        function go() external { base.bump(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Caller.go", "attacker", {})
    assert protocol.last_outcome == UNMODELLED
    assert state["Base"]["x"] == 0
    assert any("ambiguous receiver base.bump" in gap and "Base, Derived" in gap
               for gap in protocol.unmodelled_calls)


def test_a_tuple_return_binds_every_state_field():
    source = """
    contract Pair {
        function get() external view returns (uint256 x, uint256 y) {
            return (1, 2);
        }
    }
    contract Consumer {
        Pair public pair;
        uint256 public x;
        uint256 public y;
        function read() external { (x, y) = pair.get(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["x"] == 1
    assert state["Consumer"]["y"] == 2


def test_tuple_returns_fold_conditional_paths_per_component():
    source = """
    contract Pair {
        function get(bool flag) external view returns (uint256 x, uint256 y) {
            if (flag) return (1, 2);
            return (3, 4);
        }
    }
    contract Consumer {
        Pair public pair;
        uint256 public x;
        uint256 public y;
        function read(bool flag) external { (x, y) = pair.get(flag); }
    }
    """
    protocol = _protocol(source)
    for flag, expected in ((True, (1, 2)), (False, (3, 4))):
        state = protocol.reset()
        protocol.step(state, "Consumer.read", "attacker", {"flag": flag})
        assert protocol.last_outcome == "COMPLETED"
        assert (state["Consumer"]["x"], state["Consumer"]["y"]) == expected


def test_a_local_tuple_binds_before_later_expressions():
    source = """
    contract Pair {
        function get() external view returns (uint256 x, uint256 y) {
            return (1, 2);
        }
    }
    contract Consumer {
        Pair public pair;
        uint256 public seen;
        function read() external {
            uint256 a;
            uint256 b;
            (a, b) = pair.get();
            seen = a + b;
        }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["seen"] == 3


def test_a_tuple_arity_mismatch_is_unmodelled_not_partially_bound():
    source = """
    contract Pair {
        function get() external view returns (uint256 x, uint256 y) {
            return (1, 2);
        }
    }
    contract Consumer {
        Pair public pair;
        uint256 public x;
        uint256 public y;
        uint256 public z;
        function read() external { (x, y, z) = pair.get(); }
    }
    """
    protocol = _protocol(source)
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == UNMODELLED
    assert state["Consumer"]["x"] == 0
    assert state["Consumer"]["y"] == 0
    assert state["Consumer"]["z"] == 0
    assert any("assignment needs 3" in gap for gap in protocol.unmodelled_calls)


def test_a_link_return_map_selects_a_named_tuple_component():
    source = """
    contract Pair {
        function get() external view returns (uint256 x, uint256 y) {
            return (1, 2);
        }
    }
    contract Consumer {
        Pair public pair;
        uint256 public seen;
        function read() external { }
    }
    """
    protocol = _protocol(
        source, links=(Link("Consumer", "read", "Pair", "get",
                            return_map=(("seen", "y"),)),))
    state = protocol.reset()
    protocol.step(state, "Consumer.read", "attacker", {})
    assert protocol.last_outcome == "COMPLETED"
    assert state["Consumer"]["seen"] == 2
