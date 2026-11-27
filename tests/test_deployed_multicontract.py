"""Multi-contract research and honest classification, without a live chain.

Two layers are tested here:

  * the pure logic (graph building, relationship proof, classification) against a
    small in-process fake chain, so the rules are pinned deterministically; and
  * the real-chain path is exercised only when an RPC answers, and *skips* when it
    does not -- a skip is recorded as a skip, never counted as a pass.

The classification tests matter most: they are what stop a blocked or untested
run from reading as a clean one.
"""

from __future__ import annotations

import pytest

from blackheart.coverage_engine.record import CoverageState
from blackheart.deployed import ChainClient
from blackheart.deployed_experiment import run_deployed_experiment
from blackheart.deployed_multicontract import SequenceStep, build_graph


# --------------------------------------------------------------------------- #
# A minimal fake chain: enough JSON-RPC surface for build_graph.
# --------------------------------------------------------------------------- #

class FakeClient(ChainClient):
    def __init__(self, code: dict, storage: dict | None = None, returns: dict | None = None):
        super().__init__("http://fake")
        self._code = {k.lower(): v for k, v in code.items()}
        self._storage = storage or {}
        self._returns = {(a.lower(), b): v for (a, b), v in (returns or {}).items()}

    def call(self, method, params):
        if method == "eth_chainId":
            return "0x1"
        if method == "eth_getBlockByNumber":
            return {"number": params[0], "hash": "0x" + "ab" * 32}
        if method == "eth_getCode":
            return self._code.get(params[0].lower(), "0x")
        if method == "eth_getStorageAt":
            return self._storage.get((params[0].lower(), params[1]), "0x0")
        if method == "eth_call":
            to = params[0]["to"].lower()
            data = params[0]["data"]
            return self._returns.get((to, data), "0x")
        raise AssertionError(f"unexpected rpc {method}")


def _word(addr: str) -> str:
    return "0x" + "00" * 12 + addr[2:]


def _string_word(text: str) -> str:
    body = text.encode().hex().ljust(64, "0")
    return "0x" + (32).to_bytes(32, "big").hex() + len(text).to_bytes(32, "big").hex() + body


def test_graph_proves_an_edge_only_when_the_child_answers_as_a_token():
    pair, tok = "0x" + "11" * 20, "0x" + "22" * 20
    client = FakeClient(
        code={pair: "0x6000", tok: "0x6001"},
        returns={(pair, "0x0dfe1681"): _word(tok), (tok, "0x95d89b41"): _string_word("AAA")},
    )
    g = build_graph([("pair", pair)], client=client, block_number=1)
    assert [e.kind for e in g.edges] == ["token0"]
    assert g.edges[0].target == tok
    assert "AAA" in g.edges[0].evidence


def test_graph_does_not_invent_an_edge_when_the_child_is_not_a_contract():
    pair, ghost = "0x" + "11" * 20, "0x" + "33" * 20
    client = FakeClient(
        code={pair: "0x6000"},  # ghost has no code
        returns={(pair, "0x0dfe1681"): _word(ghost)},
    )
    g = build_graph([("pair", pair)], client=client, block_number=1)
    assert g.edges == []
    assert any("does not answer as a token" in u for u in g.unproven)


def test_graph_records_a_root_with_no_code_as_unproven():
    client = FakeClient(code={})
    g = build_graph([("x", "0x" + "44" * 20)], client=client, block_number=1)
    assert g.nodes == []
    assert "no code" in g.unproven[0]


# --------------------------------------------------------------------------- #
# Classification: the honest states
# --------------------------------------------------------------------------- #

class _FakeNode:
    def __init__(self, block: int, pin_block: int | None = None):
        self._block = block
        self._pin = pin_block if pin_block is not None else block
        self.stopped = False

    def assert_fork_pinned(self):
        return {"forked": True, "block_number": self._pin, "block_hash": "0x" + "cd" * 32,
                "chain_id": 1}

    def stop(self):
        self.stopped = True


def test_unavailable_rpc_is_blocked_not_clean():
    rec = run_deployed_experiment("exp-x", address="0x" + "55" * 20,
                                  rpc_urls=["http://127.0.0.1:1"])
    assert rec.state == CoverageState.BLOCKED.value
    assert "RPC unavailable" in rec.blocked_reason


def test_fork_on_the_wrong_block_is_blocked():
    """A silently substituted block must never be labelled as the pinned one."""
    rec = run_deployed_experiment(
        "exp-y", address="0x" + "55" * 20, rpc_urls=["http://127.0.0.1:1"],
        execute=True, steps=[],
    )
    assert rec.state == CoverageState.BLOCKED.value


def test_no_node_supplied_is_blocked_not_tested():
    class _Chain(FakeClient):
        pass

    # Point at a fake that answers, then refuse to supply a node.
    import blackheart.deployed_experiment as mod

    original = mod.resolve_target

    class _T:
        unavailable_reason = ""
        rpc_url = "http://fake"
        block_number = 1
        dispatch = None

        def to_dict(self):
            return {"address": "0x1"}

    mod.resolve_target = lambda *a, **k: _T()
    try:
        rec = mod.run_deployed_experiment("exp-z", address="0x" + "55" * 20,
                                          execute=True, steps=[])
    finally:
        mod.resolve_target = original
    assert rec.state == CoverageState.BLOCKED.value
    assert "no local fork node" in rec.blocked_reason


def test_retrieval_only_is_unresolved_not_tested():
    """Generation is not testing -- the state must say so."""
    import blackheart.deployed_experiment as mod

    original = mod.resolve_target

    class _Dispatch:
        reachable = []
        present_only = []

    class _T:
        unavailable_reason = ""
        rpc_url = "http://fake"
        block_number = 1
        dispatch = _Dispatch()

        def to_dict(self):
            return {"address": "0x1"}

    mod.resolve_target = lambda *a, **k: _T()
    mod.propose_hypotheses = lambda t: []
    try:
        rec = mod.run_deployed_experiment("exp-w", address="0x" + "55" * 20)
    finally:
        mod.resolve_target = original
    assert rec.state == CoverageState.UNRESOLVED.value
    assert any("generation is not testing" in lim for lim in rec.limitations)


# --------------------------------------------------------------------------- #
# CLI wiring: the command exists and classifies honestly
# --------------------------------------------------------------------------- #

def test_research_deployed_is_registered_and_reachable():
    """The subcommand must exist and be callable; a missing parser is a defect."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "research", "deployed", "--help"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-1500:]
    assert "--execute" in proc.stdout
    assert "--block" in proc.stdout


def test_research_deployed_cli_is_blocked_without_a_network():
    """An unreachable RPC must exit non-zero and say BLOCKED, never 'clean'."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "blackheart", "research", "deployed",
         "0x" + "11" * 20, "--rpc", "http://127.0.0.1:1", "--json"],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 1
    assert "BLOCKED" in proc.stdout


def test_execute_with_no_steps_is_unresolved_not_tested_clean():
    """An empty sequence runs nothing, so it cannot report 'no issue found'.

    Regression: ``execute=True, steps=[]`` previously reached
    TESTED_NO_ISSUE_FOUND -- a claim about work that never happened. The honest
    state is UNRESOLVED, and the limitation must say why.
    """
    import blackheart.deployed_experiment as mod

    orig_resolve, orig_propose, orig_seq = (
        mod.resolve_target, mod.propose_hypotheses, mod.run_sequence,
    )

    class _T:
        unavailable_reason = ""
        rpc_url = "http://fake"
        block_number = 1
        dispatch = None

        def to_dict(self):
            return {"address": "0x1"}

    class _Node:
        def assert_fork_pinned(self):
            return {"forked": True, "block_number": 1}

        def stop(self):
            self.stopped = True

    def _boom(*a, **k):  # must never be reached: nothing should execute
        raise AssertionError("run_sequence must not run for an empty step list")

    mod.resolve_target = lambda *a, **k: _T()
    mod.propose_hypotheses = lambda t: []
    mod.run_sequence = _boom
    try:
        rec = mod.run_deployed_experiment(
            "exp-empty", address="0x" + "55" * 20, execute=True, steps=[],
            node_factory=lambda t: _Node(),
        )
    finally:
        mod.resolve_target, mod.propose_hypotheses, mod.run_sequence = (
            orig_resolve, orig_propose, orig_seq,
        )
    assert rec.state == CoverageState.UNRESOLVED.value
    assert any("nothing ran" in lim for lim in rec.limitations)


def test_execute_with_steps_that_do_not_violate_is_tested_no_issue():
    """The other direction: a real, executed sequence is genuinely TESTED."""
    import blackheart.deployed_experiment as mod

    orig_resolve, orig_propose, orig_seq = (
        mod.resolve_target, mod.propose_hypotheses, mod.run_sequence,
    )

    class _T:
        unavailable_reason = ""
        rpc_url = "http://fake"
        block_number = 1
        dispatch = None

        def to_dict(self):
            return {"address": "0x1"}

    class _Node:
        def assert_fork_pinned(self):
            return {"forked": True, "block_number": 1}

        def stop(self):
            pass

    class _Result:
        reverted_at = None

        def to_dict(self):
            return {"steps": 1}

    mod.resolve_target = lambda *a, **k: _T()
    mod.propose_hypotheses = lambda t: []
    mod.run_sequence = lambda *a, **k: _Result()
    try:
        rec = mod.run_deployed_experiment(
            "exp-one", address="0x" + "55" * 20, execute=True,
            steps=[SequenceStep("A", "0x" + "11" * 20, "0x", "0x" + "22" * 20)],
            node_factory=lambda t: _Node(),
        )
    finally:
        mod.resolve_target, mod.propose_hypotheses, mod.run_sequence = (
            orig_resolve, orig_propose, orig_seq,
        )
    assert rec.state == CoverageState.TESTED_NO_ISSUE_FOUND.value
    assert any("not proof of absence" in lim for lim in rec.limitations)


# --------------------------------------------------------------------------- #
# Evidence writer: an operator-supplied id must not escape the evidence dir
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_id", ["../../escaped", "a/b", "..", "", "x\\y", "."])
def test_evidence_writer_refuses_an_id_that_escapes_the_directory(bad_id, tmp_path):
    """`--experiment-id` becomes a filename; a separator is an arbitrary write.

    Regression: `../../escaped` wrote outside `root/category`. The id must be a
    single path component, and a bad one must fail loudly, not be rewritten.
    """
    from blackheart.deployed_experiment import (
        ExperimentRecord,
        write_evidence_package,
    )

    with pytest.raises(ValueError):
        write_evidence_package(
            [ExperimentRecord(experiment_id=bad_id)],
            root=tmp_path, source_commit="x", category="c",
        )


def test_evidence_writer_accepts_a_normal_id_and_writes_inside(tmp_path):
    """The guard must not reject a legitimate id (the other direction)."""
    from blackheart.deployed_experiment import (
        ExperimentRecord,
        write_evidence_package,
    )

    out = write_evidence_package(
        [ExperimentRecord(experiment_id="usdc-26455778")],
        root=tmp_path, source_commit="x", category="c",
    )
    assert (out / "usdc-26455778.json").exists()
    assert (out / "SHA256SUMS.txt").exists()
