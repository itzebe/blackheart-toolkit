"""Regression tests for three silent-data bugs surfaced by the ruff pass (2026-11-26).

Each was a defect that silently discarded data; these pin the fix so it cannot regress.
"""

import inspect

from blackheart.evmdiff import _collect_logs
from blackheart.hypothesis import _EXPLOITABILITY
from blackheart.ingest.protocol import ProtocolTarget


def test_collect_logs_walks_nested_frames():
    trace = {
        "to": "0xAA",
        "logs": [{"topics": ["0x01"], "data": "0xdead"}],
        "calls": [{"to": "0xBB", "logs": [{"address": "0xbb", "topics": ["0x02"], "data": "0xbeef"}]}],
    }
    logs = _collect_logs(trace)
    assert len(logs) == 2
    assert logs[0] == {"address": "0xaa", "topics": ["0x01"], "data": "0xdead"}
    assert logs[1] == {"address": "0xbb", "topics": ["0x02"], "data": "0xbeef"}


def test_protocol_target_to_dict_includes_unmodelled_calls():
    # A second to_dict used to shadow the richer one and drop this field.
    assert "unmodelled_calls" in inspect.getsource(ProtocolTarget.to_dict)


def test_exploitability_duplicate_keys_resolved():
    # Duplicate keys used to silently overwrite; pin the effective (last-wins) values.
    assert _EXPLOITABILITY["callback-reentrancy"] == 0.8
    assert _EXPLOITABILITY["access-control"] == 0.9
