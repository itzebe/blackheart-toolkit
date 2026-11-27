"""Verified-source attestation must compare what it claims and never overclaim.

Two builds of identical logic differ only in compiler metadata, so a bytecode
comparison that does not strip it reports a false mismatch; and an address with no
verified source is a gap, never a pass. These tests pin both, plus the storage
layout diff, without any network.
"""

from __future__ import annotations

from blackheart.verified_source import (
    attest,
    compare_runtime,
    compare_storage_layout,
    strip_metadata,
)
from blackheart.watch.source import SourceBundle


def _with_metadata(code: bytes, marker: bytes = b"\x00\x01") -> bytes:
    metadata = bytes([0xA2]) + marker
    return code + metadata + len(metadata).to_bytes(2, "big")


def test_strip_metadata_removes_a_cbor_section():
    code = bytes.fromhex("6001600255")
    assert strip_metadata(_with_metadata(code)) == code


def test_strip_metadata_leaves_code_without_metadata_untouched():
    code = bytes.fromhex("6001600255")
    assert strip_metadata(code) == code


def test_compare_runtime_matches_two_builds_that_differ_only_in_metadata():
    code = bytes.fromhex("6001600255")
    a = _with_metadata(code, b"\x11\x22")
    b = _with_metadata(code, b"\x33\x44")
    result = compare_runtime(a, b)
    assert result.match
    assert result.compiled_len == len(code)


def test_compare_runtime_detects_a_real_difference():
    result = compare_runtime(bytes.fromhex("6001"), bytes.fromhex("6002"))
    assert not result.match
    assert "differ" in result.reason


def test_compare_runtime_refuses_an_empty_side():
    result = compare_runtime(b"", bytes.fromhex("6001"))
    assert not result.match
    assert "empty" in result.reason


def test_storage_layout_reports_moves_adds_and_removals():
    old = [
        {"label": "owner", "slot": 0, "offset": 0, "type": "address"},
        {"label": "total", "slot": 1, "offset": 0, "type": "uint256"},
        {"label": "legacy", "slot": 2, "offset": 0, "type": "uint256"},
    ]
    new = [
        {"label": "owner", "slot": 0, "offset": 0, "type": "address"},
        {"label": "total", "slot": 2, "offset": 0, "type": "uint256"},
        {"label": "added", "slot": 3, "offset": 0, "type": "bool"},
    ]
    changes = {d.label: d.change for d in compare_storage_layout(old, new)}
    assert changes == {"total": "moved", "legacy": "removed", "added": "added"}


def test_attest_reports_verified_source():
    class FakeClient:
        def fetch(self, chain_id, address):
            return SourceBundle(chain_id=chain_id, address=address, ok=True,
                                status="verified", files={"src/A.sol": "contract A {}"},
                                compiler_version="0.8.24")

    result = attest(1, "0xABC", client=FakeClient())
    assert result.verified
    assert result.files == ["src/A.sol"]
    assert result.compiler == "0.8.24"


def test_attest_reports_unverified_as_a_gap():
    class FakeClient:
        def fetch(self, chain_id, address):
            return SourceBundle(chain_id=chain_id, address=address,
                                status="not_verified", error="no source")

    result = attest(1, "0xABC", client=FakeClient())
    assert not result.verified
    assert result.status == "not_verified"


def test_attest_reports_a_raising_transport_as_error():
    class BrokenClient:
        def fetch(self, chain_id, address):
            raise RuntimeError("socket closed")

    result = attest(1, "0xABC", client=BrokenClient())
    assert result.status == "error"
    assert "socket closed" in result.reason
