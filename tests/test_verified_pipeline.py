"""The verified-source pipeline must bind, model, and certify honestly."""

from __future__ import annotations

from blackheart.ingest.verified import (
    EIP1967_IMPLEMENTATION,
    bind_runtime,
    build_verified_model,
    resolve_proxy,
    strip_metadata,
)
from blackheart.verified_source import attest
from blackheart.watch.source import SourceBundle

VULNERABLE = """
contract Vault {
    mapping(address => uint) balance;
    uint totalSupply;
    function mint(uint amount) external { balance[msg.sender] += amount; }
}
"""

CLEAN = """
contract Vault {
    mapping(address => uint) balance;
    uint totalSupply;
    function deposit(uint amount) external { balance[msg.sender] += amount; totalSupply += amount; }
}
"""

UNMODELLED = """
contract Vault {
    function f() external { assembly { } }
}
"""


class FakeClient:
    def __init__(self, bundles):
        self.bundles = bundles
        self.fetches = 0

    def fetch(self, chain_id, address):
        self.fetches += 1
        bundle = self.bundles.get(address.lower())
        if bundle is not None:
            return bundle
        return SourceBundle(chain_id=chain_id, address=address.lower(),
                            status="not_verified", ok=False, error="not found")


def _bundle(address, source, *, status="verified"):
    return SourceBundle(
        chain_id=1,
        address=address.lower(),
        status=status,
        ok=status == "verified",
        files={"Vault.sol": source} if source is not None else {},
        compiler="solc",
        compiler_version="0.8.20",
        error="" if status == "verified" else "not found",
    )


def test_a_verified_deployment_becomes_a_certified_model():
    address = "0xAbCdEf01234567890123456789012345678901234"
    client = FakeClient({address.lower(): _bundle(address, VULNERABLE)})
    result = build_verified_model(1, address, client=client)
    assert result.status == "CERTIFIED"
    assert result.certified
    assert result.certificate["proven"]
    assert result.binding["address"] == address.lower()
    assert result.binding["source_fingerprint"]
    assert result.report is not None


def test_an_unverified_address_is_not_a_model():
    address = "0x0000000000000000000000000000000000000000"
    client = FakeClient({})
    result = build_verified_model(1, address, client=client)
    assert result.status == "NOT_VERIFIED"
    assert result.target is None
    assert result.certificate == {}
    assert result.to_dict()["status"] == "NOT_VERIFIED"


def test_a_verified_bundle_without_solidity_is_unmodelled():
    address = "0x1111111111111111111111111111111111111111"
    client = FakeClient({address.lower(): _bundle(address, None)})
    result = build_verified_model(1, address, client=client)
    assert result.status == "UNMODELLED"


def test_an_unreadable_contract_is_unmodelled_not_clean():
    address = "0x2222222222222222222222222222222222222222"
    client = FakeClient({address.lower(): _bundle(address, UNMODELLED)})
    result = build_verified_model(1, address, client=client)
    assert result.status == "UNMODELLED"


def test_a_clean_contract_reports_the_bound_not_safety():
    address = "0x3333333333333333333333333333333333333333"
    client = FakeClient({address.lower(): _bundle(address, CLEAN)})
    result = build_verified_model(1, address, client=client)
    assert result.status == "NO_VIOLATION"
    assert any("bound" in reason for reason in result.reasons)
    assert not result.certificate.get("proven")


# -- runtime binding ------------------------------------------------------- #

def _with_metadata(body: bytes, metadata: bytes = b"\xa1\x65bzzr0\x00") -> bytes:
    return body + metadata + len(metadata).to_bytes(2, "big")


def test_metadata_is_stripped_but_a_real_difference_is_kept():
    body = bytes([0x60, 0x80, 0x60, 0x40, 0x52])
    assert strip_metadata(_with_metadata(body)) == body
    assert strip_metadata(body) == body


def test_bind_runtime_reports_exact_metadata_only_and_mismatch():
    body = bytes([0x60, 0x80, 0x60, 0x40, 0x52])
    exact = bind_runtime(body, body)
    assert exact.status == "EXACT" and exact.bound
    metadata = bind_runtime(_with_metadata(body, b"\xa1\x00"), body)
    assert metadata.status == "METADATA_ONLY" and metadata.bound
    mismatch = bind_runtime(body, body + b"\x00")
    assert mismatch.status == "MISMATCH" and not mismatch.bound
    assert "differs" in mismatch.detail


def test_resolve_proxy_reads_eip1967_and_eip1167():
    implementation = 0x1234567890123456789012345678901234567890
    assert resolve_proxy(b"", {EIP1967_IMPLEMENTATION: implementation}) == implementation
    prefix = bytes.fromhex("363d3d373d3d3d363d73")
    suffix = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")
    code = prefix + implementation.to_bytes(20, "big") + suffix
    assert len(code) == 45
    assert resolve_proxy(code, {}) == implementation
    assert resolve_proxy(b"\x00", {}) is None


def test_a_matching_recompilation_binds_the_source():
    address = "0x4444444444444444444444444444444444444444"
    client = FakeClient({address.lower(): _bundle(address, VULNERABLE)})
    deployed = bytes([0x60, 0x80, 0x60, 0x40, 0x52])
    result = build_verified_model(1, address, client=client,
                                  runtime_code=deployed,
                                  recompile=lambda files, compiler: deployed)
    assert result.source_bound
    assert result.binding["runtime"]["status"] == "EXACT"


def test_a_mismatching_recompilation_is_reported_not_hidden():
    address = "0x5555555555555555555555555555555555555555"
    client = FakeClient({address.lower(): _bundle(address, VULNERABLE)})
    result = build_verified_model(1, address, client=client,
                                  runtime_code=b"\x01\x02",
                                  recompile=lambda files, compiler: b"\x03\x04")
    assert not result.source_bound
    assert result.binding["runtime"]["status"] == "MISMATCH"
    assert any("does not reproduce" in reason for reason in result.reasons)


def test_runtime_code_without_a_compiler_is_not_bound():
    address = "0x6666666666666666666666666666666666666666"
    client = FakeClient({address.lower(): _bundle(address, VULNERABLE)})
    result = build_verified_model(1, address, client=client, runtime_code=b"\x01")
    assert not result.source_bound
    assert result.binding["runtime"]["status"] == "RECOMPILE_FAILED"
    assert result.binding["runtime"]["detail"]


def test_a_prefetched_attestation_is_reused_without_another_fetch():
    address = "0x7777777777777777777777777777777777777777"
    client = FakeClient({address.lower(): _bundle(address, VULNERABLE)})
    att = attest(1, address, client=client)
    assert client.fetches == 1
    result = build_verified_model(1, address, client=client, attestation=att)
    assert result.status == "CERTIFIED"
    assert client.fetches == 1
