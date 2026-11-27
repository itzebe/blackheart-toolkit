"""A clean search over an incomplete model is not a clean target."""

from __future__ import annotations

from blackheart.assurance.certify import CertifyConfig, certify
from blackheart.hunt.orchestrator import HuntConfig, hunt
from blackheart.ingest.model_coverage import coverage_for_contract
from blackheart.ingest.protocol import Link, build_protocol
from blackheart.ingest.solidity import scan_source
from blackheart.ingest.synthesize import synthesize
from blackheart.pipeline import PipelineConfig, run_source_pipeline

GOOD = """
contract Good {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }
}
"""

REACHABLE_GAP = """
contract Gap {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }
    function weird(uint256 x) external { x; }
}
"""

UNREACHABLE_GAP = """
contract Quiet {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }
    function unused(uint256 x) internal { x; }
}
"""

INTERNAL_GAP = """
contract InternalGap {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    function deposit(uint256 amount) external { _add(msg.sender, amount); }
    function _add(address who, uint256 amount) internal {
        balanceOf[who] += amount;
        totalSupply += amount;
    }
}
"""


def _contract(source: str, name: str):
    contracts = scan_source(source, f"{name}.sol")
    return next(c for c in contracts if c.name == name)


def _coverage(source: str, name: str):
    contract = _contract(source, name)
    target, report = synthesize(contract)
    return target, report, coverage_for_contract(contract, report, target)


def test_complete_model_is_complete():
    _target, _report, cov = _coverage(GOOD, "Good")
    assert cov.complete is True
    assert cov.gaps == []
    assert cov.summary["modelled_functions"] == 1


def test_a_target_that_declares_no_ledger_is_not_called_complete():
    contract = _contract(GOOD, "Good")
    target, report = synthesize(contract)
    target.model_coverage = {}
    from blackheart.ingest.model_coverage import coverage_for_target

    cov = coverage_for_target(target)
    assert cov.available is False
    assert cov.complete is False
    assert "absent measurement" in " ".join(cov.notes)


def test_reachable_unmodelled_function_is_a_named_gap():
    target, report, cov = _coverage(REACHABLE_GAP, "Gap")
    assert cov.complete is False
    assert report.model_coverage["complete"] is False
    assert target.model_coverage["complete"] is False
    names = {gap.get("name") for gap in cov.gaps if gap["kind"] == "function"}
    assert "weird" in names
    assert any(gap["path"].endswith("Gap.sol") and gap["line"] > 0 for gap in cov.gaps)


def test_unreachable_unmodelled_function_does_not_block_a_clean_result():
    _target, _report, cov = _coverage(UNREACHABLE_GAP, "Quiet")
    assert cov.complete is True
    assert any(f.name == "unused" and not f.reachable and f.status == "UNREACHABLE"
               for f in cov.functions)


def test_reachable_internal_helper_is_a_gap_and_a_bad_call_edge():
    _target, _report, cov = _coverage(INTERNAL_GAP, "InternalGap")
    assert cov.complete is False
    helper = next(f for f in cov.functions if f.name == "_add")
    assert helper.reachable and helper.status == "UNMODELLED"
    edge = next(e for e in cov.call_edges if e.caller_op == "deposit")
    assert edge.callee_op == "_add"
    assert edge.status == "UNMODELLED"


def test_certifier_refuses_to_call_an_incomplete_alphabet_clean():
    target, _report, _cov = _coverage(REACHABLE_GAP, "Gap")
    cert = certify(target, CertifyConfig(max_depth=2, price_findings=False))
    assert cert.broke is False
    assert "INCOMPLETE MODEL COVERAGE" in cert.verdict_line()
    assert cert.model_coverage["complete"] is False


def test_hunt_never_reports_a_clean_target_when_the_model_is_incomplete():
    target, _report, _cov = _coverage(REACHABLE_GAP, "Gap")
    result = hunt(target, HuntConfig(
        stages=("search", "certify"), strategies=("random",),
        random_runs=20, certify_depth=2, certify_max_sequences=2_000,
    ))
    assert result.candidates == []
    assert "INCOMPLETE MODEL COVERAGE" in result.verdict_line()
    assert result.model_coverage["complete"] is False


def test_protocol_link_resolves_an_external_edge_only_when_the_callee_is_modelled():
    source = """
contract Token {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
contract Vault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    Token internal token;
    function deposit(uint256 amount) external {
        token.transfer(msg.sender, amount);
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }
}
"""
    contracts = {c.name: c for c in scan_source(source, "Protocol.sol")}
    target, report = build_protocol(
        contracts,
        links=(Link("Vault", "deposit", "Token", "transfer"),),
        name="protocol",
    )
    cov = target.model_coverage
    assert cov["complete"] is True, cov
    assert report.model_coverage["complete"] is True
    assert target.fresh_instance().model_coverage["complete"] is True

    unresolved, _report = build_protocol(contracts, links=(), name="protocol")
    assert unresolved.model_coverage["complete"] is False
    assert any(edge["status"] == "EXTERNAL"
               for edge in unresolved.model_coverage["call_edges"])


def test_source_pipeline_returns_incomplete_not_no_violation_for_a_gap(tmp_path):
    path = tmp_path / "Gap.sol"
    path.write_text(REACHABLE_GAP, encoding="utf-8")
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path), contract_name="Gap", max_depth=2,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "INCOMPLETE", result.to_dict()
    assert "model coverage incomplete" in result.verdict_line().lower()
    assert result.model_coverage["complete"] is False


def test_source_pipeline_guarded_twin_stays_clean(tmp_path):
    path = tmp_path / "Guarded.sol"
    path.write_text(GOOD, encoding="utf-8")
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path), contract_name="Good", max_depth=2,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "NO_VIOLATION", result.to_dict()
    assert result.model_coverage["complete"] is True


def test_an_interface_declaration_with_a_concrete_implementation_is_not_a_gap():
    source = """
interface IOracle { function get() external view returns (uint256); }
contract Oracle is IOracle {
    uint256 public answer;
    function get() external view returns (uint256) { return answer + 7; }
}
contract Consumer {
    IOracle public oracle;
    uint256 public seen;
    function read() external { seen = oracle.get(); }
}
"""
    contracts = {c.name: c for c in scan_source(source, "Protocol.sol")}
    target, report = build_protocol(contracts, infer_links=True, name="protocol")
    assert report.model_coverage["complete"] is True, report.model_coverage
    assert target.model_coverage["complete"] is True
    assert not any(
        gap.get("contract") == "IOracle" and gap.get("name") == "get"
        for gap in target.model_coverage["gaps"]
    )
