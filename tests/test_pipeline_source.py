"""The source-only pipeline finds, prices and independently re-runs a witness."""

from __future__ import annotations

from blackheart.pipeline import PipelineConfig, run_source_pipeline

VULNERABLE = """
contract Vault {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function drain() external {
        require(msg.sender == owner);
        totalSupply = 0;
    }
}

contract VaultGuarded {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function deposit(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner);
        owner = newOwner;
    }

    function drain() external {
        require(msg.sender == owner);
        totalSupply = 0;
    }
}
"""


def _write(tmp_path):
    path = tmp_path / "Vault.sol"
    path.write_text(VULNERABLE, encoding="utf-8")
    return path


def test_source_pipeline_supplies_the_hypothesis_and_reruns_it(tmp_path):
    path = _write(tmp_path)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path),
        contract_name="Vault",
        max_depth=3,
        write_finding=False,
        evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED", result.to_dict()
    assert result.invariant_id.startswith(("authorization:", "conservation:"))
    assert result.verification["disposition"] == "REPRODUCED"
    assert result.verification["checks"]["independent_reproduction"]["passed"] is True
    assert result.economic["tracked"] is True
    assert any("setOwner" in str(step) for step in result.certificate["minimal_sequence"])


def test_source_pipeline_uses_a_guarded_control_when_supplied(tmp_path):
    path = _write(tmp_path)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path),
        contract_name="Vault",
        control_source=str(path),
        control_contract="VaultGuarded",
        max_depth=3,
        write_finding=False,
        evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED", result.to_dict()
    assert result.verification["checks"]["control_integrity"]["passed"] is True
    assert "control" not in " ".join(result.reasons).lower()


def test_source_pipeline_reports_a_bounded_negative_honestly(tmp_path):
    path = tmp_path / "Safe.sol"
    path.write_text(
        "contract Safe { uint256 public x; function set(uint256 v) external {"
        " require(v < 10); x = v; } }",
        encoding="utf-8",
    )
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path), contract_name="Safe", max_depth=2,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "NO_VIOLATION"
    assert "bound" in result.reasons[0]


def test_source_pipeline_writes_an_evidence_backed_strongly_supported_finding(tmp_path):
    path = _write(tmp_path)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path),
        contract_name="Vault",
        max_depth=3,
        write_finding=True,
        findings_root=str(tmp_path / "findings"),
        evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED"
    assert result.finding_id
    assert result.finding_status == "STRONGLY_SUPPORTED"
    assert (tmp_path / "findings").exists()


def test_source_pipeline_can_build_the_surface_from_a_supplied_ast(tmp_path):
    source = ("contract Vault {\n"
              "    address public owner;\n"
              "    function setOwner(address newOwner) external { owner = newOwner; }\n"
              "}\n")
    sol = tmp_path / "Vault.sol"
    sol.write_text(source, encoding="utf-8")

    def span(text):
        start = source.index(text)
        return f"{start}:{len(text)}:0"

    ast = {"nodeType": "SourceUnit", "nodes": [{
        "nodeType": "ContractDefinition", "name": "Vault",
        "contractKind": "contract",
        "src": span("contract Vault {\n    address public owner;\n    function setOwner(address newOwner) external { owner = newOwner; }\n}"),
        "baseContracts": [],
        "nodes": [
            {"nodeType": "VariableDeclaration", "name": "owner",
             "stateVariable": True, "src": span("address public owner;"),
             "typeDescriptions": {"typeString": "address"}},
            {"nodeType": "FunctionDefinition", "name": "setOwner",
             "kind": "function", "visibility": "external",
             "stateMutability": "nonpayable",
             "src": span("function setOwner(address newOwner) external { owner = newOwner; }"),
             "parameters": {"parameters": [{
                 "nodeType": "VariableDeclaration", "name": "newOwner",
                 "typeDescriptions": {"typeString": "address"}}]},
             "returnParameters": {"parameters": []},
             "modifiers": []},
        ],
    }]}
    ast_path = tmp_path / "Vault.ast.json"
    ast_path.write_text(__import__("json").dumps(ast), encoding="utf-8")

    result = run_source_pipeline(PipelineConfig(
        source_path=str(sol), contract_name="Vault", ast_path=str(ast_path),
        max_depth=1, write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED", result.to_dict()
    assert result.model["binding"]["surface_source"] == "ast"
    assert result.invariant_id == "authorization:owner"

    build_info = tmp_path / "build-info.json"
    build_info.write_text(__import__("json").dumps(
        {"output": {"sources": {"Vault.sol": {"ast": ast}}}}), encoding="utf-8")
    foundry = run_source_pipeline(PipelineConfig(
        source_path=str(sol), contract_name="Vault", ast_path=str(build_info),
        max_depth=1, write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert foundry.model["binding"]["surface_source"] == "ast"
    assert foundry.invariant_id == "authorization:owner"

    build_dir = tmp_path / "out" / "build-info"
    build_dir.mkdir(parents=True)
    (build_dir / "1.json").write_text(__import__("json").dumps(
        {"output": {"sources": {"Vault.sol": {"ast": ast}}}}), encoding="utf-8")
    directory = run_source_pipeline(PipelineConfig(
        source_path=str(sol), contract_name="Vault", ast_path=str(build_dir),
        max_depth=1, write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert directory.model["binding"]["surface_source"] == "ast"
    assert directory.invariant_id == "authorization:owner"


def test_compiler_ast_passes_the_explicit_compiler(tmp_path, monkeypatch):
    from blackheart.ingest import solc

    path = _write(tmp_path)
    seen = {}

    def fake(files, **kwargs):
        seen.update(kwargs)
        return solc.SourceCompile("NO_COMPILER", reason="test")

    monkeypatch.setattr(solc, "compile_sources", fake)
    run_source_pipeline(PipelineConfig(
        source_path=str(path), contract_name="Vault", compiler_ast=True,
        compiler="/opt/solc-0.8.16", max_depth=2, write_finding=False,
        evidence_root=str(tmp_path / "evidence"),
    ))
    assert seen["compiler"] == "/opt/solc-0.8.16"


def test_compiler_ast_passes_include_paths_and_remappings(tmp_path, monkeypatch):
    from blackheart.ingest import solc

    path = _write(tmp_path)
    seen = {}

    def fake(files, **kwargs):
        seen.update(kwargs)
        return solc.SourceCompile("NO_COMPILER", reason="test")

    monkeypatch.setattr(solc, "compile_sources", fake)
    run_source_pipeline(PipelineConfig(
        source_path=str(path), contract_name="Vault", compiler_ast=True,
        include_paths=("deps",), remappings=("@oz/=deps/",), max_depth=2,
        write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert seen["include_paths"] == ("deps",)
    assert seen["remappings"] == ("@oz/=deps/",)


def test_compiler_ast_falls_back_to_the_scanner_with_a_named_reason(tmp_path, monkeypatch):
    from blackheart.ingest import solc

    path = _write(tmp_path)
    monkeypatch.setattr(
        solc, "compile_sources",
        lambda files, **kwargs: solc.SourceCompile(
            "NO_COMPILER", reason="no compiler on PATH"),
    )
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path), contract_name="Vault", compiler_ast=True,
        max_depth=2, write_finding=False, evidence_root=str(tmp_path / "evidence"),
    ))
    assert result.status == "REPRODUCED", result.to_dict()
    assert result.model["binding"]["surface_source"] == "scanner"
    assert any("compiler AST unavailable" in reason for reason in result.model["reasons"])


def test_source_pipeline_adds_taint_leads_and_a_source_trace(tmp_path):
    path = _write(tmp_path)
    result = run_source_pipeline(PipelineConfig(
        source_path=str(path),
        contract_name="Vault",
        max_depth=3,
        write_finding=False,
        evidence_root=str(tmp_path / "evidence"),
        dataflow=True,
    ))
    assert result.status == "REPRODUCED", result.to_dict()
    assert result.dataflow["flows"]
    assert any(f["unprivileged"] for f in result.dataflow["unprivileged_flows"])
    assert result.source_trace
    assert result.source_trace[0]["function"]
    assert any(stage.stage == "dataflow" for stage in result.stages)
