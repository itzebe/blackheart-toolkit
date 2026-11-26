"""Acceptance bar for the language-aware security research policy.

The policy is only real if it cannot be bypassed and cannot drift. These tests
assert, in order:

* the policy is exposed (doctrine dict / document / prompt block) and complete;
* the gate is fail-closed -- an incomplete record, an unregistered language, an
  unverified tool, non-official evidence, or an unrun/failed smoke test all BLOCK;
* the registry and the policy agree (every policy example is registered, every
  entry carries official documentation and a verification date);
* the stack detector never confirms a language from an extension or a README;
* the policy reaches every layer a mission reads (agents, skills, templates,
  docs) -- a mission cannot "forget" to apply it;
* the four execution statuses are the only statuses, everywhere.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from blackheart import doctrine
from blackheart.doctrine import (
    COMPATIBILITY_GATE_FIELDS,
    COMPLETION_ACCEPTANCE,
    EXECUTION_STATUSES,
    LANGUAGE_AWARE_POLICY,
    LANGUAGE_AWARE_PRINCIPLE,
    NATIVE_TESTING_METHODS,
    RECONNAISSANCE_REQUIREMENTS,
)
from blackheart.mindset import TOOLING_DOCTRINE, agent_lens_block, prompt_block
from blackheart.toolchain import (
    COMPLETION_FIELD_MAP,
    GATE_FIELD_MAP,
    TOOLCHAINS,
    CompatibilityRecord,
    CompletionReport,
    admit,
    evidence_is_official,
    registry,
    resolve_language,
    status_meaning,
    statuses,
    template,
)
from blackheart.toolchain.detect import detect_stack

POLICY_DOC = "docs/SECURITY_TOOL_COMPATIBILITY.md"


def _complete_record(**overrides) -> CompatibilityRecord:
    base = dict(
        target_component="Vault.sol",
        language="Solidity",
        language_version="0.8.24",
        framework="Foundry",
        runtime="EVM (anvil)",
        tool="Foundry",
        compatibility_evidence="https://book.getfoundry.sh/",
        selection_reason="forge test is the project's native harness",
        expected_coverage="deposit/withdraw accounting, reentrancy",
        known_limitations="fork test pins one block",
        smoke_test="passed",
    )
    base.update(overrides)
    return CompatibilityRecord(**base)


# --------------------------------------------------------------------------- #
# 1. The policy is exposed and complete
# --------------------------------------------------------------------------- #

def test_policy_is_exposed_through_the_doctrine():
    data = doctrine.doctrine_dict()
    assert "language_aware_policy" in data
    policy = data["language_aware_policy"]
    for key in (
        "principle", "repository_reconnaissance", "tool_compatibility_verification",
        "native_testing_methods", "mixed_language_protocols", "pre_execution_gate",
        "execution_statuses", "honest_execution", "research_continuity",
        "completion_acceptance", "tooling_bar", "registry", "enforced_by",
    ):
        assert key in policy, key
    assert policy["principle"] == LANGUAGE_AWARE_PRINCIPLE
    assert policy["overrides"] == "generic tool-selection defaults"
    # It must serialise, because the orchestrator may hand it to a model.
    assert json.loads(json.dumps(policy))["principle"] == LANGUAGE_AWARE_PRINCIPLE


def test_policy_sections_a_to_h_are_all_present():
    assert LANGUAGE_AWARE_PRINCIPLE == (
        "RESEARCH FIRST. IDENTIFY THE STACK. VERIFY COMPATIBILITY. TEST NATIVELY. "
        "REPRODUCE INDEPENDENTLY. REPORT HONESTLY."
    )
    assert any("never infer the complete technology stack" in r.lower()
               for r in RECONNAISSANCE_REQUIREMENTS)
    assert "known limitations" in doctrine.TOOL_COMPATIBILITY_REQUIREMENTS
    assert doctrine.MIXED_LANGUAGE_REQUIREMENTS
    assert len(COMPATIBILITY_GATE_FIELDS) == 8
    assert set(EXECUTION_STATUSES) == {"PASS", "BLOCKED", "INCOMPLETE", "NO_FINDINGS"}
    assert len(COMPLETION_ACCEPTANCE) == 6


def test_document_renders_the_policy_and_principle():
    doc = doctrine.doctrine_document()
    assert "## Language-aware security research (mandatory)" in doc
    assert LANGUAGE_AWARE_PRINCIPLE in doc
    for heading in ("### A.", "### B.", "### C.", "### D.", "### E.", "### F.",
                    "### G.", "### H."):
        assert heading in doc, heading
    for status in EXECUTION_STATUSES:
        assert f"`{status}`" in doc


def test_prompt_block_carries_the_gate():
    block = doctrine.doctrine_prompt_block()
    assert "identify every implementation language" in block
    assert "smoke-test" in block
    assert "BLOCKED" in block
    # And the compact mindset prompt carries the tooling bar.
    assert " ".join(TOOLING_DOCTRINE) in prompt_block()


# --------------------------------------------------------------------------- #
# 2. The gate is fail-closed
# --------------------------------------------------------------------------- #

def test_a_complete_record_is_admitted():
    decision = admit(_complete_record())
    assert decision.admitted, decision.reasons
    assert decision.decision == "ADMIT"
    assert decision.reasons == ()


def test_an_empty_record_is_blocked_with_every_missing_field():
    decision = admit(CompatibilityRecord())
    assert not decision.admitted
    assert decision.decision == "BLOCK"
    joined = " ".join(decision.reasons)
    for field in COMPATIBILITY_GATE_FIELDS:
        assert field in joined, field


def test_each_policy_gate_field_is_enforced_individually():
    """Removing any one field blocks, and names exactly that field."""
    for policy_field, record_fields in GATE_FIELD_MAP.items():
        blanked = {f: "" for f in record_fields}
        decision = admit(_complete_record(**blanked))
        assert not decision.admitted, policy_field
        assert any(policy_field in r for r in decision.reasons), (policy_field,
                                                                 decision.reasons)


def test_an_unregistered_language_is_blocked_and_told_to_research():
    decision = admit(_complete_record(language="Zig", tool="zig test"))
    assert not decision.admitted
    joined = " ".join(decision.reasons).lower()
    assert "no verified native toolchain" in joined
    assert "research an appropriate alternative" in joined


def test_a_tool_from_another_protocol_is_blocked():
    """Slither is a Solidity tool; naming it for Rust is the classic silent miss."""
    decision = admit(_complete_record(language="Rust/Substrate", tool="Slither",
                                      compatibility_evidence="https://github.com/crytic/slither"))
    assert not decision.admitted
    assert any("not a verified tool for Rust/Substrate" in r
               for r in decision.reasons)


def test_evidence_must_be_official_documentation():
    for bad in ("README.md", "it worked on the last protocol", "", "docs/x.md"):
        decision = admit(_complete_record(compatibility_evidence=bad))
        assert not decision.admitted, bad
    # A URL, or a registry reference to a tool the registry lists, is evidence.
    assert admit(_complete_record(compatibility_evidence="https://book.getfoundry.sh/")).admitted
    assert admit(_complete_record(
        compatibility_evidence="registry:Solidity/Foundry")).admitted
    # ...but a registry reference to a tool the registry does NOT list is not.
    assert evidence_is_official("registry:Solidity/Slither",
                                resolve_language("Solidity"), "Slither")
    assert not evidence_is_official("registry:Rust/Substrate/Slither",
                                    resolve_language("Rust"), "Slither")


def test_a_registry_reference_may_name_a_language_key_containing_a_slash():
    """`Rust/Substrate` and `C/C++` contain the reference separator.

    Splitting the citation on its first slash made every Rust record
    uncitable through the registry form, so only a URL could admit a Rust
    tool. The citation must resolve against the registered language key.
    """
    rust = resolve_language("Rust/Substrate")
    assert evidence_is_official("registry:Rust/Substrate/Cargo", rust, "Cargo")
    assert evidence_is_official("registry:Rust/Substrate/proptest", rust, "proptest")
    # a tool the registry does not list for the language is still rejected
    assert not evidence_is_official("registry:Rust/Substrate/Slither", rust, "Slither")
    # and the citation must name the record's own tool
    assert not evidence_is_official("registry:Rust/Substrate/Cargo", rust, "proptest")
    # another language's key is not accepted for this record
    assert not evidence_is_official("registry:Solidity/Slither", rust, "Slither")
    cxx = resolve_language("C/C++")
    assert evidence_is_official("registry:C/C++/libFuzzer", cxx, "libFuzzer")


def test_a_rust_record_can_cite_the_registry_with_a_slashed_language():
    record = _complete_record(
        language="Rust/Substrate",
        language_version="stable rustc 1.90",
        framework="Solana programs (cargo-build-sbf)",
        runtime="native host tests",
        tool="Cargo",
        compatibility_evidence="registry:Rust/Substrate/Cargo",
        selection_reason="Cargo is the documented build/test driver for a Solana program",
        expected_coverage="host tests and the repository's own invariant harness",
        known_limitations="host tests do not exercise the compiled BPF runtime",
    )
    decision = admit(record)
    assert decision.admitted, decision.reasons


def test_smoke_test_must_have_passed():
    assert not admit(_complete_record(smoke_test="not-run")).admitted
    assert not admit(_complete_record(smoke_test="failed")).admitted
    assert not admit(_complete_record(smoke_test="maybe")).admitted
    assert admit(_complete_record(smoke_test="passed")).admitted


def test_unknown_record_fields_are_an_error_not_silently_dropped():
    with pytest.raises(ValueError, match="unknown compatibility field"):
        CompatibilityRecord.from_dict({"language": "Solidity", "tpyo": "x"})


# --------------------------------------------------------------------------- #
# 3. The registry and the policy cannot disagree
# --------------------------------------------------------------------------- #

def test_gate_fields_are_the_policy_fields_verbatim():
    assert tuple(GATE_FIELD_MAP) == COMPATIBILITY_GATE_FIELDS


def test_completion_fields_are_the_policy_criteria_verbatim():
    assert tuple(COMPLETION_FIELD_MAP) == COMPLETION_ACCEPTANCE
    report = CompletionReport(stack_documented=True)
    assert not report.complete
    assert "tool compatibility is verified" in report.missing()
    assert CompletionReport(**{v: True for v in COMPLETION_FIELD_MAP.values()}).complete


def test_every_policy_language_is_registered():
    assert set(NATIVE_TESTING_METHODS) == {t.language for t in TOOLCHAINS}


def test_every_registered_tool_has_official_documentation_and_a_date():
    for chain in TOOLCHAINS:
        assert chain.verified_at, chain.language
        assert chain.versions and chain.frameworks and chain.runtime
        assert chain.native_approaches, chain.language
        assert chain.known_incompatibilities, chain.language
        assert chain.tools, chain.language
        for tool in chain.tools:
            assert tool.official_docs.startswith("https://"), (chain.language, tool.name)
            assert tool.classes, (chain.language, tool.name)


def test_registry_resolves_compound_and_component_names():
    assert resolve_language("Solidity").language == "Solidity"
    assert resolve_language("solidity").language == "Solidity"
    assert resolve_language("Rust").language == "Rust/Substrate"
    assert resolve_language("Substrate").language == "Rust/Substrate"
    assert resolve_language("C++").language == "C/C++"
    assert resolve_language("TypeScript").language == "JavaScript/TypeScript"
    assert resolve_language("Brainfuck") is None
    assert registry("Nope")["languages"] == []


def test_statuses_are_exactly_four_and_an_unknown_one_is_an_error():
    assert statuses() == EXECUTION_STATUSES
    assert status_meaning("BLOCKED") == EXECUTION_STATUSES["BLOCKED"]
    with pytest.raises(ValueError):
        status_meaning("MOSTLY_FINE")


def test_the_template_matches_the_record_fields():
    data = template()
    record_fields = set(CompatibilityRecord().to_dict())
    assert record_fields <= set(data)
    assert data["_statuses"] == list(EXECUTION_STATUSES)
    assert data["_policy"] == POLICY_DOC


# --------------------------------------------------------------------------- #
# 4. The stack detector is honest
# --------------------------------------------------------------------------- #

def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_detection_confirms_only_with_a_manifest(tmp_path: Path):
    _write(tmp_path / "src" / "Vault.sol", "contract Vault {}")
    report = detect_stack(tmp_path)
    assert [e.language for e in report.languages] == ["Solidity"]
    assert report.unconfirmed_languages == ["Solidity"]
    assert not report.complete

    _write(tmp_path / "foundry.toml", "[profile.default]")
    report = detect_stack(tmp_path)
    assert report.confirmed_languages == ["Solidity"]
    assert report.security_relevant_languages == ["Solidity"]
    assert report.complete


def test_a_readme_is_never_evidence(tmp_path: Path):
    _write(tmp_path / "README.md", "This protocol is written in Rust and Solidity.")
    _write(tmp_path / "docs" / "intro.md", "Rust, Move, Cairo")
    report = detect_stack(tmp_path)
    assert report.languages == []
    assert "no security-relevant source files were found" in " ".join(
        report.limitations())


def test_roles_separate_production_tests_docs_and_frontend(tmp_path: Path):
    _write(tmp_path / "foundry.toml")
    _write(tmp_path / "src" / "Vault.sol")
    _write(tmp_path / "test" / "Vault.t.sol")
    _write(tmp_path / "frontend" / "App.tsx")
    _write(tmp_path / "package.json", "{}")
    report = detect_stack(tmp_path)
    by_language = {e.language: e for e in report.languages}
    assert by_language["Solidity"].by_role == {"production": 1, "test": 1}
    assert by_language["JavaScript/TypeScript"].by_role == {"frontend": 1}


def test_mixed_language_is_flagged_and_scoped_per_component(tmp_path: Path):
    _write(tmp_path / "foundry.toml")
    _write(tmp_path / "src" / "Vault.sol")
    _write(tmp_path / "Cargo.toml", "[package]")
    _write(tmp_path / "pallets" / "lib.rs")
    report = detect_stack(tmp_path)
    assert report.mixed_language
    assert set(report.security_relevant_languages) == {"Solidity", "Rust/Substrate"}
    assert any("mixed-language protocol" in n for n in report.limitations())


def test_vendored_dependencies_do_not_define_the_stack(tmp_path: Path):
    _write(tmp_path / "src" / "Vault.sol")
    _write(tmp_path / "foundry.toml")
    _write(tmp_path / "lib" / "forge-std" / "Test.sol")
    _write(tmp_path / "node_modules" / "left-pad" / "index.js")
    report = detect_stack(tmp_path)
    assert [e.language for e in report.languages] == ["Solidity"]
    assert report.languages[0].files == 1


def test_this_repository_is_detected_as_mixed_solidity_python(repo_root: Path):
    report = detect_stack(repo_root)
    assert "Python" in report.confirmed_languages
    assert "Solidity" in report.confirmed_languages
    assert report.mixed_language


# --------------------------------------------------------------------------- #
# 5. The policy reaches every layer a mission reads
# --------------------------------------------------------------------------- #

def test_the_policy_document_is_the_registry_and_has_no_drift(repo_root: Path):
    text = (repo_root / POLICY_DOC).read_text(encoding="utf-8")
    assert LANGUAGE_AWARE_PRINCIPLE in text
    for heading in ("## A. Repository reconnaissance comes first",
                    "## B. Tool compatibility verification",
                    "## C. Select technology-native testing methods",
                    "## D. Mixed-language protocols",
                    "## E. Mandatory pre-execution compatibility gate",
                    "## F. Honest execution reporting",
                    "## G. Research continuity",
                    "## H. Final acceptance criteria"):
        assert heading in text, heading
    for status, meaning in EXECUTION_STATUSES.items():
        assert f"`{status}`" in text and meaning in text
    for chain in TOOLCHAINS:
        assert f"### {chain.language}" in text, chain.language
        for tool in chain.tools:
            assert tool.official_docs in text, (chain.language, tool.name)
    for note in ("RESEARCH FIRST", "overrides generic tool-selection defaults"):
        assert note in text


def test_every_agent_carries_the_language_bar(repo_root: Path):
    agents = sorted((repo_root / "agents").glob("*.md"))
    assert agents
    missing = [p.stem for p in agents
               if "## The language bar" not in p.read_text(encoding="utf-8")]
    assert not missing, f"agents missing the language bar: {missing}"


def test_agent_lens_block_carries_the_language_bar():
    block = agent_lens_block()
    assert "## The language bar" in block
    assert "BLOCKED" in block and "NO FINDINGS" in block
    assert block.index("## The language bar") < block.index("## The operator's word")


def test_skills_reference_the_authoritative_policy(repo_root: Path):
    for skill in ("blackheart", "operational-doctrine", "exploit-verification"):
        text = (repo_root / "skills" / skill / "SKILL.md").read_text(encoding="utf-8")
        if skill == "exploit-verification":
            assert "native harness" in text
        else:
            assert POLICY_DOC in text, skill
            assert "compat" in text, skill


def test_templates_and_toolchain_doc_reference_the_policy(repo_root: Path):
    template = json.loads((repo_root / "templates" / "tool-compatibility.json")
                          .read_text(encoding="utf-8"))
    assert template["_policy"] == POLICY_DOC
    assert set(CompatibilityRecord().to_dict()) <= set(template)
    toolchain_doc = (repo_root / "docs" / "TOOLCHAIN.md").read_text(encoding="utf-8")
    assert "SECURITY_TOOL_COMPATIBILITY.md" in toolchain_doc
    assert "compat check" in toolchain_doc
    agents_md = (repo_root / "AGENTS.md").read_text(encoding="utf-8")
    assert "LANGUAGE_AWARE_POLICY" in agents_md
    assert POLICY_DOC in agents_md


# --------------------------------------------------------------------------- #
# 6. The CLI cannot bypass the gate
# --------------------------------------------------------------------------- #

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "blackheart", *args],
        capture_output=True, text=True, timeout=120,
    )


def test_cli_check_blocks_an_incomplete_record(tmp_path: Path, repo_root: Path):
    record = tmp_path / "record.json"
    record.write_text(json.dumps({"language": "Solidity"}), encoding="utf-8")
    proc = _run_cli("compat", "check", "--file", str(record))
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "BLOCK" in proc.stdout
    assert "missing required compatibility fields" in proc.stdout


def test_cli_check_admits_a_complete_record(tmp_path: Path):
    record = tmp_path / "record.json"
    record.write_text(json.dumps(_complete_record().to_dict()), encoding="utf-8")
    proc = _run_cli("compat", "check", "--file", str(record))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ADMIT" in proc.stdout


def test_cli_check_requires_a_smoke_test_override(tmp_path: Path):
    record = tmp_path / "record.json"
    data = _complete_record(smoke_test="not-run").to_dict()
    record.write_text(json.dumps(data), encoding="utf-8")
    assert _run_cli("compat", "check", "--file", str(record)).returncode == 2
    passed = _run_cli("compat", "check", "--file", str(record),
                      "--smoke-test", "passed")
    assert passed.returncode == 0, passed.stdout + passed.stderr


def test_cli_registry_detect_and_statuses_work():
    statuses_proc = _run_cli("compat", "statuses", "--json")
    assert statuses_proc.returncode == 0
    assert json.loads(statuses_proc.stdout) == EXECUTION_STATUSES

    registry_proc = _run_cli("compat", "registry", "--language", "Rust", "--json")
    assert registry_proc.returncode == 0
    data = json.loads(registry_proc.stdout)
    assert data["languages"][0]["language"] == "Rust/Substrate"

    detect_proc = _run_cli("compat", "detect", "--root", ".", "--json")
    assert detect_proc.returncode == 0
    assert "languages" in json.loads(detect_proc.stdout)

    unknown = _run_cli("compat", "registry", "--language", "Brainfuck")
    assert unknown.returncode == 2


def test_the_template_a_mission_writes_is_a_record_the_gate_can_read(tmp_path):
    """`compat template > record.json` must produce a file `compat check` accepts.

    The template carries `_policy` and `_statuses` as commentary, and the record
    parser used to reject any key it did not know -- so the documented workflow
    (emit a template, fill it in, run the gate) died with `unknown compatibility
    field(s): _policy, _statuses` before the gate ever ran. Found by writing a
    record for a real target, which is the only way this shows up.
    """
    template = _run_cli("compat", "template")
    assert template.returncode == 0
    record = tmp_path / "record.json"
    record.write_text(template.stdout, encoding="utf-8")

    # An unfilled record must BLOCK (exit 2), not crash.
    check = _run_cli("compat", "check", "--file", str(record))
    assert check.returncode == 2
    assert "missing required compatibility fields" in check.stdout + check.stderr

    # A typo in a real field name still fails closed.
    from blackheart.toolchain import CompatibilityRecord

    with pytest.raises(ValueError):
        CompatibilityRecord.from_dict({"langauge": "Rust"})
    # Commentary keys are ignored, not fatal.
    assert CompatibilityRecord.from_dict({"_policy": "x"}).language == ""
