"""Regression tests for the pipeline-honesty defects.

Each test pins one defect the functional-integrity investigation reproduced, so
the failure cannot return silently:

* a compatibility record that binds at the hunt boundary but not at the engine
  boundary (a registry alias and its canonical name are one component);
* a declared control that is a *comparison*, never a grant for a third target;
* an unestablished scope read as authorization;
* an invariant that cannot be evaluated reported as if it held;
* a CLI exit code that disagrees with the verdict it just printed.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import replace

import pytest

from blackheart.hunt import HuntConfig, hunt
from blackheart.invariants import InvariantSpec, OpSpec, StatefulFuzzer, FuzzConfig
from blackheart.invariants import run_sequence as run_invariant_sequence
from blackheart.invariants.registry import make_target
from blackheart.models import AttackStep, Finding
from blackheart.statespace.model import unevaluable, violated
from blackheart.toolchain.enforce import (
    CompatibilityError,
    ExecutionTarget,
    authorized_execution,
    check_scope,
    self_test_record,
)


def _record(**overrides) -> object:
    return replace(self_test_record(), **overrides)


def _fast(**overrides) -> HuntConfig:
    base = dict(stages=("search", "certify", "verify"), certify_depth=2,
                corpus_sequences=400, random_runs=60)
    base.update(overrides)
    return HuntConfig(**base)


# --------------------------------------------------------------------------- #
# The gate binds the same record at both boundaries
# --------------------------------------------------------------------------- #

def test_hunt_binds_a_record_naming_the_registry_alias():
    """``vulnerable`` is a registry alias for ``vulnerable-vault``.

    A record naming either must bind at the hunt boundary *and* at the nested
    engine boundary; when the two compared different strings no record could
    satisfy both and every verify stage ended in VERIFY_ERROR.
    """
    rec = _record(target_component="vulnerable", control_component="safe")
    res = hunt(
        "vulnerable",
        _fast(control_factory=lambda: make_target("safe"), control_name="safe",
              in_scope=True, authorization_gate_passed=True),
        compatibility=rec,
    )
    verify = next(s for s in res.stages if s.stage == "verify")
    assert "VERIFY_ERROR" not in verify.summary, verify.summary
    assert res.verified, "a bound record must let the hunt reach a real verdict"
    assert res.reproduced == []


def test_a_declared_control_is_a_comparison_not_a_grant():
    """The control may be executed; a third component may not."""
    rec = _record(target_component="vulnerable", control_component="safe")
    with authorized_execution(rec, ExecutionTarget(name="vulnerable")) as auth:
        check_scope(auth, ExecutionTarget(name="vulnerable"))
        check_scope(auth, ExecutionTarget(name="safe"))
        with pytest.raises(CompatibilityError):
            check_scope(auth, ExecutionTarget(name="lending-oracle"))


def test_a_record_without_a_control_does_not_authorise_the_control():
    rec = _record(target_component="vulnerable")
    with authorized_execution(rec, ExecutionTarget(name="vulnerable")) as auth:
        with pytest.raises(CompatibilityError):
            check_scope(auth, ExecutionTarget(name="safe"))


# --------------------------------------------------------------------------- #
# Scope fails closed
# --------------------------------------------------------------------------- #

def test_unestablished_scope_is_not_read_as_authorization():
    """``in_scope=None`` means "not established", never "authorized".

    The sequence still reproduces, so it is reported -- as REPRODUCED, never as
    INDEPENDENTLY_VERIFIED, because nothing established that the asset was in
    scope and authorized.
    """
    res = hunt(
        "vulnerable",
        _fast(control_factory=lambda: make_target("safe"), control_name="safe",
              in_scope=None, authorization_gate_passed=True),
        compatibility=_record(target_component="vulnerable",
                              control_component="safe"),
    )
    verify = next(s for s in res.stages if s.stage == "verify")
    assert "VERIFY_ERROR" not in verify.summary, verify.summary
    assert res.reproduced, "the reproduced sequence must still be reported"
    assert res.verified == [], "an unestablished scope cannot be a verified result"
    assert res.verdict_line().startswith("REPRODUCED, NOT YET CONTROLLED")
    dispositions = {v["disposition"] for v in res.verifications}
    assert dispositions == {"REPRODUCED"}
    for v in res.verifications:
        assert v["checks"]["scope_and_authorization"]["passed"] is None


def test_out_of_scope_still_rejects():
    res = hunt(
        "vulnerable",
        _fast(control_factory=lambda: make_target("safe"), control_name="safe",
              in_scope=False, authorization_gate_passed=True),
        compatibility=_record(target_component="vulnerable",
                              control_component="safe"),
    )
    assert res.verified == [] and res.reproduced == []
    assert {v["disposition"] for v in res.verifications} == {"REJECTED"}


# --------------------------------------------------------------------------- #
# An unevaluable invariant is not a pass
# --------------------------------------------------------------------------- #

class _RaisingTarget:
    """A target whose first invariant raises on every state."""

    name = "raising-fixture"

    def reset(self):
        return {"n": 0}

    def ops(self):
        return [OpSpec(name="bump", actors=["attacker"], param_domain={})]

    def invariants(self):
        return [
            InvariantSpec("boom", "cannot be evaluated", lambda s: 1 / 0),
            InvariantSpec("ok", "holds", lambda s: True),
        ]

    def step(self, state, op_name, actor, params):
        state["n"] += 1

    def snapshot(self, state):
        return dict(state)


def test_unevaluable_invariant_is_named_not_silently_satisfied():
    target = _RaisingTarget()
    invs = target.invariants()
    state = target.reset()
    target.step(state, "bump", "attacker", {})
    assert violated(state, invs) == []
    assert unevaluable(state, invs) == ["boom"]

    result = run_invariant_sequence(target, [AttackStep(0, "attacker", "bump", {})])
    assert result.violated == []
    assert result.unevaluable == ["boom"]


def test_fuzz_report_says_it_could_not_tell():
    report = StatefulFuzzer(_RaisingTarget(),
                            FuzzConfig(runs=3, steps_per_run=2, seed=0)).run()
    assert report.failures == []
    assert report.unevaluable == ["boom"]
    assert report.to_dict()["unevaluable"] == ["boom"]


def test_certificate_refuses_completeness_for_an_unevaluable_invariant():
    """The bounded-exhaustive certifier is the only search allowed to say "no
    counterexample exists". It may not say that about an invariant it could not
    evaluate, however completely it enumerated the space."""
    from blackheart.assurance.certify import CertifyConfig, certify

    cert = certify(_RaisingTarget(), CertifyConfig(max_depth=1, max_sequences=50))
    assert cert.unevaluable == ["boom"]
    line = cert.verdict_line()
    assert line.startswith("INCOMPLETE"), line
    assert "CERTIFIED CLEAN" not in line
    assert cert.to_dict()["unevaluable"] == ["boom"]


def test_corpus_fuzzer_reports_unevaluable():
    from blackheart.fuzz import CorpusConfig, CoverageGuidedFuzzer

    report = CoverageGuidedFuzzer(
        _RaisingTarget(), CorpusConfig(max_sequences=6, max_steps=2, seed=0)
    ).run()
    assert report.failures == []
    assert report.unevaluable == ["boom"]
    assert report.to_dict()["unevaluable"] == ["boom"]


# --------------------------------------------------------------------------- #
# The CLI exit code agrees with the verdict
# --------------------------------------------------------------------------- #

def test_verify_cli_exit_code_matches_the_verdict(tmp_path, capsys):
    from blackheart.cli import cmd_verify

    fpath = tmp_path / "f.json"
    fpath.write_text(json.dumps({"finding_id": "F", "title": "t", "target": "T",
                                 "classification": "NEEDS_MORE_EVIDENCE"}),
                     encoding="utf-8")
    ctx = tmp_path / "ctx.json"
    ctx.write_text(json.dumps({"reachable": False}), encoding="utf-8")

    code = cmd_verify(argparse.Namespace(finding=str(fpath), ctx=str(ctx)))
    captured = capsys.readouterr()
    verdict = json.loads(captured.out)["classification"]
    assert verdict != "CONFIRMED"
    assert code == 1
    assert "not a confirmed finding" in captured.err


def test_finding_from_dict_rejects_unknown_and_missing_fields():
    with pytest.raises(ValueError, match="unknown finding field"):
        Finding.from_dict({"finding_id": "F", "title": "t", "target": "T",
                           "bogus": 1})
    with pytest.raises(ValueError, match="missing required finding field"):
        Finding.from_dict({"title": "t", "target": "T"})


def test_statespace_cli_reports_an_unknown_fixture_instead_of_raising(capsys):
    """A wrong fixture name is user input, not a crash: exit 2 with the real list."""
    from blackheart.cli import cmd_statespace

    args = argparse.Namespace(sub="explore", fixture="permit-replay", model=None,
                              seed=0, steps=3, out=None)
    assert cmd_statespace(args) == 2
    payload = json.loads(capsys.readouterr().out)
    assert "unknown fixture" in payload["error"]
    assert "stale-authorization" in payload["known_fixtures"]


def test_chain_cli_reports_an_unknown_id_instead_of_raising(capsys):
    from blackheart.cli import cmd_chain

    code = cmd_chain(argparse.Namespace(list=False, run="no-such-chain", out=None))
    assert code == 2
    assert "unknown chain" in capsys.readouterr().err
