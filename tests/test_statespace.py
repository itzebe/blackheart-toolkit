"""Tests for the adversarial state-machine discovery engine.

Covers, with real execution (no mocks):

  * the model completeness gate;
  * hypothesis generation -- every strategy, the eight required fields, dedup;
  * the explorer -- detection on vulnerable fixtures, no violation on controls,
    minimality, determinism, and sequence-level (not function-level) results;
  * the independent verifier -- accept, and every rejection path (non-discriminating
    control, privileged-only, duplicate, out-of-scope, intended behaviour,
    non-reproduction);
  * the benchmark -- detection/false-positive rates and the decoy-immunity result;
  * the skill library -- ten executable skills, applicability, and file emission;
  * the threat-model adapter bridge.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from blackheart.models import AttackStep
from blackheart.statespace import (
    FIXTURE_PAIRS,
    ExploreConfig,
    HypothesisGenerator,
    IndependentSequenceVerifier,
    ModelIncomplete,
    StateSpaceExplorer,
    SystemModel,
    VerifyConfig,
    make_fixture,
    model_from_threatmodel,
)
from blackheart.statespace.benchmark import run_benchmark
from blackheart.statespace.explore import run_sequence
from blackheart.statespace.hard import HARD_PAIRS, make_hard
from blackheart.statespace.heldout import HELDOUT_PAIRS, make_heldout
from blackheart.statespace.skills import (
    SKILLS,
    run_all,
    skill,
    skill_ids,
    write_skill_files,
)


# --------------------------------------------------------------------------- #
# Model gate
# --------------------------------------------------------------------------- #

def test_model_completeness_gate():
    m = SystemModel(target="x")
    assert not m.is_complete()
    assert "summary" in m.missing() and "actors" in m.missing()
    m.summary = "s"
    m.add_actor("attacker")
    m.add_operation("do", ("attacker",), sensitive=True)
    m.add_invariant("i1", "statement")
    m.assets.append("a")
    assert m.is_complete()


def test_generation_refuses_incomplete_model():
    m = SystemModel(target="x")  # nothing filled in
    with pytest.raises(ModelIncomplete):
        HypothesisGenerator(m).generate()


# --------------------------------------------------------------------------- #
# Hypothesis generation
# --------------------------------------------------------------------------- #

def test_every_strategy_is_reachable_on_a_rich_model():
    # a model rich enough to satisfy every strategy's applicability
    m = SystemModel(target="rich", summary="a system with two actors and a dependency",
                    assets=["value"], dependencies=["oracle"],
                    trust_boundaries=["a <-> b"])
    m.add_actor("attacker", roles=("user",), unprivileged=True)
    m.add_actor("victim", roles=("user",), unprivileged=True)
    m.add_actor("owner", roles=("owner",), unprivileged=False)
    m.add_operation("grant", ("owner",), sensitive=False, guard="owner-only", guard_roles=("owner",))
    m.add_operation("act", ("user", "owner"), sensitive=True, asset="value",
                    guard="user-role", guard_roles=("user",))
    m.add_operation("transfer", ("user",), sensitive=True, asset="value")
    m.add_invariant("inv1", "value is conserved", applies_to=("value",))
    # Each strategy must be able to produce a hypothesis on its own. (Across the
    # whole set some strategies legitimately collapse, because duplicate sequence
    # shapes are suppressed -- e.g. stale-state and partial-failure both emit
    # a-b-a -- so we test per-strategy reachability here.)
    for sid in ("ordering", "repetition", "cross-user", "privilege-change",
                "ownership-change", "partial-failure", "concurrency", "stale-state",
                "replay", "cross-component"):
        rep = HypothesisGenerator(m, strategies=[sid]).generate()
        assert rep.hypotheses, f"strategy {sid} produced no hypothesis on a rich model"
        assert all(h.strategy_id == sid for h in rep.hypotheses)


def test_hypothesis_has_all_eight_required_fields():
    t = make_fixture("stale-authorization")
    rep = HypothesisGenerator(t.model()).generate()
    assert rep.hypotheses
    for h in rep.hypotheses:
        assert h.capability.strip()                     # 1 capability
        assert h.preconditions                           # 2 preconditions
        assert h.asset.strip()                           # 3 asset
        assert h.vulnerable_sequence                     # 4 vulnerable sequence
        assert h.expected_secure.strip()                 # 5 expected secure behaviour
        assert h.evidence_needed                         # 6 evidence needed
        assert h.falsification                           # 7 falsification
        assert h.authorization_boundary.strip()          # 8 authorization boundary


def test_duplicate_sequences_are_suppressed():
    t = make_fixture("partial-failure")
    rep = HypothesisGenerator(t.model()).generate()
    keys = [h.sequence_key() for h in rep.hypotheses]
    assert len(keys) == len(set(keys)), "duplicate sequence shapes were not suppressed"
    assert rep.suppressed_duplicates >= 0


def test_hypotheses_are_ranked_deterministically():
    t = make_fixture("cross-user-idor")
    r1 = HypothesisGenerator(t.model()).generate()
    r2 = HypothesisGenerator(t.model()).generate()
    assert [h.hyp_id for h in r1.hypotheses] == [h.hyp_id for h in r2.hypotheses]


# --------------------------------------------------------------------------- #
# Explorer -- detection, controls, minimality, determinism
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("vuln,guard,invariant,desc", FIXTURE_PAIRS)
def test_engine_breaks_vulnerable_and_holds_control(vuln, guard, invariant, desc):
    vt = make_fixture(vuln)
    vrep = StateSpaceExplorer(vt, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(vt.model()).generate().hypotheses)
    hits = [v for v in vrep.violations if v.invariant_id == invariant]
    assert hits, f"{vuln}: no violation of {invariant} found"

    gt = make_fixture(guard)
    grep = StateSpaceExplorer(gt, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(gt.model()).generate().hypotheses)
    assert not [v for v in grep.violations if v.invariant_id == invariant], (
        f"{guard}: control must hold {invariant}, but the engine reported a violation")


@pytest.mark.parametrize("vuln,guard,invariant,desc", HELDOUT_PAIRS)
def test_heldout_pairs(vuln, guard, invariant, desc):
    vt = make_heldout(vuln)
    vrep = StateSpaceExplorer(vt, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(vt.model()).generate().hypotheses)
    assert [v for v in vrep.violations if v.invariant_id == invariant], f"{vuln}: not detected"
    gt = make_heldout(guard)
    grep = StateSpaceExplorer(gt, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(gt.model()).generate().hypotheses)
    assert not [v for v in grep.violations if v.invariant_id == invariant], f"{guard}: false positive"


@pytest.mark.parametrize("vuln,guard,invariant,desc", HARD_PAIRS)
def test_hard_pairs_with_decoys(vuln, guard, invariant, desc):
    vt = make_hard(vuln)
    vrep = StateSpaceExplorer(vt, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(vt.model()).generate().hypotheses)
    assert [v for v in vrep.violations if v.invariant_id == invariant], f"{vuln}: not detected"
    gt = make_hard(guard)
    grep = StateSpaceExplorer(gt, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(gt.model()).generate().hypotheses)
    assert not [v for v in grep.violations if v.invariant_id == invariant], f"{guard}: false positive"


def test_violation_is_minimal_and_reproducible():
    t = make_fixture("stale-authorization")
    rep = StateSpaceExplorer(t, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(t.model()).generate().hypotheses)
    v = rep.violations[0]
    assert v.reproducible
    assert len(v.minimal_sequence) <= len(v.sequence)
    # re-running the minimal sequence still violates
    _, bad = run_sequence(t, v.minimal_sequence)
    assert v.invariant_id in bad


def test_explorer_is_deterministic():
    t = make_fixture("cross-user-idor")
    hyps = HypothesisGenerator(t.model()).generate().hypotheses
    a = StateSpaceExplorer(t, ExploreConfig(seed=7)).explore(hyps)
    b = StateSpaceExplorer(t, ExploreConfig(seed=7)).explore(hyps)
    assert [v.minimal_sequence for v in a.violations] == [v.minimal_sequence for v in b.violations]


def test_results_are_sequences_not_single_ops():
    """A cross-user violation must be reported as an ordered sequence."""
    t = make_fixture("cross-user-idor")
    rep = StateSpaceExplorer(t, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(t.model()).generate().hypotheses)
    assert rep.violations
    assert all(len(v.minimal_sequence) >= 2 for v in rep.violations), (
        "the IDOR is a multi-step bug; a single-op result would be wrong")


# --------------------------------------------------------------------------- #
# Independent verifier -- accept and every rejection path
# --------------------------------------------------------------------------- #

def _violation(fixture: str, invariant: str):
    t = make_fixture(fixture)
    rep = StateSpaceExplorer(t, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(t.model()).generate().hypotheses)
    hits = [v for v in rep.violations if v.invariant_id == invariant]
    assert hits
    return t, hits[0]


def test_verifier_accepts_a_genuine_violation():
    t, v = _violation("stale-authorization", "no-withdrawal-after-revoke")
    cfg = VerifyConfig(control_factory=lambda: make_fixture("stale-authorization-guarded"),
                       in_scope=True, scope_reference="fixture", authorization_gate_passed=True)
    r = IndependentSequenceVerifier(lambda: make_fixture("stale-authorization"), cfg).verify(
        v, model=t.model(), preconditions_satisfiable=True)
    assert r.disposition == "INDEPENDENTLY_VERIFIED"
    assert r.checks["control_integrity"][0] is True


def test_verifier_rejects_non_discriminating_control():
    t, v = _violation("partial-failure", "no-value-duplication")
    # control is the *vulnerable* target -> control also violates -> reject
    cfg = VerifyConfig(control_factory=lambda: make_fixture("partial-failure"),
                       in_scope=True, authorization_gate_passed=True)
    r = IndependentSequenceVerifier(lambda: make_fixture("partial-failure"), cfg).verify(
        v, model=t.model(), preconditions_satisfiable=True)
    assert r.disposition == "REJECTED"
    assert r.checks["control_integrity"][0] is False


def test_verifier_rejects_privileged_only_sequence():
    t, _ = _violation("partial-failure", "no-value-duplication")
    priv = _priv_violation()
    cfg = VerifyConfig(control_factory=lambda: make_fixture("partial-failure-guarded"),
                       in_scope=True, authorization_gate_passed=True)
    r = IndependentSequenceVerifier(lambda: make_fixture("partial-failure"), cfg).verify(priv, model=t.model())
    assert r.disposition == "REJECTED"
    assert r.checks["attacker_reachable"][0] is False


def test_verifier_rejects_duplicate_sequence():
    t, v = _violation("stale-authorization", "no-withdrawal-after-revoke")
    key = tuple((s.actor, s.action) for s in v.minimal_sequence)
    cfg = VerifyConfig(control_factory=lambda: make_fixture("stale-authorization-guarded"),
                       in_scope=True, authorization_gate_passed=True, known_sequences={key})
    r = IndependentSequenceVerifier(lambda: make_fixture("stale-authorization"), cfg).verify(
        v, model=t.model(), preconditions_satisfiable=True)
    assert r.disposition == "REJECTED"
    assert r.checks["not_duplicate"][0] is False


def test_verifier_rejects_out_of_scope():
    t, v = _violation("stale-authorization", "no-withdrawal-after-revoke")
    cfg = VerifyConfig(control_factory=lambda: make_fixture("stale-authorization-guarded"),
                       in_scope=False)
    r = IndependentSequenceVerifier(lambda: make_fixture("stale-authorization"), cfg).verify(
        v, model=t.model(), preconditions_satisfiable=True)
    assert r.disposition == "REJECTED"
    assert r.checks["scope_and_authorization"][0] is False


def test_verifier_rejects_unsatisfiable_precondition():
    t, v = _violation("stale-authorization", "no-withdrawal-after-revoke")
    cfg = VerifyConfig(control_factory=lambda: make_fixture("stale-authorization-guarded"),
                       in_scope=True, authorization_gate_passed=True)
    r = IndependentSequenceVerifier(lambda: make_fixture("stale-authorization"), cfg).verify(
        v, model=t.model(), preconditions_satisfiable=False)
    assert r.disposition == "REJECTED"


def test_verifier_rejects_intended_behaviour():
    t, v = _violation("stale-authorization", "no-withdrawal-after-revoke")
    model = t.model()
    model.intended_behaviours = ["withdraw is a documented behaviour"]
    cfg = VerifyConfig(control_factory=lambda: make_fixture("stale-authorization-guarded"),
                       in_scope=True, authorization_gate_passed=True)
    r = IndependentSequenceVerifier(lambda: make_fixture("stale-authorization"), cfg).verify(
        v, model=model, preconditions_satisfiable=True)
    assert r.disposition == "REJECTED"
    assert r.checks["not_intended"][0] is False


def test_verifier_returns_insufficient_evidence_when_not_reproduced():
    # a fabricated violation whose invariant never actually breaks
    bogus = _priv_violation()
    bogus.invariant_id = "no-such-invariant"
    bogus.reachable_by_attacker = True
    cfg = VerifyConfig(control_factory=lambda: make_fixture("partial-failure-guarded"),
                       in_scope=True, authorization_gate_passed=True)
    r = IndependentSequenceVerifier(lambda: make_fixture("partial-failure"), cfg).verify(bogus)
    assert r.disposition == "INSUFFICIENT_EVIDENCE"
    assert r.checks["independent_reproduction"][0] is False


def _priv_violation():
    from blackheart.statespace.explore import Violation
    seq = [AttackStep(index=0, actor="owner", action="revoke", params={})]
    return Violation(invariant_id="no-value-duplication", sequence=seq, minimal_sequence=seq,
                     seed=0, actor_roles=["owner"], observed={}, reproducible=True,
                     reachable_by_attacker=False)


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #

def test_benchmark_reports_detection_and_no_false_positives():
    rep = run_benchmark(guided_runs=100, baseline_runs=120)
    alls = rep.summary()
    assert alls["guided_detection_rate"] == 1.0
    assert alls["guided_false_positive_rate"] == 0.0
    assert alls["baseline_false_positive_rate"] == 0.0


def test_benchmark_hard_suite_is_decoy_immune_for_guided():
    """The headline honest result: the guided cost does not blow up with decoys."""
    rep = run_benchmark(guided_runs=100, baseline_runs=120)
    dev = rep.summary(heldout=False)
    hard = rep.summary(hard=True)
    # guided sequences-to-detect on the hard (decoy) suite is bounded, and far
    # below the random baseline's, which degrades sharply with decoys.
    assert hard["guided_seqs_to_detect_total"] < hard["baseline_seqs_to_detect_total"]


def test_benchmark_is_deterministic():
    a = run_benchmark(guided_runs=50, baseline_runs=60)
    b = run_benchmark(guided_runs=50, baseline_runs=60)
    assert a.to_dict()["all"] == b.to_dict()["all"]


# --------------------------------------------------------------------------- #
# Skill library
# --------------------------------------------------------------------------- #

def test_ten_skills_and_all_executable():
    assert len(SKILLS) == 10
    assert len(skill_ids()) == len(set(skill_ids())) == 10
    t = make_fixture("cross-user-idor")
    model = t.model()
    for s in SKILLS:
        # every skill must be constructible and produce a document
        assert s.name and s.authorization and s.completion
        assert s.to_dict()["skill_id"] == s.skill_id
    # the executable ones run against an applicable model and emit hypotheses
    out = run_all(model)
    assert out, "no skill produced hypotheses on a rich model"
    for sid, hyps in out.items():
        assert isinstance(hyps, list)


def test_skill_applicability_filters_by_model():
    bare = SystemModel(target="bare", summary="s", assets=["a"])
    bare.add_actor("attacker")
    bare.add_operation("do", ("attacker",), sensitive=True)
    bare.add_invariant("i", "stmt")
    # a cross-user skill must not be applicable when there is only one actor
    cu = skill("identity-authorization")
    assert not cu.is_applicable(bare)


def test_skill_files_are_written(tmp_path: Path):
    written = write_skill_files(tmp_path)
    assert len(written) == 10
    for p in written:
        text = Path(p).read_text(encoding="utf-8")
        assert text.startswith("---")           # frontmatter
        assert "Activates when" in text
        assert "Falsification criteria" in text
        assert "adversarial-" in Path(p).parent.name


def test_skill_writer_never_clobbers_a_handwritten_file(tmp_path: Path):
    # a foreign skill with the same directory name as a generated one must survive
    foreign = tmp_path / "adversarial-exploit-verification"
    foreign.mkdir(parents=True)
    (foreign / "SKILL.md").write_text("---\nname: mine\n---\nhand written\n", encoding="utf-8")
    write_skill_files(tmp_path)
    assert (foreign / "SKILL.md").read_text(encoding="utf-8").endswith("hand written\n")


# --------------------------------------------------------------------------- #
# Threat-model bridge
# --------------------------------------------------------------------------- #

def test_model_from_threatmodel_bridge():
    from blackheart.threatmodel import ThreatModel
    tm = ThreatModel(target="bridge-target", summary="a bridge target")
    tm.critical_assets.append("funds")
    tm.add_invariant("INV-1", "funds are conserved", applies_to=["funds"])
    tm.add_transition("withdraw", "from-locked", "to-open", trigger="withdraw",
                      guard="owner-only", authorized_actors=["owner"])
    model = model_from_threatmodel(tm)
    assert model.target == "bridge-target"
    assert any(o.name == "withdraw" for o in model.operations)
    assert any(i.inv_id == "INV-1" for i in model.invariants)
    assert model.operations[0].guard == "owner-only"


# --------------------------------------------------------------------------- #
# Adversarial / malformed inputs
# --------------------------------------------------------------------------- #

def test_unknown_strategy_and_fixture_raise():
    with pytest.raises(KeyError):
        from blackheart.statespace import strategy
        strategy("does-not-exist")
    with pytest.raises(KeyError):
        make_fixture("does-not-exist")
    with pytest.raises(KeyError):
        skill("does-not-exist")


def test_sequence_with_unknown_operation_is_ignored_not_crashed():
    """An operation the target does not implement must not raise out of the engine."""
    t = make_fixture("partial-failure")
    seq = [AttackStep(index=0, actor="attacker", action="nonexistent_op", params={})]
    _, bad = run_sequence(t, seq)
    assert bad == []


def test_json_serialisation_roundtrip():
    t = make_fixture("cross-user-idor")
    rep = StateSpaceExplorer(t, ExploreConfig(seed=0)).explore(
        HypothesisGenerator(t.model()).generate().hypotheses)
    blob = json.dumps(rep.to_dict())
    assert "violations" in blob and json.loads(blob)["target"] == t.name


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent.parent


def _cli(*args):
    import subprocess
    import sys
    return subprocess.run([sys.executable, "-m", "blackheart", *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=180)


def test_cli_strategies():
    r = _cli("statespace", "strategies")
    assert r.returncode == 0
    assert "cross-user" in r.stdout and "partial-failure" in r.stdout


def test_cli_explore_then_discover_verifies():
    r = _cli("statespace", "--fixture", "stale-authorization", "discover")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["violations"]
    assert "INDEPENDENTLY_VERIFIED" in [v["disposition"] for v in payload["verdicts"]]


def test_cli_guarded_fixture_yields_no_violation():
    r = _cli("statespace", "--fixture", "stale-authorization-guarded", "explore")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["violations"] == []


def test_cli_without_a_target_errors_cleanly():
    # model/hypotheses need a target too
    r = _cli("statespace", "model")
    assert r.returncode == 2
    assert "provide --fixture or --model" in r.stdout
    # explore additionally requires an executable target
    e = _cli("statespace", "explore")
    assert e.returncode == 2
    assert "executable target" in e.stdout


def test_cli_benchmark_runs_without_a_fixture():
    r = _cli("statespace", "benchmark")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["all"]["guided_detection_rate"] == 1.0
    assert payload["all"]["guided_false_positive_rate"] == 0.0
    assert payload["hard"]["guided_seqs_to_detect_total"] < payload["hard"]["baseline_seqs_to_detect_total"]


def test_cli_model_only_supports_model_and_hypotheses(tmp_path: Path):
    from blackheart.threatmodel import ThreatModel

    tm = ThreatModel(target="cli-bridge", summary="a bridge target")
    tm.critical_assets.append("funds")
    tm.add_invariant("INV", "funds are conserved", applies_to=["funds"])
    tm.add_transition("withdraw", "x", "y", trigger="withdraw", guard="owner-only",
                      authorized_actors=["owner"])
    model_file = tmp_path / "tm.json"
    model_file.write_text(json.dumps(tm.to_dict()), encoding="utf-8")

    m = _cli("statespace", "--model", str(model_file), "model")
    assert m.returncode == 0 and json.loads(m.stdout)["target"] == "cli-bridge"
    h = _cli("statespace", "--model", str(model_file), "hypotheses")
    assert h.returncode == 0 and json.loads(h.stdout)["hypotheses"]
    # explore needs an executable target, so a model alone must fail cleanly
    e = _cli("statespace", "--model", str(model_file), "explore")
    assert e.returncode == 2 and "executable target" in e.stdout


def test_cli_skill_run_emits_hypotheses(tmp_path: Path):
    from blackheart.threatmodel import ThreatModel

    tm = ThreatModel(target="skill-run", summary="a two-step workflow target")
    tm.critical_assets.append("a")
    tm.add_invariant("INV", "conservation", applies_to=["a"])
    tm.add_transition("initiate", "x", "y", trigger="initiate", guard="owner-only",
                      authorized_actors=["owner"])
    tm.add_transition("settle", "y", "z", trigger="settle", guard="owner-only",
                      authorized_actors=["owner"])
    model_file = tmp_path / "tm.json"
    model_file.write_text(json.dumps(tm.to_dict()), encoding="utf-8")
    r = _cli("statespace", "--model", str(model_file), "skills", "--run", "business-logic")
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["business-logic"]                       # the skill produced hypotheses
    assert all(h["strategy_id"] == "partial-failure" for h in out["business-logic"])


def test_cli_skills_list_and_write(tmp_path: Path):
    r = _cli("statespace", "skills")
    assert r.returncode == 0 and "exploit-verification" in r.stdout
    w = _cli("statespace", "skills", "--write", str(tmp_path))
    assert w.returncode == 0
    assert len(list(tmp_path.glob("adversarial-*/SKILL.md"))) == 10


def test_generated_skills_carry_the_operators_word(tmp_path: Path):
    # The operator's word is universal: every generated adversarial skill carries
    # it too, so no strategy second-guesses a clear instruction into a summary.
    from blackheart.mindset import OPERATOR_AUTHORITY
    from blackheart.statespace.skills import write_skill_files

    write_skill_files(tmp_path, only_missing=False)
    for p in tmp_path.glob("adversarial-*/SKILL.md"):
        body = p.read_text(encoding="utf-8")
        assert "## The operator's word" in body, p
        for rule in OPERATOR_AUTHORITY:
            assert rule in body, p


# --------------------------------------------------------------------------- #
# Portability: a provisioned project inherits the adversarial skills
# --------------------------------------------------------------------------- #

def test_provisioned_project_discovers_adversarial_skills(tmp_path: Path):
    import shutil

    from blackheart.provision import provision_project

    root = tmp_path / "fresh-project"
    root.mkdir()
    # a fresh project checked out with BLACKHEART's canonical skills/agents
    shutil.copytree(ROOT / "skills", root / "skills")
    shutil.copytree(ROOT / "agents", root / "agents")
    provision_project(root)
    discovered = {p.name for p in (root / ".openhands" / "skills").iterdir() if p.is_dir()}
    adversarial = {n for n in discovered if n.startswith("adversarial-")}
    assert len(adversarial) == 10, f"adversarial skills not discovered: {discovered}"
    # the hand-written skills are still there (no clobbering)
    assert "exploit-verification" in discovered
    assert "attacker-mindset" in discovered


# --------------------------------------------------------------------------- #
# Resource hygiene: the verifier must release the targets it constructs
# --------------------------------------------------------------------------- #

class _CloseCountingTarget:
    """A minimal SequenceTarget whose adapter records whether it was closed.

    Regression guard for the resource leak: the verifier builds throwaway
    instances (a fresh target for the independent re-run, a control for the
    differential check) and must close each one. For the real EVM adapter an
    unclosed target leaves its ``anvil`` node alive.
    """

    def __init__(self, inner, closed: list):
        self._inner = inner
        self.adapter = _CountingAdapter(closed)
        self.name = inner.name

    def __getattr__(self, item):
        return getattr(self._inner, item)


class _CountingAdapter:
    def __init__(self, closed: list):
        self._closed = closed

    def close(self):
        self._closed.append(True)


def test_verifier_closes_every_target_it_constructs():
    t, v = _violation("stale-authorization", "no-withdrawal-after-revoke")
    closed: list = []

    def fresh():
        return _CloseCountingTarget(make_fixture("stale-authorization"), closed)

    def control():
        return _CloseCountingTarget(make_fixture("stale-authorization-guarded"), closed)

    cfg = VerifyConfig(control_factory=control, in_scope=True,
                       scope_reference="fixture", authorization_gate_passed=True)
    r = IndependentSequenceVerifier(fresh, cfg).verify(
        v, model=t.model(), preconditions_satisfiable=True)
    assert r.disposition == "INDEPENDENTLY_VERIFIED"
    # one close for the fresh reproduction target, one for the control target
    assert len(closed) == 2, f"verifier leaked a target: {len(closed)} closed"


def test_close_helper_tolerates_a_target_without_close():
    from blackheart.statespace.verify import _close_target

    class _Bare:
        pass

    _close_target(_Bare())            # no adapter -> no-op, no raise
    _close_target(None)               # None -> no-op, no raise
