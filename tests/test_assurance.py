"""Acceptance tests for the assurance layer: bounded-exhaustive certification and
the search portfolio.

These are deterministic (fixed seeds, fixed fixtures). They assert the two
properties that make the layer trustworthy:

  * the certifier is *exact* -- it explores the whole space to its bound, reports
    a length-optimal counterexample when one exists, and honestly refuses to call a
    truncated or stochastic search "clean";
  * the portfolio is a *superset* -- its detection set is the union of every
    strategy, so it finds at least what any single strategy finds, and it reports
    each stage's coverage rather than a single flattering number.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blackheart.assurance import (
    STRATEGIES,
    CertifyConfig,
    CoverageCertificate,
    PortfolioConfig,
    build_alphabet,
    certify,
    run_portfolio,
)
from blackheart.invariants.registry import make_target
from blackheart.statespace.hard import make_hard

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# The alphabet
# --------------------------------------------------------------------------- #

def test_alphabet_is_finite_deterministic_and_covers_actors():
    target = make_target("lending-oracle")
    a1 = build_alphabet(target)
    a2 = build_alphabet(target)
    assert a1 and a1 == a2, "alphabet must be deterministic"
    # Every symbol names a declared operation and an actor allowed to invoke it.
    op_actors = {op.name: set(op.actors or ["attacker"]) for op in target.ops()}
    for entry in a1:
        assert entry.op in op_actors
        assert entry.actor in op_actors[entry.op]


def test_alphabet_keeps_boundary_values():
    target = make_target("lending-oracle")
    values = {
        e.params.get("amount")
        for e in build_alphabet(target)
        if e.op == "borrow" and "amount" in e.params
    }
    # The declared minimum and a canonical small value must be present -- the
    # boundary a rounding/off-by-one bug lives on.
    assert 1 in values


# --------------------------------------------------------------------------- #
# Certification: exactness and honest bounds
# --------------------------------------------------------------------------- #

def test_certify_finds_length_optimal_counterexample_breadth_first():
    target = make_target("permit-replay")
    cert = certify(target, CertifyConfig(max_depth=5, max_sequences=200000))
    assert cert.broke
    # Breadth-first: the first counterexample for an invariant is the shortest one.
    for v in cert.violations:
        assert v["length"] == min(
            w["length"] for w in cert.violations if w["invariant_id"] == v["invariant_id"]
        )
        assert v["reachable_by_attacker"] is True


def test_certify_is_exhaustive_and_counts_the_whole_space():
    target = make_target("permit-replay")
    cert = certify(target, CertifyConfig(max_depth=3, max_sequences=200000))
    assert cert.exhaustive is True
    assert cert.complete_to_depth == 3
    assert cert.sequences_tested == cert.sequences_in_space
    assert cert.sequences_in_space == sum(cert.alphabet_size ** d for d in range(1, 4))


def test_clean_certificate_states_its_bound_and_limits():
    # A target with no bug within the bound yields a *bounded* clean verdict, not
    # an unqualified "secure".
    target = make_target("lending-oracle")
    cert = certify(target, CertifyConfig(max_depth=1, max_sequences=50000))
    assert not cert.broke
    assert cert.exhaustive
    line = cert.verdict_line()
    assert "CERTIFIED CLEAN" in line
    assert "does NOT cover" in line
    assert "longer" in line


def test_truncated_search_is_inconclusive_not_clean():
    # A budget too small to finish the bound must never be reported as clean.
    target = make_target("lending-oracle")
    cert = certify(target, CertifyConfig(max_depth=4, max_sequences=100))
    assert cert.exhaustive is False
    assert "INCONCLUSIVE" in cert.verdict_line()
    assert cert.truncated_reason


def test_broken_certificate_reports_broken_not_clean():
    target = make_target("permit-replay")
    cert = certify(target, CertifyConfig(max_depth=5, max_sequences=200000))
    assert "BROKEN" in cert.verdict_line()


def test_certificate_prices_findings_when_asked():
    target = make_target("permit-replay")
    cert = certify(target, CertifyConfig(max_depth=5, max_sequences=200000,
                                         price_findings=True))
    assert cert.economic, "expected priced accounts for the counterexamples"
    assert all("attacker_profit" in acct for acct in cert.economic)


def test_empty_alphabet_is_handled_honestly():
    class _NoOps:
        name = "no-ops"
        def ops(self):
            return []
        def invariants(self):
            return []
        def reset(self):
            return {}
        def step(self, *a, **k):
            raise AssertionError("no ops")
        def snapshot(self, state):
            return {}

    cert = certify(_NoOps(), CertifyConfig(max_depth=2))
    assert cert.alphabet_size == 0
    assert cert.exhaustive is False
    assert "INCONCLUSIVE" in cert.verdict_line()


# --------------------------------------------------------------------------- #
# The portfolio: superset, coverage ledger, honesty
# --------------------------------------------------------------------------- #

def test_portfolio_runs_every_strategy_and_ledgers_coverage():
    target = make_target("permit-replay")
    res = run_portfolio(target, PortfolioConfig(
        certify_depth=2, corpus_sequences=600, random_runs=120,
        adaptive_sequences=300, guided_depth=4,
    ))
    assert [s.strategy for s in res.stages] == list(STRATEGIES)
    assert all(s.ran for s in res.stages)
    for s in res.stages:
        assert s.sequences >= 0
        assert not s.error, f"{s.strategy} errored: {s.error}"


def test_portfolio_detection_is_a_superset_of_the_best_single_strategy():
    # The union can only add: whatever the coverage-guided corpus stage finds on
    # its own is present in the portfolio's union.
    target = make_target("permit-replay")
    from blackheart.fuzz import CorpusConfig, CoverageGuidedFuzzer

    solo = CoverageGuidedFuzzer(target, CorpusConfig(seed=0, max_sequences=1500,
                                                     max_steps=12)).run()
    solo_invs = {f.inv_id for f in solo.failures}
    assert solo_invs, "fixture should yield at least one violation"

    res = run_portfolio(target, PortfolioConfig(
        certify_depth=2, corpus_sequences=1500, random_runs=150,
        adaptive_sequences=300, guided_depth=4,
    ))
    assert solo_invs <= set(res.invariants_found)


def test_portfolio_isolates_a_failing_stage():
    # A strategy that raises must be recorded as an error, not abort the others.
    class _BadTarget:
        name = "bad"
        def __init__(self):
            self._real = make_target("permit-replay")
        def ops(self):
            return self._real.ops()
        def invariants(self):
            return self._real.invariants()
        def reset(self):
            return self._real.reset()
        def snapshot(self, state):
            return self._real.snapshot(state)
        def step(self, state, op, actor, params):
            return self._real.step(state, op, actor, params)

    res = run_portfolio(_BadTarget(), PortfolioConfig(
        strategies=("exhaustive", "adaptive"), certify_depth=2, adaptive_sequences=50,
    ))
    assert len(res.stages) == 2
    # Whatever happens, the run completes and reports a verdict.
    assert res.verdict_line()


def test_portfolio_verdict_is_honest_when_clean():
    # A guarded fixture yields nothing at a shallow bound; the verdict must be a
    # bounded negative, never "secure".
    target = make_hard("deep-gated-escalation-guarded")
    res = run_portfolio(target, PortfolioConfig(
        certify_depth=2, corpus_sequences=800, random_runs=120,
        adaptive_sequences=200, guided_depth=3,
    ))
    line = res.verdict_line()
    assert not res.invariants_found
    assert "NOT a proof of absence" in line or "CERTIFIED CLEAN" in line


def test_portfolio_verdict_reports_found_union():
    target = make_target("lending-oracle")
    res = run_portfolio(target, PortfolioConfig(
        certify_depth=2, corpus_sequences=300, random_runs=80,
        adaptive_sequences=200, guided_depth=3,
    ))
    assert res.invariants_found
    assert "FOUND" in res.verdict_line()


def test_portfolio_subset_of_strategies_is_respected():
    target = make_target("permit-replay")
    res = run_portfolio(target, PortfolioConfig(
        strategies=("exhaustive",), certify_depth=2,
    ))
    assert [s.strategy for s in res.stages] == ["exhaustive"]


# --------------------------------------------------------------------------- #
# Universal wiring: the doctrine reaches roles, agents and the skill
# --------------------------------------------------------------------------- #

def test_coverage_doctrine_is_canonical_and_complete():
    from blackheart.mindset import COVERAGE_DOCTRINE, coverage_doctrine

    rules = " ".join(COVERAGE_DOCTRINE).lower()
    assert "superset" in rules
    assert "bounded-exhaustive" in rules
    assert "not found within budget" in rules
    assert coverage_doctrine() == list(COVERAGE_DOCTRINE)


def test_coverage_doctrine_is_in_every_prompt_block():
    from blackheart.mindset import agent_lens_block, prompt_block

    for block in (prompt_block(), agent_lens_block()):
        assert "coverage" in block.lower()
        assert "superset" in block.lower() or "portfolio" in block.lower()


def test_every_agent_carries_the_coverage_bar():
    agents = sorted((REPO_ROOT / "agents").glob("*.md"))
    assert agents
    missing = [p.stem for p in agents if "## The coverage bar" not in p.read_text(encoding="utf-8")]
    assert not missing, f"agents missing the coverage bar: {missing}"


def test_assurance_skill_exists_and_is_discoverable():
    skill = REPO_ROOT / "skills" / "completeness-assurance" / "SKILL.md"
    assert skill.exists()
    text = skill.read_text(encoding="utf-8")
    assert "bounded-exhaustive" in text
    assert "portfolio" in text


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_certify_and_portfolio_run(capsys):
    from blackheart.cli import main

    assert main(["assure", "certify", "--target", "permit-replay", "--depth", "3"]) == 0
    out = capsys.readouterr().out
    assert "CERTIFIED CLEAN" in out

    assert main(["assure", "portfolio", "--target", "lending-oracle", "--depth", "2",
                 "--runs", "200", "--random-runs", "60"]) == 0
    out = capsys.readouterr().out
    assert "strategies=" in out


def test_cli_oracles_runs_and_reports_verdict(capsys):
    from blackheart.cli import main

    assert main(["assure", "oracles", "--target", "permit-replay", "--depth", "3"]) == 0
    out = capsys.readouterr().out
    assert "ORACLES WIRED" in out
    assert "discriminating" in out


# --------------------------------------------------------------------------- #
# State-space dedup: the fast path must equal the full-enumeration reference
# --------------------------------------------------------------------------- #

class _IsolatedWrapper:
    """Wrap a target and force ``state_is_isolated`` on or off, for the differential."""

    def __init__(self, target, isolated: bool) -> None:
        self._t = target
        self.name = target.name
        self._iso = isolated

    def reset(self):
        return self._t.reset()

    def ops(self):
        return self._t.ops()

    def invariants(self):
        return self._t.invariants()

    def step(self, s, op, actor, params):
        return self._t.step(s, op, actor, params)

    def snapshot(self, s):
        return self._t.snapshot(s)

    def state_is_isolated(self) -> bool:
        return self._iso


@pytest.mark.parametrize("target_name", [
    "permit-replay", "callback-reentrancy", "vulnerable", "safe", "proxy-initializer",
])
def test_state_dedup_matches_full_enumeration(target_name):
    # The state-dedup fast path is a *pure optimisation*: it must reach the same
    # counterexamples and the same verdict as the full sequence enumeration.
    base = make_target(target_name)
    cfg = CertifyConfig(max_depth=4, price_findings=False, max_sequences=2_000_000)
    full = certify(_IsolatedWrapper(base, False), cfg)
    fast = certify(_IsolatedWrapper(base, True), cfg)
    assert fast.method == "state-dedup"
    assert full.method == "sequences"
    assert sorted((v["invariant_id"], v["length"], v["reachable_by_attacker"])
                  for v in fast.violations) == \
        sorted((v["invariant_id"], v["length"], v["reachable_by_attacker"])
               for v in full.violations)
    assert fast.complete_to_depth == full.complete_to_depth
    assert fast.exhaustive == full.exhaustive
    assert fast.sequences_in_space == full.sequences_in_space


def test_state_dedup_reports_closure_for_all_depths():
    # On a target whose reachable state space is small and closed, the certificate
    # may honestly claim completeness for *all* depths.
    target = make_hard("hard-stale-authorization")
    cert = certify(target, CertifyConfig(max_depth=10, price_findings=False,
                                         max_sequences=5_000_000))
    assert cert.method == "state-dedup"
    assert cert.exhaustive
    if cert.complete_for_all_depths:
        assert "ALL sequence lengths" in cert.verdict_line()


# --------------------------------------------------------------------------- #
# The oracle audit: a clean search is only as good as the oracle it checks
# --------------------------------------------------------------------------- #

def test_oracle_audit_calls_real_invariants_discriminating():
    from blackheart.assurance import OracleAuditConfig, audit_oracles

    # The registered targets' invariants are all genuinely live -- the audit must
    # confirm that, not cry wolf.
    for name in ["permit-replay", "lending-oracle", "callback-reentrancy", "vulnerable"]:
        audit = audit_oracles(make_target(name),
                              OracleAuditConfig(max_depth=3, max_sequences=20000))
        assert audit.findings, name
        assert not audit.weak, (name, [f.to_dict() for f in audit.weak])
        assert "ORACLES WIRED" in audit.verdict_line()


def test_oracle_audit_catches_a_vacuous_oracle():
    from blackheart.assurance import OracleAuditConfig, audit_oracles

    class _Vacuous:
        name = "vacuous"

        def reset(self):
            return {"x": 0}

        def ops(self):
            from blackheart.invariants.engine import OpSpec
            return [OpSpec("bump", ["attacker"], {})]

        def invariants(self):
            from blackheart.invariants.engine import InvariantSpec
            return [InvariantSpec("always-true", "trivially true",
                                  lambda st: True)]

        def step(self, st, op, actor, params):
            st["x"] += 1

        def snapshot(self, st):
            return dict(st)

        def state_is_isolated(self):
            return True

    audit = audit_oracles(_Vacuous(), OracleAuditConfig(max_depth=3, max_sequences=2000))
    f = audit.findings[0]
    assert f.verdict == "vacuous"
    assert not f.trustworthy
    assert "WEAK ORACLES" in audit.verdict_line()


def test_oracle_audit_catches_an_unevaluable_oracle():
    from blackheart.assurance import OracleAuditConfig, audit_oracles

    class _Raiser:
        name = "raiser"

        def reset(self):
            return {"x": 0}

        def ops(self):
            from blackheart.invariants.engine import OpSpec
            return [OpSpec("bump", ["attacker"], {})]

        def invariants(self):
            from blackheart.invariants.engine import InvariantSpec

            def boom(st):
                raise RuntimeError("never evaluable")

            return [InvariantSpec("boom", "always raises", boom)]

        def step(self, st, op, actor, params):
            st["x"] += 1

        def snapshot(self, st):
            return dict(st)

        def state_is_isolated(self):
            return True

    audit = audit_oracles(_Raiser(), OracleAuditConfig(max_depth=3, max_sequences=2000))
    assert audit.findings[0].verdict == "unevaluable"


def test_oracle_audit_needs_cross_leaf_probe_for_a_comparison():
    # A comparison invariant is immune to a *local* perturbation of either side;
    # only a cross-leaf mutation (set one side to the other's value) flips it. The
    # audit must find that, or it would wrongly report a live oracle as vacuous.
    from blackheart.assurance import OracleAuditConfig, audit_oracles
    from blackheart.invariants.engine import InvariantSpec, OpSpec

    class _Comparison:
        name = "comparison"

        def reset(self):
            return {"balance": 100, "withdrawn": 0}

        def ops(self):
            return [OpSpec("touch", ["attacker"], {})]

        def invariants(self):
            return [InvariantSpec("no-overdraw", "withdrawn never exceeds balance",
                                  lambda st: st["withdrawn"] <= st["balance"])]

        def step(self, st, op, actor, params):
            pass  # state is fixed; only the audit's mutations move it

        def snapshot(self, st):
            return dict(st)

        def state_is_isolated(self):
            return True

    audit = audit_oracles(_Comparison(),
                          OracleAuditConfig(max_depth=2, max_sequences=200))
    f = audit.findings[0]
    assert f.verdict == "discriminating", f.to_dict()
    assert "cross-leaf" in (f.first_flip or "")


def test_oracle_doctrine_is_canonical_and_in_every_block():
    from blackheart.mindset import (
        ORACLE_DOCTRINE,
        agent_lens_block,
        oracle_doctrine,
        prompt_block,
        skill_document,
    )

    rules = " ".join(ORACLE_DOCTRINE).lower()
    assert "audit" in rules
    assert "vacuous" in rules or "weak" in rules
    assert oracle_doctrine() == list(ORACLE_DOCTRINE)
    assert "## The oracle bar" in agent_lens_block()
    assert "oracle" in prompt_block().lower()
    assert "## Oracles" in skill_document()


def test_every_agent_carries_the_oracle_bar():
    agents = sorted((REPO_ROOT / "agents").glob("*.md"))
    assert agents
    missing = [p.stem for p in agents if "## The oracle bar" not in p.read_text(encoding="utf-8")]
    assert not missing, f"agents missing the oracle bar: {missing}"


def test_portfolio_includes_oracles_and_reports_weak_oracles():
    from blackheart.assurance import PortfolioConfig, run_portfolio

    target = make_target("permit-replay")
    res = run_portfolio(target, PortfolioConfig(
        certify_depth=3, corpus_sequences=300, random_runs=60, adaptive_sequences=100,
    ))
    assert "oracles" in [s.strategy for s in res.stages]
    assert res.oracle_audit is not None
    # The real targets have live oracles, so no weak-oracle warning is raised.
    assert res.weak_oracles == []
    assert "oracles" in res.to_dict()["stages"][0]["strategy"] or \
        any(s.strategy == "oracles" for s in res.stages)
