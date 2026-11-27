"""Tests for the independent verifier and the seven quality gates."""

from __future__ import annotations

from blackheart.models import Classification, Finding, GateStatus, ReviewIndependence
from blackheart.verify import IndependentVerifier, VerificationContext


def _finding() -> Finding:
    return Finding(finding_id="f:1", title="candidate", target="t")


def _ctx(**overrides) -> VerificationContext:
    base = dict(
        in_scope=True,
        scope_reference="scope#1",
        protection_exists=False,
        behavior_intentional=False,
        duplicate_known=False,
        attacker_controls_input=True,
        reachable=True,
        measurable_impact=True,
        reproduce=lambda: True,
        evidence_ids=["ev-1"],
    )
    base.update(overrides)
    return VerificationContext(**base)


def test_all_gates_pass_is_confirmed():
    result = IndependentVerifier().verify(_finding(), _ctx())
    assert result.classification == Classification.CONFIRMED
    assert all(g.status == GateStatus.PASS for g in result.gates)


def test_unreproducible_finding_is_not_confirmed():
    result = IndependentVerifier().verify(_finding(), _ctx(reproduce=lambda: False))
    assert result.classification != Classification.CONFIRMED


def test_reproduction_that_raises_is_not_reproduction():
    def boom():
        raise RuntimeError("poc failed to run")

    result = IndependentVerifier().verify(_finding(), _ctx(reproduce=boom))
    assert result.classification != Classification.CONFIRMED
    gate4 = [g for g in result.gates if g.gate == 4][0]
    assert gate4.status == GateStatus.FAIL


def test_existing_protection_blocks_the_finding():
    result = IndependentVerifier().verify(_finding(), _ctx(protection_exists=True))
    assert result.classification != Classification.CONFIRMED
    gate3 = [g for g in result.gates if g.gate == 3][0]
    assert gate3.status == GateStatus.FAIL


def test_out_of_scope_finding_is_classified_out_of_scope():
    result = IndependentVerifier().verify(_finding(), _ctx(in_scope=False))
    assert result.classification == Classification.OUT_OF_SCOPE


def test_duplicate_is_classified():
    result = IndependentVerifier().verify(_finding(), _ctx(duplicate_known=True))
    assert result.classification == Classification.DUPLICATE_OR_KNOWN


def test_intentional_behaviour_is_informational():
    result = IndependentVerifier().verify(_finding(), _ctx(behavior_intentional=True))
    assert result.classification == Classification.INFORMATIONAL


def test_unreachable_and_uncontrolled_is_false_positive():
    result = IndependentVerifier().verify(
        _finding(), _ctx(reachable=False, attacker_controls_input=False)
    )
    assert result.classification == Classification.FALSE_POSITIVE


def test_unknown_gate_blocks_confirmed():
    result = IndependentVerifier().verify(_finding(), _ctx(measurable_impact=None))
    assert result.classification != Classification.CONFIRMED
    assert any(g.status == GateStatus.UNKNOWN for g in result.gates)


def test_finding_gates_pass_requires_seven_passes():
    finding = _finding()
    IndependentVerifier().verify(finding, _ctx())
    assert finding.gates_pass()


# --------------------------------------------------------------------------- #
# Gate 6 must state the reviewer's real provenance, never assume independence
# --------------------------------------------------------------------------- #

def _gate6(result):
    return next(g for g in result.gates if g.gate == 6)


def test_gate6_does_not_claim_independence_when_none_is_recorded():
    """The default is the deterministic verifier, not an independent model review."""
    result = IndependentVerifier().verify(_finding(), _ctx())
    assert _gate6(result).status == GateStatus.PASS
    assert "independently authenticated model" not in _gate6(result).detail
    assert "not an independent-model review" in _gate6(result).detail
    assert result.review_independence == ReviewIndependence.UNRECORDED


def test_a_same_model_review_is_never_confirmed_as_independent():
    """A same-model review is real but is not independent verification."""
    result = IndependentVerifier().verify(
        _finding(), _ctx(review_independence=ReviewIndependence.SAME_MODEL)
    )
    assert _gate6(result).status == GateStatus.FAIL
    assert result.classification != Classification.CONFIRMED
    assert "same-model" in _gate6(result).detail
    assert "NOT an independent" in _gate6(result).detail


def test_an_independent_model_review_passes_gate6():
    result = IndependentVerifier().verify(
        _finding(), _ctx(review_independence=ReviewIndependence.INDEPENDENT_MODEL)
    )
    assert _gate6(result).status == GateStatus.PASS
    assert result.classification == Classification.CONFIRMED
    assert result.review_independence == ReviewIndependence.INDEPENDENT_MODEL


def test_review_independence_survives_a_finding_round_trip():
    finding = _finding()
    IndependentVerifier().verify(
        finding, _ctx(review_independence=ReviewIndependence.SAME_MODEL)
    )
    restored = Finding.from_dict(finding.to_dict())
    assert restored.review_independence == ReviewIndependence.SAME_MODEL


def test_an_unrecognised_provenance_fails_closed_to_same_model():
    """A JSON ctx with a bad value must never be read as independent."""
    result = IndependentVerifier().verify(_finding(), _ctx(review_independence="bogus"))
    assert result.review_independence == ReviewIndependence.SAME_MODEL
    assert _gate6(result).status == GateStatus.FAIL
    assert result.classification != Classification.CONFIRMED


def test_a_finding_loaded_from_a_bad_provenance_fails_closed():
    """A hand-edited finding file cannot smuggle in a fabricated provenance."""
    base = {"finding_id": "x", "title": "t", "target": "t"}
    assert Finding.from_dict({**base, "review_independence": "bogus"}).review_independence \
        is ReviewIndependence.SAME_MODEL
    # A missing value is honestly unrecorded, not silently promoted.
    assert Finding.from_dict(base).review_independence is ReviewIndependence.UNRECORDED


def test_verify_cli_rejects_a_malformed_ctx_file_cleanly(tmp_path, capsys):
    """A bad ``--ctx`` file is user input: it must fail with a clear message, not
    a traceback, and it must never be silently dropped or coerced into a pass."""
    import argparse
    import json

    from blackheart.cli import cmd_verify

    finding = {"finding_id": "F1", "title": "t", "target": "T",
               "classification": "NEEDS_MORE_EVIDENCE"}
    fpath = tmp_path / "f.json"
    fpath.write_text(json.dumps(finding), encoding="utf-8")

    # An unknown field is a typo, not something to ignore.
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps({"reachable": True, "bogus_key": 1}), encoding="utf-8")
    rc = cmd_verify(argparse.Namespace(finding=str(fpath), ctx=str(unknown)))
    assert rc == 2
    assert "unknown --ctx field" in capsys.readouterr().err

    # A non-object is not a context.
    notobj = tmp_path / "notobj.json"
    notobj.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    rc = cmd_verify(argparse.Namespace(finding=str(fpath), ctx=str(notobj)))
    assert rc == 2
    assert "must be a JSON object" in capsys.readouterr().err


def test_verify_cli_records_provenance_without_trusting_the_string(tmp_path, capsys):
    """A raw provenance string in ``--ctx`` is coerced through the shared rule:
    an unreadable value fails closed to SAME_MODEL, never to INDEPENDENT_MODEL."""
    import argparse
    import json

    from blackheart.cli import cmd_verify

    finding = {"finding_id": "F1", "title": "t", "target": "T",
               "classification": "NEEDS_MORE_EVIDENCE"}
    fpath = tmp_path / "f.json"
    fpath.write_text(json.dumps(finding), encoding="utf-8")

    for claimed, expected in [("INDEPENDENT_MODEL", "INDEPENDENT_MODEL"),
                              ("TRUST_ME", "SAME_MODEL")]:
        ctx = tmp_path / f"{claimed}.json"
        ctx.write_text(json.dumps({"reachable": True, "review_independence": claimed}),
                       encoding="utf-8")
        # This finding is not confirmed, so the exit code must say so (a rejected
        # finding is not a pass); the provenance rule is what this test pins.
        assert cmd_verify(argparse.Namespace(finding=str(fpath), ctx=str(ctx))) == 1
        captured = capsys.readouterr()
        out = json.loads(captured.out)
        assert out["review_independence"] == expected
        assert "not a confirmed finding" in captured.err
