"""Mutation testing tells a sensitive invariant from a decorative one."""

from __future__ import annotations

from blackheart.assurance.mutation import Mutation, audit_mutations
from blackheart.invariants.engine import InvariantSpec, OpSpec


class Box:
    name = "box"

    def reset(self):
        return {"x": 0, "y": 0}

    def ops(self):
        return [OpSpec("touch", ["attacker"], {})]

    def invariants(self):
        return [InvariantSpec("x-zero", "x stays zero", lambda s: s["x"] == 0)]

    def snapshot(self, state):
        return dict(state)

    def step(self, state, op_name, actor, params):
        return None


def _increment_x(state):
    state["x"] += 1


def test_a_sensitive_invariant_catches_the_mutation():
    audit = audit_mutations(Box(), mutations=(
        Mutation("inc-x", "increment x", _increment_x),
    ))
    assert audit.findings[0].status == "CAUGHT"
    assert audit.trustworthy


def test_an_insensitive_invariant_survives_and_is_reported_weak():
    audit = audit_mutations(Box())
    statuses = {f.mutation: f.status for f in audit.findings}
    assert statuses["increment-first-numeric"] == "CAUGHT"
    assert statuses["zero-first-numeric"] == "SURVIVED"
    assert audit.weak
    assert not audit.trustworthy
    assert "weak evidence" in audit.weak[0].reason


class OwnerBox:
    name = "owner-box"

    def reset(self):
        return {"owner": 0, "x": 0}

    def ops(self):
        return [OpSpec("touch", ["attacker"], {})]

    def invariants(self):
        return [InvariantSpec("owner-zero", "owner stays zero", lambda s: s["owner"] == 0)]

    def snapshot(self, state):
        return dict(state)

    def step(self, state, op_name, actor, params):
        return None


def test_class_specific_mutations_are_selected_and_catch_their_class():
    from blackheart.assurance.mutation import mutations_for
    names = {m.name for m in mutations_for(["access-control"])}
    assert names == {"owner-to-attacker", "zero-owner"}
    audit = audit_mutations(OwnerBox(), classes=["access-control"])
    statuses = {f.mutation: f.status for f in audit.findings}
    assert statuses["owner-to-attacker"] == "CAUGHT"
    assert statuses["zero-owner"] == "SURVIVED"
    assert all(m.classes == ("access-control",) for m in mutations_for(["access-control"]))
