"""A transferred attack must satisfy the assumptions its certificate relied on."""

from __future__ import annotations

from blackheart.invariants.engine import OpSpec
from blackheart.learning.transfer import AttackMemory, MemoryEntry, TargetSignature
from blackheart.models import AttackStep


class FakeTarget:
    def __init__(self, name, ops):
        self.name = name
        self._ops = ops

    def ops(self):
        return self._ops

    def invariants(self):
        return []


def _source():
    return FakeTarget("source-vault", [
        OpSpec("withdraw", ["attacker"], {"amount": [1]}),
        OpSpec("liquidate", ["attacker"], {}),
    ])


def _record(memory):
    sequence = [
        AttackStep(0, "attacker", "withdraw", {"amount": 1}),
        AttackStep(1, "attacker", "liquidate", {}),
    ]
    return memory.record_from_certificate(
        target=_source(), sequence=sequence, root_cause="liquidation",
        invariant_id="no-unfair-liquidation",
        certificate={"proven": True, "witness": [s.to_dict() for s in sequence]},
        outcome="seize a healthy position",
    )


def test_a_certificate_records_the_capabilities_it_relied_on(tmp_path):
    memory = AttackMemory(tmp_path / "memory.jsonl")
    entry = _record(memory)
    assert entry is not None
    assert entry.assumptions["required_ops"] == ["withdraw", "liquidate"]
    assert entry.assumptions["min_actors"] == 1


def test_a_target_missing_an_operation_refuses_the_transfer(tmp_path):
    memory = AttackMemory(tmp_path / "memory.jsonl")
    _record(memory)
    partial = FakeTarget("partial-vault", [
        OpSpec("withdraw", ["attacker"], {"amount": [1]}),
    ])
    assert memory.seeds_for(partial, min_score=0.0) == []
    decisions = memory.transfer_decisions(partial, min_score=0.0)
    assert decisions and not decisions[0]["accepted"]
    assert "liquidate" in decisions[0]["reason"]


def test_a_target_with_the_same_surface_accepts_the_transfer(tmp_path):
    memory = AttackMemory(tmp_path / "memory.jsonl")
    _record(memory)
    twin = FakeTarget("twin-vault", [
        OpSpec("withdraw", ["attacker"], {"amount": [1]}),
        OpSpec("liquidate", ["attacker"], {}),
    ])
    seeds = memory.seeds_for(twin, min_score=0.0)
    assert seeds and [s.action for s in seeds[0]] == ["withdraw", "liquidate"]
    assert memory.transfer_decisions(twin, min_score=0.0)[0]["accepted"]


def test_assumptions_survive_a_json_round_trip():
    entry = MemoryEntry(
        entry_id="e1", source_target="t", root_cause="r", invariant_id="i",
        signature=TargetSignature(target="t"),
        assumptions={"required_ops": ["a", "b"], "min_actors": 2},
    )
    restored = MemoryEntry.from_dict(entry.to_dict())
    assert restored.assumptions == {"required_ops": ["a", "b"], "min_actors": 2}
