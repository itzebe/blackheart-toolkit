"""Acceptance tests for cross-target attack memory (T2.6).

The memory must be useful *and* safe: it lets a proven attack on one target seed
the search on a structurally similar one, but it must never record an unproven
lead, never assert a vulnerability on its own, and never transfer a sequence that
does not project onto the new target's operations. These tests pin all four.
"""

from __future__ import annotations

from blackheart.learning.transfer import (
    AttackMemory,
    MemoryEntry,
    StepShape,
    TargetSignature,
    _project,
    signature_of,
    similarity,
)
from blackheart.models import AttackStep


# -- minimal fake targets --------------------------------------------------- #

class _Op:
    def __init__(self, name, actors=("attacker",), domain=None):
        self.name = name
        self.actors = list(actors)
        self.param_domain = domain or {}
        self.description = ""


class _Inv:
    def __init__(self, inv_id):
        self.inv_id = inv_id


class _Target:
    def __init__(self, name, ops, inv_ids=("inv",)):
        self.name = name
        self._ops = ops
        self._invs = [_Inv(i) for i in inv_ids]

    def ops(self):
        return list(self._ops)

    def invariants(self):
        return list(self._invs)


VAULT_A = _Target("vault-a", [_Op("deposit", domain={"amount": [1, 100]}),
                              _Op("redeem", domain={"shares": [1, 100]})],
                  inv_ids=("no-over-redeem",))
VAULT_B = _Target("vault-b", [_Op("deposit", domain={"amount": [2, 200]}),
                              _Op("redeem", domain={"shares": [2, 200]})],
                  inv_ids=("no-over-redeem",))


def test_signature_captures_tokens_roles_and_invariants():
    sig = signature_of(VAULT_A, root_cause="accounting-rounding")
    assert "deposit" in sig.op_tokens and "redeem" in sig.op_tokens
    assert sig.actor_roles == {"attacker"}
    assert sig.invariant_ids == {"no-over-redeem"}
    assert sig.root_cause == "accounting-rounding"


def test_similarity_is_symmetric_and_higher_for_closer_targets():
    a = signature_of(VAULT_A, root_cause="accounting-rounding")
    b = signature_of(VAULT_B, root_cause="accounting-rounding")
    far = signature_of(_Target("thing", [_Op("ping")], inv_ids=("liveness",)),
                       root_cause="dos")
    assert similarity(a, b) == similarity(b, a)
    assert similarity(a, b) > similarity(a, far)


def test_only_certified_findings_are_recorded(tmp_path):
    mem = AttackMemory(tmp_path / "mem.jsonl")
    seq = [AttackStep(0, "attacker", "redeem", {"shares": 1})]

    # An unproven certificate must NOT be promoted into the memory.
    assert mem.record_from_certificate(
        target=VAULT_A, sequence=seq, root_cause="accounting-rounding",
        invariant_id="no-over-redeem", certificate={"proven": False}) is None
    assert mem.entries() == []

    entry = mem.record_from_certificate(
        target=VAULT_A, sequence=seq, root_cause="accounting-rounding",
        invariant_id="no-over-redeem",
        certificate={"proven": True, "witness": [seq[0].to_dict()]})
    assert entry is not None
    assert len(mem.entries()) == 1
    assert mem.entries()[0].root_cause == "accounting-rounding"


def test_memory_persists_and_reloads(tmp_path):
    path = tmp_path / "mem.jsonl"
    mem = AttackMemory(path)
    mem.record(MemoryEntry(
        entry_id="e1", source_target="vault-a", root_cause="accounting-rounding",
        invariant_id="no-over-redeem", signature=signature_of(VAULT_A),
        steps=[StepShape("redeem", {"redeem"}, "attacker")]))
    reloaded = AttackMemory(path)
    assert len(reloaded.entries()) == 1
    assert reloaded.entries()[0].entry_id == "e1"


def test_seeds_project_onto_a_similar_targets_operations(tmp_path):
    mem = AttackMemory(tmp_path / "mem.jsonl")
    mem.record(MemoryEntry(
        entry_id="e1", source_target="vault-a", root_cause="accounting-rounding",
        invariant_id="no-over-redeem", signature=signature_of(VAULT_A, root_cause="accounting-rounding"),
        steps=[StepShape("redeem", {"redeem"}, "attacker",
                         params={"shares": 1}, param_is_boundary={"shares": True})]))
    seeds = mem.seeds_for(VAULT_B, min_score=0.2, root_cause="accounting-rounding")
    assert len(seeds) == 1
    assert seeds[0][0].action == "redeem"
    # The boundary was re-derived on the *new* target's domain (min = 2), not copied.
    assert seeds[0][0].params["shares"] == 2


def test_a_distant_target_receives_no_seed(tmp_path):
    mem = AttackMemory(tmp_path / "mem.jsonl")
    mem.record(MemoryEntry(
        entry_id="e1", source_target="vault-a", root_cause="accounting-rounding",
        invariant_id="no-over-redeem", signature=signature_of(VAULT_A),
        steps=[StepShape("redeem", {"redeem"}, "attacker")]))
    far = _Target("thing", [_Op("ping")], inv_ids=("liveness",))
    assert mem.seeds_for(far, min_score=0.35) == []


def test_projection_stops_at_the_first_unmappable_step():
    entry = MemoryEntry(
        entry_id="e", source_target="x", root_cause="r", invariant_id="i",
        signature=TargetSignature("x"),
        steps=[StepShape("redeem", {"redeem"}, "attacker"),
               StepShape("totally_unrelated_verb", {"totally", "unrelated", "verb"}, "attacker")])
    seq = _project(entry, VAULT_B.ops(), VAULT_B)
    assert [s.action for s in seq] == ["redeem"]      # the projectable prefix only


def test_actor_is_mapped_to_a_role_the_operation_permits():
    op = _Op("redeem", actors=("keeper",), domain={"shares": [1]})
    entry = MemoryEntry(
        entry_id="e", source_target="x", root_cause="r", invariant_id="i",
        signature=TargetSignature("x"),
        steps=[StepShape("redeem", {"redeem"}, "attacker", params={"shares": 1})])
    seq = _project(entry, [op], VAULT_B)
    assert seq[0].actor == "keeper"       # not the stored 'attacker', which is invalid here


def test_harness_records_certified_findings_and_transfers_them(tmp_path):
    """End-to-end: a certified corpus case grows the memory, and a similar case
    then receives a transferred seed -- while the run stays at zero false positives."""
    from blackheart.discovery import corpus as c
    from blackheart.discovery import heldout as h
    from blackheart.discovery.harness import run_case

    mem = AttackMemory(tmp_path / "mem.jsonl")
    cases = {x.case_id: x for x in c.corpus()}
    hh = {x.case_id: x for x in h.holdout_cases()}

    trained = run_case(cases["H06-rounding-up"], memory=mem)
    assert trained.certified and trained.recorded_to_memory
    assert len(mem.entries()) == 1

    later = run_case(hh["HH4-round-up-redeem"], memory=mem)
    assert later.certified                       # still certified
    assert later.enhanced_false_positive is False
    assert later.transferred_seeds >= 1          # the rounding shape carried over
