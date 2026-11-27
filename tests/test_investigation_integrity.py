"""Tamper-evidence for the P3 investigation log — the full threat matrix.

The investigation log is the record of what was *actually* reproduced, so a
verdict fabricated by editing the log must not be trusted. These tests cover the
whole integrity threat model the mission names, and they state the honest
limitation where a local, keyless log cannot defend itself:

  1. accidental corruption ......................... detected
  2. a single record edited ........................ detected
  3. a record + its adjacent hash edited ........... detected
  4. delete / reorder / insert / truncate records .. detected
  5. wholesale rewrite of the log .................. detected *with a key*
  6. host or signing-key compromise ................ NOT defended (documented)
  7. legacy records ................................ reported LEGACY, not trusted

The last row of the "wholesale rewrite" case (an attacker who recomputes the
whole hash chain and holds no key) is asserted to be *undetectable by the chain
alone* -- the design does not pretend otherwise, and the keyed layer is what
closes it.
"""

from __future__ import annotations

import json

import pytest

from blackheart.hypothesis.generation import GeneratedHypothesis
from blackheart.integrity import (
    GENESIS,
    FAILED,
    LEGACY,
    UNAVAILABLE,
    VERIFIED,
    Checkpoint,
    IntegrityKey,
    chain_hash,
    content_hash,
    generate_key,
    key_from_file,
    key_to_file,
    verify_chain,
)
from blackheart.investigation import InvestigationEngine, InvestigationStore


def _hypothesis() -> GeneratedHypothesis:
    return GeneratedHypothesis(
        hyp_id="P2-Target:accounting-manipulation::x",
        objective_id="Target:accounting-manipulation",
        title="Donation breaks the share/asset accounting invariant",
        category="accounting-manipulation",
        component="Vault",
        entry_point="flashLoan",
        attacker_capability="any external actor with a token balance",
        trust_boundary="user <-> vault",
        critical_asset="vault-liquidity",
        invariant="convertToShares(totalSupply) == totalAssets()",
        expected_impact="state-corruption: accounting diverges from assets",
        impact_id="state-corruption",
        strategy="donate to shift the live balance without minting shares",
        required_tools=["forge"],
        reproduction_criteria="after a donation the invariant is false",
        falsification_criteria="the invariant holds for every donation",
        authorization_requirement="asset must be AUTHORIZED",
        novelty_requirement="a NoveltyReview must classify it LIKELY_NEW",
    )


def _start(tmp_path, *, key=None):
    store = InvestigationStore(tmp_path / "investigations", key=key)
    engine = InvestigationEngine(store, memory=None)
    state = engine.start(_hypothesis(), scope_reference="local://test",
                         investigation_id="INV-test")
    return store, engine, state


def _events(store) -> list[dict]:
    return [json.loads(l) for l in store.path.read_text(encoding="utf-8").splitlines()
            if l.strip()]


def _write(store, events: list[dict]) -> None:
    store.path.write_text(
        "\n".join(json.dumps(e, default=str) for e in events) + "\n", encoding="utf-8"
    )


def _rewrite_chain(events: list[dict], mutate) -> list[dict]:
    """Recompute the whole hash chain after applying ``mutate`` to each payload.

    This is the *capable* attacker: edit the payload, recompute every content and
    chain hash. It defeats the in-band chain alone; only the keyed MAC stops it.
    """
    prev = GENESIS
    out = []
    for i, ev in enumerate(events):
        mutate(ev)
        ev["seq"] = i
        ev["prev"] = prev
        ch = content_hash(ev["content"])
        ev["content_sha256"] = ch
        prev = chain_hash(i, prev, ch)
        ev["chain_sha256"] = prev
        out.append(ev)
    return out


# --------------------------------------------------------------------------- #
# 1. Ordinary valid records
# --------------------------------------------------------------------------- #

def test_a_fresh_log_verifies(tmp_path):
    store, _engine, _state = _start(tmp_path)
    result = store.verify_integrity()
    assert result["status"] == VERIFIED
    assert result["ok"] is True
    assert result["checked"] >= 1
    assert result["mismatched"] == []


def test_every_persisted_state_is_stamped(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    for ev in _events(store):
        if ev.get("type") == "state":
            assert ev.get("content_sha256"), "a persisted state was not stamped"
            assert ev.get("chain_sha256"), "a persisted state was not chained"
            assert "seq" in ev and "prev" in ev


def test_a_valid_chain_grows_and_stays_verified(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    for _ in range(3):
        store.save_state(state)
    assert store.verify_integrity()["status"] == VERIFIED
    seq, _chain = store.head()
    assert seq == len([e for e in _events(store) if e.get("type") == "state"]) - 1


# --------------------------------------------------------------------------- #
# 2. A single record edited (content hash layer)
# --------------------------------------------------------------------------- #

def test_an_edited_verdict_is_detected(tmp_path):
    """Fabricating an EXPLOITABLE verdict by editing the log must fail the check."""
    store, _engine, state = _start(tmp_path)
    events = _events(store)
    for ev in events:
        if ev.get("type") == "state" and ev.get("content"):
            ev["content"]["stage"] = "VERDICT"
            ev["content"]["status"] = "CLOSED"
            ev["content"]["verdict"] = "EXPLOITABLE"
    _write(store, events)

    result = store.verify_integrity()
    assert result["status"] == FAILED
    assert result["ok"] is False
    assert state.investigation_id in result["mismatched"]


# --------------------------------------------------------------------------- #
# 3. A record + its adjacent hash edited (chain layer)
# --------------------------------------------------------------------------- #

def test_record_and_its_own_hash_edited_is_still_detected(tmp_path):
    """Recomputing a record's own content hash is not enough: the chain catches it."""
    store, _engine, _state = _start(tmp_path)
    events = _events(store)
    events[0]["content"]["status"] = "CLOSED"
    events[0]["content_sha256"] = content_hash(events[0]["content"])
    # The adjacent hash was fixed, but the chain hash was not.
    _write(store, events)
    result = store.verify_integrity()
    assert result["status"] == FAILED
    assert any("chain hash mismatch" in r for r in result["reasons"])


# --------------------------------------------------------------------------- #
# 4. Delete / reorder / insert / truncate
# --------------------------------------------------------------------------- #

def test_deleted_record_is_detected(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    store.save_state(state)  # three records total
    events = _events(store)
    del events[1]
    _write(store, events)
    result = store.verify_integrity()
    assert result["status"] == FAILED


def test_reordered_records_are_detected(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _events(store)
    events[0], events[-1] = events[-1], events[0]
    _write(store, events)
    assert store.verify_integrity()["status"] == FAILED


def test_inserted_record_is_detected(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _events(store)
    injected = dict(events[0])
    injected["id"] = "INV-injected"
    injected["content"] = dict(events[0]["content"], investigation_id="INV-injected")
    events.insert(1, injected)
    _write(store, events)
    assert store.verify_integrity()["status"] == FAILED


def test_truncated_tail_is_undetectable_by_chain_alone(tmp_path):
    """Honest limitation: a shorter, internally-consistent log still verifies.

    The in-band chain cannot see records that are simply gone. This is asserted
    so the limitation is explicit, not hidden.
    """
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    store.save_state(state)
    events = _events(store)
    _write(store, events[:-2])  # drop the tail
    assert store.verify_integrity()["status"] == VERIFIED  # documented gap


def test_truncated_tail_is_detected_with_a_checkpoint(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    store.save_state(state)
    seq, chain = store.head()
    cp = Checkpoint(log_path=str(store.path), head_seq=seq, head_chain=chain)
    events = _events(store)
    _write(store, events[:-2])
    result = store.verify_integrity(checkpoint=cp)
    assert result["status"] == FAILED
    assert result["checkpoint_ok"] is False


def test_appended_record_after_checkpoint_is_detected(tmp_path):
    """A checkpoint also catches records *added* after it was taken."""
    store, engine, state = _start(tmp_path)
    seq, chain = store.head()
    cp = Checkpoint(log_path=str(store.path), head_seq=seq, head_chain=chain)
    engine.triage(state, "PURSUE", reason="selected")  # appends a record
    result = store.verify_integrity(checkpoint=cp)
    assert result["status"] == FAILED
    assert result["checkpoint_ok"] is False


# --------------------------------------------------------------------------- #
# 5. Wholesale rewrite
# --------------------------------------------------------------------------- #

def test_broken_hash_chain_is_detected(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _events(store)
    events[1]["prev"] = "f" * 64  # sever the link
    _write(store, events)
    result = store.verify_integrity()
    assert result["status"] == FAILED
    assert any("predecessor" in r for r in result["reasons"])


def test_wholesale_rewrite_is_undetectable_without_a_key(tmp_path):
    """Honest limitation: a keyless chain can be fully recomputed by an attacker."""
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _rewrite_chain(_events(store),
                            lambda e: e["content"].update(status="CONFIRMED"))
    _write(store, events)
    assert store.verify_integrity()["status"] == VERIFIED  # documented gap


def test_wholesale_rewrite_is_detected_with_a_key(tmp_path):
    """The keyed MAC closes the wholesale-rewrite gap the chain cannot."""
    key = generate_key("k-rot-a")
    store, engine, state = _start(tmp_path, key=key)
    engine.triage(state, "PURSUE", reason="selected")
    events = _rewrite_chain(_events(store),
                            lambda e: e["content"].update(status="CONFIRMED"))
    _write(store, events)
    result = store.verify_integrity(require_signatures=True)
    assert result["status"] == FAILED
    assert any("HMAC signature invalid" in r for r in result["reasons"])


# --------------------------------------------------------------------------- #
# 6. Signature / key handling
# --------------------------------------------------------------------------- #

def test_signed_log_verifies_with_the_key(tmp_path):
    key = generate_key("k1")
    store, engine, state = _start(tmp_path, key=key)
    engine.triage(state, "PURSUE", reason="selected")
    result = store.verify_integrity(require_signatures=True)
    assert result["status"] == VERIFIED
    assert result["signatures_checked"] is True
    assert result["key_id"] == "k1"


def test_invalid_hmac_is_detected(tmp_path):
    key = generate_key("k1")
    store, engine, state = _start(tmp_path, key=key)
    engine.triage(state, "PURSUE", reason="selected")
    bad = IntegrityKey("k1", b"\x00" * 32)
    result = verify_chain(store.path, key=bad)
    assert result.status == FAILED
    assert any("HMAC signature invalid" in r for r in result.reasons)


def test_missing_verification_key_is_unavailable_not_ok(tmp_path):
    """Requiring signatures without a key must never read as success."""
    key = generate_key("k1")
    store, engine, state = _start(tmp_path, key=key)
    engine.triage(state, "PURSUE", reason="selected")
    result = verify_chain(store.path, require_signatures=True)
    assert result.status == UNAVAILABLE
    assert result.ok is False
    assert result.unavailable_reason


def test_missing_signature_on_a_record_is_detected(tmp_path):
    key = generate_key("k1")
    store, engine, state = _start(tmp_path, key=key)
    events = _events(store)
    events[0].pop("hmac", None)
    _write(store, events)
    result = store.verify_integrity(require_signatures=True)
    assert result["status"] == FAILED
    assert any("missing HMAC signature" in r for r in result["reasons"])


def test_key_rotation_old_key_still_verifies_old_records(tmp_path):
    """A rotated-in key does not invalidate records signed by the old key.

    Records keep their ``key_id``, so a verifier can select the right key per
    record; here we simply confirm the old key still verifies its own records.
    """
    old = generate_key("k-old")
    store, engine, state = _start(tmp_path, key=old)
    engine.triage(state, "PURSUE", reason="selected")
    # Rotate: a new key signs subsequent records into a fresh store.
    new = generate_key("k-new")
    store2 = InvestigationStore(tmp_path / "rotated", key=new)
    engine2 = InvestigationEngine(store2)
    st2 = engine2.start(_hypothesis(), investigation_id="INV-rot")
    engine2.triage(st2, "PURSUE", reason="selected")

    assert store.verify_integrity(require_signatures=True)["status"] == VERIFIED
    assert store2.verify_integrity(require_signatures=True)["status"] == VERIFIED
    assert store.verify_integrity()["key_id"] == "k-old"
    assert store2.verify_integrity()["key_id"] == "k-new"


def test_key_file_round_trip_and_permissions(tmp_path):
    key = generate_key("k1")
    p = tmp_path / "key.json"
    key_to_file(key, p)
    loaded = key_from_file(p)
    assert loaded.key == key.key and loaded.key_id == "k1"
    assert oct(p.stat().st_mode)[-3:] == "600"


# --------------------------------------------------------------------------- #
# 7. Legacy records
# --------------------------------------------------------------------------- #

def test_legacy_unstamped_record_is_reported_not_trusted(tmp_path):
    """A record with no integrity fields at all is LEGACY, and never 'ok'."""
    store = InvestigationStore(tmp_path / "legacy")
    store._append({"type": "state", "id": "LEGACY-1",
                   "content": {"investigation_id": "LEGACY-1", "stage": "HYPOTHESIS",
                               "status": "OPEN"}})
    result = store.verify_integrity()
    assert result["status"] == LEGACY
    assert result["ok"] is False
    assert result["unstamped"] == ["LEGACY-1"]
    assert result["legacy"] == ["LEGACY-1"]


def test_stripped_stamp_after_a_stamped_record_is_tampering(tmp_path):
    """Removing integrity fields from a stamped log is a failure, not legacy."""
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _events(store)
    # Remove the stamp from only the last record; earlier records stay stamped,
    # so the stripped record must be reported as tampering, not as legacy.
    for k in ("content_sha256", "chain_sha256", "prev", "seq"):
        events[-1].pop(k, None)
    _write(store, events)
    result = store.verify_integrity()
    assert result["status"] == FAILED


def test_partial_stamp_is_treated_as_tampering(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _events(store)
    events[0].pop("chain_sha256", None)  # some fields gone, some present
    _write(store, events)
    result = store.verify_integrity()
    assert result["status"] == FAILED
    assert any("incomplete integrity stamp" in r for r in result["reasons"])


# --------------------------------------------------------------------------- #
# 8. Checkpoint integrity
# --------------------------------------------------------------------------- #

def test_checkpoint_detects_head_mismatch(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    seq, chain = store.head()
    key = generate_key("k1")
    cp = Checkpoint(log_path=str(store.path), head_seq=seq, head_chain=chain).sign(key)
    # Rewrite the log with a fabricated tail (still internally consistent).
    events = _events(store)
    events[-1]["content"]["status"] = "CONFIRMED"
    events[-1]["content_sha256"] = content_hash(events[-1]["content"])
    _write(store, events)
    result = store.verify_integrity(key=key, checkpoint=cp)
    assert result["status"] == FAILED
    assert result["checkpoint_ok"] is False


def test_signed_checkpoint_rejects_a_forged_checkpoint(tmp_path):
    store, engine, state = _start(tmp_path)
    key = generate_key("k1")
    other = generate_key("k2")
    seq, chain = store.head()
    cp = Checkpoint(log_path=str(store.path), head_seq=seq, head_chain=chain).sign(other)
    ok, why = cp.matches(seq, chain, key=key)
    assert ok is False and "signature invalid" in why


# --------------------------------------------------------------------------- #
# 9. Recovery and resumption after integrity failures
# --------------------------------------------------------------------------- #

def test_tamper_check_does_not_break_replay(tmp_path):
    """Detection is additive: replay still returns the (now suspect) state."""
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    assert store.get("INV-test") is not None
    assert store.corruption_report()["ok"] is True


def test_a_tampered_log_still_replays_but_fails_verification(tmp_path):
    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    events = _events(store)
    events[0]["content"]["status"] = "CONFIRMED"
    _write(store, events)
    # Resumption still works (replay is not blocked) ...
    resumed = store.get("INV-test")
    assert resumed is not None
    # ... but the log is not trustworthy.
    assert store.verify_integrity()["status"] == FAILED


def test_engine_refuses_to_confirm_over_a_tampered_log(tmp_path):
    """A CONFIRMED verdict cannot be recorded on top of a tampered log."""
    from blackheart.evidence import EvidenceStore
    from blackheart.investigation import Observation, Triage, plan_from_tools
    from tests.test_investigation import _authorized_record

    store = InvestigationStore(tmp_path / "inv")
    engine = InvestigationEngine(store, authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    hyp = _hypothesis()
    state = engine.start(hyp, investigation_id="INV-conf")
    state = engine.triage(state, Triage.PURSUE, reason="selected")
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, plan_from_tools(hyp, tools_available={"forge"}))
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    state = engine.challenge(state, independent=True, reproduced=True)

    # Tamper: fabricate a confirmed status in an earlier record.
    events = _events(store)
    events[0]["content"]["status"] = "CONFIRMED"
    _write(store, events)

    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    assert state.status != "CONFIRMED"
    assert "integrity" in state.verdict["gated_reason"]


# --------------------------------------------------------------------------- #
# 10. CLI
# --------------------------------------------------------------------------- #

def test_verify_integrity_cli_exit_codes(tmp_path):
    from blackheart import cli

    store, _engine, _state = _start(tmp_path)
    rc = cli.main(["investigate", "--dir", str(tmp_path / "investigations"),
                   "--name", "investigations", "verify"])
    assert rc == 0

    path = store.path
    path.write_text(path.read_text(encoding="utf-8").replace("HYPOTHESIS", "VERDICT"),
                    encoding="utf-8")
    rc = cli.main(["investigate", "--dir", str(tmp_path / "investigations"),
                   "--name", "investigations", "verify"])
    assert rc == 1


def test_integrity_cli_verifies_a_standalone_log(tmp_path):
    from blackheart import cli

    store, engine, state = _start(tmp_path)
    engine.triage(state, "PURSUE", reason="selected")
    rc = cli.main(["integrity", str(store.path)])
    assert rc == 0


def test_keygen_and_checkpoint_cli(tmp_path):
    from blackheart import cli

    _start(tmp_path)
    rc = cli.main(["investigate", "--dir", str(tmp_path / "investigations"),
                   "--name", "investigations", "keygen"])
    assert rc == 0
    keyfile = tmp_path / "investigations" / "integrity-key.json"
    assert keyfile.exists()

    rc = cli.main(["investigate", "--dir", str(tmp_path / "investigations"),
                   "--name", "investigations", "checkpoint",
                   "--key-path", str(keyfile)])
    assert rc == 0
    assert (tmp_path / "investigations" / "investigations.checkpoint.json").exists()


# --------------------------------------------------------------------------- #
# 11. Confirmation gate: every non-VERIFIED state blocks CONFIRMED
# --------------------------------------------------------------------------- #

def _confirmed_state(tmp_path, *, require_signatures: bool, store_key=None):
    """Drive a fully-authorized, independently-reproduced investigation to VERDICT."""
    from blackheart.evidence import EvidenceStore
    from blackheart.investigation import Observation, Triage, plan_from_tools
    from tests.test_investigation import _authorized_record

    store = InvestigationStore(tmp_path / "inv", key=store_key)
    engine = InvestigationEngine(
        store, authorization=_authorized_record(),
        evidence=EvidenceStore(tmp_path / "ev"),
        require_signatures=require_signatures,
    )
    hyp = _hypothesis()
    state = engine.start(hyp, investigation_id="INV-gate")
    state = engine.triage(state, Triage.PURSUE, reason="selected")
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, plan_from_tools(hyp, tools_available={"forge"}))
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    state = engine.challenge(state, independent=True, reproduced=True)
    return engine, state


def test_unavailable_integrity_blocks_confirmation(tmp_path):
    """Requiring signatures with no key must not yield CONFIRMED.

    docs/INTEGRITY.md states UNAVAILABLE is never success. A deployment that
    demands signatures but holds no key must hold the finding as UNCONFIRMED.
    """
    from blackheart.investigation import Observation

    engine, state = _confirmed_state(tmp_path, require_signatures=True, store_key=None)
    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    assert state.status != "CONFIRMED"
    assert "integrity" in state.verdict["gated_reason"]
    assert "unavailable" in state.verdict["gated_reason"].lower()


def test_verified_integrity_allows_confirmation(tmp_path):
    """The positive control: a keyed, VERIFIED log still confirms."""
    from blackheart.investigation import Observation

    key = generate_key("k-conf")
    engine, state = _confirmed_state(tmp_path, require_signatures=True, store_key=key)
    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    assert state.status == "CONFIRMED"
    assert state.verdict["gated_reason"] == ""


def test_legacy_records_block_confirmation(tmp_path):
    """A verdict in a log with unstamped (legacy) records cannot be CONFIRMED.

    A pre-PR#35 log (records with no integrity fields) that is then appended to
    with stamped records verifies as LEGACY, not VERIFIED: tampering in the
    legacy prefix cannot be excluded, so a CONFIRMED verdict in it is not
    trustworthy.
    """
    from blackheart.evidence import EvidenceStore
    from blackheart.investigation import Observation, Triage, plan_from_tools
    from tests.test_investigation import _authorized_record

    store = InvestigationStore(tmp_path / "inv")
    # A legacy record from before integrity protection existed.
    store._append({"type": "state", "id": "L1",
                   "content": {"investigation_id": "L1", "hypothesis_id": "h",
                               "target": "t", "asset": "vault-liquidity",
                               "stage": "HYPOTHESIS", "status": "OPEN"}})
    engine = InvestigationEngine(store, authorization=_authorized_record(),
                                 evidence=EvidenceStore(tmp_path / "ev"))
    hyp = _hypothesis()
    state = engine.start(hyp, investigation_id="INV-legacy")
    state = engine.triage(state, Triage.PURSUE, reason="selected")
    engine.add_source(state, "src/Vault.sol", function="flashLoan")
    state = engine.design_test(state, plan_from_tools(hyp, tools_available={"forge"}))
    state = engine.reproduce(state, reproduce=lambda: (True, "violated"))
    state = engine.challenge(state, independent=True, reproduced=True)
    assert store.verify_integrity()["status"] == LEGACY

    state = engine.verdict(state, Observation(reproduced=True, impact_demonstrated=True))
    assert state.status != "CONFIRMED"
    assert "legacy" in state.verdict["gated_reason"].lower()


