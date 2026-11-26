"""Leases are epoch-fenced, recoverable, and never complete stale work."""

from __future__ import annotations

from blackheart.distributed import LeaseQueue


def test_two_workers_never_hold_the_same_live_lease(tmp_path):
    q = LeaseQueue(tmp_path / "queue.jsonl", ttl=100)
    first = q.claim("w1", ["a", "b"], limit=2, now=0)
    assert [l.key for l in first] == ["a", "b"]
    second = q.claim("w2", ["a", "b"], limit=2, now=1)
    assert second == []
    assert q.stats().leased == 2


def test_an_expired_lease_is_recovered_and_epoch_advances(tmp_path):
    q = LeaseQueue(tmp_path / "queue.jsonl", ttl=10)
    first = q.claim("w1", ["a"], now=0)[0]
    assert q.recover_stale(["a"], now=11)["recovered"] == ["a"]
    second = q.claim("w2", ["a"], now=12)[0]
    assert second.epoch == first.epoch + 1
    assert not q.complete("w1", "a", first.epoch, verdict="DONE", now=13)["ok"]


def test_completion_is_fenced_by_worker_epoch_and_expiry(tmp_path):
    q = LeaseQueue(tmp_path / "queue.jsonl", ttl=10)
    lease = q.claim("w1", ["a"], now=0)[0]
    assert not q.complete("w2", "a", lease.epoch, verdict="DONE", now=1)["ok"]
    assert not q.complete("w1", "a", lease.epoch + 1, verdict="DONE", now=1)["ok"]
    assert not q.complete("w1", "a", lease.epoch, verdict="DONE", now=11)["ok"]
    assert q.complete("w1", "a", lease.epoch, verdict="DONE", now=1)["ok"]
    assert q.stats().done == 1


def test_failure_retries_then_dead_letters(tmp_path):
    q = LeaseQueue(tmp_path / "queue.jsonl", ttl=100, max_attempts=2)
    lease = q.claim("w1", ["a"], now=0)[0]
    assert q.fail("w1", "a", lease.epoch, error="boom", now=1)["status"] == "pending"
    lease = q.claim("w1", ["a"], now=2)[0]
    assert q.fail("w1", "a", lease.epoch, error="boom again", now=3)["status"] == "dead"
    assert q.claim("w1", ["a"], now=4) == []
    assert q.stats().dead == 1


def test_duplicate_keys_are_claimed_once(tmp_path):
    q = LeaseQueue(tmp_path / "queue.jsonl", ttl=100)
    leases = q.claim("w1", ["a", "a"], limit=2, now=0)
    assert [l.key for l in leases] == ["a"]
    assert q.stats().leased == 1


def test_pending_and_integrity(tmp_path):
    q = LeaseQueue(tmp_path / "queue.jsonl")
    assert q.pending(["a", "b"]) == ["a", "b"]
    lease = q.claim("w1", ["a"], now=0)[0]
    assert q.pending(["a", "b"], now=1) == ["b"]
    assert q.verify_integrity()["ok"]
