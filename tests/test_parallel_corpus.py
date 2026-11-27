"""Parallel batches preserve order; the corpus deduplicates and verifies."""

from __future__ import annotations

import time

from blackheart.corpus import CorpusStore, input_key
from blackheart.parallel import map_parallel, successful


def test_parallel_results_keep_input_order():
    def worker(value):
        time.sleep(0.01 * (3 - value))
        return value * 10

    outcomes = map_parallel([0, 1, 2], worker, workers=3)
    assert [o.value for o in outcomes] == [0, 10, 20]
    assert all(o.ok for o in outcomes)


def test_one_failure_does_not_cancel_the_batch():
    def worker(value):
        if value == 1:
            raise ValueError("boom")
        return value

    outcomes = map_parallel([0, 1, 2], worker, workers=2)
    assert [o.ok for o in outcomes] == [True, False, True]
    assert "boom" in outcomes[1].error
    assert successful(outcomes) == [0, 2]


def test_empty_batch_is_empty():
    assert map_parallel([], lambda x: x) == []


def test_corpus_deduplicates_by_input_identity(tmp_path):
    store = CorpusStore(tmp_path / "corpus.jsonl")
    first = store.add({"target": "A", "op": "mint"}, verdict="PASS",
                      result={"profit": 1})
    second = store.add({"op": "mint", "target": "A"}, verdict="FAIL")
    assert first.new
    assert not second.new
    assert second.verdict == "PASS"
    assert store.get({"target": "A", "op": "mint"}).payload == {"profit": 1}
    assert len(store.all()) == 1
    assert store.verify_integrity()["ok"]


def test_corpus_input_key_is_order_independent():
    assert input_key({"a": 1, "b": 2}) == input_key({"b": 2, "a": 1})


def test_resume_runs_only_unseen_inputs_and_skips_existing(tmp_path):
    from blackheart.corpus import CorpusStore
    store = CorpusStore(tmp_path / "corpus.jsonl")
    store.add({"target": "A"}, verdict="PASS", result={"ok": True})
    calls = []

    def worker(payload):
        calls.append(payload)
        return {"verdict": "DONE", "result": {"target": payload["target"]}}

    report = store.resume([{"target": "A"}, {"target": "B"}], worker, workers=2)
    assert report["skipped"] == 1
    assert report["ran"] == 1
    assert calls == [{"target": "B"}]
    assert store.get({"target": "B"}).verdict == "DONE"


def test_invalidation_supersedes_and_makes_the_entry_pending(tmp_path):
    from blackheart.corpus import CorpusStore
    store = CorpusStore(tmp_path / "corpus.jsonl")
    store.add({"target": "A"}, verdict="PASS")
    store.invalidate({"target": "A"}, reason="stale source")
    assert store.get({"target": "A"}).verdict == "INVALIDATED"
    assert store.pending([{"target": "A"}]) == [{"target": "A"}]
    store.add({"target": "A"}, verdict="PASS", replace_invalidated=True)
    assert store.get({"target": "A"}).verdict == "PASS"


def test_shards_merge_only_matching_keys(tmp_path):
    from blackheart.corpus import CorpusStore, input_key
    source = CorpusStore(tmp_path / "a.jsonl")
    source.add({"target": "A"}, verdict="PASS", result={"n": 1})
    shard = tmp_path / "shard.json"
    assert source.export_shard(shard)["entries"] == 1
    target = CorpusStore(tmp_path / "b.jsonl")
    assert target.merge_shard(shard)["merged"] == 1
    assert target.get({"target": "A"}).verdict == "PASS"
    assert target.merge_shard(shard)["merged"] == 0

    bad = tmp_path / "bad.json"
    bad.write_text('{"format":"blackheart-corpus-shard-v1","entries":'
                   '[{"key":"wrong","content":{"input":{"target":"X"}}}]}',
                   encoding="utf-8")
    result = target.merge_shard(bad)
    assert result["ok"] is False
    assert result["rejected"] == 1


def test_resume_retries_a_stored_error(tmp_path):
    from blackheart.corpus import CorpusStore
    store = CorpusStore(tmp_path / "corpus.jsonl")

    def broken(payload):
        raise RuntimeError("transient")

    store.resume([{"target": "A"}], broken)
    assert store.get({"target": "A"}).verdict == "ERROR"
    store.resume([{"target": "A"}], lambda payload: {"verdict": "DONE", "result": {}})
    assert store.get({"target": "A"}).verdict == "DONE"
