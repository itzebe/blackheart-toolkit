"""A layout diff must separate an appended variable from an inserted one."""

from __future__ import annotations

import pytest

from blackheart.ingest.storage_layout import (StorageEntry, diff_layouts,
                                              parse_layout)


def _layout(*items: tuple[str, int, int, str]) -> tuple[StorageEntry, ...]:
    return tuple(StorageEntry(label, slot, offset, type_)
                 for label, slot, offset, type_ in items)


def test_parse_resolves_the_solc_type_label_and_hex_slot():
    payload = {
        "storage": [{"contract": "C.sol:C", "label": "total", "slot": "0x02",
                     "offset": 0, "type": "t_uint256"}],
        "types": {"t_uint256": {"label": "uint256", "numberOfBytes": "32"}},
    }
    entries = parse_layout(payload)
    assert entries == (StorageEntry("total", 2, 0, "uint256", "C.sol:C"),)


def test_parse_accepts_the_bare_storage_list():
    assert parse_layout([{"label": "a", "slot": 0, "offset": 0, "type": "uint256"}]) == (
        StorageEntry("a", 0, 0, "uint256"),
    )


def test_identical_layouts_are_compatible():
    layout = _layout(("a", 0, 0, "uint256"), ("b", 1, 0, "address"))
    diff = diff_layouts(layout, layout)
    assert diff.compatible is True
    assert diff.changes == ()


def test_appending_a_variable_is_compatible():
    before = _layout(("a", 0, 0, "uint256"), ("b", 1, 0, "address"))
    after = _layout(("a", 0, 0, "uint256"), ("b", 1, 0, "address"),
                    ("c", 2, 0, "bool"))
    diff = diff_layouts(before, after)
    assert diff.compatible is True
    assert diff.counts()["added"] == 1


def test_inserting_a_variable_moves_the_rest_and_is_incompatible():
    before = _layout(("a", 0, 0, "uint256"), ("b", 1, 0, "address"))
    after = _layout(("c", 0, 0, "bool"), ("a", 1, 0, "uint256"),
                    ("b", 2, 0, "address"))
    diff = diff_layouts(before, after)
    assert diff.compatible is False
    assert diff.counts()["moved"] == 2
    assert diff.counts()["added"] == 1


def test_a_type_change_at_the_same_position_is_incompatible():
    before = _layout(("a", 0, 0, "uint256"))
    after = _layout(("a", 0, 0, "uint128"))
    diff = diff_layouts(before, after)
    assert diff.compatible is False
    assert diff.counts()["type_changed"] == 1


def test_a_removed_variable_is_incompatible():
    diff = diff_layouts(_layout(("a", 0, 0, "uint256")), ())
    assert diff.compatible is False
    assert diff.counts()["removed"] == 1


def test_duplicate_labels_are_rejected_rather_than_silently_collapsed():
    with pytest.raises(ValueError, match="duplicate storage label"):
        parse_layout([{"label": "a", "slot": 0, "offset": 0, "type": "uint256"},
                      {"label": "a", "slot": 1, "offset": 0, "type": "uint256"}])


def test_layouts_from_build_info_reads_the_foundry_and_solc_shapes():
    from blackheart.ingest.storage_layout import layouts_from_build_info

    layout = {"storage": [{"label": "a", "slot": 0, "offset": 0, "type": "uint256"}]}
    foundry = {"output": {"contracts": {"src/C.sol": {"C": {"storageLayout": layout},
                                                      "I": {"abi": []}}}}}
    solc = {"contracts": {"C.sol": {"C": {"storageLayout": layout}}}}
    assert list(layouts_from_build_info(foundry)) == ["src/C.sol:C"]
    assert list(layouts_from_build_info(solc)) == ["C.sol:C"]
    assert layouts_from_build_info(foundry)["src/C.sol:C"][0].label == "a"


def test_a_contract_without_a_layout_is_skipped_not_reported_empty():
    from blackheart.ingest.storage_layout import layouts_from_build_info

    payload = {"contracts": {"C.sol": {"C": {"abi": []}}}}
    assert layouts_from_build_info(payload) == {}


def test_a_single_foundry_artifact_is_accepted():
    from blackheart.ingest.storage_layout import layouts_from_build_info

    artifact = {"contractName": "Vault", "storageLayout": {
        "storage": [{"label": "owner", "slot": 0, "offset": 0, "type": "address"}]}}
    layouts = layouts_from_build_info(artifact)
    assert list(layouts) == ["Vault"]
    assert layouts["Vault"][0].label == "owner"
