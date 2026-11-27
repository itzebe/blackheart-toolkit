"""Compare two solc storage layouts, because equal bytecode is not enough.

A proxy upgrade can keep the runtime bytecode identical and still corrupt every
variable below an inserted slot. The layout is the contract's memory, so a
changed slot, offset or type is a real compatibility break. Appending a variable
is safe; inserting one is not. This module states that difference instead of
leaving it to a reviewer's eye.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class StorageEntry:
    label: str
    slot: int
    offset: int
    type: str
    contract: str = ""

    @property
    def key(self) -> str:
        return f"{self.contract}:{self.label}" if self.contract else self.label

    @property
    def position(self) -> tuple[int, int]:
        return (self.slot, self.offset)

    def to_dict(self) -> dict:
        return {"label": self.label, "slot": self.slot, "offset": self.offset,
                "type": self.type, "contract": self.contract}


@dataclass(frozen=True)
class LayoutChange:
    kind: str  # added / removed / moved / type_changed
    key: str
    before: StorageEntry | None
    after: StorageEntry | None
    detail: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "key": self.key, "detail": self.detail,
                "before": self.before.to_dict() if self.before else None,
                "after": self.after.to_dict() if self.after else None}


@dataclass(frozen=True)
class LayoutDiff:
    changes: tuple[LayoutChange, ...]
    compatible: bool

    def counts(self) -> dict[str, int]:
        out = {"added": 0, "removed": 0, "moved": 0, "type_changed": 0}
        for change in self.changes:
            out[change.kind] = out.get(change.kind, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {"compatible": self.compatible, "counts": self.counts(),
                "changes": [c.to_dict() for c in self.changes]}


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("a storage slot is not a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    raise ValueError(f"cannot read a storage position from {value!r}")


def parse_layout(payload: Any) -> tuple[StorageEntry, ...]:
    """Read a solc ``storageLayout`` object (or its ``storage`` list)."""
    if isinstance(payload, (str, bytes)):
        payload = json.loads(payload)
    if isinstance(payload, dict):
        storage = payload.get("storage", payload.get("layout", []))
        types = payload.get("types", {})
        if not isinstance(types, dict):
            types = {}
    elif isinstance(payload, list):
        storage, types = payload, {}
    else:
        raise ValueError("a storage layout must be a JSON object or list")
    if not isinstance(storage, list):
        raise ValueError("the storage layout has no 'storage' list")

    entries: list[StorageEntry] = []
    seen: dict[str, int] = {}
    for item in storage:
        if not isinstance(item, dict) or "label" not in item:
            continue
        raw_type = str(item.get("type", ""))
        label = raw_type
        meta = types.get(raw_type)
        if isinstance(meta, dict) and meta.get("label"):
            label = str(meta["label"])
        entry = StorageEntry(
            label=str(item["label"]),
            slot=_as_int(item.get("slot", 0)),
            offset=_as_int(item.get("offset", 0)),
            type=label,
            contract=str(item.get("contract", "")),
        )
        key = entry.key
        if key in seen:
            raise ValueError(f"duplicate storage label {key!r}")
        seen[key] = 1
        entries.append(entry)
    return tuple(entries)


def layouts_from_build_info(payload: Any) -> dict[str, tuple[StorageEntry, ...]]:
    """Extract every ``storageLayout`` from a Foundry build-info or solc JSON.

    Foundry nests artifacts under ``output.contracts``; solc's combined JSON puts
    them at ``contracts``. Both are accepted. A contract with no layout is
    skipped rather than reported as empty, because "not compiled with
    ``storageLayout``" is not the same as "uses no storage".
    """
    if isinstance(payload, (str, bytes)):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise ValueError("build info must be a JSON object")
    if isinstance(payload.get("storageLayout"), dict):
        name = payload.get("contractName") or "artifact"
        return {name: parse_layout(payload["storageLayout"])}
    output = payload.get("output", payload)
    contracts = output.get("contracts", {}) if isinstance(output, dict) else {}
    if not isinstance(contracts, dict):
        raise ValueError("build info has no 'contracts' object")

    layouts: dict[str, tuple[StorageEntry, ...]] = {}
    for source, by_name in contracts.items():
        if not isinstance(by_name, dict):
            continue
        for name, artifact in by_name.items():
            if not isinstance(artifact, dict):
                continue
            layout = artifact.get("storageLayout")
            if isinstance(layout, dict):
                layouts[f"{source}:{name}"] = parse_layout(layout)
    return layouts


def diff_layouts(before: Iterable[StorageEntry],
                 after: Iterable[StorageEntry]) -> LayoutDiff:
    """Report every position or type change; additions alone stay compatible."""
    old = {entry.key: entry for entry in before}
    new = {entry.key: entry for entry in after}
    changes: list[LayoutChange] = []

    for key in sorted(old.keys() - new.keys()):
        changes.append(LayoutChange("removed", key, old[key], None,
                                    "the variable no longer exists"))
    for key in sorted(new.keys() - old.keys()):
        changes.append(LayoutChange("added", key, None, new[key],
                                    "a new variable occupies storage"))
    for key in sorted(old.keys() & new.keys()):
        left, right = old[key], new[key]
        if left.position != right.position:
            changes.append(LayoutChange(
                "moved", key, left, right,
                f"slot/offset {left.position} -> {right.position}"))
        elif left.type != right.type:
            changes.append(LayoutChange(
                "type_changed", key, left, right,
                f"type {left.type} -> {right.type}"))

    incompatible = any(c.kind in ("removed", "moved", "type_changed") for c in changes)
    return LayoutDiff(tuple(changes), not incompatible)
