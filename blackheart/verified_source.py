"""Verified-source attestation: is the code I am reading the code that runs?

``deployed`` proves a deployment's *fingerprint* read-only; the watchtower fetches
verified source when a deployment moves. Neither answers the research question a
mission actually asks before it trusts a repository: does the verified source,
recompiled, reproduce the on-chain runtime bytecode and the expected storage
layout? This module answers that with two pure comparisons and a thin,
network-injectable fetch.

It is honest by construction:

* a bytecode comparison strips compiler metadata first (metadata differs between
  builds of identical logic), and reports the *sizes* and *hashes* it compared;
* a storage-layout comparison reports moved, added and removed slots -- it does
  not claim a layout is safe, only where two builds differ;
* an address Sourcify does not have is ``not_verified`` -- a gap, never a claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .watch.source import SourceBundle, SourceClient


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value or "").strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def strip_metadata(bytecode: bytes) -> bytes:
    """Remove the trailing CBOR metadata solc appends, when it is present.

    solc appends a CBOR blob and a 2-byte big-endian length. Two builds of the
    same logic differ only in that blob, so comparing bytecode without stripping
    it reports a false mismatch. When the trailing bytes do not form a plausible
    metadata section, the input is returned unchanged.
    """
    if len(bytecode) < 4:
        return bytecode
    length = int.from_bytes(bytecode[-2:], "big")
    if length == 0 or length + 2 > len(bytecode):
        return bytecode
    start = len(bytecode) - 2 - length
    if bytecode[start] not in range(0xA1, 0xA6):  # CBOR map header
        return bytecode
    return bytecode[:start]


@dataclass(frozen=True)
class RuntimeComparison:
    """Whether recompiled runtime bytecode reproduces the on-chain runtime."""

    match: bool
    compiled_len: int
    onchain_len: int
    compiled_hash: str = ""
    onchain_hash: str = ""
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "match": self.match,
            "compiled_len": self.compiled_len,
            "onchain_len": self.onchain_len,
            "compiled_hash": self.compiled_hash,
            "onchain_hash": self.onchain_hash,
            "reason": self.reason,
        }


def compare_runtime(compiled: Any, onchain: Any, *, strip: bool = True) -> RuntimeComparison:
    """Compare recompiled runtime bytecode with the on-chain runtime bytecode."""
    import hashlib

    c = _to_bytes(compiled)
    o = _to_bytes(onchain)
    if strip:
        c, o = strip_metadata(c), strip_metadata(o)
    ch = "0x" + hashlib.sha256(c).hexdigest() if c else ""
    oh = "0x" + hashlib.sha256(o).hexdigest() if o else ""
    if not c or not o:
        return RuntimeComparison(False, len(c), len(o), ch, oh,
                                 "one side is empty; nothing was compared")
    match = c == o
    return RuntimeComparison(
        match, len(c), len(o), ch, oh,
        "the recompiled runtime reproduces the on-chain runtime"
        if match else
        "the runtimes differ; the verified source does not reproduce this deployment",
    )


@dataclass
class LayoutDifference:
    label: str
    change: str  # "moved" | "added" | "removed" | "retyped"
    old: Optional[dict] = None
    new: Optional[dict] = None

    def to_dict(self) -> dict:
        return {"label": self.label, "change": self.change,
                "old": self.old, "new": self.new}


def _layout_index(layout: Iterable[Any]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for entry in layout or ():
        if isinstance(entry, dict):
            label = str(entry.get("label") or entry.get("name") or "")
            if label:
                index[label] = dict(entry)
        elif hasattr(entry, "label"):
            index[str(entry.label)] = {
                "label": str(entry.label),
                "slot": getattr(entry, "slot", None),
                "offset": getattr(entry, "offset", None),
                "type": getattr(entry, "type", ""),
            }
    return index


def compare_storage_layout(old: Iterable[Any], new: Iterable[Any]) -> list[LayoutDifference]:
    """Report slots that moved, were added, removed, or changed type between builds.

    This is a structural diff, not a verdict: a moved slot between an old and a new
    implementation is a lead to review, and its impact depends on the proxy and the
    upgrade path.
    """
    old_index = _layout_index(old)
    new_index = _layout_index(new)
    diffs: list[LayoutDifference] = []
    for label in sorted(set(old_index) | set(new_index)):
        a, b = old_index.get(label), new_index.get(label)
        if a is None:
            diffs.append(LayoutDifference(label, "added", None, b))
        elif b is None:
            diffs.append(LayoutDifference(label, "removed", a, None))
        elif (a.get("slot"), a.get("offset")) != (b.get("slot"), b.get("offset")):
            diffs.append(LayoutDifference(label, "moved", a, b))
        elif str(a.get("type", "")) != str(b.get("type", "")):
            diffs.append(LayoutDifference(label, "retyped", a, b))
    return diffs


@dataclass
class Attestation:
    """The verified-source facts for one deployment, with the gap stated."""

    chain_id: int
    address: str
    status: str  # "verified" | "not_verified" | "error"
    bundle: Optional[SourceBundle] = None
    files: list[str] = field(default_factory=list)
    compiler: str = ""
    reason: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "verified"

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "address": self.address,
            "status": self.status,
            "files": list(self.files),
            "compiler": self.compiler,
            "reason": self.reason,
        }


def attest(chain_id: int, address: str, *, client: Optional[Any] = None) -> Attestation:
    """Fetch the verified source for an address and report it honestly.

    Network is injectable so the pipeline is testable without a live Sourcify. A
    fetch failure is ``error``; an address Sourcify does not have is
    ``not_verified``. Neither is ever reported as a clean attestation.
    """
    client = client or SourceClient()
    try:
        bundle = client.fetch(chain_id, address)
    except Exception as exc:  # a transport that raises is an error, not "verified"
        return Attestation(chain_id, address, "error", reason=f"fetch failed: {exc}")
    return Attestation(
        chain_id=chain_id,
        address=address.lower(),
        status=bundle.status,
        bundle=bundle,
        files=sorted(bundle.files),
        compiler=bundle.compiler_version or bundle.compiler,
        reason=bundle.error or (
            "verified source fetched" if bundle.status == "verified"
            else "not verified at this source"
        ),
    )
