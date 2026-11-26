"""FunC source surface recovery: entry points, op dispatch and their guards.

A *surface*, not a model. FunC has no ``receive`` keyword: an entry point
(``recv_internal`` / ``recv_external``) loads an op code from the message body and
branches on it (``if (op == op::mint()) { ... }``). This scanner recovers those
dispatch sites as handlers and reports, per handler, whether the block checks the
sender against an owner/admin and whether it writes state.

It is deliberately coarse and says so: FunC is a stack language, so guard and
write attribution is a source heuristic, and dispatch reached through a helper
function is not seen. A recovered surface is a lead about reachability and
authorization, never a finding. It mirrors :mod:`blackheart.ton.tact`.
"""

from __future__ import annotations

import re
from pathlib import Path

from .tact import SKIP_DIRS, TonOpCandidate, TonSurface, _block

UNMODELLED = (
    "FunC stack semantics and the cell (boc) layout",
    "asynchronous message delivery order and bounce handling",
    "the masterchain / workchain split and sharding",
    "TEP-74 forward payloads and excess-message returns",
    "get-methods, and per-op guard attribution is a source heuristic",
    "op dispatch reached through a helper function, not a literal `op == op::X()`",
)

_ENTRY = re.compile(r"\b(recv_internal|recv_external)\s*\(")
_DISPATCH = re.compile(r"op\s*==\s*op::(\w+)\s*\(\s*\)|op\s*==\s*(0x[0-9a-fA-F]+)")
_GUARD = re.compile(
    r"throw_unless\s*\([^;]*?(?:equal_slices|sender|owner|my_address|not_owner)"
    r"|throw_if\s*\([^;]*?(?:not_owner|sender|owner|my_address)"
    r"|equal_slices\s*\([^;]*?(?:sender|owner|my_address)"
)
_WRITE = re.compile(
    r"\bset_data\s*\(|~store_|\bstore_(?:uint|int|slice|ref|dict|coins)\s*\("
)


def _candidate(name: str, contract: str, path: str, line: int, kind: str,
               guarded: bool, writes: bool) -> TonOpCandidate:
    if guarded:
        reason = "checks sender() against an owner/admin"
    elif writes:
        reason = "writes state with no sender()/owner check"
    else:
        reason = "no state write"
    return TonOpCandidate(name=name, contract=contract, path=path, line=line,
                          kind=kind, guarded=guarded, writes_state=writes,
                          reason=reason)


def _scan_file(text: str, path: str, surface: TonSurface) -> None:
    for m in _ENTRY.finditer(text):
        entry = m.group(1)
        open_idx = text.find("{", m.end())
        if open_idx == -1:
            continue
        body = _block(text, open_idx)
        base_line = text.count("\n", 0, m.start())

        found = False
        for d in _DISPATCH.finditer(body):
            name = d.group(1) or d.group(2)
            block_open = body.find("{", d.end())
            block = _block(body, block_open) if block_open != -1 else ""
            line = base_line + body.count("\n", 0, d.start()) + 1
            surface.handlers.append(_candidate(
                name, entry, path, line, "func-op",
                bool(_GUARD.search(block)), bool(_WRITE.search(block))))
            found = True

        if not found:
            guarded = bool(_GUARD.search(body))
            writes = bool(_WRITE.search(body))
            if guarded or writes:
                surface.handlers.append(_candidate(
                    entry, "", path, base_line + 1, "func-entry", guarded, writes))


def scan_func(root: str) -> TonSurface:
    """Recover the entry-point/dispatch surface of every ``.fc``/``.func`` file."""
    root_path = Path(root).expanduser()
    surface = TonSurface(root=str(root_path), unmodelled=list(UNMODELLED))
    files: list[Path] = []
    if root_path.is_file():
        if root_path.suffix in (".fc", ".func"):
            files = [root_path]
    elif root_path.is_dir():
        for candidate in root_path.rglob("*"):
            if candidate.suffix in (".fc", ".func") and not any(
                    part in SKIP_DIRS for part in candidate.parts):
                files.append(candidate)
    for path in sorted(files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            surface.errors.append(f"{path}: {exc}")
            continue
        _scan_file(text, str(path), surface)
    return surface
