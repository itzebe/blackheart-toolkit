"""Tact source surface recovery: contracts, message handlers and their guards.

A *surface*, not a model. It names the ``receive`` handlers an inbound message can
reach, whether the handler checks ``sender()`` against an owner/admin, and whether
it writes state. It never invents accounting semantics -- that is the reference
model's job, or a reproduction's. This mirrors ``blackheart.cosmos.model_from_go``:
the surface is a lead about reachability and authorization, never a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "build", "dist", "out", "target", ".venv", "venv",
    "cache", "__pycache__", "tests", "test",
})

#: What this scanner does not recover. Reported so a surface is never read as a
#: complete model of the contract.
UNMODELLED = (
    "TVM gas accounting and cell (boc) layout",
    "asynchronous message delivery order and bounce handling",
    "the masterchain / workchain split and sharding",
    "TEP-74 jetton forward payloads and excess-message returns",
    "get-methods and the Tact compiler's own runtime checks",
)

_CONTRACT = re.compile(r"\bcontract\s+(\w+)")
_MESSAGE = re.compile(r"\bmessage\s*(?:\([^)]*\))?\s+(\w+)")
_RECEIVE = re.compile(r"\breceive\s*\(([^)]*)\)")
_MSG_ARG = re.compile(r"msg\s*:\s*(\w+)")
_STR_ARG = re.compile(r'"([^"]+)"')
_WRITE = re.compile(r"self\.\w+\s*(?:\+=|-=|\*=|/=|=)(?!=)")
#: A sender()/owner comparison or an explicit require/throw_unless on sender().
_GUARD = re.compile(
    r"(?:require|throw_unless)\s*\([^;]*sender\(\)"
    r"|sender\(\)\s*==\s*self\.\w+"
    r"|self\.\w+\s*==\s*sender\(\)"
)


@dataclass
class TonOpCandidate:
    """One ``receive`` handler recovered from Tact source, with its guard state."""

    name: str
    contract: str
    path: str
    line: int
    kind: str                 # "message" | "string" | "internal"
    guarded: bool
    writes_state: bool
    reason: str = ""


@dataclass
class TonSurface:
    root: str
    contracts: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    handlers: list[TonOpCandidate] = field(default_factory=list)
    unmodelled: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "contracts": list(self.contracts),
            "messages": list(self.messages),
            "handlers": [h.__dict__ for h in self.handlers],
            "unmodelled": list(self.unmodelled),
            "errors": list(self.errors),
        }


def _block(text: str, open_idx: int) -> str:
    """The body between ``text[open_idx] == '{'`` and its matching '}'."""
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
    return text[open_idx + 1:]


def _scan_file(text: str, path: str, surface: TonSurface) -> None:
    contracts = [(m.group(1), m.start()) for m in _CONTRACT.finditer(text)]
    for name, _ in contracts:
        if name not in surface.contracts:
            surface.contracts.append(name)
    for m in _MESSAGE.finditer(text):
        if m.group(1) not in surface.messages:
            surface.messages.append(m.group(1))

    for m in _RECEIVE.finditer(text):
        inner = m.group(1)
        msg = _MSG_ARG.search(inner)
        lit = _STR_ARG.search(inner)
        if msg:
            name, kind = msg.group(1), "message"
        elif lit:
            name, kind = lit.group(1), "string"
        else:
            name, kind = "(empty)", "internal"

        open_idx = text.find("{", m.end())
        body = _block(text, open_idx) if open_idx != -1 else ""
        guarded = bool(_GUARD.search(body))
        writes = bool(_WRITE.search(body))
        contract = ""
        for cname, start in contracts:
            if start < m.start():
                contract = cname
        line = text.count("\n", 0, m.start()) + 1
        if guarded:
            reason = "checks sender() against an owner/admin"
        elif writes:
            reason = "writes state with no sender()/owner check"
        else:
            reason = "no state write"
        surface.handlers.append(TonOpCandidate(
            name=name, contract=contract, path=path, line=line, kind=kind,
            guarded=guarded, writes_state=writes, reason=reason))


def scan_tact(root: str) -> TonSurface:
    """Recover the ``receive`` surface of every ``.tact`` file under ``root``."""
    root_path = Path(root).expanduser()
    surface = TonSurface(root=str(root_path), unmodelled=list(UNMODELLED))
    files: list[Path] = []
    if root_path.is_file():
        if root_path.suffix == ".tact":
            files = [root_path]
    elif root_path.is_dir():
        for candidate in root_path.rglob("*.tact"):
            if any(part in SKIP_DIRS for part in candidate.parts):
                continue
            files.append(candidate)
    for path in sorted(files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            surface.errors.append(f"{path}: {exc}")
            continue
        _scan_file(text, str(path), surface)
    return surface
