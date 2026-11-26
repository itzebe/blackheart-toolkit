"""Structured engagement ledger + hypothesis database (mission section 11).

The ledger records, per engagement, every hypothesis and its status, so a
campaign never re-runs a hypothesis it has already disproven (mission section 6:
"do not repeat disproven hypotheses merely to generate more activity").

It is append-only JSONL. Status transitions are recorded as new events; the
current view is derived by replaying events.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import Classification, utcnow


class EngagementLedger:
    def __init__(self, root: str | os.PathLike, engagement: str) -> None:
        self.root = Path(root)
        self.engagement = engagement
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{engagement}.jsonl"

    # ------------------------------------------------------------------ #
    def record_event(self, event: dict) -> None:
        event = {"at": utcnow(), "engagement": self.engagement, **event}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, default=str) + "\n")

    # ------------------------------------------------------------------ #
    def add_hypothesis(self, hypothesis_id: str, title: str, detail: str = "") -> None:
        self.record_event(
            {"type": "hypothesis", "id": hypothesis_id, "title": title, "detail": detail,
             "status": Classification.NEEDS_MORE_EVIDENCE.value}
        )

    def set_status(
        self, hypothesis_id: str, status: Classification | str, note: str = ""
    ) -> None:
        value = status.value if isinstance(status, Classification) else status
        self.record_event(
            {"type": "status", "id": hypothesis_id, "status": value, "note": note}
        )

    def record_evidence(self, hypothesis_id: str, evidence_id: str, note: str = "") -> None:
        self.record_event(
            {"type": "evidence", "id": hypothesis_id, "evidence_id": evidence_id, "note": note}
        )

    def record_command(self, hypothesis_id: str, command: str, exit_code: int, note: str = "") -> None:
        self.record_event(
            {"type": "command", "id": hypothesis_id, "command": command,
             "exit_code": exit_code, "note": note}
        )

    # ------------------------------------------------------------------ #
    def events(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def view(self) -> dict[str, dict]:
        """Replay events into the current state of every hypothesis."""
        state: dict[str, dict] = {}
        for ev in self.events():
            hid = ev.get("id")
            if not hid:
                continue
            if ev["type"] == "hypothesis":
                state[hid] = {
                    "id": hid,
                    "title": ev.get("title", ""),
                    "detail": ev.get("detail", ""),
                    "status": ev.get("status", Classification.NEEDS_MORE_EVIDENCE.value),
                    "evidence": [],
                    "commands": [],
                    "notes": [],
                }
            elif hid in state:
                if ev["type"] == "status":
                    state[hid]["status"] = ev.get("status")
                    if ev.get("note"):
                        state[hid]["notes"].append(ev["note"])
                elif ev["type"] == "evidence":
                    state[hid]["evidence"].append(ev.get("evidence_id"))
                elif ev["type"] == "command":
                    state[hid]["commands"].append(
                        {"command": ev.get("command"), "exit_code": ev.get("exit_code")}
                    )
        return state

    def disproven_hypotheses(self) -> set[str]:
        """Ids already classified FALSE_POSITIVE (must not be re-run as-is)."""
        return {
            hid
            for hid, rec in self.view().items()
            if rec["status"] == Classification.FALSE_POSITIVE.value
        }

    def open_hypotheses(self) -> list[dict]:
        terminal = {
            Classification.CONFIRMED.value,
            Classification.FALSE_POSITIVE.value,
            Classification.OUT_OF_SCOPE.value,
            Classification.DUPLICATE_OR_KNOWN.value,
        }
        return [rec for rec in self.view().values() if rec["status"] not in terminal]
