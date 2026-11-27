"""Authorization registry: a durable, append-only set of authorization records.

The registry is what the campaign loop consults before every active test. It is
stored as JSONL so records are never overwritten, and it refuses to hold records
whose evidence is missing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import AuthorizationRecord


class AuthorizationRegistry:
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, record: AuthorizationRecord) -> None:
        if not record.evidence:
            raise ValueError("refusing to store an authorization record with no evidence")
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_dict()) + "\n")

    def all(self) -> list[AuthorizationRecord]:
        if not self.path.exists():
            return []
        out: list[AuthorizationRecord] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(AuthorizationRecord.from_dict(json.loads(line)))
        return out

    def latest_for(self, program: str) -> AuthorizationRecord | None:
        matches = [r for r in self.all() if r.program == program]
        return matches[-1] if matches else None
