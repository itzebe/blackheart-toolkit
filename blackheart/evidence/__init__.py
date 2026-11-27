"""Append-only, content-addressed evidence store (mission sections 9, 11).

Guarantees:
  * Artefacts are written under ``<root>/objects/<sha256[:2]>/<sha256>`` so the
    same content is never stored twice and is never overwritten.
  * An index (JSONL) records metadata for every artefact.
  * Writing an artefact whose id already exists is a no-op that returns the
    existing record -- evidence is immutable.
  * Private engagement evidence lives under ``research/private`` (gitignored);
    nothing here writes into tracked paths by default.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ..models import Evidence, utcnow


class EvidenceStore:
    def __init__(self, root: str | os.PathLike) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.index_path = self.root / "index.jsonl"
        self.objects.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _object_path(self, digest: str) -> Path:
        return self.objects / digest[:2] / digest

    def _existing(self, digest: str) -> Evidence | None:
        if not self.index_path.exists():
            return None
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("sha256") == digest:
                return Evidence(**rec)
        return None

    # ------------------------------------------------------------------ #
    def put_bytes(
        self,
        data: bytes,
        *,
        kind: str,
        description: str,
        command: str = "",
        metadata: dict | None = None,
    ) -> Evidence:
        digest = self._hash_bytes(data)
        existing = self._existing(digest)
        if existing is not None:
            return existing

        obj = self._object_path(digest)
        obj.parent.mkdir(parents=True, exist_ok=True)
        if not obj.exists():
            tmp = obj.with_suffix(".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, obj)  # atomic

        ev = Evidence(
            evidence_id=f"ev-{digest[:16]}",
            kind=kind,
            description=description,
            sha256=digest,
            path=str(obj.relative_to(self.root)),
            command=command,
            created_at=utcnow(),
            metadata=metadata or {},
        )
        with self.index_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev.to_dict()) + "\n")
        return ev

    def put_text(self, text: str, **kwargs) -> Evidence:
        return self.put_bytes(text.encode("utf-8"), **kwargs)

    def put_json(self, obj: object, **kwargs) -> Evidence:
        data = json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")
        return self.put_bytes(data, **kwargs)

    def put_file(self, path: str | os.PathLike, **kwargs) -> Evidence:
        p = Path(path)
        return self.put_bytes(p.read_bytes(), **kwargs)

    # ------------------------------------------------------------------ #
    def get(self, evidence_id: str) -> Evidence | None:
        if not self.index_path.exists():
            return None
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("evidence_id") == evidence_id:
                return Evidence(**rec)
        return None

    def all(self) -> list[Evidence]:
        if not self.index_path.exists():
            return []
        return [
            Evidence(**json.loads(line))
            for line in self.index_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def read(self, evidence_id: str) -> bytes:
        ev = self.get(evidence_id)
        if ev is None:
            raise KeyError(f"unknown evidence id: {evidence_id}")
        return (self.root / ev.path).read_bytes()

    def verify_integrity(self) -> dict:
        """Re-hash every artefact and report mismatches (tamper check)."""
        checked = 0
        bad: list[str] = []
        for ev in self.all():
            checked += 1
            data = (self.root / ev.path).read_bytes()
            if self._hash_bytes(data) != ev.sha256:
                bad.append(ev.evidence_id)
        return {"checked": checked, "mismatched": bad, "ok": not bad}
