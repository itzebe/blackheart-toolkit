"""The durable job store: a tamper-evident, replay-rebuilt log of job snapshots.

The durability guarantees live in :class:`blackheart.chainedlog.ChainedLog` -- one
implementation shared with the trigger and bounty ledgers. This class is the thin
replayer on top of it: it turns each stored snapshot back into a :class:`Job` and
exposes the lookups the scheduler needs.

Keeping it this way means the chain, the lock, and the verification are written
(and tested) once, and a bug fixed there is fixed for every ledger.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..chainedlog import ChainedLog
from ..integrity import IntegrityKey
from .jobs import Job


class JobStore:
    def __init__(
        self, root: str | os.PathLike, name: str = "jobs",
        *, key: Optional[IntegrityKey] = None,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = ChainedLog(self.root / f"{name}.jsonl", key=key)
        self.path = self.log.path
        self.key = key

    # -- integrity ------------------------------------------------------ #
    def corruption_report(self) -> dict:
        return self.log.corruption_report()

    def verify_integrity(
        self, *, key: Optional[IntegrityKey] = None,
        require_signatures: bool = False, checkpoint=None,
    ) -> dict:
        return self.log.verify_integrity(
            key=key, require_signatures=require_signatures, checkpoint=checkpoint,
        )

    def head(self) -> tuple[int, str]:
        return self.log.head()

    # -- state persistence --------------------------------------------- #
    def save(self, job: Job) -> None:
        """Append a hash-chained snapshot of *job*'s current state."""
        self.log.append(job.job_id, job.to_dict())

    # -- replay --------------------------------------------------------- #
    def all(self) -> list[Job]:
        """Replay the log into the current state of every job."""
        return [Job.from_dict(content) for content in self.log.state().values()]

    def get(self, job_id: str) -> Optional[Job]:
        return next((j for j in self.all() if j.job_id == job_id), None)

    def by_dedupe_key(self, key: str) -> Optional[Job]:
        if not key:
            return None
        return next((j for j in self.all() if j.dedupe_key() == key), None)


__all__ = ["JobStore"]
