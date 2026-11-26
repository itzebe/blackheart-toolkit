"""Bounded parallel execution for independent research tasks.

Every task is isolated and its exception is captured as a result, not allowed to
cancel its siblings. Results stay in input order so a parallel run is
reproducible and a caller can correlate task N with result N. The worker count
is clamped: more threads than independent jobs is not speed.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

MAX_WORKERS = 32


@dataclass
class TaskOutcome:
    index: int
    value: Any = None
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict:
        return {"index": self.index, "ok": self.ok, "value": self.value,
                "error": self.error}


def map_parallel(tasks: Sequence[Any], worker: Callable[[Any], Any], *,
                 workers: int = 4) -> list[TaskOutcome]:
    """Run ``worker`` over ``tasks`` with at most ``workers`` threads."""
    if not tasks:
        return []
    count = max(1, min(int(workers), MAX_WORKERS, len(tasks)))
    outcomes: dict[int, TaskOutcome] = {}
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = {pool.submit(worker, task): i for i, task in enumerate(tasks)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                outcomes[index] = TaskOutcome(index, future.result())
            except Exception as exc:  # noqa: BLE001 -- one task must not kill the batch
                outcomes[index] = TaskOutcome(index, error=str(exc))
    return [outcomes[i] for i in range(len(tasks))]


def successful(outcomes: Iterable[TaskOutcome]) -> list[Any]:
    return [o.value for o in outcomes if o.ok]
