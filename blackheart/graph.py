"""Dual research graph: an asset graph and an exploration graph, linked by anchors.

Adapted from ARTEX's dual-graph architecture. It answers two questions a finding
record alone cannot:

* **What exists?** The *asset graph* -- root domain / subdomain / service /
  endpoint / contract / component, deduplicated, with containment. It is the
  coverage denominator: an untested asset is visible, not forgotten.
* **How did we get here?** The *exploration graph* -- goal / intent / fact /
  finding / hint, connected by ``spawns`` / ``derived_from`` / ``yields`` /
  ``proves`` edges, so a finding carries an auditable lineage back to the goal.

*Anchors* tie the two: which assets a direction touched, and which intents and
findings tested a given asset. That link powers asset-test coverage.

It is stdlib only (``sqlite3``), holds no engine, and asserts no vulnerability --
it is the record of what was explored and what it touched.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

#: Ordered asset kinds (a child may only hang under an earlier-or-equal kind).
ASSET_KINDS = ("root_domain", "subdomain", "service", "endpoint", "contract", "component")
#: Exploration node kinds.
NODE_KINDS = ("goal", "intent", "fact", "finding", "hint")
#: Edge relations.
EDGE_RELATIONS = ("spawns", "derived_from", "yields", "proves", "hints")
#: A node of these kinds counts an anchored asset as *tested* (not merely explored).
TESTED_NODE_KINDS = ("intent", "finding")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL,
    key       TEXT NOT NULL,
    parent_id INTEGER REFERENCES assets(id),
    company   TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, key, company)
);
CREATE TABLE IF NOT EXISTS nodes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL,
    key       TEXT NOT NULL,
    task      TEXT NOT NULL DEFAULT '',
    parent_id INTEGER REFERENCES nodes(id)
);
CREATE TABLE IF NOT EXISTS edges (
    src      INTEGER NOT NULL REFERENCES nodes(id),
    dst      INTEGER NOT NULL REFERENCES nodes(id),
    relation TEXT NOT NULL,
    UNIQUE(src, dst, relation)
);
CREATE TABLE IF NOT EXISTS anchors (
    node_id  INTEGER NOT NULL REFERENCES nodes(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    UNIQUE(node_id, asset_id)
);
"""


@dataclass
class Asset:
    id: int
    kind: str
    key: str
    parent_id: Optional[int]
    company: str


@dataclass
class Node:
    id: int
    kind: str
    key: str
    task: str
    parent_id: Optional[int]


def _check(value: str, allowed: Iterable[str], what: str) -> str:
    if value not in allowed:
        raise ValueError(f"unknown {what} {value!r}; expected one of {tuple(allowed)}")
    return value


class ResearchGraph:
    """A SQLite-backed asset + exploration graph. Use ``:memory:`` for tests."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.isolation_level = None  # autocommit: every write is durable
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ResearchGraph":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    # -- asset graph ----------------------------------------------------- #
    def add_asset(
        self,
        kind: str,
        key: str,
        *,
        parent: int | None = None,
        company: str = "",
    ) -> int:
        """Upsert an asset; returns its id. Deduplicated by (kind, key, company)."""
        _check(kind, ASSET_KINDS, "asset kind")
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO assets(kind, key, parent_id, company) VALUES(?,?,?,?)",
            (kind, key, parent, company),
        )
        if cur.rowcount:
            return int(cur.lastrowid)
        row = self._conn.execute(
            "SELECT id FROM assets WHERE kind=? AND key=? AND company=?",
            (kind, key, company),
        ).fetchone()
        return int(row["id"])

    def asset(self, asset_id: int) -> Asset | None:
        row = self._conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        return Asset(**dict(row)) if row else None

    # -- exploration graph ----------------------------------------------- #
    def add_node(
        self,
        kind: str,
        key: str,
        *,
        task: str = "",
        parent: int | None = None,
    ) -> int:
        _check(kind, NODE_KINDS, "node kind")
        cur = self._conn.execute(
            "INSERT INTO nodes(kind, key, task, parent_id) VALUES(?,?,?,?)",
            (kind, key, task, parent),
        )
        return int(cur.lastrowid)

    def node(self, node_id: int) -> Node | None:
        row = self._conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return Node(**dict(row)) if row else None

    def add_edge(self, src: int, dst: int, relation: str) -> None:
        _check(relation, EDGE_RELATIONS, "edge relation")
        self._conn.execute(
            "INSERT OR IGNORE INTO edges(src, dst, relation) VALUES(?,?,?)",
            (src, dst, relation),
        )

    # -- anchors --------------------------------------------------------- #
    def anchor(self, node_id: int, asset_id: int) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO anchors(node_id, asset_id) VALUES(?,?)",
            (node_id, asset_id),
        )

    # -- queries --------------------------------------------------------- #
    def lineage(self, node_id: int) -> list[Node]:
        """The parent chain from the goal down to ``node_id`` (root first)."""
        chain: list[Node] = []
        seen: set[int] = set()
        cur: int | None = node_id
        while cur is not None and cur not in seen:
            seen.add(cur)
            row = self.node(cur)
            if row is None:
                break
            chain.append(row)
            cur = row.parent_id
        return list(reversed(chain))

    def coverage(self, company: str | None = None) -> list[dict]:
        """Per-asset exploration/test status (the coverage denominator).

        ``explored`` means the asset is anchored to any node; ``tested`` means it
        is anchored to an ``intent`` or ``finding`` node. A ``company`` filters
        to one owner; ``None`` covers everything.
        """
        assets = self._conn.execute(
            "SELECT id, kind, key, company FROM assets"
            + (" WHERE company=?" if company is not None else "")
            + " ORDER BY kind, key",
            (company,) if company is not None else (),
        ).fetchall()
        out: list[dict] = []
        for a in assets:
            anchored = self._conn.execute(
                "SELECT n.id, n.kind FROM anchors an JOIN nodes n ON n.id=an.node_id "
                "WHERE an.asset_id=?",
                (a["id"],),
            ).fetchall()
            node_ids = [r["id"] for r in anchored]
            tested = any(r["kind"] in TESTED_NODE_KINDS for r in anchored)
            out.append(
                {
                    "asset_id": int(a["id"]),
                    "kind": a["kind"],
                    "key": a["key"],
                    "company": a["company"],
                    "explored": bool(anchored),
                    "tested": tested,
                    "node_ids": node_ids,
                }
            )
        return out

    def coverage_summary(self, company: str | None = None) -> dict:
        rows = self.coverage(company)
        total = len(rows)
        explored = sum(1 for r in rows if r["explored"])
        tested = sum(1 for r in rows if r["tested"])
        return {
            "total": total,
            "explored": explored,
            "tested": tested,
            "untested": total - tested,
        }
