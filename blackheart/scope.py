"""Engagement authorization registry with dated, verbatim scope capture
(mission section 5).

The authorization gate in :mod:`blackheart.authz` is the pure decision logic. This
module is the durable, auditable side of it: it records an authorization check as
**append-only JSONL plus a content-addressed evidence artefact**, so a later
reviewer can see exactly which program page was read, when, and what it said.

Nothing here fetches the network. The operator pastes the scope text they actually
read into ``AuthorizationRecord.retrieved_scope``; the text is stored verbatim and
hashed, so the record cannot be silently rewritten after the fact. A record may
only be marked ``verified`` when that scope text is present -- an assertion of
authorization with no captured scope is refused.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .authz import (
    GateDecision,
    asset_classification_report,
    authorize_active_testing,
)
from .authz.registry import AuthorizationRegistry
from .evidence import EvidenceStore
from .models import AssetStatus, AuthorizationRecord


class ScopeError(ValueError):
    """Raised when an authorization record is not fit to be recorded."""


def _require_scope_text(record: AuthorizationRecord) -> None:
    """A verified record must carry the scope text it was verified against."""
    if not record.verified:
        return
    scope_text = record.retrieved_scope.get("text", "") if record.retrieved_scope else ""
    if not scope_text.strip():
        raise ScopeError(
            "refusing to record a VERIFIED authorization with no retrieved scope text; "
            "paste the official scope you actually read into retrieved_scope.text"
        )
    if not record.retrieved_scope.get("source_url"):
        raise ScopeError(
            "refusing to record a VERIFIED authorization with no retrieved_scope.source_url"
        )


def _validate_asset_classes(record: AuthorizationRecord) -> None:
    for asset, status in {**record.assets, **record.asset_classes}.items():
        try:
            AssetStatus(status)
        except ValueError as exc:
            raise ScopeError(
                f"asset '{asset}' has invalid classification '{status}'; must be one of "
                f"{', '.join(s.value for s in AssetStatus)}"
            ) from exc


def record_authorization(
    record: AuthorizationRecord,
    *,
    registry_path: str | os.PathLike,
    evidence_root: str | os.PathLike,
) -> dict:
    """Persist a dated authorization record and return the gate decision.

    The record is written to an append-only registry and stored as a
    content-addressed evidence artefact (the evidence id is recorded on the record
    so tampering is detectable). Returns a JSON-serialisable summary including the
    per-asset classification and the gate decision.
    """
    _require_scope_text(record)
    _validate_asset_classes(record)

    evidence = EvidenceStore(evidence_root)
    if record.retrieved_scope:
        ev = evidence.put_json(
            {
                "program": record.program,
                "scope_url": record.scope_url,
                "retrieved_scope": record.retrieved_scope,
                "assets": record.asset_classes or record.assets,
                "checked_at": record.checked_at,
            },
            kind="authorization-scope",
            description=f"scope evidence for {record.program} retrieved {record.checked_at}",
        )
        if ev.evidence_id not in record.evidence:
            record.evidence = list(record.evidence) + [ev.evidence_id]

    if not record.evidence:
        raise ScopeError(
            "refusing to record an authorization with no evidence; attach dated scope "
            "evidence or paste retrieved_scope so it can be captured"
        )

    registry = AuthorizationRegistry(registry_path)
    registry.add(record)

    classes = asset_classification_report(record)
    decisions = {
        asset: authorize_active_testing(record, asset).to_dict() for asset in classes
    }
    return {
        "program": record.program,
        "platform": record.platform,
        "scope_url": record.scope_url,
        "checked_at": record.checked_at,
        "verified": record.verified,
        "asset_classification": classes,
        "authorized_assets": [
            a for a, s in classes.items() if s == AssetStatus.AUTHORIZED.value
        ],
        "decisions": decisions,
        "registry": str(registry_path),
        "evidence_ids": record.evidence,
    }


def check_asset(record: AuthorizationRecord, asset: str) -> GateDecision:
    """The gate decision for one asset, with no side effects (safe to call anytime)."""
    return authorize_active_testing(record, asset)


def load_record(path: str | os.PathLike) -> AuthorizationRecord:
    return AuthorizationRecord.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
