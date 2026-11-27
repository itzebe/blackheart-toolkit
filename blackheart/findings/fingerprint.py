"""A stable identity for a finding across edits and re-runs.

The fingerprint is deliberately *content* based, not the ``finding_id``: the same
defect re-recorded under a new id must still match its baseline. It is built from
the fields that define "the same bug" -- component, category, root-cause file and
line, and the design mistake -- and falls back to the id and title when the
record has no root cause yet.

Two consumers share it, so they can never disagree: the SARIF writer's
``partialFingerprints`` and the incremental baseline.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

_LINE = re.compile(r"(?<!\d)(\d+)(?!\d)")


def _line(location: str) -> str:
    match = _LINE.search(location or "")
    return match.group(1) if match else ""


def finding_fingerprint(record: Any) -> str:
    """``sha256:<hex>`` over the fields that identify the defect."""
    parts = (
        (getattr(record, "component", "") or "").strip().lower(),
        (getattr(record, "category", "") or "").strip().lower(),
        (getattr(record, "root_cause_file", "") or "").strip().replace("\\", "/").lower(),
        _line(getattr(record, "root_cause_location", "") or ""),
        (getattr(record, "design_mistake", "") or "").strip().lower(),
    )
    if not any(parts[2:]):
        parts = (
            (getattr(record, "finding_id", "") or "").strip().lower(),
            (getattr(record, "title", "") or "").strip().lower(),
        )
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
