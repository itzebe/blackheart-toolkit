"""SARIF 2.1.0 export for the findings repository.

SARIF is an interchange format, not a verdict. The result's ``level`` is a
presentation hint; the truth travels in ``properties``:

* ``properties.verdict`` is the record's own verdict;
* ``properties.confirmed`` is the *evidence-gated* answer
  (:meth:`FindingRecord.is_confirmed`), so a hand-set ``CONFIRMED`` that lacks
  evidence is exported as a warning with ``confirmed: false`` and can never be
  read back as a confirmed vulnerability;
* ``properties.record`` carries the full A-J record, so
  :func:`from_sarif` round-trips a finding without a second schema.

The ``partialFingerprints`` entry is the same content fingerprint the baseline
uses, so a SARIF consumer and ``blackheart baseline`` agree on identity.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable
from urllib.parse import quote

from ..integrity import content_hash
from .fingerprint import finding_fingerprint

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "BLACKHEART"
TOOL_URI = "https://github.com/itzebe/blackheart"

_LEVELS = frozenset({"none", "note", "warning", "error"})
_LINE = re.compile(r"(?<!\d)(\d+)(?!\d)")
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def rule_id(record: Any) -> str:
    raw = (getattr(record, "category", "") or "uncategorized").strip().lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", raw).strip("-") or "uncategorized"
    return f"blackheart/{slug}"


def result_level(record: Any) -> str:
    """A presentation hint; never an upgrade of the record's verdict."""
    status = (getattr(record, "status", "") or "").upper()
    if status in {"FALSE_POSITIVE", "OUT_OF_SCOPE", "NOT_REPRODUCIBLE"}:
        return "none"
    severity = (getattr(record, "severity", "") or "info").strip().lower()
    if record.is_confirmed():
        if severity in {"critical", "high"}:
            return "error"
        if severity in {"medium", "low"}:
            return "warning"
        return "note"
    if status in {"CONFIRMED", "STRONGLY_SUPPORTED"}:
        return "warning" if severity in {"critical", "high", "medium"} else "note"
    return "note"


def _message(record: Any) -> str:
    title = (getattr(record, "title", "") or "").strip()
    if not title:
        title = f"finding {getattr(record, 'finding_id', '')}".strip()
    target = (getattr(record, "target", "") or "").strip()
    component = (getattr(record, "component", "") or "").strip()
    where = ": ".join(part for part in (target, component) if part)
    suffix = f" ({where})" if where else ""
    return f"{title} [{getattr(record, 'status', '')}]{suffix}"


def _location(record: Any) -> dict | None:
    file = (getattr(record, "root_cause_file", "") or "").strip()
    location = (getattr(record, "root_cause_location", "") or "").strip()
    if not file:
        refs = getattr(record, "source_refs", None) or []
        if refs:
            file = str(refs[0]).strip()
    if not file:
        return None
    if ":" in file:
        head, tail = file.rsplit(":", 1)
        if tail.isdigit():
            file, location = head, location or tail
    uri = quote(file.replace("\\", "/"), safe="/._-~")
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    line = _LINE.search(location)
    if line:
        physical["region"] = {"startLine": int(line.group(1))}
    return {"physicalLocation": physical}


def _rule(record: Any) -> dict:
    category = (getattr(record, "category", "") or "uncategorized").strip()
    return {
        "id": rule_id(record),
        "name": re.sub(r"[^A-Za-z0-9_]+", "_", category).strip("_") or "uncategorized",
        "shortDescription": {"text": category},
        "helpUri": TOOL_URI,
        "properties": {"tags": [category]},
    }


def result_for(record: Any) -> dict:
    result: dict[str, Any] = {
        "ruleId": rule_id(record),
        "level": result_level(record),
        "message": {"text": _message(record)},
        "partialFingerprints": {"blackheart/v1": finding_fingerprint(record)},
        "properties": {
            "finding_id": getattr(record, "finding_id", ""),
            "verdict": getattr(record, "status", ""),
            "confirmed": record.is_confirmed(),
            "severity": getattr(record, "severity", ""),
            "target": getattr(record, "target", ""),
            "component": getattr(record, "component", ""),
            "evidence_ids": list(getattr(record, "evidence_ids", None) or []),
            "review_independence": getattr(record, "review_independence", ""),
            "record_sha256": content_hash(record.to_dict()),
            "record": record.to_dict(),
        },
    }
    location = _location(record)
    if location is not None:
        result["locations"] = [location]
    return result


def to_sarif(records: Iterable[Any], *, tool_uri: str = TOOL_URI) -> dict:
    records = list(records)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for record in records:
        rules.setdefault(rule_id(record), _rule(record))
        results.append(result_for(record))
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": tool_uri,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "properties": {
                    "blackheart/summary": {
                        "total": len(records),
                        "confirmed": sum(1 for r in records if r.is_confirmed()),
                    }
                },
            }
        ],
    }


def dumps(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=False, default=str)


def validate(document: dict) -> list[str]:
    """Structural SARIF 2.1.0 checks. An empty list means valid enough to emit."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document is not an object"]
    if document.get("version") != SARIF_VERSION:
        errors.append(f"version must be {SARIF_VERSION!r}")
    schema = document.get("$schema")
    if not isinstance(schema, str) or "sarif-2.1.0" not in schema:
        errors.append("$schema must name the SARIF 2.1.0 schema")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty array")
        return errors
    for ri, run in enumerate(runs):
        prefix = f"runs[{ri}]"
        if not isinstance(run, dict):
            errors.append(f"{prefix} is not an object")
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        if not isinstance(driver.get("name"), str) or not driver.get("name"):
            errors.append(f"{prefix}.tool.driver.name is required")
        rule_ids: list[str] = []
        for rj, rule in enumerate(driver.get("rules") or []):
            rid = rule.get("id") if isinstance(rule, dict) else None
            if not isinstance(rid, str) or not rid:
                errors.append(f"{prefix}.tool.driver.rules[{rj}].id is required")
            else:
                rule_ids.append(rid)
        if len(rule_ids) != len(set(rule_ids)):
            errors.append(f"{prefix}.tool.driver.rules has duplicate ids")
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"{prefix}.results must be an array")
            continue
        for si, result in enumerate(results):
            rp = f"{prefix}.results[{si}]"
            if not isinstance(result, dict):
                errors.append(f"{rp} is not an object")
                continue
            if not isinstance(result.get("ruleId"), str) or not result.get("ruleId"):
                errors.append(f"{rp}.ruleId is required")
            elif result["ruleId"] not in rule_ids:
                errors.append(f"{rp}.ruleId does not resolve to a declared rule")
            if result.get("level") not in _LEVELS:
                errors.append(f"{rp}.level must be one of {sorted(_LEVELS)}")
            message = result.get("message") or {}
            if not isinstance(message.get("text"), str) or not message["text"].strip():
                errors.append(f"{rp}.message.text is required")
            locations = result.get("locations")
            if locations is not None:
                if not isinstance(locations, list):
                    errors.append(f"{rp}.locations must be an array")
                else:
                    for li, location in enumerate(locations):
                        physical = (location or {}).get("physicalLocation") or {}
                        uri = (physical.get("artifactLocation") or {}).get("uri")
                        if not isinstance(uri, str) or not uri:
                            errors.append(f"{rp}.locations[{li}].physicalLocation.artifactLocation.uri is required")
                        line = (physical.get("region") or {}).get("startLine")
                        if line is not None and (not isinstance(line, int) or line < 1):
                            errors.append(f"{rp}.locations[{li}].region.startLine must be a positive integer")
            fingerprint = (result.get("partialFingerprints") or {}).get("blackheart/v1")
            if fingerprint is not None and not _FINGERPRINT.match(str(fingerprint)):
                errors.append(f"{rp}.partialFingerprints['blackheart/v1'] is malformed")
            digest = (result.get("properties") or {}).get("record_sha256")
            if digest is not None and not _SHA256.match(str(digest)):
                errors.append(f"{rp}.properties.record_sha256 is malformed")
            elif digest and isinstance((result.get("properties") or {}).get("record"), dict):
                if digest != content_hash(result["properties"]["record"]):
                    errors.append(f"{rp}.properties.record_sha256 does not match the embedded record")
            props = result.get("properties") or {}
            if props.get("confirmed") is not None and not isinstance(props["confirmed"], bool):
                errors.append(f"{rp}.properties.confirmed must be a boolean")
            if props.get("finding_id") and isinstance(props.get("record"), dict):
                if props["record"].get("finding_id") != props["finding_id"]:
                    errors.append(f"{rp}.properties.record.finding_id disagrees with properties.finding_id")
    return errors


def from_sarif(document: dict) -> list[Any]:
    """Recover the embedded records, re-applying the confirmation gate.

    A SARIF file is untrusted input. A record claiming ``CONFIRMED`` without the
    evidence-gated fields is downgraded exactly as the repository does on save.
    """
    from . import FindingRecord, FindingVerdict

    errors = validate(document)
    if errors:
        raise ValueError("invalid SARIF: " + "; ".join(errors))
    records: list[Any] = []
    for run in document["runs"]:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            raw = props.get("record")
            if not isinstance(raw, dict):
                continue
            expected_digest = props.get("record_sha256")
            if expected_digest and expected_digest != content_hash(raw):
                raise ValueError(
                    f"record digest mismatch for {props.get('finding_id')!r}: "
                    "the embedded record was edited"
                )
            record = FindingRecord.from_dict(raw)
            expected = (result.get("partialFingerprints") or {}).get("blackheart/v1")
            if expected and expected != finding_fingerprint(record):
                raise ValueError(
                    f"fingerprint mismatch for {record.finding_id!r}: "
                    "the embedded record was edited"
                )
            if record.status == FindingVerdict.CONFIRMED.value and not record.is_confirmed():
                record.status = FindingVerdict.STRONGLY_SUPPORTED.value
            records.append(record)
    return records
