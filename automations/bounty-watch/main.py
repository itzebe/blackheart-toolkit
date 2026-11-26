#!/usr/bin/env python3
"""Hourly bounty-watch automation (option 1: OpenHands scheduled execution).

This is a thin wrapper around the real engine. It does not reimplement anything:
it loads the durable state from the automation KV store (or a local file), runs
one read-only cycle, writes the state back, and fires the completion callback.

The GitHub Actions workflow is the primary scheduler because its execution is
verifiable from the repository. This wrapper exists so the same cycle can run on
OpenHands' own scheduler without consuming GitHub minutes, and so a local run
behaves identically.

It is read-only against the world: no transaction, no active testing, no
submission, no program contact.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(REPO_ROOT))

from blackheart.watch.cycle import CycleConfig, run_cycle  # noqa: E402
from blackheart.watch.report import render_cycle, render_status  # noqa: E402

KV_TOKEN = os.environ.get("AUTOMATION_KV_TOKEN", "")
KV_BASE = os.environ.get("AUTOMATION_API_URL", "").rstrip("/")
LOCAL_STATE = REPO_ROOT / "research" / "private" / "bounty-watch"
STATE_KEY = "bounty-watch-state"
REPORT_KEY = "bounty-watch-latest-report"


def kv_available() -> bool:
    return bool(KV_TOKEN and KV_BASE)


def kv_get(key: str):
    req = urllib.request.Request(
        f"{KV_BASE}/v1/kv/{key}", headers={"Authorization": f"Bearer {KV_TOKEN}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["value"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def kv_set(key: str, value) -> None:
    req = urllib.request.Request(
        f"{KV_BASE}/v1/kv/{key}",
        data=json.dumps(value).encode(),
        headers={
            "Authorization": f"Bearer {KV_TOKEN}",
            "Content-Type": "application/json",
        },
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def fire_callback(status: str = "COMPLETED", error: str | None = None) -> None:
    url = os.environ.get("AUTOMATION_CALLBACK_URL", "")
    if not url:
        return
    body = {"status": status, "run_id": os.environ.get("AUTOMATION_RUN_ID", "")}
    if error:
        body["error"] = error
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                url,
                data=json.dumps(body).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {os.environ.get('AUTOMATION_CALLBACK_API_KEY', '')}",
                },
            ),
            timeout=30,
        )
    except Exception as exc:  # a callback failure must not hide the result
        print(f"callback error: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", dest="targets")
    parser.add_argument("--email", action="store_true")
    parser.add_argument("--email-to", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout", type=int, default=25)
    args = parser.parse_args(argv)

    if kv_available():
        work = Path(tempfile.mkdtemp(prefix="bounty-watch-"))
    else:
        work = LOCAL_STATE
    state_dir = work / "state"
    out_dir = work / "out"
    state_dir.mkdir(parents=True, exist_ok=True)

    if not args.dry_run:
        doc = kv_get(STATE_KEY) if kv_available() else _read_json(state_dir / "state.json")
        if isinstance(doc, dict):
            (state_dir / "state.json").write_text(json.dumps(doc), encoding="utf-8")

    report = run_cycle(
        CycleConfig(
            state_dir=str(state_dir),
            out_dir=str(out_dir),
            targets=tuple(args.targets or ()),
            timeout=args.timeout,
            dry_run=args.dry_run,
            email=args.email,
            email_to=args.email_to,
        )
    )

    if not args.dry_run:
        doc = _read_json(state_dir / "state.json")
        if isinstance(doc, dict):
            if kv_available():
                kv_set(STATE_KEY, doc)
                kv_set(REPORT_KEY, {
                    "cycle_id": report.cycle_id,
                    "finished_at": report.finished_at,
                    "counts": report.counts(),
                    "markdown": render_cycle(report),
                })
            else:
                (state_dir / "state.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    print(render_status(report))
    for lead in report.leads:
        if lead.status in ("NEW ACTIONABLE CHANGE", "INVESTIGATE", "POLICY BLOCKED"):
            print(f"  [{lead.status}] {lead.target.slug}/{lead.event.component} "
                  f"score={lead.score} {lead.event.summary}")
    for slug, failure in report.failures:
        print(f"  [GAP] {slug}: {failure}")
    fire_callback("COMPLETED")
    return 0 if report.exit_code in (0, 1) else 2


def _read_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


if __name__ == "__main__":
    raise SystemExit(main())
