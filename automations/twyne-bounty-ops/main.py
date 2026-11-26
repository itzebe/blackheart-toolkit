"""Twyne daily bounty-operations monitor (deterministic, read-only, no LLM).

Self-contained: standard library only, no import of the BLACKHEART package, so it
runs identically in a fresh OpenHands sandbox. Cross-run state lives in the
automation KV store (cloud runs get a fresh pod each time) with a local-file
fallback for local runs.

Each run:
  1. fetches the current official Twyne Immunefi program page(s);
  2. extracts the facts that matter (program status, in-scope repos/addresses,
     Safe Harbor, PoC/KYC requirements, reward cap);
  3. diffs them against the last verified snapshot (KV-backed);
  4. revalidates every known asset's authorization against the fresh scope,
     failing closed when the program cannot be confirmed active;
  5. emits a concise daily result and fires the completion callback.

It is read-only: it never broadcasts a transaction, never runs active testing,
never submits a report, and never contacts the program. The refreshed
authorization evidence is recorded in the private (git-ignored) evidence dir
*and* in the KV store so the decision survives a fresh sandbox.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "scope-config.json"
REPO_ROOT = HERE.parents[1]
STATE_DIR = REPO_ROOT / "research" / "private" / "twyne-monitor"
EVIDENCE_DIR = REPO_ROOT / "research" / "private" / "authz" / "evidence"
UA = "Mozilla/5.0 (compatible; blackheart-twyne-monitor/1.0)"

_KV_TOKEN = os.environ.get("AUTOMATION_KV_TOKEN", "")
_KV_BASE = os.environ.get("AUTOMATION_API_URL", "").rstrip("/")


# --- KV store (per-automation state that survives fresh sandboxes) -----------

def kv_available() -> bool:
    return bool(_KV_TOKEN and _KV_BASE)


def kv_get(key: str):
    req = urllib.request.Request(
        f"{_KV_BASE}/v1/kv/{key}", headers={"Authorization": f"Bearer {_KV_TOKEN}"}
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
        f"{_KV_BASE}/v1/kv/{key}",
        data=json.dumps(value).encode(),
        headers={"Authorization": f"Bearer {_KV_TOKEN}", "Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def load_state(key: str):
    """KV first (cloud), then a local file (dev), else None."""
    if kv_available():
        return kv_get(key)
    path = STATE_DIR / f"{key}.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_state(key: str, value) -> None:
    if kv_available():
        kv_set(key, value)
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / f"{key}.json").write_text(json.dumps(value, indent=2), encoding="utf-8")


# --- automation-service callback (no-op outside the service) -----------------

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
    except Exception as exc:  # never let a callback failure hide the result
        print(f"callback error: {exc}", file=sys.stderr)


# --- fetch + fact extraction -------------------------------------------------

def http_get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


def _visible_text(html: str) -> str:
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.replace("&amp;", "&").replace("&#x27;", "'").replace("&quot;", '"')
    return re.sub(r"\s+", " ", text)


def extract_facts(html: str) -> dict:
    text = _visible_text(html)
    lowered = text.lower()
    repos = sorted(set(re.findall(r"github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+", html)))
    addresses = sorted({a.lower() for a in re.findall(r"0x[a-fA-F0-9]{40}", html)})
    reward_match = re.search(r"up to \$?([\d,]+)", lowered)
    return {
        "program_present": "twyne" in lowered,
        "program_active": "twyne" in lowered and "inactive" not in lowered,
        "repos": repos,
        "addresses": addresses,
        "safe_harbor": "safe harbor" in lowered or "safe-harbor" in lowered,
        "poc_required": "poc" in lowered or "proof of concept" in lowered,
        "kyc_required": "kyc not required" not in lowered and "no kyc" not in lowered,
        "reward_cap": reward_match.group(1) if reward_match else None,
    }


def scope_urls(config: dict) -> list[str]:
    urls = [config["scope_url"]]
    if config.get("program_url") and config["program_url"] not in urls:
        urls.append(config["program_url"])
    return urls


def fetch_scope(config: dict) -> tuple[dict, dict, list[dict]]:
    pages: dict[str, str] = {}
    retrievals: list[dict] = []
    for url in scope_urls(config):
        html = http_get(url)
        pages[url] = html
        retrievals.append({"url": url, "retrieved_at": datetime.now(timezone.utc).isoformat()})
    return extract_facts(pages[config["scope_url"]]), pages, retrievals


# --- snapshot diff -----------------------------------------------------------

VOLATILE_FACTS = frozenset()


def diff_snapshot(prev: dict | None, cur: dict) -> list[str]:
    if not prev:
        return ["no previous snapshot; baseline established"]
    changes: list[str] = []
    for key in sorted((set(prev) | set(cur)) - VOLATILE_FACTS):
        before, after = prev.get(key), cur.get(key)
        if before != after:
            changes.append(f"{key}: {before!r} -> {after!r}")
    return changes


# --- authorization revalidation ----------------------------------------------

def revalidate_assets(config: dict, facts: dict) -> dict[str, dict]:
    """Classify every known asset against the fresh scope. Fails closed."""
    program_ok = bool(facts.get("program_active")) and bool(facts.get("program_present"))
    scope_blob = " ".join(facts.get("repos", [])) + " " + " ".join(facts.get("addresses", []))
    decisions: dict[str, dict] = {}
    for asset, recorded in config["assets"].items():
        reasons: list[str] = []
        status = "UNKNOWN"
        if not program_ok:
            reasons.append("program status not confirmed active")
        elif recorded != "AUTHORIZED":
            status = recorded
            reasons.append(f"recorded as {recorded}; active testing not authorized")
        else:
            token = asset.split("/")[-1]
            if token in scope_blob or token in json.dumps(facts):
                status = "AUTHORIZED"
                reasons.append("present in current official scope and program checks pass")
            else:
                reasons.append("asset no longer referenced in current official scope")
        decisions[asset] = {"status": status, "reasons": reasons}
    return decisions


def refresh_authorization(
    config: dict, facts: dict, pages: dict[str, str], retrievals: list[dict]
) -> dict:
    """Record fresh dated authorization evidence (KV + private dir). Never active."""
    primary_html = pages[config["scope_url"]]
    sha = hashlib.sha256(primary_html.encode()).hexdigest()
    decisions = revalidate_assets(config, facts)
    recorded = config.get("recorded_facts", {})
    # Program-page facts are re-derived every run; eligibility/payout feasibility
    # are policy facts from the manual review and must be carried forward, or the
    # authorization gate rejects the refreshed record for missing checks.
    record = {
        "program": config["program"],
        "platform": config["platform"],
        "target_url": config["program_url"],
        "scope_url": config["scope_url"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "program_active": bool(facts.get("program_active")),
        "safe_harbor": bool(facts.get("safe_harbor")),
        "poc_required": bool(recorded.get("poc_required", facts.get("poc_required"))),
        "nigerian_eligible": recorded.get("nigerian_eligible"),
        "payout_feasible": recorded.get("payout_feasible"),
        "zero_cost": bool(recorded.get("zero_cost", True)),
        "asset_classes": {a: d["status"] for a, d in decisions.items()},
        "evidence": [f"ev-{sha[:16]}"],
        "verified": True,
    }
    save_state("authorization", record)
    if not os.environ.get("AUTOMATION_KV_TOKEN"):
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        (EVIDENCE_DIR / f"immunefi-twyne-{stamp}.html").write_text(primary_html, encoding="utf-8")
    return record


# --- daily result ------------------------------------------------------------

def build_result(
    facts: dict, changes: list[str], decisions: dict, retrievals: list[dict], evidence_id: str
) -> dict:
    newly_eligible = [a for a, d in decisions.items() if d["status"] == "AUTHORIZED"]
    excluded = [a for a, d in decisions.items() if d["status"] in ("OUT_OF_SCOPE", "PASSIVE_ONLY")]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scope_verified": bool(facts.get("program_active")),
        "changes": changes,
        "newly_eligible_assets": newly_eligible,
        "excluded_assets": excluded,
        "authorization_decisions": decisions,
        "sources": retrievals,
        "research_opportunities": (
            ["local-fork research on the wrapper remains authorized (see fork harness)"]
            if newly_eligible
            else []
        ),
        "blockers": [] if facts.get("program_active") else ["program status not confirmed active"],
        "evidence_id": evidence_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="do not write state")
    args = parser.parse_args()

    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    try:
        facts, pages, retrievals = fetch_scope(config)
    except Exception as exc:
        # Fail closed: no verified scope, no monitoring result, no authz refresh.
        msg = f"scope fetch failed: {exc}"
        print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}")
        fire_callback("FAILED", msg)
        return 2

    changes = diff_snapshot(load_state("snapshot"), facts)
    decisions = revalidate_assets(config, facts)

    evidence_id = ""
    if not args.dry_run:
        record = refresh_authorization(config, facts, pages, retrievals)
        evidence_id = record["evidence"][0]

    result = build_result(facts, changes, decisions, retrievals, evidence_id)
    print(json.dumps(result, indent=2))
    if not args.dry_run:
        save_state("snapshot", facts)
        save_state("last-result", result)

    fire_callback("COMPLETED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - top-level guard for the service
        fire_callback("FAILED", str(exc))
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
