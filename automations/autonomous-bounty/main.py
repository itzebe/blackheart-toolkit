"""Autonomous bounty orchestrator (deterministic shell around BLACKHEART).

Send it a brief; it runs unattended and only needs a human to submit.

Given a ``brief.json`` listing programs (policy URL/file + in-scope
repos/contracts/source trees + requested environments), one run:

  1. verifies each program's official policy (fail-CLOSED: an unverifiable policy
     never becomes an authorization);
  2. gates the requested environments (``local_fork`` / ``devnet``) against the
     policy text - a requested environment the policy does not permit is BLOCKED,
     never escalated to a heavier environment;
  3. builds and runs the research plan (``blackheart mission`` for source trees,
     ``blackheart hunt`` for deployed targets) inside the authorized scope;
  4. collects findings and PREPARES (never sends) a submission package with
     ``blackheart bounty prepare-submission``;
  5. writes a human-facing NEEDS-SUBMISSION.md into the sandbox and fires the
     automation callback. SUBMISSION IS ALWAYS HUMAN.

Design rules (non-negotiable, enforced here, not by the model):

* Self-contained: standard library only. It never imports the ``blackheart``
  package; it drives the CLI via ``subprocess`` so it runs in a bare sandbox that
  has the repo checked out.
* Never submits: no code path signs, sends, emails or contacts a program. The
  only external side effects are (a) fetching the public policy page and (b)
  running the engines - both authorized, both local/read-only to other systems.
* Fail-closed: missing policy, missing authorization, or an environment the
  policy forbids leaves the program/job BLOCKED with a reason, and no research
  runs for it.
* No spend/rate cap is imposed (per operator instruction); cadence is the cron
  or webhook that invokes this script.

CLI:
    python3 main.py                        # run the brief at ./brief.json
    python3 main.py --brief PATH           # run a specific brief
    python3 main.py --dry-run              # print the exact plan, run nothing
    python3 main.py --loop --interval 300  # drain repeatedly (unattended)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = Path(os.environ.get("BLACKHEART_ROOT", HERE.parents[1]))
PRIVATE_DIR = REPO_ROOT / "research" / "private" / "autonomous-bounty"
UA = "Mozilla/5.0 (compatible; blackheart-autonomous-bounty/1.0)"

# The engine command. Default: the repo's CLI. Overridable for tests / alt installs.
BH = shlex.split(os.environ.get("BLACKHEART_CMD", f"{sys.executable} -m blackheart"))

# Phrases in a policy that FORBID testing a given environment. If any appears, the
# environment is not permitted. Absence of a prohibition is treated as permission,
# because the brief is the operator's declaration; a hard prohibition is respected.
_FORBID = {
    "local_fork": ("no fork", "do not fork", "do not test on a fork", "fork testing is not",
                   "mainnet only", "production only", "only on mainnet", "only on production"),
    "devnet": ("no devnet", "do not test on devnet", "devnet is not", "mainnet only",
               "production only", "only on mainnet", "only on production"),
}


class Blocked(Exception):
    """A program or job cannot proceed; carried as a reason, never raised to abort peers."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- engine invocation -------------------------------------------------------

def run(cmd: list[str], *, dry: bool = False, timeout: int = 3600) -> tuple[int, str, str]:
    """Run a blackheart command (or, in dry-run, print it). Never raises on rc!=0."""
    pretty = " ".join(shlex.quote(c) for c in cmd)
    if dry:
        print(f"[dry-run] (cwd={REPO_ROOT})")
        print(f"[dry-run]   $ {pretty}")
        return 0, "", ""
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", f"engine not found: {exc}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "ignore")


# --- brief -------------------------------------------------------------------

def load_brief(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("programs"), list) or not data["programs"]:
        raise ValueError("brief must have a non-empty 'programs' list")
    for prog in data["programs"]:
        if not prog.get("name"):
            raise ValueError("every program needs a 'name'")
    return data


def permitted_environments(program: dict, policy_text: str) -> set[str]:
    """Requested environments minus those the policy forbids. Fail-closed."""
    requested = set(program.get("environments", ["local_fork"]))
    low = (policy_text or "").lower()
    permitted: set[str] = set()
    for env in requested:
        markers = _FORBID.get(env, ())
        if any(m in low for m in markers):
            continue  # policy forbids it -> not permitted
        permitted.add(env)
    return permitted


# --- policy verification (fail-closed) --------------------------------------

def verify_policy(program: dict, workdir: Path, *, dry: bool, net=fetch) -> tuple[Path, str]:
    """Capture + verify the official policy. Returns (snapshot_path, policy_text).

    Raises Blocked if the policy cannot be obtained or verified.
    """
    text_file = program.get("policy_text_file")
    url = program.get("policy_url", "")
    workdir.mkdir(parents=True, exist_ok=True)

    if text_file:
        src = Path(text_file)
        if not src.exists():
            raise Blocked(f"policy_text_file not found: {text_file}")
        body = src.read_text(encoding="utf-8", errors="ignore")
        source_url = url or f"file://{src}"
    elif url:
        if dry:
            raise Blocked("dry-run cannot fetch a policy_url; supply policy_text_file to dry-run")
        try:
            body = net(url)
        except Exception as exc:  # noqa: BLE001
            raise Blocked(f"policy fetch failed: {exc}") from exc
        src = workdir / "policy.txt"
        src.write_text(body, encoding="utf-8")
        source_url = url
    else:
        raise Blocked("program has neither policy_url nor policy_text_file")

    snapshot = workdir / "policy-snapshot.json"
    rc, _out, err = run([*BH, "bounty", "capture", "--program", program["name"],
                         "--source-url", source_url, "--retrieved-at", now_iso(),
                         "--text", str(src), "--out", str(snapshot)], dry=dry)
    if rc != 0:
        raise Blocked(f"bounty capture failed rc={rc}: {err.strip()[:200]}")
    rc, _out, err = run([*BH, "bounty", "verify-policy", "--snapshot", str(snapshot)], dry=dry)
    if rc != 0:
        raise Blocked(f"policy not verified rc={rc}: {err.strip()[:200]}")
    return snapshot, body


# --- research plan -----------------------------------------------------------

def build_plan(program: dict, snapshot: Path, workdir: Path, permitted: set[str]) -> tuple[list[dict], list[str]]:
    """Build the engine steps for one program. Returns (steps, blockers)."""
    steps: list[dict] = []
    blockers: list[str] = []
    scope_ref = program.get("policy_url", "")
    findings_dir = workdir / "findings"
    evidence_dir = workdir / "evidence"
    out_dir = workdir / "out"

    sources = program.get("source_paths", [])
    if sources:
        resolver = set(program.get("environments", ["local_fork"]))
        if not (resolver & permitted):
            blockers.append(
                "source research needs local_fork/devnet, none permitted by policy: "
                + ",".join(sorted(resolver - permitted))
            )
        else:
            for src in sources:
                steps.append({
                    "engine": "mission",
                    "cmd": [*BH, "mission", "--source", str(src), "--in-scope", "--authorized",
                            "--scope-reference", scope_ref, "--poc",
                            "--findings", str(findings_dir), "--evidence", str(evidence_dir),
                            "--out", str(out_dir), "--json"],
                })

    for addr in program.get("contracts", []):
        compat = program.get("compatibility")
        if not compat:
            blockers.append(f"deployed target {addr} needs a compatibility record (brief: 'compatibility')")
            continue
        steps.append({
            "engine": "hunt",
            "cmd": [*BH, "hunt", "--compatibility", str(compat), "--json"],
            "target": addr,
        })

    return steps, blockers


# --- gate + prepare (never submit) ------------------------------------------
#
# `bounty prepare-submission` runs `evaluate()` and returns the formal Gate-D
# disposition (A_SUBMISSION_READY .. F_NOT_ASSESSED) plus `submission_allowed`.
# We gate on that: only A/B warrant waking the human; C/D/E/F are recorded in the
# digest as "gated, not submittable" so a valid-but-not-payable finding never
# masquerades as a submission.

_SUBMITTABLE = frozenset({"A_SUBMISSION_READY", "B_POTENTIALLY_PAYABLE"})


def _parse_package(stdout: str) -> dict | None:
    s = (stdout or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        a, b = s.find("{"), s.rfind("}")
        if 0 <= a < b:
            try:
                return json.loads(s[a:b + 1])
            except Exception:  # noqa: BLE001
                return None
    return None


def gate_and_prepare(snapshot: Path, workdir: Path, *, dry: bool) -> tuple[list[dict], list[dict]]:
    """Gate each finding; return (submittable, gated).

    ``submittable`` holds findings whose formal disposition is A or B (the only
    ones that notify you). ``gated`` holds everything else (C valid-not-payable,
    D invalid, E informational, F not-assessed, or an evaluation error) for an
    honest digest line. Nothing is ever sent.
    """
    findings_dir = workdir / "findings"
    submittable: list[dict] = []
    gated: list[dict] = []
    if not findings_dir.exists():
        return submittable, gated
    for finding in sorted(findings_dir.rglob("*.json")):
        rc, out, err = run([*BH, "bounty", "prepare-submission",
                            "--policy", str(snapshot), "--finding", str(finding)], dry=dry)
        if dry:
            continue  # command printed; nothing to parse
        if rc != 0:
            gated.append({"finding": finding.name, "disposition": "ERROR",
                          "label": (err or "").strip()[:160]})
            continue
        pkg = _parse_package(out) or {}
        entry = {"finding": finding.name,
                 "disposition": pkg.get("disposition", ""),
                 "label": pkg.get("disposition_label", ""),
                 "submission_allowed": bool(pkg.get("submission_allowed", False)),
                 "blockers": pkg.get("blockers", [])}
        if entry["disposition"] in _SUBMITTABLE or entry["submission_allowed"]:
            submittable.append(entry)
        else:
            gated.append(entry)
    return submittable, gated


# --- integrity ledger --------------------------------------------------------

def ledger_append(entry: dict) -> str:
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    ledger = PRIVATE_DIR / "ledger.jsonl"
    prev = ""
    if ledger.exists():
        lines = ledger.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            try:
                prev = json.loads(lines[-1]).get("hash", "")
            except Exception:  # noqa: BLE001
                prev = ""
    record = {"ts": now_iso(), "prev": prev, **entry}
    record["hash"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record["hash"]


def fire_callback(status: str, error: str | None = None) -> None:
    url = os.environ.get("AUTOMATION_CALLBACK_URL", "")
    if not url:
        return
    body = {"status": status, "run_id": os.environ.get("AUTOMATION_RUN_ID", "")}
    if error:
        body["error"] = error
    try:
        urllib.request.urlopen(urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {os.environ.get('AUTOMATION_CALLBACK_API_KEY', '')}"},
        ), timeout=30)
    except Exception as exc:  # noqa: BLE001 - never hide the result on callback failure
        print(f"callback error: {exc}", file=sys.stderr)


# --- one program -------------------------------------------------------------

def run_program(program: dict, *, dry: bool, net=fetch) -> dict:
    slug = "".join(c if c.isalnum() or c in "-_" else "_" for c in program["name"]).lower()
    workdir = PRIVATE_DIR / slug
    result = {"program": program["name"], "report_to": program.get("report_to", ""),
              "status": "UNKNOWN", "blockers": [], "steps": [], "packages": [], "gated": [],
              "policy_snapshot": ""}
    try:
        snapshot, body = verify_policy(program, workdir, dry=dry, net=net)
        result["policy_snapshot"] = str(snapshot)
        permitted = permitted_environments(program, body)
        requested = set(program.get("environments", ["local_fork"]))
        for env in sorted(requested - permitted):
            result["blockers"].append(f"environment '{env}' not permitted by policy -> BLOCKED")

        steps, plan_blockers = build_plan(program, snapshot, workdir, permitted)
        result["blockers"].extend(plan_blockers)

        for step in steps:
            rc, _out, err = run(step["cmd"], dry=dry)
            result["steps"].append({"engine": step["engine"], "rc": rc, "error": err.strip()[:200]})
            if rc != 0:
                result["blockers"].append(f"{step['engine']} rc={rc}")

        submittable, gated = gate_and_prepare(snapshot, workdir, dry=dry)
        result["packages"] = submittable
        result["gated"] = gated
        result["status"] = "NEEDS_SUBMISSION" if submittable else "NO_FINDING"
    except Blocked as exc:
        result["status"] = "BLOCKED"
        result["blockers"].append(str(exc))
    return result


def write_reports(results: list[dict], *, dry: bool) -> Path | None:
    if dry:
        print(json.dumps(results, indent=2))
        return None
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    needs = [r for r in results if r["status"] == "NEEDS_SUBMISSION"]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    lines = [f"# Autonomous bounty run - {stamp}", "",
             "Reminder: submission is a human action. Nothing here has been sent.", ""]
    for r in results:
        lines.append(f"## {r['program']} - {r['status']}")
        if r.get("report_to"):
            lines.append(f"- report_to: `{r['report_to']}`")
        if r.get("policy_snapshot"):
            lines.append(f"- policy snapshot: `{r['policy_snapshot']}` (verified)")
        for b in r["blockers"]:
            lines.append(f"- blocker: {b}")
        for p in r["packages"]:
            lines.append(
                f"- SUBMITTABLE [{p.get('disposition','')}]: {p.get('label','')} "
                f"(finding {p.get('finding','')})")
        for g in r.get("gated", []):
            extra = f" — {g.get('finding','')}" if g.get("finding") else ""
            lines.append(f"- gated, not submittable: {g.get('disposition','')}{extra} {g.get('label','')}".rstrip())
        lines.append("")
    digest = PRIVATE_DIR / ("NEEDS-SUBMISSION.md" if needs else "RUN-DIGEST.md")
    digest.write_text("\n".join(lines), encoding="utf-8")
    (PRIVATE_DIR / f"run-{stamp}.md").write_text("\n".join(lines), encoding="utf-8")
    return digest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Autonomous bounty orchestrator around BLACKHEART")
    ap.add_argument("--brief", default=str(HERE / "brief.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--loop", action="store_true", help="drain repeatedly (unattended)")
    ap.add_argument("--interval", type=int, default=300, help="seconds between loop runs")
    args = ap.parse_args(argv)

    def one_pass() -> int:
        try:
            brief = load_brief(Path(args.brief))
        except Exception as exc:  # noqa: BLE001
            print(f"brief error: {exc}", file=sys.stderr)
            fire_callback("FAILED", f"brief error: {exc}")
            return 2
        results = [run_program(p, dry=args.dry_run) for p in brief["programs"]]
        digest = write_reports(results, dry=args.dry_run)
        if not args.dry_run:
            for r in results:
                ledger_append({"program": r["program"], "status": r["status"],
                               "blockers": r["blockers"],
                               "submittable": [p.get("disposition") for p in r["packages"]],
                               "gated": [g.get("disposition") for g in r.get("gated", [])]})
        needs = any(r["status"] == "NEEDS_SUBMISSION" for r in results)
        verified = any(r["status"] in ("NO_FINDING", "NEEDS_SUBMISSION") for r in results)
        print(f"[run] programs={len(results)} needs_submission={needs} "
              f"verified={verified} digest={digest}")
        fire_callback("NEEDS_SUBMISSION" if needs else ("COMPLETED" if verified else "BLOCKED"))
        # Fail-closed exit: if NO program could be verified, signal it.
        return 0 if verified else 2

    if not args.loop:
        return one_pass()
    while True:
        try:
            one_pass()
        except Exception as exc:  # noqa: BLE001
            fire_callback("FAILED", str(exc))
            print(f"loop error: {exc}", file=sys.stderr)
        time.sleep(max(30, args.interval))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - top-level guard for the automation service
        fire_callback("FAILED", str(exc))
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
