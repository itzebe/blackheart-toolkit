"""Acceptance tests for the bounty watchtower.

The HTTP and JSON-RPC sources are real local servers, so the tests exercise the
real ``urllib`` clients and the real proxy-slot/bytecode reader rather than a
mock. Every assertion is about observable behaviour: a change is detected, a
repeat is deduplicated, a known issue is suppressed, a participation gate blocks
promotion, and a failed source is reported as a gap.
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from blackheart.deployed import PROXY_SLOTS
from blackheart.watch.classify import (
    CONTRACT_KINDS,
    Kind,
    SCORE_THRESHOLD,
    SCORE_WEIGHTS,
    Status,
    classify_event,
    make_event,
    score_lead,
)
from blackheart.watch.cycle import CycleConfig, run_cycle
from blackheart.watch.fetch import (
    FetchResult,
    GitHubClient,
    HttpFetcher,
    RpcClient,
    rpc_for_chain,
)
from blackheart.watch.notify import EmailConfig, send_email
from blackheart.watch.registry import (
    ContractRef,
    Eligibility,
    KnownIssue,
    PolicyRef,
    RepoRef,
    Target,
    load_registry,
    validate_targets,
    write_target_records,
)
from blackheart.watch.report import render_cycle, render_investigation
from blackheart.watch.source import SourceBundle, SourceClient, diff_bundles

PROXY = "0x" + "aa" * 20
IMPL_A = "0x" + "11" * 20
IMPL_B = "0x" + "44" * 20
ADMIN_A = "0x" + "22" * 20
ADMIN_B = "0x" + "55" * 20
OWNER_A = "0x" + "33" * 20
OWNER_B = "0x" + "66" * 20

POLICY_HTML = """<html><head><title>Test Program</title></head><body>
<h1>Bug Bounty</h1><p>In scope: the vault and bridge contracts on mainnet.</p>
<p>Rewards are paid after KYC. Out of scope: test files.</p>
<p>Scope Review: 100. Automated scanners are not allowed on the platform.</p>
</body></html>"""


def _pad(addr: str) -> str:
    return "0x" + ("0" * 24) + addr[2:]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        pass

    def _send(self, status: int, body: bytes, ctype: str = "text/html",
              etag: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)

    def _not_modified(self, etag: str) -> bool:
        if self.headers.get("If-None-Match", "").strip() == etag:
            self._send(304, b"", etag=etag)
            return True
        return False

    def do_GET(self):  # noqa: N802
        st = self.server.state  # type: ignore[attr-defined]
        path = self.path.split("?", 1)[0]
        if path == "/policy":
            if st["policy_status"] != 200:
                self._send(st["policy_status"], b"unavailable")
                return
            etag = '"p' + hashlib.sha1(st["policy"].encode()).hexdigest() + '"'
            if self._not_modified(etag):
                return
            self._send(200, st["policy"].encode(), etag=etag)
            return
        if path == "/down":
            self._send(503, b"down")
            return
        if path == "/repos/o/r":
            if st["repo_meta_status"] != 200:
                self._send(st["repo_meta_status"], b'{"message":"error"}', "application/json")
                return
            etag = '"meta-' + st["default_branch"] + '"'
            if self._not_modified(etag):
                return
            self._send(200, json.dumps({
                "full_name": "o/r", "default_branch": st["default_branch"],
                "archived": False, "pushed_at": "2026-11-21T00:00:00Z",
            }).encode(), "application/json", etag=etag)
            return
        if path == "/repos/o/r/commits":
            if st["head_status"] != 200:
                self._send(st["head_status"], b'{"message":"Git Repository is empty."}',
                           "application/json")
                return
            etag = '"head-' + st["head"] + '"'
            if self._not_modified(etag):
                return
            self._send(200, json.dumps([{
                "sha": st["head"],
                "commit": {"message": st["head_message"],
                           "author": {"date": "2026-11-21T00:00:00Z"}},
            }]).encode(), "application/json", etag=etag)
            return
        if path == "/repos/o/r/releases/latest":
            if not st["release"]:
                self._send(404, b'{"message":"Not Found"}', "application/json")
                return
            etag = '"rel-' + st["release"] + '"'
            if self._not_modified(etag):
                return
            self._send(200, json.dumps({
                "tag_name": st["release"], "name": st["release"],
                "published_at": "2026-11-21T00:00:00Z", "body": st["release_body"],
            }).encode(), "application/json", etag=etag)
            return
        if path == "/repos/o/r/tags":
            etag = '"tags-' + "-".join(st["tags"]) + '"'
            if self._not_modified(etag):
                return
            self._send(200, json.dumps([{"name": t} for t in st["tags"]]).encode(),
                       "application/json", etag=etag)
            return
        if path.startswith("/repos/o/r/compare/"):
            self._send(200, json.dumps({
                "files": [{"filename": f} for f in st["files"]],
                "commits": [{"commit": {"message": m}} for m in st["messages"]],
            }).encode(), "application/json")
            return
        self._send(404, b'{"message":"Not Found"}', "application/json")

    def do_POST(self):  # noqa: N802
        st = self.server.state  # type: ignore[attr-defined]
        if self.path.split("?", 1)[0] != "/rpc":
            self._send(404, b"no")
            return
        length = int(self.headers.get("Content-Length", "0"))
        req = json.loads(self.rfile.read(length) or b"{}")
        method = req.get("method")
        params = req.get("params") or []
        result = "0x0"
        if method == "eth_chainId":
            result = "0x1"
        elif method == "eth_blockNumber":
            result = "0x100"
        elif method == "eth_getCode":
            addr = str(params[0]).lower()
            if addr == PROXY.lower():
                result = st["proxy_code"]
            else:
                result = st["impls"].get(addr, "0x")
        elif method == "eth_getStorageAt":
            slot = str(params[1]).lower()
            if slot == PROXY_SLOTS["eip1967"].lower():
                result = _pad(st["impl_addr"])
            elif slot == PROXY_SLOTS["eip1967_admin"].lower():
                result = _pad(st["admin"])
            else:
                result = "0x" + "0" * 64
        elif method == "eth_call":
            data = (params[0] or {}).get("data", "")
            result = _pad(st["owner"]) if data == "0x8da5cb5b" else "0x"
        body = json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}).encode()
        self._send(200, body, "application/json")


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.state = {  # type: ignore[attr-defined]
        "policy": POLICY_HTML,
        "policy_status": 200,
        "repo_meta_status": 200,
        "default_branch": "main",
        "head_status": 200,
        "head": "a" * 40,
        "head_message": "refactor",
        "release": "",
        "release_body": "",
        "tags": ["v1"],
        "files": ["src/Vault.sol"],
        "messages": ["refactor vault"],
        "proxy_code": "0x6001600055",
        "impl_addr": IMPL_A,
        "impls": {IMPL_A.lower(): "0x6002600055"},
        "admin": ADMIN_A,
        "owner": OWNER_A,
    }
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _base(server) -> str:
    return f"http://127.0.0.1:{server.server_port}"


def _targets(base: str, *, permitted: bool = False, known: bool = False) -> tuple[Target, ...]:
    elig = Eligibility(
        ai_agent_allowed="true" if permitted else "unknown",
        participation_authorized=permitted,
        platform_participation_allowed=permitted,
        nigeria_eligible="unknown",
        kyc_required="unknown",
    )
    known_issues = (
        (KnownIssue("KI-1", "Approved hash replay", "PUBLIC_FIXED",
                    ("approved hash", "hash replay")),)
        if known else ()
    )
    main = Target(
        slug="blocked" if not permitted else "permitted",
        name="Test Target",
        group="A",
        program_status="ACTIVE",
        platforms=("test",),
        policy_urls=(PolicyRef(base + "/policy"),),
        repos=(RepoRef("o/r"),),
        contracts=(ContractRef("c1", 1, PROXY, "Test proxy", True, base + "/deploy"),),
        eligibility=elig,
        known_issues=known_issues,
        value_class="high",
    )
    failing = Target(
        slug="failing",
        name="Failing Source",
        group="A",
        program_status="ACTIVE",
        policy_urls=(PolicyRef(base + "/down"),),
        repos=(RepoRef("o/r"),),
        eligibility=Eligibility(),
        value_class="low",
    )
    return (main, failing)


def _config(tmp_path: Path) -> CycleConfig:
    return CycleConfig(
        state_dir=str(tmp_path / "state"),
        out_dir=str(tmp_path / "out"),
        timeout=5,
        source_diff=False,
    )


class _FakeSource:
    """Deterministic stand-in for Sourcify: bundles keyed by address."""

    def __init__(self, bundles: dict[str, dict[str, str]] | None = None) -> None:
        self.bundles = {k.lower(): v for k, v in (bundles or {}).items()}
        self.calls: list[tuple[int, str]] = []

    def fetch(self, chain_id: int, address: str) -> SourceBundle:
        self.calls.append((chain_id, address.lower()))
        files = self.bundles.get(address.lower())
        url = f"https://sourcify.test/{chain_id}/{address}"
        if files is None:
            return SourceBundle(
                chain_id=chain_id, address=address.lower(), url=url, status="not_verified"
            )
        return SourceBundle(
            chain_id=chain_id,
            address=address.lower(),
            url=url,
            ok=True,
            status="verified",
            files=dict(files),
            match="exact_match",
            compiler="solc",
            compiler_version="0.8.24+commit.e11b9ed9",
        )


def _run(server, targets, cfg, *, fetcher=None, github=None, rpc=None, source=None):
    base = _base(server)
    return run_cycle(
        cfg,
        registry=targets,
        fetcher=fetcher or HttpFetcher(timeout=5, retries=0),
        github=github or GitHubClient(base_url=base, timeout=5, retries=0),
        rpc=rpc or RpcClient(timeout=5, overrides={1: base + "/rpc"}),
        source=source,
    )


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

def test_packaged_registry_is_complete_and_independent():
    targets = load_registry()
    assert len(targets) == 43
    assert validate_targets(targets) == []
    groups = {t.group for t in targets}
    assert groups == {"A", "B", "C", "D"}
    # Every record is separate and no two share a slug.
    assert len({t.slug for t in targets}) == len(targets)
    # The mission's participation restrictions are enforced by default.
    assert [t.slug for t in targets if t.submission_permitted] == []
    ticko = next(t for t in targets if t.slug == "ticko")
    assert ticko.program_status == "TESTNET_ONLY"
    assert any("Testnet only" in r for r in ticko.restrictions)
    # Known issues are present and specific.
    safe = next(t for t in targets if t.slug == "safe")
    assert any(k.id == "SAFE-APPROVED-HASH-REPLAY-187" for k in safe.known_issues)
    phala = next(t for t in targets if t.slug == "phala")
    assert any(k.id == "PHALA-001-KMS-KEY-SUBSTITUTION" and k.monitor for k in phala.known_issues)
    # Verified contract inventory is non-trivial.
    assert sum(len(t.contracts) for t in targets) >= 25


def test_write_target_records_creates_one_file_per_target(tmp_path):
    targets = load_registry()
    written = write_target_records(targets, tmp_path)
    assert len(written) == len(targets) + 1  # + index
    for t in targets:
        assert (tmp_path / t.group / f"{t.slug}.json").is_file()
    index = json.loads((tmp_path / "index.json").read_text())
    assert index["count"] == len(targets)


# --------------------------------------------------------------------------- #
# Real local-server cycle
# --------------------------------------------------------------------------- #

def test_first_cycle_baselines_and_reports_failure(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    report = _run(server, targets, cfg)
    assert report.exit_code == 2  # the /down source failed
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    # First observation is a baseline, not a "new contract"/"new commit" alert.
    assert not any(e.kind in (Kind.CONTRACT_NEW, Kind.REPO_HEAD) for e in blocked.events)
    assert any(e.kind == Kind.POLICY_NEW for e in blocked.events)
    failing = next(t for t in report.targets if t.target.slug == "failing")
    assert any(l.status == Status.SOURCE_INACCESSIBLE for l in failing.leads)
    assert (tmp_path / "state" / "state.json").is_file()
    assert list((tmp_path / "out" / "reports").glob("*.md"))


def test_second_cycle_deduplicates_and_survives_restart(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    # A fresh state object is loaded from disk, as after a process restart.
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    assert not [e for e in blocked.events if e.kind == Kind.POLICY_NEW]
    assert report.counts()[Status.NO_CHANGE] >= 1
    assert report.counts()[Status.SOURCE_INACCESSIBLE] >= 1
    assert blocked.deduped >= 0
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["cycles"] == 2
    assert state["targets"]["blocked"]["policy"]
    assert state["targets"]["blocked"]["contracts"]["c1"]["fingerprint"]


def test_policy_change_is_detected_with_diff(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["policy"] = POLICY_HTML.replace(
        "In scope: the vault and bridge contracts on mainnet.",
        "In scope: the vault and bridge contracts on mainnet and the new oracle.",
    )
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    change = next(e for e in blocked.events if e.kind == Kind.POLICY_CHANGED)
    assert "oracle" in json.dumps(change.detail.get("changed_lines"))
    review = change.detail.get("ai_agent_review") or {}
    assert review.get("detected") is True
    assert review.get("prohibited_language") is True
    lead = next(l for l in blocked.leads if l.event.kind == Kind.POLICY_CHANGED)
    assert lead.policy_blocked
    assert lead.status == Status.POLICY_BLOCKED


def test_metric_only_policy_change_is_suppressed(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["policy"] = POLICY_HTML.replace("Scope Review: 100", "Scope Review: 101")
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    assert not [e for e in blocked.events if e.kind == Kind.POLICY_CHANGED]


def test_numeric_only_policy_diff_is_not_material():
    from blackheart.watch.cycle import policy_diff

    summary, changed, material = policy_diff(
        "Total rewards: $8,230. Scope is the vault.",
        "Total rewards: $8,231. Scope is the vault.",
    )
    assert material is False
    assert changed == []

    summary, changed, material = policy_diff(
        "Submissions: 190. Scope is the dApp.",
        "Submissions <counter>. Scope is the dApp.",
    )
    assert material is False and changed == []


def test_decimal_metric_change_is_not_a_policy_change():
    """Live program pages tick TVL every hour; that is not a scope change."""
    from blackheart.watch.cycle import policy_diff

    summary, changed, material = policy_diff(
        "Primary Pool $56,000 Vault TVL $79,950.72 Start Date 02 November 2026.",
        "Primary Pool $56,000 Vault TVL $79,952 Start Date 02 November 2026.",
    )
    assert material is False and changed == []
    assert "metric" in summary

    summary, changed, material = policy_diff(
        "Vault TVL $79,952. Rewards are USDC.",
        "Vault TVL $79,952. Rewards are paid in ETH only.",
    )
    assert material is True and changed


def test_contract_bytecode_change_is_a_deployment_change(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["impls"][IMPL_A.lower()] = "0x6003600055"  # same impl, new code
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    change = next(e for e in blocked.events if e.kind == Kind.CONTRACT_CODE)
    assert change.detail["deployment_evidence"] is True
    assert change.old != change.new
    lead = next(l for l in blocked.leads if l.event.kind == Kind.CONTRACT_CODE)
    assert lead.status == Status.POLICY_BLOCKED


def test_implementation_repoint_and_admin_owner_changes(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["impl_addr"] = IMPL_B
    server.state["impls"][IMPL_B.lower()] = "0x6004600055"
    server.state["admin"] = ADMIN_B
    server.state["owner"] = OWNER_B
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    kinds = {e.kind for e in blocked.events}
    assert Kind.CONTRACT_IMPL in kinds
    assert Kind.CONTRACT_ADMIN in kinds
    assert Kind.CONTRACT_OWNER in kinds


def test_permitted_target_can_reach_actionable_but_blocked_cannot(server, tmp_path):
    base = _base(server)
    cfg = _config(tmp_path)
    targets = _targets(base, permitted=True)
    _run(server, targets, cfg)
    server.state["impls"][IMPL_A.lower()] = "0x6005600055"
    report = _run(server, targets, cfg)
    permitted = next(t for t in report.targets if t.target.slug == "permitted")
    lead = next(l for l in permitted.leads if l.event.kind == Kind.CONTRACT_CODE)
    assert lead.status == Status.NEW_ACTIONABLE_CHANGE
    assert lead.score >= SCORE_THRESHOLD
    assert lead.recommend

    blocked_cfg = _config(tmp_path / "blocked")
    blocked_targets = _targets(base, permitted=False)
    _run(server, blocked_targets, blocked_cfg)
    server.state["impls"][IMPL_A.lower()] = "0x6006600055"
    blocked_report = _run(server, blocked_targets, blocked_cfg)
    blocked = next(t for t in blocked_report.targets if t.target.slug == "blocked")
    blocked_lead = next(l for l in blocked.leads if l.event.kind == Kind.CONTRACT_CODE)
    assert blocked_lead.status == Status.POLICY_BLOCKED
    assert not blocked_lead.recommend
    assert "AI-agent" in blocked_lead.block_reason


def test_known_issue_is_suppressed(server, tmp_path):
    base = _base(server)
    targets = _targets(base, known=True)
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["head"] = "b" * 40
    server.state["files"] = ["contracts/Safe.sol"]
    server.state["messages"] = ["fix approved hash replay"]
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    lead = next(l for l in blocked.leads if l.event.kind == Kind.REPO_HEAD)
    assert lead.status == Status.KNOWN_DUPLICATE
    assert lead.known_issue is not None and lead.known_issue.id == "KI-1"


def test_repo_304_keeps_previous_head(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    head_before = state["targets"]["blocked"]["repos"]["o/r"]["head"]
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    assert not [e for e in blocked.events if e.kind == Kind.REPO_HEAD]
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert state["targets"]["blocked"]["repos"]["o/r"]["head"] == head_before


def test_repo_metadata_failure_is_a_gap_not_a_branch_guess(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["repo_meta_status"] = 500
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    assert any(e.kind == Kind.SOURCE_FAILED and e.component == "o/r" for e in blocked.events)
    assert not [e for e in blocked.events if e.kind == Kind.REPO_HEAD]


def test_empty_repo_then_first_commit_is_an_event(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    server.state["head_status"] = 409
    first = _run(server, targets, cfg)
    blocked = next(t for t in first.targets if t.target.slug == "blocked")
    assert blocked.failures == []
    assert any("empty" in g for g in blocked.gaps)
    server.state["head_status"] = 200
    server.state["head"] = "d" * 40
    server.state["head_message"] = "initial contracts"
    second = _run(server, targets, cfg)
    blocked = next(t for t in second.targets if t.target.slug == "blocked")
    ev = next(e for e in blocked.events if e.kind == Kind.REPO_HEAD)
    assert "first commit" in ev.summary
    assert ev.detail["deployment_evidence"] is False


def test_repo_without_default_branch_fails_closed(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["default_branch"] = ""
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    assert any("default_branch" in f for f in blocked.failures)
    assert not [e for e in blocked.events if e.kind == Kind.REPO_HEAD]


def test_repo_change_is_not_deployment_evidence(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["head"] = "c" * 40
    server.state["files"] = ["src/Vault.sol"]
    server.state["messages"] = ["fix withdrawal accounting"]
    report = _run(server, targets, cfg)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    ev = next(e for e in blocked.events if e.kind == Kind.REPO_HEAD)
    assert ev.detail["deployment_evidence"] is False
    assert "commit is not a deployment" in ev.detail["note"]


def test_failed_source_is_reported_honestly(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    report = _run(server, targets, cfg)
    failures = report.failures
    assert any("policy" in f and "down" in f for _, f in failures)
    assert report.exit_code == 2
    failing = next(t for t in report.targets if t.target.slug == "failing")
    assert failing.leads and all(
        l.status == Status.SOURCE_INACCESSIBLE for l in failing.leads
    )
    rendered = render_cycle(report)
    assert "Source failures (gaps, not clean results)" in rendered
    assert "never reported as" in rendered


def test_report_has_seventeen_fields_and_no_finding_claim(server, tmp_path):
    base = _base(server)
    targets = _targets(base, permitted=True)
    cfg = _config(tmp_path)
    _run(server, targets, cfg)
    server.state["impls"][IMPL_A.lower()] = "0x6007600055"
    report = _run(server, targets, cfg)
    permitted = next(t for t in report.targets if t.target.slug == "permitted")
    lead = next(l for l in permitted.leads if l.event.kind == Kind.CONTRACT_CODE)
    text = render_investigation(lead)
    for n in range(1, 18):
        assert f"## {n}." in text
    assert "not a confirmed vulnerability" in text.lower()
    assert "Local fork" in text
    assert "no mainnet transaction" in text.lower()


# --------------------------------------------------------------------------- #
# Scoring and gates
# --------------------------------------------------------------------------- #

def test_score_weights_sum_to_100_and_components_are_bounded():
    assert sum(SCORE_WEIGHTS.values()) == 100
    target = Target(slug="t", name="T", group="A", program_status="ACTIVE",
                    value_class="high")
    event = make_event(target="t", kind=Kind.CONTRACT_IMPL, component="c",
                       summary="impl changed", security_relevant=True)
    score, comps, rationale = score_lead(event, target)
    assert 0 <= score <= 100
    for name, maximum in SCORE_WEIGHTS.items():
        assert 0 <= comps[name] <= maximum
    assert sum(comps.values()) == score
    assert rationale


def test_policy_block_prevents_promotion_even_at_high_score():
    target = Target(slug="t", name="T", group="A", program_status="ACTIVE",
                    value_class="high", eligibility=Eligibility())
    event = make_event(target="t", kind=Kind.CONTRACT_IMPL, component="c",
                       summary="impl changed", security_relevant=True)
    lead = classify_event(event, target)
    assert lead.score >= SCORE_THRESHOLD  # the change is genuinely strong
    assert lead.status == Status.POLICY_BLOCKED
    assert not lead.recommend
    assert "AI-agent" in lead.block_reason


def test_source_failure_is_never_no_change():
    target = Target(slug="t", name="T", group="A", program_status="ACTIVE")
    event = make_event(target="t", kind=Kind.SOURCE_FAILED, component="u",
                       summary="unreadable")
    lead = classify_event(event, target)
    assert lead.status == Status.SOURCE_INACCESSIBLE
    assert lead.score == 0


def test_email_refuses_without_credentials():
    result = send_email("subject", "body", config=EmailConfig())
    assert result["configured"] is False
    assert result["sent"] is False
    assert "not configured" in result["reason"]


def test_email_never_leaks_a_password():
    cfg = EmailConfig(host="127.0.0.1", port=1, user="u", password="super-secret",
                      sender="u@example.com")
    result = send_email("s", "b", config=cfg, timeout=1)
    assert result["sent"] is False
    assert "super-secret" not in json.dumps(result)


# --------------------------------------------------------------------------- #
# Verified source (Sourcify)
# --------------------------------------------------------------------------- #

class _StaticFetcher:
    def __init__(self, *, ok: bool, status: int = 200, body: bytes = b"") -> None:
        self.ok, self.status, self.body = ok, status, body
        self.urls: list[str] = []

    def fetch(self, url: str, **_kwargs) -> FetchResult:
        self.urls.append(url)
        return FetchResult(url=url, ok=self.ok, status=self.status, body=self.body,
                           error="" if self.ok else f"HTTP {self.status}")


def test_source_client_parses_a_verified_bundle():
    payload = {
        "sources": {"src/Vault.sol": {"content": "contract Vault {}"}},
        "compilation": {"compiler": "solc", "compilerVersion": "0.8.24+commit.e11b9ed9"},
        "match": "exact_match",
        "verifiedAt": "2026-11-21T00:00:00Z",
    }
    client = SourceClient(fetcher=_StaticFetcher(ok=True, body=json.dumps(payload).encode()))
    bundle = client.fetch(1, "0xAbC0000000000000000000000000000000000001")
    assert bundle.ok and bundle.status == "verified"
    assert bundle.files == {"src/Vault.sol": "contract Vault {}"}
    assert bundle.compiler_version.startswith("0.8.24")
    record = bundle.record()
    assert record["address"] == "0xabc0000000000000000000000000000000000001"
    assert record["files"] == 1 and record["fingerprint"]
    assert "content" not in json.dumps(record)


def test_source_client_treats_404_as_not_verified():
    client = SourceClient(fetcher=_StaticFetcher(ok=False, status=404))
    bundle = client.fetch(1, "0x" + "00" * 20)
    assert bundle.ok is False and bundle.status == "not_verified"


def test_source_diff_names_changed_files_and_functions():
    old = SourceBundle(chain_id=1, address="0x" + "11" * 20, ok=True, status="verified",
                       files={"src/Vault.sol": "function withdraw() {}\nfunction ping() {}\n",
                              "src/Gone.sol": "contract Gone {}\n"})
    new = SourceBundle(chain_id=1, address="0x" + "44" * 20, ok=True, status="verified",
                       files={"src/Vault.sol": "function withdraw() { require(false); }\nfunction ping() {}\n",
                              "src/New.sol": "contract New {}\n"})
    diff = diff_bundles(old, new)
    assert diff.files_modified == ["src/Vault.sol"]
    assert diff.files_added == ["src/New.sol"]
    assert diff.files_removed == ["src/Gone.sol"]
    assert "withdraw" in diff.functions
    assert "withdraw" in diff.sensitive_functions
    assert "src/Vault.sol" in diff.unified and diff.empty is False


def test_deployment_change_carries_a_verified_source_diff(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    source = _FakeSource({
        IMPL_A: {"src/Vault.sol": "contract Vault { function withdraw() {} }\n"},
        IMPL_B: {"src/Vault.sol": "contract Vault { function withdraw() { revert(); } }\n"},
    })
    _run(server, targets, cfg, source=source)
    assert source.calls == [(1, IMPL_A.lower())]

    server.state["impl_addr"] = IMPL_B
    server.state["impls"][IMPL_B.lower()] = "0x6004600055"
    report = _run(server, targets, cfg, source=source)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    change = next(e for e in blocked.events if e.kind == Kind.CONTRACT_IMPL)
    delta = change.detail["source_diff"]
    assert delta["files_modified"] == ["src/Vault.sol"]
    assert "withdraw" in delta["sensitive_functions"]
    assert delta["address_old"] == IMPL_A.lower() and delta["address_new"] == IMPL_B.lower()
    diff_file = Path(delta["diff_path"])
    assert diff_file.is_file() and "withdraw" in diff_file.read_text()
    # The old implementation is fetched too, so the diff is real text.
    assert (1, IMPL_A.lower()) in source.calls[1:]
    lead = next(l for l in blocked.leads if l.event.kind == Kind.CONTRACT_IMPL)
    record = render_investigation(lead)
    assert "Verified source delta" in record and "withdraw" in record


def test_source_diff_names_added_external_calls():
    old = SourceBundle(
        chain_id=1, address="0x" + "aa" * 20, ok=True, status="verified",
        files={"src/Vault.sol": "contract Vault { function f() external {} }\n"},
    )
    new = SourceBundle(
        chain_id=1, address="0x" + "bb" * 20, ok=True, status="verified",
        files={
            "src/Vault.sol": (
                "contract Vault { function f() external { token.transfer(to, 1); } }\n"
            )
        },
    )
    delta = diff_bundles(old, new)
    assert any("token.transfer" in line for line in delta.external_calls)
    assert delta.to_dict()["external_calls"] == delta.external_calls


def test_source_absent_is_a_gap_not_a_failure_or_a_change(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    source = _FakeSource({})
    report = _run(server, targets, cfg, source=source)
    blocked = next(t for t in report.targets if t.target.slug == "blocked")
    assert blocked.failures == []
    assert [e for e in blocked.events if e.kind in CONTRACT_KINDS] == []
    assert blocked.contracts[0]["source"]["status"] == "not_verified"


def test_source_is_not_refetched_when_nothing_moved(server, tmp_path):
    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    source = _FakeSource({IMPL_A: {"src/Vault.sol": "contract Vault {}\n"}})
    _run(server, targets, cfg, source=source)
    assert len(source.calls) == 1
    _run(server, targets, cfg, source=source)
    _run(server, targets, cfg, source=source)
    assert len(source.calls) == 1


def test_source_transient_error_is_retried_without_a_false_diff(server, tmp_path):
    class _Flaky(_FakeSource):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.fail = True

        def fetch(self, chain_id, address):
            if self.fail:
                self.calls.append((chain_id, address.lower()))
                return SourceBundle(
                    chain_id=chain_id, address=address.lower(), status="error",
                    error="timeout",
                )
            return super().fetch(chain_id, address)

    targets = _targets(_base(server))
    cfg = _config(tmp_path)
    source = _Flaky({IMPL_A: {"src/Vault.sol": "contract Vault {}\n"}})
    first = _run(server, targets, cfg, source=source)
    blocked = next(t for t in first.targets if t.target.slug == "blocked")
    assert any(g.startswith("verified source unavailable") for g in blocked.gaps)
    assert blocked.contracts[0]["source"]["status"] == "error"

    source.fail = False
    second = _run(server, targets, cfg, source=source)
    blocked = next(t for t in second.targets if t.target.slug == "blocked")
    assert [e for e in blocked.events if e.kind in CONTRACT_KINDS] == []
    assert blocked.contracts[0]["source"]["status"] == "verified"
    assert len(source.calls) == 2


# --------------------------------------------------------------------------- #
# Real public sources (excluded by default)
# --------------------------------------------------------------------------- #

def test_hourly_workflow_is_guarded_and_runs_the_real_cycle():
    yaml = pytest.importorskip("yaml")
    root = Path(__file__).resolve().parents[1]
    path = root / ".github/workflows/bounty-watch.yml"
    d = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert d[True]["schedule"] == [{"cron": "7 * * * *"}]
    assert d["permissions"] == {"contents": "read", "issues": "write"}
    assert d["concurrency"] == {"group": "bounty-watch", "cancel-in-progress": False}
    steps = d["jobs"]["watch"]["steps"]
    names = [s.get("name") for s in steps]
    assert "Restore durable monitoring state" in names
    assert "Save durable monitoring state" in names
    assert "Publish deduplicated issues" in names
    assert "Fail only on a total outage" in names
    cycle = next(s for s in steps if s.get("id") == "cycle")
    assert "python3 -m blackheart watch cycle" in cycle["run"]
    assert "pip install" not in path.read_text(encoding="utf-8")
    assert "eth_sendRawTransaction" not in path.read_text(encoding="utf-8")
    publish = next(s for s in steps if s.get("name") == "Publish deduplicated issues")
    assert "bounty-watch-hash" in publish["run"]
    assert "source gaps" in publish["run"]
    # The embedded Python must at least compile.
    import re
    for block in re.findall(r"python3 - <<'PY'\n(.*?)\n\s*PY", path.read_text(encoding="utf-8"), re.S):
        compile("\n".join(line[10:] if line.startswith(" " * 10) else line
                          for line in block.splitlines()), "<workflow>", "exec")


def test_automation_wrapper_exists_and_is_zero_dependency():
    root = Path(__file__).resolve().parents[1]
    plugin = json.loads((root / "automations/bounty-watch/.plugin/plugin.json").read_text())
    assert plugin["automation"]["suggested_trigger"]["schedule"] == "7 * * * *"
    assert plugin["automation"]["suggested_trigger"]["timezone"] == "UTC"
    main = (root / "automations/bounty-watch/main.py").read_text()
    assert "run_cycle" in main
    assert "kv_get" in main and "kv_set" in main
    assert "eth_sendRawTransaction" not in main


@pytest.mark.network
def test_real_public_sources_smoke():
    targets = load_registry()
    lido = next(t for t in targets if t.slug == "lido")
    res = HttpFetcher(timeout=25, retries=1).fetch(lido.policy_urls[0].url)
    assert res.ok and res.text_sha256
    repo = GitHubClient(timeout=25, retries=1).repo(lido.repos[0].repo)
    assert repo.ok
    obs = RpcClient(timeout=25).observe(lido.contracts[0])
    assert obs.ok and obs.fingerprint
    assert obs.chain_id == 1


def test_unknown_chain_is_a_gap_not_an_observation_on_mainnet(monkeypatch):
    """A chain with no endpoint must not be answered by another chain's node."""
    import blackheart.rpc as rpcmod

    monkeypatch.setattr(rpcmod, "resolve_rpc",
                        lambda *a, **k: rpcmod.RpcResolution(error="none"))
    assert rpc_for_chain(999999) == ""

    ref = ContractRef(key="x", chain_id=999999, address="0x" + "11" * 20, name="X")
    obs = RpcClient().observe(ref)
    assert obs.ok is False
    assert obs.error_kind != "ok"
    assert "no RPC endpoint resolved for chain 999999" in obs.error
    assert obs.fingerprint == ""
