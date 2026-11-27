"""Read-only fetch clients for the bounty watchtower.

Three sources, one discipline: an unreachable or unparseable source is recorded
as a *gap*, never as "no change". Nothing here writes to a chain, a repository,
or a program. Every request is a GET or a read-only JSON-RPC call.

* :class:`HttpFetcher` -- official policy pages. HTML is normalised to visible
  text before hashing, because SPA pages carry a new build id on every load while
  their *content* is unchanged.
* :class:`GitHubClient` -- repository metadata, releases, tags, HEAD commits and
  the compare API. A commit is a code change, **not** a deployment.
* :class:`RpcClient` -- runtime bytecode, proxy implementation/admin slots and
  ``owner()``. The bytecode fingerprint is the ground truth for "did the deployed
  code change".
"""

from __future__ import annotations

import gzip
import hashlib
import html as html_mod
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

from ..deployed import (
    ChainClient,
    RpcUnavailable,
    keccak256,
    verify_contract,
)
from ..models import utcnow
from .registry import ContractRef

__all__ = [
    "USER_AGENT",
    "ErrorKind",
    "FetchResult",
    "GitHubResult",
    "ContractObservation",
    "HttpFetcher",
    "GitHubClient",
    "RpcClient",
    "normalize_html",
    "page_title",
    "RPC_BY_CHAIN",
    "rpc_for_chain",
]

USER_AGENT = "blackheart-bounty-watch/1.0 (+https://github.com/itzebe/blackheart)"

#: Free, no-key public endpoints. An operator override always wins.
RPC_BY_CHAIN: dict[int, str] = {
    1: "https://gateway.tenderly.co/public/mainnet",
    10: "https://mainnet.optimism.io",
    56: "https://bsc-dataseed.binance.org",
    137: "https://polygon-rpc.com",
    8453: "https://mainnet.base.org",
    42161: "https://arb1.arbitrum.io/rpc",
    59144: "https://rpc.linea.build",
}


class ErrorKind:
    OK = "ok"
    HTTP = "http"
    NOT_MODIFIED = "not_modified"
    TIMEOUT = "timeout"
    DNS = "dns"
    TLS = "tls"
    NETWORK = "network"
    TOO_LARGE = "too_large"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    PARSE = "parse"
    CHAIN_MISMATCH = "chain_mismatch"


@dataclass
class FetchResult:
    url: str
    ok: bool = False
    status: int = 0
    final_url: str = ""
    error: str = ""
    error_kind: str = ErrorKind.NETWORK
    title: str = ""
    text: str = ""
    text_sha256: str = ""
    raw_sha256: str = ""
    bytes: int = 0
    # Raw response body, kept for callers that need the exact bytes (JSON source
    # bundles must not go through the HTML text normaliser).
    body: bytes = b""
    etag: str = ""
    last_modified: str = ""
    not_modified: bool = False
    retrieved_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "ok": self.ok,
            "status": self.status,
            "final_url": self.final_url,
            "error": self.error,
            "error_kind": self.error_kind,
            "title": self.title,
            "text_sha256": self.text_sha256,
            "raw_sha256": self.raw_sha256,
            "bytes": self.bytes,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "not_modified": self.not_modified,
            "retrieved_at": self.retrieved_at,
        }


@dataclass
class GitHubResult:
    path: str
    ok: bool = False
    status: int = 0
    data: Any = None
    error: str = ""
    error_kind: str = ErrorKind.NETWORK
    etag: str = ""
    not_modified: bool = False
    remaining: Optional[int] = None
    reset: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "ok": self.ok,
            "status": self.status,
            "error": self.error,
            "error_kind": self.error_kind,
            "remaining": self.remaining,
            "reset": self.reset,
        }


@dataclass
class ContractObservation:
    key: str
    name: str
    chain_id: int
    expected_chain_id: int
    address: str
    ok: bool = False
    verified: bool = False
    block_number: Optional[int] = None
    proxy: bool = False
    proxy_kind: str = ""
    implementation: str = ""
    admin: str = ""
    beacon: str = ""
    owner: str = ""
    code_size: int = 0
    code_keccak256: str = ""
    implementation_code_keccak256: str = ""
    fingerprint: str = ""
    rpc_url: str = ""
    error: str = ""
    error_kind: str = ErrorKind.OK
    limitations: list[str] = field(default_factory=list)
    retrieved_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "chain_id": self.chain_id,
            "expected_chain_id": self.expected_chain_id,
            "address": self.address,
            "ok": self.ok,
            "verified": self.verified,
            "block_number": self.block_number,
            "proxy": self.proxy,
            "proxy_kind": self.proxy_kind,
            "implementation": self.implementation,
            "admin": self.admin,
            "beacon": self.beacon,
            "owner": self.owner,
            "code_size": self.code_size,
            "code_keccak256": self.code_keccak256,
            "implementation_code_keccak256": self.implementation_code_keccak256,
            "fingerprint": self.fingerprint,
            "rpc_url": self.rpc_url,
            "error": self.error,
            "error_kind": self.error_kind,
            "limitations": list(self.limitations),
            "retrieved_at": self.retrieved_at,
        }


# --------------------------------------------------------------------------- #
# HTML -> stable text
# --------------------------------------------------------------------------- #

_SCRIPT_RE = re.compile(r"<(script|style|noscript|svg|template)\b.*?</\1>", re.S | re.I)
_TAG_RE = re.compile(r"<[^>]+>")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_OG_TITLE_RE = re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']*)', re.I)
_OG_TITLE_RE2 = re.compile(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']og:title["\']', re.I)
_WS_RE = re.compile(r"\s+")


def normalize_html(body: bytes) -> str:
    """Visible text of an HTML page, stripped of volatile scripts/styles."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    text = _SCRIPT_RE.sub(" ", text)
    text = _TAG_RE.sub(" ", text)
    text = html_mod.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def page_title(body: bytes) -> str:
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    for pattern in (_OG_TITLE_RE, _OG_TITLE_RE2, _TITLE_RE):
        m = pattern.search(text)
        if m:
            return _WS_RE.sub(" ", html_mod.unescape(m.group(1))).strip()[:300]
    return ""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

class HttpFetcher:
    """Polite, bounded HTTP GET with retries and conditional requests."""

    def __init__(
        self,
        *,
        timeout: int = 25,
        max_bytes: int = 1_500_000,
        retries: int = 2,
        user_agent: str = USER_AGENT,
        sleep=time.sleep,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.retries = max(0, retries)
        self.user_agent = user_agent
        self._sleep = sleep

    def fetch(
        self,
        url: str,
        *,
        etag: str = "",
        last_modified: str = "",
        accept: str = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    ) -> FetchResult:
        result = FetchResult(url=url, final_url=url)
        headers = {"User-Agent": self.user_agent, "Accept": accept}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        last_error = ""
        last_kind = ErrorKind.NETWORK
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    result.status = resp.status
                    result.final_url = resp.geturl()
                    result.etag = resp.headers.get("ETag", "") or ""
                    result.last_modified = resp.headers.get("Last-Modified", "") or ""
                    if resp.status == 304:
                        result.ok = True
                        result.not_modified = True
                        result.error_kind = ErrorKind.NOT_MODIFIED
                        return result
                    body = resp.read(self.max_bytes + 1)
                    if len(body) > self.max_bytes:
                        result.error = f"body exceeds {self.max_bytes} bytes"
                        result.error_kind = ErrorKind.TOO_LARGE
                        return result
                    if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                        try:
                            body = gzip.decompress(body)
                        except OSError:
                            pass
                    result.bytes = len(body)
                    result.body = body
                    result.raw_sha256 = _sha256_hex(body)
                    result.text = normalize_html(body)
                    result.text_sha256 = _sha256_hex(result.text.encode("utf-8"))
                    result.title = page_title(body)
                    result.ok = True
                    result.error_kind = ErrorKind.OK
                    return result
            except urllib.error.HTTPError as exc:
                result.status = exc.code
                if exc.code == 304:
                    result.ok = True
                    result.not_modified = True
                    result.error_kind = ErrorKind.NOT_MODIFIED
                    return result
                if exc.code == 429:
                    last_kind = ErrorKind.RATE_LIMITED
                elif exc.code in (401, 403):
                    last_kind = ErrorKind.BLOCKED
                else:
                    last_kind = ErrorKind.HTTP
                last_error = f"HTTP {exc.code}"
                if exc.code not in (429, 500, 502, 503, 504):
                    break
                retry_after = exc.headers.get("Retry-After", "") if exc.headers else ""
                delay = _retry_delay(retry_after, attempt)
            except urllib.error.URLError as exc:
                reason = exc.reason
                if isinstance(reason, socket.timeout):
                    last_kind = ErrorKind.TIMEOUT
                elif isinstance(reason, socket.gaierror):
                    last_kind = ErrorKind.DNS
                elif isinstance(reason, ssl.SSLError):
                    last_kind = ErrorKind.TLS
                else:
                    last_kind = ErrorKind.NETWORK
                last_error = f"{type(reason).__name__}: {reason}"
                delay = _retry_delay("", attempt)
            except (TimeoutError, socket.timeout):
                last_kind = ErrorKind.TIMEOUT
                last_error = "timeout"
                delay = _retry_delay("", attempt)
            except Exception as exc:  # noqa: BLE001 -- record, never crash the cycle
                last_kind = ErrorKind.NETWORK
                last_error = f"{type(exc).__name__}: {exc}"
                delay = _retry_delay("", attempt)
            if attempt < self.retries:
                self._sleep(delay)
        result.error = last_error or "fetch failed"
        result.error_kind = last_kind
        return result


def _retry_delay(retry_after: str, attempt: int) -> float:
    try:
        return min(10.0, max(0.0, float(retry_after)))
    except (TypeError, ValueError):
        return min(4.0, 0.5 * (2 ** attempt))


# --------------------------------------------------------------------------- #
# GitHub
# --------------------------------------------------------------------------- #

class GitHubClient:
    """Minimal read-only GitHub REST client with ETag and rate-limit handling."""

    def __init__(
        self,
        token: Optional[str] = None,
        *,
        base_url: str = "https://api.github.com",
        timeout: int = 25,
        retries: int = 2,
        sleep=time.sleep,
    ) -> None:
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = max(0, retries)
        self._sleep = sleep

    def get(self, path: str, *, etag: str = "") -> GitHubResult:
        url = path if path.startswith("http") else f"{self.base_url}/{path.lstrip('/')}"
        result = GitHubResult(path=path)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if etag:
            headers["If-None-Match"] = etag

        last_error = ""
        last_kind = ErrorKind.NETWORK
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    result.status = resp.status
                    result.etag = resp.headers.get("ETag", "") or ""
                    result.remaining = _int_or_none(resp.headers.get("X-RateLimit-Remaining"))
                    result.reset = _int_or_none(resp.headers.get("X-RateLimit-Reset"))
                    if resp.status == 304:
                        result.ok = True
                        result.not_modified = True
                        result.error_kind = ErrorKind.NOT_MODIFIED
                        return result
                    body = resp.read()
                    result.data = json.loads(body.decode("utf-8")) if body else None
                    result.ok = True
                    result.error_kind = ErrorKind.OK
                    return result
            except urllib.error.HTTPError as exc:
                result.status = exc.code
                result.remaining = _int_or_none(exc.headers.get("X-RateLimit-Remaining") if exc.headers else None)
                result.reset = _int_or_none(exc.headers.get("X-RateLimit-Reset") if exc.headers else None)
                if exc.code == 404:
                    result.error_kind = ErrorKind.HTTP
                    result.error = "HTTP 404"
                    return result
                if exc.code == 304:
                    result.ok = True
                    result.not_modified = True
                    result.error_kind = ErrorKind.NOT_MODIFIED
                    return result
                if exc.code == 403 and (result.remaining == 0):
                    result.error_kind = ErrorKind.RATE_LIMITED
                    result.error = (
                        f"GitHub rate limit exhausted; resets at {result.reset}"
                    )
                    return result
                if exc.code in (401, 403):
                    result.error_kind = ErrorKind.BLOCKED
                    result.error = f"HTTP {exc.code} (token missing/invalid or blocked)"
                    return result
                last_kind = ErrorKind.HTTP
                last_error = f"HTTP {exc.code}"
                if exc.code not in (500, 502, 503, 504):
                    break
                delay = _retry_delay(exc.headers.get("Retry-After", "") if exc.headers else "", attempt)
            except (TimeoutError, socket.timeout):
                last_kind = ErrorKind.TIMEOUT
                last_error = "timeout"
                delay = _retry_delay("", attempt)
            except urllib.error.URLError as exc:
                last_kind = ErrorKind.NETWORK
                last_error = f"{type(exc.reason).__name__}: {exc.reason}"
                delay = _retry_delay("", attempt)
            except Exception as exc:  # noqa: BLE001
                last_kind = ErrorKind.PARSE
                last_error = f"{type(exc).__name__}: {exc}"
                delay = _retry_delay("", attempt)
            if attempt < self.retries:
                self._sleep(delay)
        result.error = last_error or "GitHub request failed"
        result.error_kind = last_kind
        return result

    # -- typed helpers ----------------------------------------------------- #
    def repo(self, repo: str, *, etag: str = "") -> GitHubResult:
        return self.get(f"/repos/{repo}", etag=etag)

    def latest_release(self, repo: str, *, etag: str = "") -> GitHubResult:
        return self.get(f"/repos/{repo}/releases/latest", etag=etag)

    def tags(self, repo: str, *, limit: int = 5, etag: str = "") -> GitHubResult:
        return self.get(f"/repos/{repo}/tags?per_page={limit}", etag=etag)

    def head_commit(self, repo: str, branch: str, *, etag: str = "") -> GitHubResult:
        return self.get(
            f"/repos/{repo}/commits?sha={branch}&per_page=1", etag=etag
        )

    def compare(self, repo: str, base: str, head: str) -> GitHubResult:
        return self.get(f"/repos/{repo}/compare/{base}...{head}")


def _int_or_none(value: Any) -> Optional[int]:
    try:
        return int(value) if value is not None and str(value) != "" else None
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# RPC
# --------------------------------------------------------------------------- #

def rpc_for_chain(chain_id: int, override: Optional[str] = None) -> str:
    """An RPC endpoint for ``chain_id``: operator override, env, map, registry.

    Returns ``""`` when no endpoint can be resolved. It never substitutes another
    chain's endpoint: an observation attributed to the wrong chain is worse than a
    recorded gap.
    """
    if override:
        return override
    env = os.environ.get("BLACKHEART_ETH_RPC", "")
    if env and chain_id == 1:
        return env
    if chain_id in RPC_BY_CHAIN:
        return RPC_BY_CHAIN[chain_id]
    from ..rpc import resolve_rpc

    res = resolve_rpc(chain_id, use_search=False, timeout=10)
    return res.url if res.ok else ""


def _hex_code_keccak(code: str) -> str:
    raw = code[2:] if isinstance(code, str) and code.startswith("0x") else (code or "")
    try:
        return "0x" + keccak256(bytes.fromhex(raw)).hex()
    except ValueError:
        return ""


class RpcClient:
    """Read-only EVM observation with honest failure states."""

    def __init__(self, *, timeout: int = 20, overrides: Optional[dict[int, str]] = None) -> None:
        self.timeout = timeout
        self.overrides = dict(overrides or {})

    def observe(self, contract: ContractRef, *, rpc_url: Optional[str] = None) -> ContractObservation:
        url = rpc_url or rpc_for_chain(contract.chain_id, self.overrides.get(contract.chain_id))
        obs = ContractObservation(
            key=contract.key,
            name=contract.name,
            chain_id=contract.chain_id,
            expected_chain_id=contract.chain_id,
            address=contract.address,
            rpc_url=url,
        )
        if not url:
            obs.error = f"no RPC endpoint resolved for chain {contract.chain_id}"
            obs.error_kind = ErrorKind.NETWORK
            return obs
        try:
            client = ChainClient(url, timeout=self.timeout)
            facts = verify_contract(
                contract.address, url, detect_proxy=True, client=client
            )
        except RpcUnavailable as exc:
            obs.error = f"RPC unavailable: {exc}"
            obs.error_kind = ErrorKind.NETWORK
            return obs
        except Exception as exc:  # noqa: BLE001 -- a gap, not a crash
            obs.error = f"{type(exc).__name__}: {exc}"
            obs.error_kind = ErrorKind.NETWORK
            return obs

        obs.verified = facts.verified
        obs.block_number = facts.block_number
        obs.proxy = facts.proxy
        obs.proxy_kind = facts.proxy_kind
        obs.implementation = facts.implementation
        obs.admin = facts.admin
        obs.beacon = facts.beacon
        obs.code_size = facts.code_size
        obs.limitations = list(facts.limitations)
        if facts.chain_id is not None and facts.chain_id != contract.chain_id:
            obs.error = (
                f"RPC returned chain_id {facts.chain_id}, expected {contract.chain_id}"
            )
            obs.error_kind = ErrorKind.CHAIN_MISMATCH
            return obs
        obs.chain_id = facts.chain_id if facts.chain_id is not None else contract.chain_id
        if not facts.verified:
            obs.error = "; ".join(facts.limitations) or "address holds no runtime code"
            obs.error_kind = ErrorKind.HTTP
            return obs

        obs.code_keccak256 = _hex_code_keccak(facts.code)
        if facts.proxy and facts.implementation:
            try:
                impl_code = client.call("eth_getCode", [facts.implementation, "latest"])
                obs.implementation_code_keccak256 = _hex_code_keccak(impl_code)
            except RpcUnavailable as exc:
                obs.limitations.append(f"implementation code unread: {exc}")
        obs.owner = _read_owner(client, contract.address)
        obs.fingerprint = (
            obs.implementation_code_keccak256
            if obs.proxy and obs.implementation_code_keccak256
            else obs.code_keccak256
        )
        obs.ok = bool(obs.fingerprint)
        obs.error_kind = ErrorKind.OK if obs.ok else ErrorKind.HTTP
        if not obs.ok:
            obs.error = "no executable code fingerprint could be read"
        return obs


def _read_owner(client: ChainClient, address: str) -> str:
    """Best-effort ``owner()`` read. Reverts/unsupported selectors are empty."""
    try:
        out = client.call(
            "eth_call",
            [{"to": address, "data": "0x8da5cb5b"}, "latest"],
        )
    except RpcUnavailable:
        return ""
    if not isinstance(out, str) or not out.startswith("0x"):
        return ""
    raw = out[2:]
    if len(raw) < 40:
        return ""
    candidate = "0x" + raw[-40:]
    if int(candidate, 16) == 0:
        return ""
    return candidate
