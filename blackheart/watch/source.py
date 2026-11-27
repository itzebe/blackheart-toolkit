"""Verified-source capture and diffing for monitored deployments.

The watchtower's deployment evidence is the on-chain runtime fingerprint. This
module adds the next layer: when a deployment actually changes, fetch the
verified source for the *old* and *new* implementation addresses from Sourcify
(free, no API key) and diff them, so a lead carries the changed files, the
changed function names and a bounded unified diff instead of a promise to look
later.

It is deliberately bounded:

* the baseline fetch happens once per contract;
* an unchanged address is never re-fetched, because deployed code is immutable;
* a change costs two requests (old implementation, new implementation);
* the diff text is capped and only written when a deployment changed.

Sourcify absence is recorded as ``not_verified`` -- a gap, never a claim that
the source is unchanged.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from .fetch import ErrorKind, HttpFetcher

SOURCIFY_V2 = (
    "https://sourcify.dev/server/v2/contract/{chain}/{address}"
    "?fields=sources,compilation"
)

#: A single diff is capped so one large contract cannot bloat a cycle report.
MAX_DIFF_BYTES = 200_000
#: Added files are shown as a short head only; the manifest carries the rest.
MAX_ADDED_FILE_LINES = 80

_FUNCTION_RE = re.compile(
    r"\b(?:function|constructor|modifier|def|fn|func)\s+([A-Za-z_]\w*)"
)
_SENSITIVE_FUNCTION_RE = re.compile(
    r"(withdraw|deposit|mint|burn|transfer|claim|settle|refund|upgrade|initialize|"
    r"initializ|auth|owner|role|admin|oracle|price|fee|reward|stake|bridge|verify|"
    r"sign|replay|nonce|balance|account|liquidat|borrow|repay|swap|flash|permit|"
    r"approve|delegate|pause|unpause|rescue|sweep|emergency)",
    re.I,
)
#: Lines added by a diff that call out of the contract. A pointer for review,
#: not a finding: comments and strings can match.
_EXTERNAL_CALL_RE = re.compile(
    r"\.(?:safeTransferFrom|safeTransfer|safeApprove|transferFrom|transfer|"
    r"delegatecall|staticcall|call|send|approve|permit)\s*[({]"
)


@dataclass
class SourceBundle:
    """Verified source for one deployed address, as published by Sourcify."""

    chain_id: int
    address: str
    url: str = ""
    ok: bool = False
    status: str = "error"  # verified | not_verified | error
    files: dict[str, str] = field(default_factory=dict)
    match: str = ""
    compiler: str = ""
    compiler_version: str = ""
    verified_at: str = ""
    error: str = ""
    error_kind: str = ErrorKind.OK

    def manifest(self) -> dict[str, str]:
        """Per-file SHA-256, the stable identity of a verified source bundle."""
        return {
            path: hashlib.sha256(content.encode("utf-8")).hexdigest()
            for path, content in sorted(self.files.items())
        }

    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for path, sha in self.manifest().items():
            digest.update(path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(sha.encode("utf-8"))
            digest.update(b"\n")
        return digest.hexdigest()

    def record(self) -> dict:
        """Compact, secret-free state record (no source text is stored)."""
        return {
            "address": self.address.lower(),
            "status": self.status,
            "match": self.match,
            "compiler": self.compiler,
            "compiler_version": self.compiler_version,
            "verified_at": self.verified_at,
            "fingerprint": self.fingerprint() if self.ok else "",
            "manifest": self.manifest() if self.ok else {},
            "files": len(self.files),
            "url": self.url,
            "error": self.error,
        }


@dataclass
class SourceDiff:
    """The bounded delta between two verified source bundles."""

    address_old: str = ""
    address_new: str = ""
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    sensitive_functions: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    unified: str = ""
    truncated: bool = False
    url_old: str = ""
    url_new: str = ""

    @property
    def empty(self) -> bool:
        return not (self.files_added or self.files_removed or self.files_modified)

    def to_dict(self) -> dict:
        return {
            "address_old": self.address_old,
            "address_new": self.address_new,
            "files_added": list(self.files_added),
            "files_removed": list(self.files_removed),
            "files_modified": list(self.files_modified),
            "functions": list(self.functions),
            "sensitive_functions": list(self.sensitive_functions),
            "external_calls": list(self.external_calls),
            "unified": self.unified,
            "truncated": self.truncated,
            "url_old": self.url_old,
            "url_new": self.url_new,
        }


class SourceClient:
    """Sourcify v2 client with the same bounded, polite transport as the rest."""

    def __init__(
        self,
        *,
        fetcher: Optional[HttpFetcher] = None,
        timeout: int = 25,
        base: str = SOURCIFY_V2,
    ) -> None:
        self.fetcher = fetcher or HttpFetcher(timeout=timeout, retries=1)
        self.base = base

    def url(self, chain_id: int, address: str) -> str:
        return self.base.format(chain=chain_id, address=address)

    def fetch(self, chain_id: int, address: str) -> SourceBundle:
        url = self.url(chain_id, address)
        bundle = SourceBundle(chain_id=chain_id, address=address.lower(), url=url)
        result = self.fetcher.fetch(url, accept="application/json")
        if not result.ok:
            # 404/400 means "not verified here", which is a gap, not an outage.
            bundle.status = "not_verified" if result.status in (400, 404) else "error"
            bundle.error = result.error or f"HTTP {result.status}"
            bundle.error_kind = result.error_kind
            return bundle
        try:
            payload = json.loads(result.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            bundle.status = "error"
            bundle.error = f"unparseable JSON: {exc}"
            bundle.error_kind = ErrorKind.PARSE
            return bundle
        if not isinstance(payload, dict) or not payload.get("sources"):
            bundle.status = "not_verified"
            bundle.error = str(payload.get("error", ""))[:300] if isinstance(payload, dict) else ""
            return bundle

        sources = payload.get("sources") or {}
        for path, value in sources.items():
            if isinstance(value, dict) and isinstance(value.get("content"), str):
                bundle.files[str(path)] = value["content"]
        if not bundle.files:
            bundle.status = "not_verified"
            bundle.error = "no source content in the response"
            return bundle

        compilation = payload.get("compilation") or {}
        bundle.ok = True
        bundle.status = "verified"
        bundle.match = str(payload.get("match", ""))
        bundle.compiler = str(compilation.get("compiler", ""))
        bundle.compiler_version = str(compilation.get("compilerVersion", ""))
        bundle.verified_at = str(payload.get("verifiedAt", ""))
        return bundle


def _changed_functions(lines: list[str]) -> tuple[list[str], list[str]]:
    names: set[str] = set()
    for line in lines:
        if line.startswith(("+++", "---")):
            continue
        if not line.startswith(("+", "-")):
            continue
        for name in _FUNCTION_RE.findall(line):
            names.add(name)
    ordered = sorted(names)
    sensitive = [n for n in ordered if _SENSITIVE_FUNCTION_RE.search(n)]
    return ordered, sensitive


def diff_bundles(
    old: Optional[SourceBundle],
    new: SourceBundle,
    *,
    old_manifest: Optional[dict[str, str]] = None,
    max_bytes: int = MAX_DIFF_BYTES,
) -> SourceDiff:
    """Diff two verified bundles (or a manifest-only baseline) honestly.

    When the old source text is unavailable, only the file-level delta from the
    stored manifest is reported; the unified diff stays empty rather than
    inventing a delta.
    """
    diff = SourceDiff(
        address_old=(old.address if old else ""),
        address_new=new.address,
        url_old=(old.url if old else ""),
        url_new=new.url,
    )
    old_files = old.files if old and old.ok else {}
    old_hashes = (
        old.manifest() if old and old.ok else dict(old_manifest or {})
    )
    new_hashes = new.manifest()

    diff.files_added = sorted(set(new_hashes) - set(old_hashes))
    diff.files_removed = sorted(set(old_hashes) - set(new_hashes))
    diff.files_modified = sorted(
        p for p in set(old_hashes) & set(new_hashes) if old_hashes[p] != new_hashes[p]
    )

    chunks: list[str] = []
    used = 0
    changed_lines: list[str] = []
    for path in diff.files_modified:
        before = old_files.get(path)
        after = new.files.get(path)
        if before is None or after is None:
            continue
        lines = list(
            difflib.unified_diff(
                before.splitlines(),
                after.splitlines(),
                fromfile=f"{diff.address_old or 'previous'}:{path}",
                tofile=f"{diff.address_new}:{path}",
                lineterm="",
                n=3,
            )
        )
        changed_lines.extend(lines)
        text = "\n".join(lines) + "\n"
        if used + len(text) > max_bytes:
            diff.truncated = True
            break
        chunks.append(text)
        used += len(text)
    for path in diff.files_added:
        content = new.files.get(path, "")
        head = content.splitlines()[:MAX_ADDED_FILE_LINES]
        text = f"--- /dev/null\n+++ {diff.address_new}:{path}\n" + "\n".join(
            f"+{line}" for line in head
        )
        if len(head) < len(content.splitlines()):
            text += "\n+... (truncated)"
        text += "\n"
        if used + len(text) > max_bytes:
            diff.truncated = True
            break
        chunks.append(text)
        used += len(text)

    diff.unified = "\n".join(chunks)
    diff.functions, diff.sensitive_functions = _changed_functions(changed_lines)
    diff.external_calls = _added_external_calls(changed_lines)
    return diff


def _added_external_calls(lines: list[str], *, limit: int = 8) -> list[str]:
    out: list[str] = []
    for line in lines:
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = line[1:].strip()
        if _EXTERNAL_CALL_RE.search(body) and body not in out:
            out.append(body[:200])
    return out[:limit]
