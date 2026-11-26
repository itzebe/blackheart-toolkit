"""Verified commit pins for the historical corpus.

The corpus names a real repository for each case. A repository name alone is a
weak reference: it moves. A *pin* -- a commit SHA -- is what makes a case
reproducible and what makes the claim "this is a real, publicly-disclosed
vulnerability" checkable by a third party. The corpus therefore carries a
``pin``/``pin_verified`` pair, and this module is the thing that can actually
*verify* a pin rather than assert it.

Two levels of verification, both honest about what they prove:

  * :func:`verify_pin` asks GitHub whether the SHA exists in the named repository.
    It proves the pin is *real and resolvable*, nothing more -- not that the
    repository contains the vulnerable code, and not that the pin predates the
    fix.
  * :func:`resolve_tag` turns a release tag into its commit SHA (dereferencing an
    annotated tag), so a pin can be recorded from a human-meaningful tag.

Network access is optional and explicit: with no network, :func:`verify_pin`
returns ``unknown`` rather than a fabricated success. The pins below were
resolved against the live GitHub API and are recorded with the resolution date;
they are re-verifiable, not trusted.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from typing import Optional

_GITHUB = "https://api.github.com"
_UA = "blackheart-pin-verifier"


@dataclass(frozen=True)
class Pin:
    """A repository and the commit that anchors a corpus case."""

    repository: str
    sha: str
    ref: str = ""            # the tag/branch the SHA was resolved from, if any
    resolved: str = ""       # ISO date the pin was recorded

    def to_dict(self) -> dict:
        return {"repository": self.repository, "sha": self.sha,
                "ref": self.ref, "resolved": self.resolved}


# Pins resolved against the live GitHub API (recorded 2026-11-18). Each is a
# real, resolvable commit; ``verify_pin`` re-checks existence on demand. Where a
# repository publishes releases the pin is a release tag's commit; otherwise it
# is the default-branch head at the recorded date.
PINS: dict[str, Pin] = {
    "OpenZeppelin/openzeppelin-contracts": Pin(
        "OpenZeppelin/openzeppelin-contracts",
        "cab19933c33c2ad1d4c7a84864a3601dddfd16f3", ref="v5.7.0", resolved="2026-11-18"),
    "aave/aave-v3-core": Pin(
        "aave/aave-v3-core",
        "b74526a7bc67a3a117a1963fc871b3eb8cea8435", ref="v1.19.4", resolved="2026-11-18"),
    "compound-finance/compound-protocol": Pin(
        "compound-finance/compound-protocol",
        "23eac9425accafb82551777c93896ee7678a85a3", ref="v2.8.1", resolved="2026-11-18"),
    "paritytech/parity-signer": Pin(
        "paritytech/parity-signer",
        "3c46e7dd6bd1bbbf768a6d5304e8a4711dd34760", ref="v7.2.0", resolved="2026-11-18"),
    "Uniswap/v2-core": Pin(
        "Uniswap/v2-core",
        "6a9e7c97860676e0992f22a49665760444c1cdf5", ref="default-branch-head",
        resolved="2026-11-18"),
    "ethereum/EIPs": Pin(
        "ethereum/EIPs",
        "b055feec322fbc37e9d77a393a50b3ff56b31c92", ref="default-branch-head",
        resolved="2026-11-18"),
}

# A short alias table so a corpus case that names a repository gets its pin.
_ALIASES: dict[str, str] = {
    "OpenZeppelin/openzeppelin-contracts": "OpenZeppelin/openzeppelin-contracts",
    "aave/aave-v3-core": "aave/aave-v3-core",
    "compound-finance/compound-protocol": "compound-finance/compound-protocol",
    "paritytech/parity-signer": "paritytech/parity-signer",
    "Uniswap/v2-core": "Uniswap/v2-core",
    "ethereum/EIPs": "ethereum/EIPs",
}


def pin_for(repository: str) -> Optional[Pin]:
    if not repository:
        return None
    return PINS.get(_ALIASES.get(repository, repository))


def _get_json(url: str, *, timeout: int = 25) -> dict:
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def verify_pin(repository: str, sha: str, *, timeout: int = 25) -> str:
    """Return ``"verified"``, ``"missing"``, or ``"unknown"`` for a pin.

    ``verified`` means GitHub confirms the SHA exists as a commit in the named
    repository. ``unknown`` means the check could not be performed (no network, a
    rate limit, a non-2xx answer) -- never a fabricated success. Nothing here
    claims the pin contains the vulnerable code; that is a separate, human step.
    """
    if not repository or not sha:
        return "missing"
    try:
        _get_json(f"{_GITHUB}/repos/{repository}/commits/{sha}", timeout=timeout)
        return "verified"
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 422):
            return "missing"
        return "unknown"
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return "unknown"


def resolve_tag(repository: str, tag: str, *, timeout: int = 25) -> Optional[str]:
    """Resolve a tag to its commit SHA, dereferencing an annotated tag."""
    try:
        ref = _get_json(f"{_GITHUB}/repos/{repository}/git/ref/tags/{tag}", timeout=timeout)
        obj = ref["object"]
        if obj.get("type") == "tag":
            obj = _get_json(obj["url"], timeout=timeout)["object"]
        return obj["sha"]
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, TimeoutError,
            json.JSONDecodeError, OSError):
        return None


def verify_all(*, timeout: int = 25) -> dict:
    """Verify every recorded pin. Returns a report; ``unknown`` is not a failure."""
    results: dict[str, str] = {}
    for repo, pin in PINS.items():
        results[repo] = verify_pin(repo, pin.sha, timeout=timeout)
    verified = sum(1 for v in results.values() if v == "verified")
    return {
        "results": results,
        "verified": verified,
        "total": len(results),
        "checked_on": date.today().isoformat(),
        "note": "verified = the SHA exists in the repository; it does NOT assert the "
                "pin contains the vulnerable code",
    }
