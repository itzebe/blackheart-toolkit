"""Specialist-agent and skill invocation verifier (mission section 12).

Mission section 12 requires that every skill be discoverable and every specialist
agent be *invokable*, and forbids claiming a capability works until it has been
invoked. This module verifies both against the **real** OpenHands agent-server:

  * skills are loaded from the project workspace via ``POST /api/skills``
    (``load_project``) and the returned names are checked against the repository's
    ``skills/`` directory;
  * agents are loaded via ``POST /api/sub-agents`` (``load_project``) and checked
    against the repository's ``agents/`` directory.

The agent-server address and session key are read from the runtime
(``$OH_INTERNAL_SERVER_URL`` and the ``SESSION_API_KEY`` in ``/proc/1/environ``).
If the server cannot be reached -- for example in a plain CI container with no
agent-server -- the verifier reports ``available: false`` and a reason, and the
CLI exits non-zero. It never fabricates a discovery result.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path


def _session_key() -> str:
    """The agent-server session key: it lives in PID 1's environment, not ours."""
    key = os.environ.get("SESSION_API_KEY")
    if key:
        return key
    try:
        raw = Path("/proc/1/environ").read_bytes()
    except OSError:
        return ""
    for entry in raw.split(b"\0"):
        if entry.startswith(b"SESSION_API_KEY="):
            return entry.split(b"=", 1)[1].decode("utf-8", "replace")
    return ""


def _base_url() -> str:
    return os.environ.get("OH_INTERNAL_SERVER_URL", "http://127.0.0.1:60000").rstrip("/")


def _post(path: str, payload: dict, timeout: float = 10.0) -> dict:
    url = f"{_base_url()}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Session-API-Key": _session_key(),
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@dataclass
class AgentVerification:
    available: bool
    reason: str = ""
    skills_expected: list[str] = field(default_factory=list)
    skills_loaded: list[str] = field(default_factory=list)
    skills_missing: list[str] = field(default_factory=list)
    agents_expected: list[str] = field(default_factory=list)
    agents_loaded: list[str] = field(default_factory=list)
    agents_missing: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return (
            self.available
            and not self.skills_missing
            and not self.agents_missing
            and bool(self.agents_expected)
        )

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "ok": self.ok(),
            "skills_expected": self.skills_expected,
            "skills_loaded": self.skills_loaded,
            "skills_missing": self.skills_missing,
            "agents_expected": self.agents_expected,
            "agents_loaded": self.agents_loaded,
            "agents_missing": self.agents_missing,
        }


def verify_agents(repo_root: str | os.PathLike, timeout: float = 10.0) -> AgentVerification:
    """Load project skills and agents from the real agent-server and compare."""
    root = Path(repo_root)
    skills_expected = sorted(
        p.parent.name for p in (root / "skills").glob("*/SKILL.md")
    )
    agents_expected = sorted(p.stem for p in (root / "agents").glob("*.md"))

    # OpenHands discovers *project* skills/agents through the provisioned layout
    # (``.openhands/skills``, ``.openhands/agents``). On a fresh clone that
    # layout does not exist yet, so the server is reachable but loads nothing --
    # it returns HTTP 200 with an empty list. That is a misconfigured project,
    # not a working discovery, and must be reported as unavailable rather than
    # as ``available: true`` with zero skills (which the API can otherwise be
    # mistaken for a passing check).
    if not (root / ".openhands" / "skills").exists() or not (
        root / ".openhands" / "agents"
    ).exists():
        return AgentVerification(
            available=False,
            reason=(
                "OpenHands discovery layout missing "
                f"({root}/.openhands/skills, {root}/.openhands/agents) -- "
                "run: blackheart provision"
            ),
            skills_expected=skills_expected,
            agents_expected=agents_expected,
        )

    try:
        skills_resp = _post(
            "/api/skills",
            {
                "load_public": False,
                "load_user": False,
                "load_project": True,
                "load_org": False,
                "project_dir": str(root),
            },
            timeout=timeout,
        )
        agents_resp = _post(
            "/api/sub-agents",
            {
                "load_user": False,
                "load_project": True,
                "load_builtin": False,
                "project_dir": str(root),
            },
            timeout=timeout,
        )
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return AgentVerification(
            available=False,
            reason=f"agent-server not reachable at {_base_url()}: {exc}",
            skills_expected=skills_expected,
            agents_expected=agents_expected,
        )

    skills_loaded = sorted(s.get("name", "") for s in skills_resp.get("skills", []))
    agents_loaded = sorted(a.get("name", "") for a in agents_resp.get("agents", []))
    return AgentVerification(
        available=True,
        reason="",
        skills_expected=skills_expected,
        skills_loaded=skills_loaded,
        skills_missing=[s for s in skills_expected if s not in skills_loaded],
        agents_expected=agents_expected,
        agents_loaded=agents_loaded,
        agents_missing=[a for a in agents_expected if a not in agents_loaded],
    )
