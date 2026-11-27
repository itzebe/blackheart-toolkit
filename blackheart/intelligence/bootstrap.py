"""Project bootstrap for the external-intelligence capability.

The capability itself lives in the installed ``blackheart`` package, so *every*
project that has BLACKHEART installed can use it: ``blackheart intel route ...``
works from any directory. What a *project* additionally needs is discoverable
configuration so an agent working in that project sees the capability. This
module writes that configuration into a project's ``.openhands/`` directory:

  * ``.openhands/mcp.json`` -- the You.com MCP servers, in the OpenHands dialect.
    The API key is referenced as ``${YDC_API_KEY}``; the secret is **never**
    written. An existing ``mcp.json`` is merged, not clobbered.
  * ``.openhands/intelligence.env.example`` -- documents the canonical env var
    and the REST-vs-MCP auth difference. No secret is written.

Inheritance rules (mission requirement: a project override must not silently
disable the global capability):

  * The built-in providers are always present. A project config may **add**
    providers and may **disable** one only by listing it in ``disable`` together
    with a non-empty ``reason`` -- an explicit, auditable decision, not an
    accident. A disable entry with no reason is ignored.
  * Credentials are read from the runtime environment (or the host's secret
    store). Nothing here reads, writes, or logs a key value.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .mcp import openhands_mcp_config
from .youcom import KEY_ENV

#: The project config filename the registry reads (relative to the project root).
PROJECT_CONFIG_NAME = os.path.join(".openhands", "intelligence.json")

#: The env template written for the operator.
ENV_EXAMPLE_NAME = os.path.join(".openhands", "intelligence.env.example")

_ENV_EXAMPLE = f"""\
# BLACKHEART external intelligence -- environment template (no secrets here).
#
# The primary provider (best coverage) is You.com. Set the key in the runtime
# environment or the host's secret store; never commit it.
#
#   export {KEY_ENV}=...
#
# REST APIs (search/contents/research) authenticate with:
#     X-API-Key: <{KEY_ENV}>
# The hosted MCP server authenticates with:
#     Authorization: Bearer <{KEY_ENV}>
# These are different headers on different endpoints -- do not mix them.
#
# Keyless fallbacks need no configuration: duckduckgo, wikipedia.
#
# Verify:  blackheart intel providers --probe
# Setup:   blackheart intel setup
"""


@dataclass
class BootstrapResult:
    root: str
    mcp_path: str
    env_example_path: str
    mcp_written: bool
    env_example_written: bool
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root, "mcp_path": self.mcp_path,
            "env_example_path": self.env_example_path,
            "mcp_written": self.mcp_written,
            "env_example_written": self.env_example_written,
            "notes": self.notes,
        }


def _merge_mcp(existing: dict, incoming: dict) -> dict:
    """Merge the You.com servers into an existing mcpServers block.

    Servers already defined by the project are preserved; only ``youdotcom*``
    entries are added or refreshed. This keeps a project's own MCP servers
    intact while guaranteeing the intelligence capability is present.
    """
    merged = dict(existing)
    servers = dict(merged.get("mcpServers") or {})
    for name, entry in (incoming.get("mcpServers") or {}).items():
        servers[name] = entry
    merged["mcpServers"] = servers
    return merged


def bootstrap_project(root: str | os.PathLike, *, force: bool = False) -> BootstrapResult:
    """Write the intelligence configuration into ``root/.openhands``.

    Idempotent. ``force`` overwrites ``mcp.json`` wholesale instead of merging;
    the default merges so a project's own MCP servers survive.
    """
    root_path = Path(root).resolve()
    openhands = root_path / ".openhands"
    openhands.mkdir(parents=True, exist_ok=True)
    mcp_path = openhands / "mcp.json"
    env_path = root_path / ENV_EXAMPLE_NAME

    notes: list[str] = []
    incoming = openhands_mcp_config(with_key=True, docs=True)

    mcp_written = False
    if mcp_path.exists() and not force:
        try:
            existing = json.loads(mcp_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            # Unreadable config: rewrite it with the intelligence servers rather
            # than leaving a broken file that no host can load.
            mcp_path.write_text(json.dumps(incoming, indent=2) + "\n", encoding="utf-8")
            notes.append("existing mcp.json was unreadable; rewrote it")
            mcp_written = True
            existing = None
        if existing is not None:
            merged = _merge_mcp(existing, incoming)
            mcp_written = merged != existing
            mcp_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
            if not mcp_written:
                notes.append("mcp.json already contained the intelligence servers")
    else:
        mcp_path.write_text(json.dumps(incoming, indent=2) + "\n", encoding="utf-8")
        mcp_written = True

    env_written = False
    if not env_path.exists() or force:
        env_path.write_text(_ENV_EXAMPLE, encoding="utf-8")
        env_written = True
    else:
        notes.append("intelligence.env.example already present; left unchanged")

    return BootstrapResult(
        root=str(root_path), mcp_path=str(mcp_path),
        env_example_path=str(env_path),
        mcp_written=mcp_written, env_example_written=env_written, notes=notes,
    )


def load_project_config(root: str | os.PathLike) -> dict:
    """Read a project's intelligence config, if present.

    Returns an empty dict when there is no config. The shape is::

        {"disable": {"<name>": "<reason>"}}

    A ``disable`` entry without a non-empty reason is dropped (it is not an
    explicit decision), so a project cannot accidentally disable the global
    capability by writing a bare name.
    """
    path = Path(root) / PROJECT_CONFIG_NAME
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    disable = raw.get("disable")
    if isinstance(disable, dict):
        raw["disable"] = {k: v for k, v in disable.items()
                          if isinstance(v, str) and v.strip()}
    elif disable is not None:
        raw.pop("disable", None)
    return raw
