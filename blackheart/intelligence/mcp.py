"""You.com MCP server configuration for agent hosts (OpenHands, and others).

The You.com MCP server exposes the same capabilities as the REST APIs above as
MCP tools (``you-search``, ``you-contents``, ``you-research``, ``you-finance``,
``you-balance``, ``you-discover``). This module emits the *configuration* an
agent host needs; it never connects on its own, and it never embeds a key in a
committed file.

Two servers matter here:

  * the **product** server at ``https://api.you.com/mcp`` -- live web tools. It
    accepts either a keyless free profile (``?profile=free``: ``you-search`` +
    ``you-discover``, 100 queries/day) or an API key.
  * the **docs** server at ``https://you.com/docs/_mcp/server`` -- a free,
    read-only server for searching You.com's own documentation. Useful to an
    agent that must pick the right API.

Authentication for the keyed product server is ``Authorization: Bearer <key>``
(an MCP transport detail), NOT the ``X-API-Key`` header the REST APIs use. The
key is referenced as ``${YDC_API_KEY}`` so the emitted config never contains the
secret itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Product MCP server endpoints (from https://you.com/docs/agents/mcp-server).
MCP_PRODUCT_URL = "https://api.you.com/mcp"
MCP_FREE_PROFILE_URL = "https://api.you.com/mcp?profile=free"
MCP_RESEARCH_URL = "https://api.you.com/mcp/research"
MCP_FINANCE_URL = "https://api.you.com/mcp/finance"
MCP_DOCS_URL = "https://you.com/docs/_mcp/server"

#: The MCP tools the product server can expose.
MCP_TOOLS = ("you-search", "you-contents", "you-research", "you-finance",
             "you-balance", "you-discover")

#: Tools that are free to call (subject to rate limits). Everything else is paid.
FREE_TOOLS = ("you-search", "you-discover")

#: The env var the key is read from; the emitted config references it, never the
#: value.
KEY_ENV = "YDC_API_KEY"


@dataclass
class MCPServer:
    """One MCP server entry, in the common ``mcpServers`` shape."""

    name: str
    url: str
    transport: str = "http"
    headers: dict[str, str] = field(default_factory=dict)
    tools: tuple[str, ...] = ()
    free: bool = False

    def to_entry(self, *, style: str = "openhands") -> dict[str, Any]:
        """Emit the entry in the requested host's dialect.

        OpenHands (FastMCP) keys the transport as ``transport``
        (https://gofastmcp.com/clients/client); Claude Desktop/Code and several
        other hosts key it as ``type`` (the form You.com's own docs show). Emitting
        the wrong key would silently produce a non-connecting server, so the
        dialect is explicit rather than assumed.
        """
        key = "transport" if style == "openhands" else "type"
        entry: dict[str, Any] = {key: self.transport, "url": self.url}
        if self.headers:
            entry["headers"] = dict(self.headers)
        return entry

    def to_dict(self) -> dict:
        return {"name": self.name, "url": self.url, "transport": self.transport,
                "tools": list(self.tools), "free": self.free,
                "authenticated": bool(self.headers)}


def mcp_config(
    *,
    with_key: bool = True,
    research: bool = False,
    finance: bool = False,
    docs: bool = False,
    scoped_tools: tuple[str, ...] = (),
    style: str = "openhands",
) -> dict:
    """Build an ``mcpServers`` configuration block for a host.

    ``with_key=False`` emits the keyless free profile (search + discover only).
    With a key, the header references ``${YDC_API_KEY}`` so no secret is written.
    ``scoped_tools`` uses the ``?tools=`` allowlist to narrow what an agent may
    call -- the cost-control lever for expensive tools like ``you-research``.
    ``style`` selects the transport-key dialect (``openhands`` or ``claude``).
    """
    servers: dict[str, Any] = {}
    if with_key and scoped_tools:
        url = f"{MCP_PRODUCT_URL}?tools={','.join(scoped_tools)}"
        headers = {"Authorization": f"Bearer ${{{KEY_ENV}}}"}
        servers["youdotcom"] = MCPServer(
            "youdotcom", url, headers=headers,
            tools=tuple(scoped_tools)).to_entry(style=style)
    elif with_key:
        headers = {"Authorization": f"Bearer ${{{KEY_ENV}}}"}
        servers["youdotcom"] = MCPServer(
            "youdotcom", MCP_PRODUCT_URL, headers=headers,
            tools=MCP_TOOLS).to_entry(style=style)
    else:
        servers["youdotcom"] = MCPServer(
            "youdotcom", MCP_FREE_PROFILE_URL, tools=FREE_TOOLS,
            free=True).to_entry(style=style)

    if research:
        servers["youdotcom_research"] = MCPServer(
            "youdotcom_research", MCP_RESEARCH_URL,
            tools=("you-research",)).to_entry(style=style)
    if finance:
        servers["youdotcom_finance"] = MCPServer(
            "youdotcom_finance", MCP_FINANCE_URL,
            tools=("you-finance",)).to_entry(style=style)
    if docs:
        servers["youcom_docs"] = MCPServer(
            "youcom_docs", MCP_DOCS_URL, tools=(), free=True).to_entry(style=style)
    return {"mcpServers": servers}


def openhands_mcp_config(*, with_key: bool = True, docs: bool = True) -> dict:
    """The You.com MCP block sized for an OpenHands agent host.

    OpenHands reads MCP servers from its own config; this returns the standard
    ``mcpServers`` block in the ``transport`` dialect OpenHands (FastMCP) expects.
    The docs server is included by default because it is free and helps the agent
    choose the right You.com API.
    """
    return mcp_config(with_key=with_key, docs=docs, style="openhands")
