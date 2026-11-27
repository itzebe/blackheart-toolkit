"""Tool-driving adapters: turn a live tool's output into structured evidence.

BLACKHEART already *verifies* that its external tools are installed and
functional (:mod:`blackheart.tools`). What it could not do is **drive** them and
read their results back as evidence -- so a live scan by ``nuclei``, ``ffuf``,
``sqlmap``, ``dalfox``, ``gobuster``, or ``gitleaks`` produced a wall of text an
operator had to eyeball, and none of it could become a finding's evidence.

This package closes that gap. Each adapter:

  * **Refuses to run without authorization.** Every adapter is called with an
    :class:`~blackheart.models.AuthorizationRecord` and an asset, and calls
    :func:`blackheart.authz.assert_authorized` first. An unauthorized asset is a
    hard error, not a warning -- the tool never starts.
  * **Runs the real binary** on the real target and captures the exact command,
    exit code, stdout and stderr. Nothing is simulated.
  * **Parses the tool's own machine-readable output** (``-json``/``-oJ``/``-jsonl``)
    into structured :class:`ToolFinding` records -- URL/endpoint, the class of
    issue, severity, and the raw evidence line. Parsing is best-effort and
    *honest*: an output the adapter cannot parse is recorded as unparsed rather
    than dropped or invented.
  * **Is honest about absence.** If the binary is missing, the adapter returns
    ``available=False`` with the reason; it never fabricates a scan.

The result of a run is a :class:`~blackheart.tools.adapters.base.ToolRun` that can
be written to the evidence store (``evidence_store.put_json``) and attached to a
finding. A tool finding is **not** a vulnerability -- it is a lead that still has
to pass the verification gate, exactly as the doctrine requires.
"""

from __future__ import annotations

from .base import ToolFinding, ToolRun, ToolUnavailable
from .web import (
    run_dalfox,
    run_ffuf,
    run_gitleaks,
    run_gobuster,
    run_nuclei,
    run_sqlmap,
)
from .registry import ADAPTERS, adapter_for, available_adapters

__all__ = [
    "ToolFinding",
    "ToolRun",
    "ToolUnavailable",
    "run_dalfox",
    "run_ffuf",
    "run_gobuster",
    "run_gitleaks",
    "run_nuclei",
    "run_sqlmap",
    "ADAPTERS",
    "adapter_for",
    "available_adapters",
]
