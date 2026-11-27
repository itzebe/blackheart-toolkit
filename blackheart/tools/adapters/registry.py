"""A small registry so the CLI and any campaign can dispatch to an adapter by name.

The registry is data, not behaviour: it maps a tool name to the callable that
drives it and the argument shape it needs. Adding a tool is one entry here plus
its parser in :mod:`.web`, exactly as adding an attack class is one registry edit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from .base import locate
from .web import (
    run_dalfox,
    run_ffuf,
    run_gitleaks,
    run_gobuster,
    run_nuclei,
    run_sqlmap,
)


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    fn: Callable
    requires_wordlist: bool = False
    description: str = ""


ADAPTERS: dict[str, AdapterSpec] = {
    "ffuf": AdapterSpec("ffuf", run_ffuf, requires_wordlist=True,
                        description="content/endpoint discovery (needs a wordlist)"),
    "gobuster": AdapterSpec("gobuster", run_gobuster, requires_wordlist=True,
                            description="directory/DNS brute forcing (needs a wordlist)"),
    "nuclei": AdapterSpec("nuclei", run_nuclei,
                          description="template-based vulnerability scanning"),
    "sqlmap": AdapterSpec("sqlmap", run_sqlmap,
                          description="SQL injection detection (batch mode)"),
    "dalfox": AdapterSpec("dalfox", run_dalfox,
                          description="XSS scanning"),
    "gitleaks": AdapterSpec("gitleaks", run_gitleaks,
                            description="secret scanning of a local path"),
}


def adapter_for(name: str) -> Optional[AdapterSpec]:
    return ADAPTERS.get(name)


def available_adapters() -> list[str]:
    """Names of the adapters whose binary is actually present on this host."""
    return sorted(name for name in ADAPTERS if locate(name) is not None)
