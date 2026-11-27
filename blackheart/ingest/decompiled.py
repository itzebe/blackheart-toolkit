"""A decompiled surface is a lead, never source.

Heimdall reconstructs an ABI and a CFG from runtime bytecode. That recovers the
function surface of a *closed* component -- which functions exist and what they
take -- but not what they do. This module parses that surface into the same
``ContractSurface`` the Solidity path uses, with every body marked ``assembly { }``
so the interpreter records each operation as unmodelled.

The honest result is ``UNMODELLED`` with the recovered names in the report. A
surface is enough to ask "is this function reachable by an unprivileged account?"
and not enough to answer "what does it do?".
"""

from __future__ import annotations

import re

from .solidity import ContractSurface, FunctionSurface

_FUNCTION = re.compile(
    r"function\s+(?:(0x[0-9a-fA-F]{8})\s+)?([A-Za-z_]\w*)?\s*\(([^)]*)\)\s*([^;{]*)"
)
_VISIBILITIES = ("external", "public", "internal", "private")


def parse_decompiled(
    text: str,
    *,
    name: str = "Decompiled",
    path: str = "<decompiled>",
) -> ContractSurface:
    """Recover the function surface from a decompiler's text output."""
    functions: list[FunctionSurface] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        match = _FUNCTION.search(line)
        if not match:
            continue
        selector, function_name, params, tail = match.groups()
        if not function_name:
            function_name = f"selector_{selector[2:]}" if selector else f"fn_{line_number}"
        visibility = next((v for v in _VISIBILITIES if v in tail), "external")
        if "view" in tail:
            mutability = "view"
        elif "pure" in tail:
            mutability = "pure"
        elif "payable" in tail:
            mutability = "payable"
        else:
            mutability = "nonpayable"
        cleaned = tuple(p.strip() for p in params.split(",") if p.strip())
        functions.append(FunctionSurface(
            contract=name,
            name=function_name,
            signature=f"{function_name}({params.strip()})",
            visibility=visibility,
            mutability=mutability,
            modifiers=(),
            params=cleaned,
            # Every body is unknown. ``interpret`` records this as unmodelled
            # rather than treating the function as a no-op.
            body="assembly { }",
            line=line_number,
        ))
    return ContractSurface(name=name, kind="contract", path=path, line=1,
                           functions=tuple(functions))
