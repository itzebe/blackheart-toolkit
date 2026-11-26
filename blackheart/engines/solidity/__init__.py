"""Solidity analysis engines as BLACKHEART capability providers.

Five engines, one contract. Each adapter implements
:class:`blackheart.engines.contract.EngineAdapter`, so the existing orchestrator
supplies deduplication, corroboration, contradiction detection, chain
correlation and the no-self-promotion gate without knowing which engine ran.

The engines are deliberately split by *analysis method*, because that is what
makes their findings independent evidence rather than five opinions:

  * ``slither`` -- static analysis (AST/IR detectors)
  * ``wake``    -- independent static analysis (own compiler front end)
  * ``halmos``  -- symbolic execution (SMT counterexamples)
  * ``echidna`` -- property-based fuzzing (random sequences)
  * ``medusa``  -- coverage-guided sequence fuzzing

Two honesty rules are enforced in code, not documented and hoped for:

  * **A non-zero exit is not a failure.** Echidna, Medusa and Halmos exit
    non-zero *because they found a counterexample*. Treating that as a tool
    failure would silently convert every real bug into a "clean scan". Each
    adapter declares its own ``FINDING_EXIT_CODES``; anything else is a failure.
  * **A scan with no parseable output is PARTIAL, never COMPLETED.** An engine
    that crashed before writing its artifact must not read as "no findings".
"""

from __future__ import annotations

from .base import SolidityEngineAdapter, ToolPaths, resolve_tool
from .echidna import EchidnaAdapter
from .halmos import HalmosAdapter
from .medusa import MedusaAdapter
from .slither import SlitherAdapter
from .wake import WakeAdapter

#: The Solidity engines, in the doctrine's integration order.
SOLIDITY_ADAPTERS: dict[str, str] = {
    "slither": "blackheart.engines.solidity.slither:SlitherAdapter",
    "wake": "blackheart.engines.solidity.wake:WakeAdapter",
    "halmos": "blackheart.engines.solidity.halmos:HalmosAdapter",
    "echidna": "blackheart.engines.solidity.echidna:EchidnaAdapter",
    "medusa": "blackheart.engines.solidity.medusa:MedusaAdapter",
}

__all__ = [
    "SolidityEngineAdapter",
    "ToolPaths",
    "resolve_tool",
    "SlitherAdapter",
    "WakeAdapter",
    "HalmosAdapter",
    "EchidnaAdapter",
    "MedusaAdapter",
    "SOLIDITY_ADAPTERS",
]
