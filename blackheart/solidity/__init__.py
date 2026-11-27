"""Solidity source -> :class:`SystemModel`: the model extractor.

The state-space engine can only attack a system it has a *model* of -- actors,
operations, guards, assets, invariants. For a Python target the model is written
by hand or proposed from ``ast`` (see ``statespace.runtime.source_model``). For
Solidity -- the language almost every on-chain protocol is written in -- there was
no extractor at all: an operator had to hand-write the case declaration (which
contracts to deploy, the actors, the operations, the invariants) before the engine
could do anything. That hand-written declaration is the bottleneck the whole
"hunt any protocol" promise turns on, so this package removes it.

Design rules, inherited from the Python path because they are correct:

  * **Propose, then validate.** A source read is a *proposal*, never a claim.
    :func:`propose_model` reads ``.sol`` with a real (if deliberately small)
    Solidity parser and emits a :class:`SystemModel` where every element carries
    ``provenance`` (``file:line``). Nothing here executes anything.

  * **Never invent an architecture.** Where the source does not reveal a fact --
    an operation's authorization role, an invariant's semantics -- the extractor
    records it as *unknown* rather than guessing. A model that invents a
    structure is worse than no model: it produces confident hypotheses about a
    system that does not exist.

  * **The extractor is honest about its own limits.** It is not ``solc``. It does
    not do type checking, inheritance resolution across unvendored imports, or
    full expression semantics. It reports what it can read and what it cannot,
    and ``solidity doctor`` says whether the optional external tools (``solc``,
    ``slither``) are present so the operator knows when a deeper read is possible.

The parse is a real lexer plus a brace-matching declaration scanner, not a regex
over the file: function bodies are tracked so that a *nested* call inside a body
is never mistaken for a top-level declaration, and modifiers, visibility, and
state-mutability are read from the declaration header rather than pattern-matched
loosely.
"""

from __future__ import annotations

from .lexer import Token, lex
from .parser import (
    ContractDecl,
    FunctionDecl,
    ModifierDecl,
    ParsedSource,
    StateVariable,
    parse_source,
)
from .extract import (
    SolidityProposal,
    propose_model,
    propose_model_from_files,
    validate_against_operations,
)
from .abi import (
    AbiFunction,
    operations_from_abi,
    param_domain,
    parse_abi,
    propose_model_from_abi,
)
from .taxonomy import (
    infer_asset,
    infer_category,
    infer_guard_roles,
    is_privileged,
    is_sensitive,
)

__all__ = [
    "Token",
    "lex",
    "ContractDecl",
    "FunctionDecl",
    "ModifierDecl",
    "StateVariable",
    "ParsedSource",
    "parse_source",
    "SolidityProposal",
    "propose_model",
    "propose_model_from_files",
    "validate_against_operations",
    "infer_asset",
    "infer_category",
    "infer_guard_roles",
    "is_privileged",
    "is_sensitive",
    "AbiFunction",
    "parse_abi",
    "param_domain",
    "operations_from_abi",
    "propose_model_from_abi",
]
