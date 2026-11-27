"""Assurance: the oracle audit, the search portfolio, and the bounded-exhaustive
certifier.

The rest of BLACKHEART *samples* the attack space: the random fuzzer, the
coverage-guided corpus fuzzer, the adaptive explorer and the model-guided
explorer each search a different way, and each can only ever report "found" or
"not found within budget". None of them can honestly say "there is no bug here".

This package adds the three things that make the hunt as complete and as honest
as it can be:

  * :func:`blackheart.assurance.oracles.audit_oracles` -- **the oracle audit**:
    for every declared invariant, decide whether it can catch anything at all
    (is it ever evaluated, can it be false, does any reachable-state mutation
    flip it?). Every search is bounded by these oracles, so this runs first.
  * :func:`blackheart.assurance.certify.certify` -- **bounded-exhaustive**
    enumeration: every sequence up to a depth over the declared alphabet, run and
    checked. It is the *only* search allowed to say "no counterexample exists",
    and only up to its declared bound, which it prints with its limits.
  * :func:`blackheart.assurance.portfolio.run_portfolio` -- **the union** of every
    strategy on one target, deduplicated and priced, with a coverage ledger that
    records what each strategy covered and what none of them could. It is a strict
    superset of any single strategy, so it can only find *more*.

The doctrine this encodes is in :data:`blackheart.mindset.COVERAGE_DOCTRINE` and
:data:`blackheart.mindset.ORACLE_DOCTRINE`: a bounded-exhaustive search is the
only one that may report "clean", every stochastic search reports "not found
within budget" and nothing stronger, and no clean result is trusted until the
declared invariants are shown to be live.

Nothing here touches a network or a real system: every stage drives a local
``Target``.
"""

from .certify import (
    AlphabetEntry,
    CertifyConfig,
    CoverageCertificate,
    build_alphabet,
    certify,
)
from .oracles import (
    OracleAudit,
    OracleAuditConfig,
    OracleFinding,
    OracleVerdict,
    audit_oracles,
)
from .portfolio import (
    STRATEGIES,
    PortfolioConfig,
    PortfolioResult,
    StageResult,
    run_portfolio,
)

__all__ = [
    "AlphabetEntry",
    "CertifyConfig",
    "CoverageCertificate",
    "build_alphabet",
    "certify",
    "OracleAudit",
    "OracleAuditConfig",
    "OracleFinding",
    "OracleVerdict",
    "audit_oracles",
    "STRATEGIES",
    "PortfolioConfig",
    "PortfolioResult",
    "StageResult",
    "run_portfolio",
]
