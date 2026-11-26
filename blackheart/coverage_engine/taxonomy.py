"""An extensible vulnerability-class taxonomy, larger than the objective catalogue.

The objective catalogue (:mod:`blackheart.objectives`) enumerates 30 *attack
objectives* the engine can model. This module is the wider **universe** of
vulnerability classes a target may exhibit, including classes that have no
executable model yet. The two are linked, not merged: a taxonomy class may map to
an objective category (and thus to a model) or may be a named gap.

Why a separate taxonomy matters:

  * **Discovery beyond the model set.** The engine can only *break* a class it has
    a model for, but it must still *know about* the rest -- otherwise an
    unmodelled class is invisible rather than a recorded gap. The taxonomy makes
    every class a first-class item with an explicit coverage state.
  * **Target-aware applicability.** A class records which *surfaces* it needs
    (:attr:`VulnClass.requires`), so the applicability engine can decide a class is
    inapplicable to a target that has none of them -- with a reason.
  * **Extensibility.** :meth:`Taxonomy.extend` accepts a class discovered during
    research, so a target that reveals a new class does not fall outside the map.
    An extension is marked ``discovered`` so it is distinguishable from the
    curated set.

This is a taxonomy, not a checklist: an entry says *what class of defect this is
and what surface it needs*, never "test this one thing and move on".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SeverityBand(str, Enum):
    """A coarse impact band, used only for prioritisation -- never for payability.

    Payability is always decided by the *program's own* policy
    (:mod:`blackheart.bounty`), never by a universal threshold. This enum exists so
    the controller can order work, and it says so rather than implying a global
    severity rule.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


#: Surface tokens a vulnerability class may require. A target declares which of
#: these it exposes; a class whose required surface is absent is inapplicable
#: *with a reason*. Kept aligned with the surface model in
#: :mod:`blackheart.hypothesis.surface` but expressed as explicit tokens.
SURFACES: tuple[str, ...] = (
    "auth",              # authentication / session handling
    "authorization",     # access control / roles / permissions
    "business-logic",    # workflows, ordering, multi-step state
    "input",             # user-controlled input reaching a sink
    "state-machine",     # explicit state transitions
    "financial",         # value, balances, accounting
    "arithmetic",        # integer / fixed-point / rounding math
    "concurrency",       # parallel execution / ordering / timing
    "signature",         # signatures / permits / nonces
    "crypto",            # cryptographic primitives / protocols
    "resource",          # CPU / memory / gas / quota limits
    "cross-component",   # multiple contracts/services interacting
    "api",               # HTTP / RPC / API surface
    "config",            # deployment / configuration
    "upgrade",           # upgradeability / governance
    "supply-chain",      # dependencies / build
    "data-isolation",    # multi-tenant / object ownership
    "compositional",     # multi-stage attack paths
)


@dataclass
class VulnClass:
    """One vulnerability class in the taxonomy.

    ``requires`` is the set of surfaces the class needs to be *applicable*. An
    empty set means the class can apply to almost any target (e.g. a generic
    business-logic flaw). ``objective_category`` links to the objective catalogue
    when one exists, so the model-coverage ledger can be consulted.
    """

    key: str
    title: str
    description: str
    requires: tuple[str, ...] = ()
    objective_category: str = ""          # link into objectives ("" = no model)
    default_band: SeverityBand = SeverityBand.MEDIUM
    #: True when the class was discovered during research rather than curated.
    discovered: bool = False
    #: How a hypothesis of this class is typically proven (free text, for prompts).
    proof_style: str = ""

    def needs_any(self, available: set[str]) -> bool:
        """Applicable only if the target exposes at least one required surface."""
        if not self.requires:
            return True
        return bool(set(self.requires) & available)

    def to_dict(self) -> dict:
        return {
            "key": self.key, "title": self.title, "description": self.description,
            "requires": list(self.requires),
            "objective_category": self.objective_category,
            "default_band": self.default_band.value,
            "discovered": self.discovered,
            "proof_style": self.proof_style,
        }


def _curated() -> list[VulnClass]:
    """The curated starting universe, grouped by the named families."""
    C = VulnClass
    return [
        # Authentication and authorization
        C("auth-bypass", "Authentication bypass", "Reach a protected operation without authenticating.",
          ("auth",), "auth-bypass", SeverityBand.HIGH,
          proof_style="an unauthenticated request reaches a privileged action"),
        C("access-control", "Broken access control", "Act on another principal's resource (IDOR/BOLA).",
          ("authorization", "data-isolation"), "access-control", SeverityBand.HIGH),
        C("privilege-escalation", "Privilege escalation", "Turn a low role into an owner/admin role.",
          ("authorization",), "privilege-escalation", SeverityBand.CRITICAL),
        # Business logic and workflow
        C("business-logic", "Business-logic flaw", "Abuse a workflow's intended steps to gain value or bypass a rule.",
          ("business-logic",), "accounting-manipulation", SeverityBand.HIGH),
        C("state-machine-violation", "State-machine violation", "Drive the system into an illegal state transition.",
          ("state-machine",), "state-inconsistency", SeverityBand.HIGH),
        # Input and injection
        C("injection", "Injection", "Untrusted input reaches an interpreter/sink unescaped.",
          ("input",), "auth-bypass", SeverityBand.CRITICAL,
          proof_style="a crafted input changes the command/query executed"),
        C("input-validation", "Input-validation failure", "Malformed input is accepted and corrupts state.",
          ("input",), "", SeverityBand.MEDIUM),
        # Financial and accounting
        C("accounting-manipulation", "Accounting / settlement error", "Internal bookkeeping desyncs from real value.",
          ("financial",), "accounting-manipulation", SeverityBand.CRITICAL),
        C("unbacked-debt", "Unbacked debt", "Credit minted without equal backing.",
          ("financial",), "unbacked-debt", SeverityBand.CRITICAL),
        C("reward-manipulation", "Reward manipulation", "Claim rewards without the qualifying stake/time.",
          ("financial",), "reward-manipulation", SeverityBand.HIGH),
        # Arithmetic
        C("rounding-precision", "Rounding / precision", "Amplify a rounding error across repeated operations.",
          ("arithmetic",), "rounding-precision", SeverityBand.MEDIUM),
        C("integer-overflow", "Integer overflow / underflow", "Arithmetic wraps outside the representable range.",
          ("arithmetic",), "", SeverityBand.HIGH),
        C("decimals-mismatch", "Decimals mismatch", "Amounts scaled by the wrong decimals.",
          ("arithmetic", "financial"), "decimals-mismatch", SeverityBand.HIGH),
        # Concurrency and timing
        C("race-condition", "Race condition / TOCTOU", "Exploit a gap between check and use.",
          ("concurrency",), "ordering-timing", SeverityBand.HIGH),
        C("ordering-timing", "Ordering / timing", "An operation accepted or front-run at the wrong time.",
          ("concurrency",), "ordering-timing", SeverityBand.MEDIUM),
        # Replay and signatures
        C("replay", "Replay", "Reuse a valid authorization/message a second time.",
          ("signature",), "replay-forgery", SeverityBand.HIGH),
        C("signature-bypass", "Signature verification bypass", "Make an invalid signature verify.",
          ("signature", "crypto"), "signature-bypass", SeverityBand.CRITICAL),
        # Cryptography
        C("crypto-implementation", "Cryptographic implementation error", "A primitive is used incorrectly (IV, padding, key reuse).",
          ("crypto",), "signature-bypass", SeverityBand.HIGH),
        C("protocol-error", "Protocol implementation error", "The protocol's rules are implemented wrongly.",
          ("crypto", "cross-component"), "cross-protocol-trust", SeverityBand.HIGH),
        # Resource exhaustion
        C("dos", "Resource exhaustion / DoS", "One actor's input blocks a shared critical path.",
          ("resource",), "denial-of-service", SeverityBand.MEDIUM,
          proof_style="a cheap input makes a shared path unusable for others"),
        # Cross-component
        C("cross-contract", "Cross-contract interaction", "Interaction between components exposes a flaw neither has alone.",
          ("cross-component",), "cross-contract", SeverityBand.HIGH),
        C("cross-chain-replay", "Cross-chain replay", "A message is replayed on the wrong chain/domain.",
          ("cross-component", "signature"), "cross-chain-replay", SeverityBand.CRITICAL),
        C("reentrancy", "Reentrancy / callback", "A callback re-enters before effects settle.",
          ("cross-component",), "callback-reentrancy", SeverityBand.CRITICAL),
        # API and integration
        C("api-security", "API security", "An API surface leaks data or honours the wrong caller.",
          ("api",), "token-audience-confusion", SeverityBand.HIGH),
        C("integration-security", "Integration security", "A third-party integration trusts input it should not.",
          ("api", "cross-component"), "cross-protocol-trust", SeverityBand.HIGH),
        # Configuration and deployment
        C("misconfiguration", "Misconfiguration", "A deployed setting weakens a control.",
          ("config",), "auth-bypass", SeverityBand.HIGH),
        C("info-disclosure", "Information disclosure", "Protected data is observable by the wrong principal.",
          ("data-isolation",), "info-disclosure", SeverityBand.MEDIUM),
        # Upgradeability and governance
        C("upgradeability", "Upgrade / governance weakness", "An unsafe upgrade or governance path changes behaviour.",
          ("upgrade",), "governance-manipulation", SeverityBand.CRITICAL),
        C("proxy-initializer", "Proxy / initializer", "A proxy can be re-initialized or hijacked.",
          ("upgrade",), "", SeverityBand.HIGH),
        # Supply chain
        C("supply-chain", "Supply-chain weakness", "A dependency or build artefact is unsafe.",
          ("supply-chain",), "", SeverityBand.HIGH),
        # Data isolation
        C("cross-tenant-disclosure", "Cross-tenant disclosure", "One tenant observes another's data.",
          ("data-isolation",), "info-disclosure", SeverityBand.CRITICAL),
        # Compositional
        C("compositional-chain", "Multi-stage attack path", "Individually benign conditions combine into a break.",
          ("compositional", "cross-component"), "", SeverityBand.CRITICAL,
          proof_style="two safe-looking behaviours sequence into one violation"),
        # Value-moving classes with a modelled pair, named so the plan can select them
        C("asset-theft", "Direct asset theft", "Value is moved out without the owner's authority.",
          ("financial", "business-logic"), "asset-theft", SeverityBand.CRITICAL),
        C("oracle-manipulation", "Oracle manipulation", "A price/feed is moved so the system trusts a false value.",
          ("financial", "cross-component"), "oracle-manipulation", SeverityBand.CRITICAL),
        C("liquidation-bypass", "Liquidation bypass", "A position avoids liquidation it should incur.",
          ("financial",), "liquidation-bypass", SeverityBand.HIGH),
        C("slippage-manipulation", "Slippage manipulation", "A trade executes at a price the victim did not accept.",
          ("financial", "ordering"), "slippage-manipulation", SeverityBand.HIGH),
        C("silent-transfer-failure", "Silent transfer failure", "A transfer fails without reverting, leaving state wrong.",
          ("financial", "integration"), "silent-transfer-failure", SeverityBand.HIGH),
        C("storage-collision", "Storage collision", "Two variables share a slot, corrupting state.",
          ("upgrade", "arithmetic"), "storage-collision", SeverityBand.CRITICAL),
        C("cors-credential-leak", "CORS credential leak", "A permissive origin policy exposes credentials.",
          ("api", "config"), "cors-credential-leak", SeverityBand.HIGH),
    ]


class Taxonomy:
    """A mutable, extensible collection of :class:`VulnClass` keyed by ``key``."""

    def __init__(self, classes: list[VulnClass] | None = None) -> None:
        self._classes: dict[str, VulnClass] = {}
        for c in classes if classes is not None else _curated():
            self._classes[c.key] = c

    def __len__(self) -> int:
        return len(self._classes)

    def __iter__(self):
        return iter(self._classes.values())

    def get(self, key: str) -> VulnClass | None:
        return self._classes.get(key)

    def keys(self) -> list[str]:
        return list(self._classes)

    def curated(self) -> list[VulnClass]:
        return [c for c in self._classes.values() if not c.discovered]

    def discovered(self) -> list[VulnClass]:
        return [c for c in self._classes.values() if c.discovered]

    def extend(self, key: str, title: str, description: str, *,
               requires: tuple[str, ...] = (),
               objective_category: str = "",
               default_band: SeverityBand = SeverityBand.MEDIUM,
               proof_style: str = "") -> VulnClass:
        """Add a class discovered during research.

        Idempotent by key: re-discovering the same class returns the existing
        entry rather than duplicating it, so a research loop cannot inflate the
        taxonomy with repeats.
        """
        existing = self._classes.get(key)
        if existing is not None:
            return existing
        cls = VulnClass(
            key=key, title=title, description=description, requires=requires,
            objective_category=objective_category, default_band=default_band,
            discovered=True, proof_style=proof_style,
        )
        self._classes[key] = cls
        return cls

    def summary(self) -> dict:
        by_band: dict[str, int] = {}
        for c in self._classes.values():
            by_band[c.default_band.value] = by_band.get(c.default_band.value, 0) + 1
        modelled = sum(1 for c in self._classes.values() if c.objective_category)
        return {
            "classes": len(self._classes),
            "curated": len(self.curated()),
            "discovered": len(self.discovered()),
            "with_objective_model_link": modelled,
            "by_band": dict(sorted(by_band.items())),
        }


#: The default taxonomy, built once. A caller that extends it should hold its own
#: instance (:class:`Taxonomy`) rather than mutating this module-level default.
DEFAULT_TAXONOMY = Taxonomy()
