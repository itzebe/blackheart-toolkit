"""Explicit capability declarations for execution backends.

BLACKHEART must not be coupled to one sandbox, chain, framework, or repository
layout. The remedy is not a generic "adapter" that claims to do everything; it is
a **declaration** each backend makes about what it can actually do, which the
research core reads before it plans any work.

Two rules make this honest rather than decorative:

  * A capability is a *claim*, and :mod:`blackheart.environments.adapter` requires
    a real probe before the claim is trusted. A backend with an impressive
    declaration and no working interface is ``UNSUPPORTED``, never "integrated".
  * An absent capability is *reported*, not silently degraded into a substitute.
    A backend that cannot roll state back says so, and the core records the
    limitation instead of assuming a clean environment.

The taxonomy of capability *keys* is fixed so the core can compare backends
uniformly; the values and limitations stay specific to the real backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# The capability vocabulary
# --------------------------------------------------------------------------- #

#: Target kinds a backend may declare it can research. Kept as plain strings so a
#: future environment adds a kind without editing this module.
TARGET_TYPES: tuple[str, ...] = (
    "source-repository",   # a local source tree (any language)
    "test-environment",    # a local runnable test/dev environment
    "container",           # a containerised workload
    "remote-service",      # an authorized remote test endpoint
    "evm-chain",           # an EVM-compatible chain via JSON-RPC
    "non-evm-chain",       # a non-EVM ledger environment
    "http-service",        # an HTTP/API endpoint
    "web-application",     # a browser-facing application
    "backend-service",     # a process/service under test
    "protocol-implementation",  # a protocol's reference implementation
)

#: Operations a backend may support. A research probe is compiled to one of these;
#: a backend that does not declare an operation cannot be asked to perform it.
OPERATIONS: tuple[str, ...] = (
    "inspect",        # read-only static inspection of the target
    "enumerate",      # enumerate surfaces / entry points
    "execute",        # run an operation against a live target
    "sequence",       # run an ordered sequence of operations
    "reset",          # return the target to a known state
    "snapshot",       # capture the target's observable state
    "rollback",       # restore a captured state
    "capture",        # capture evidence (output, logs, artefacts)
    "transact",       # submit a state-changing transaction
)

#: What a backend may be *asked* to prove. Deliberately separate from
#: :data:`OPERATIONS`: a backend can execute a sequence without being able to
#: prove real-world exploitability (a simulator), and that distinction must be
#: visible to the verifier.
EVIDENCE_TIERS: tuple[str, ...] = (
    "real-execution",   # ran against the real target; may support a finding
    "simulation",       # synthetic state; supports hypothesis development only
    "static-only",      # read from source/artefacts; no execution at all
)


@dataclass
class Capabilities:
    """What one execution backend can actually do, stated explicitly.

    A field left at its falsy default is a capability the backend does **not**
    have. Nothing here is inferred from the presence of an adapter class: the
    adapter's ``probe`` must confirm the interface works, and a capability the
    probe cannot exercise is reported as a declared limitation.
    """

    target_types: tuple[str, ...] = ()
    operations: tuple[str, ...] = ()
    #: Discovered tools this backend can use (name -> present). Populated by the
    #: probe, so a declaration cannot claim a tool the host does not have.
    tools: dict[str, bool] = field(default_factory=dict)
    #: Can the backend reach a network at all? ``False`` means every probe is
    #: local, so an unreachable target is a limitation, not a failure.
    network: bool = False
    #: Can the backend control the target's state (reset/snapshot/rollback)?
    state_control: bool = False
    #: Can the backend submit a state-changing transaction?
    transactions: bool = False
    snapshot_rollback: bool = False
    evidence_capture: bool = False
    #: The strongest evidence tier this backend can produce. A ``simulation``
    #: backend can never independently prove real-world exploitability.
    evidence_tier: str = "static-only"
    #: Concrete things this backend cannot do, in its own words. Reported to the
    #: operator and recorded in the coverage ledger; never hidden.
    limitations: list[str] = field(default_factory=list)
    #: Credentials/permissions the backend needs to run at all.
    required_permissions: list[str] = field(default_factory=list)
    #: Safety constraints the backend enforces or requires from the caller.
    safety_constraints: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Queries the research core asks
    # ------------------------------------------------------------------ #

    def supports_target(self, target_type: str) -> bool:
        return target_type in self.target_types

    def supports_operation(self, operation: str) -> bool:
        return operation in self.operations

    def can_prove_real_execution(self) -> bool:
        """Only real execution may support a real-world finding.

        A simulation backend is valuable for developing a hypothesis, but its
        result must never be presented as a real exploit -- so this boolean, not a
        caller's optimism, decides whether an outcome may be promoted.
        """
        return self.evidence_tier == "real-execution"

    def missing_tools(self) -> list[str]:
        return sorted(name for name, present in self.tools.items() if not present)

    def to_dict(self) -> dict:
        return {
            "target_types": list(self.target_types),
            "operations": list(self.operations),
            "tools": dict(self.tools),
            "missing_tools": self.missing_tools(),
            "network": self.network,
            "state_control": self.state_control,
            "transactions": self.transactions,
            "snapshot_rollback": self.snapshot_rollback,
            "evidence_capture": self.evidence_capture,
            "evidence_tier": self.evidence_tier,
            "can_prove_real_execution": self.can_prove_real_execution(),
            "limitations": list(self.limitations),
            "required_permissions": list(self.required_permissions),
            "safety_constraints": list(self.safety_constraints),
        }


def validate_declaration(caps: Capabilities) -> list[str]:
    """Return the problems with a capability declaration (empty means valid).

    Catches the two ways a declaration lies: a value outside the fixed vocabulary
    (which would let a backend invent a target kind the core cannot plan for), and
    an evidence tier that claims real execution while declaring no execution
    operation.
    """
    problems: list[str] = []
    for t in caps.target_types:
        if t not in TARGET_TYPES:
            problems.append(f"unknown target type '{t}'")
    for o in caps.operations:
        if o not in OPERATIONS:
            problems.append(f"unknown operation '{o}'")
    if caps.evidence_tier not in EVIDENCE_TIERS:
        problems.append(f"unknown evidence tier '{caps.evidence_tier}'")
    if caps.evidence_tier == "real-execution" and "execute" not in caps.operations:
        problems.append("declares real-execution evidence but no 'execute' operation")
    if caps.transactions and "transact" not in caps.operations:
        problems.append("declares transactions but no 'transact' operation")
    return problems
