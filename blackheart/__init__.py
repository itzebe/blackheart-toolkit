"""BLACKHEART — attacker-driven security research and exploit-verification engine.

The package is organised around the attack lifecycle:

    authz      -> authorization gate that every campaign must pass first
    objectives -> attacker objective generation
    chains     -> multi-operation attack-chain hypotheses
    invariants -> stateful invariant-breaking engine (fuzz / minimize / reproduce)
    verify     -> independent verification that tries to falsify findings
    evidence   -> append-only, content-addressed evidence store
    ledger     -> structured engagement ledger + hypothesis database
    report     -> submission-ready bounty reports
    tools      -> verified toolchain registry
    campaign   -> the continuous attack loop that ties it together

Nothing in this package fabricates results: every classification is derived from
evidence that a real command produced.
"""

__version__ = "1.1.0"
