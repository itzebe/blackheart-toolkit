"""The universal hunt: one entry point that runs every engine, in order.

BLACKHEART already has every *part* of a hunt -- the search portfolio, the path
certifier, the independent verifier, the ordering search, the cross-target attack
memory, and structured infrastructure discovery. What it did not have was the
single composition that makes them one operation: a hunt that a caller (or an
operator) can point at any target and get the *whole* pipeline, in the order the
doctrine requires, with one honest verdict at the end.

This package is that composition, and nothing more -- it introduces no new engine.
Every stage calls an existing, tested module and the result carries that module's
own verdict; the hunt never upgrades a lead it did not prove.

The order is fixed by the doctrine:

  1. **Recall** (:mod:`blackheart.learning.transfer`) -- pull proven attacks from
     earlier targets that structurally resemble this one, as candidate seeds.
     A proven shape is the cheapest lead a hunt can start from.
  2. **Search** (:mod:`blackheart.assurance.portfolio`) -- run every strategy,
     union the counterexamples, audit the oracles, and price each hit with the
     universal value engine. This is a strict superset of any single search.
  3. **Certify** (:mod:`blackheart.discovery.certify`) -- turn each candidate into
     a *proof* (a reproducible, prefix-minimal witness) or state the bound. A
     candidate that is not proven is reported as a lead, never as a finding.
  4. **Verify** (:mod:`blackheart.statespace.verify`) -- an independent re-run in a
     fresh instance, with the discriminating control, decides the disposition. The
     hunt reports the verifier's verdict; it never rubber-stamps it.
  5. **Order** (:mod:`blackheart.statespace.mempool`) -- where the target has a
     victim flow, search the interleavings, because a large family of real
     extractions is an *ordering*, not a single-party sequence.
  6. **Remember** -- record every *proven* attack back into the memory as a
     transferable shape, so the next hunt starts stronger. An unproven lead is
     never promoted.

The hunt is honest by construction: it distinguishes a proven, independently
verified violation from a candidate lead from a bounded negative, and it states
which bound it reached. ``can't miss`` is not a claim this module makes -- it makes
the strictly stronger, honest claim that every strategy is run and the result is
the union, with the coverage ledger attached.
"""

from .orchestrator import (
    HUNT_STAGES,
    HuntConfig,
    HuntResult,
    StageOutcome,
    hunt,
)

__all__ = [
    "HUNT_STAGES",
    "HuntConfig",
    "HuntResult",
    "StageOutcome",
    "hunt",
]
