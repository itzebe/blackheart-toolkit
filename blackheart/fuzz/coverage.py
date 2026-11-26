"""Behavioural coverage signal for the coverage-guided fuzzer.

A coverage-guided fuzzer needs one thing above all: a way to tell two executions
apart that a *random* fuzzer cannot. AFL/Echidna/Medusa get this from compiler
instrumentation (edge coverage). BLACKHEART runs against the abstract ``Target``
protocol -- a Python reference model, a state-space model, or a real-runtime
adapter -- so it cannot rely on an instrumented binary. Instead it derives a
**behavioural** signal from what the target itself exposes, which works on every
target without any per-target work:

  * **operation coverage** -- which operations executed;
  * **edge coverage** -- which ``(prev_op -> op)`` transitions executed (the
    ordering signal: a state machine's behaviour lives in its transitions);
  * **actor/op coverage** -- which ``(actor, operation)`` pairs executed (who can
    drive which transition);
  * **state coverage** -- a discretised read of the snapshot after each step
    (which fields moved, and into which magnitude band), so two sequences that
    reach *different states* are distinguished even when they use the same
    operations.

Each feature is hashed into a fixed bitmap, exactly like an AFL coverage map, so
"did this execution teach us anything new?" is a bitmap comparison -- cheap, and
the whole thing stays deterministic.

This is honest about what it is: it is *behaviour* coverage, not source-line
coverage. It cannot see a branch the target does not reflect in its operations or
its snapshot. What it does guarantee is that a sequence which reaches a state no
earlier sequence reached is kept and mutated -- which is precisely the signal a
multi-step, state-dependent exploit needs and a blind random walk throws away.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

#: Size of the coverage bitmap in bytes (AFL's default map size). Feature hashes
#: are folded into ``8 * BITMAP_BYTES`` buckets; a larger map keeps collisions
#: rare without a measurable cost.
BITMAP_BYTES = 65536
_BITMAP_BITS = BITMAP_BYTES * 8

#: Numeric values with ``|value|`` below this are hashed *exactly* (a state
#: counter's value is the signal); larger values are banded by order of magnitude
#: (a token balance's exact value is noise). See :func:`_magnitude_band`.
_EXACT_BELOW = 4096


def _hash_feature(feature: tuple) -> int:
    """Deterministic, process-independent bucket index for one feature.

    ``hash()`` is salted per process (PYTHONHASHSEED) and must not be used for a
    reproducible bitmap, so this is a small explicit FNV-1a over the feature's
    repr. The result is stable across runs and machines.
    """
    h = 2166136261
    for ch in repr(feature):
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return h % _BITMAP_BITS


def _magnitude_band(value: int) -> int:
    """Band for a numeric value: exact when small, order-of-magnitude when large.

    A state counter (a stage index, a streak length, a retry count) is small and
    its *exact* value is the signal -- stage 2 and stage 3 are different states
    and must land in different buckets, or the search cannot tell that it made
    progress. A token balance is large (wei-scale) and its exact value is noise --
    a one-unit jitter must *not* masquerade as new coverage, or the corpus fills
    with near-duplicates.

    So: below ``_EXACT_BELOW`` the value is its own band; at or above it, the band
    is the sign plus the bit length (order of magnitude). This is the one heuristic
    in the coverage signal, and it is chosen so both regimes are handled without a
    per-target hint.
    """
    if value == 0:
        return 0
    if -_EXACT_BELOW < value < _EXACT_BELOW:
        return value
    sign = 1 if value > 0 else -1
    return sign * (abs(value).bit_length())


def _state_features(snapshot: Any) -> Iterable[tuple]:
    """Features describing a final snapshot, target-agnostically.

    Handles the snapshot shapes the engine sees: a flat ``{name: int}``, a
    per-actor ``{name: {actor: int}}``, a per-actor boolean map (a grant), and
    scalar flags/strings. Anything else is summarised by its type name, so an
    unknown shape still contributes a (coarse) signal rather than crashing.
    """
    if not isinstance(snapshot, dict):
        yield ("snapshot_type", type(snapshot).__name__)
        return
    for name, value in snapshot.items():
        if isinstance(value, bool):
            yield ("flag", str(name), value)
        elif isinstance(value, int):
            yield ("scalar", str(name), _magnitude_band(value))
        elif isinstance(value, dict):
            for actor, held in value.items():
                if isinstance(held, bool):
                    yield ("actor_flag", str(name), str(actor), held)
                elif isinstance(held, int):
                    yield ("actor_scalar", str(name), str(actor), _magnitude_band(held))
                else:
                    yield ("actor_other", str(name), str(actor), type(held).__name__)
        elif isinstance(value, (list, tuple, set)):
            yield ("collection", str(name), len(value))
        else:
            yield ("other", str(name), type(value).__name__)


def _target_coverage_features(target: Any, when: str) -> Iterable[tuple]:
    """Extra coverage features a target opts into, via an optional hook.

    A target may expose a *real instrumentation* signal the universal behavioural
    map cannot see -- for example an EVM contract's opcode/pc coverage from
    ``debug_traceTransaction`` (:mod:`blackheart.statespace.runtime.evm_coverage`).
    The hook is deliberately optional and duck-typed, so every existing target is
    unaffected and a target without it simply contributes nothing:

      * ``step_coverage_features()`` -- features for the most recent step (called
        after each step);
      * ``run_coverage_features()`` -- features for the whole run (called once).

    The features must already be hashable tuples; they fold into the same bitmap as
    the behavioural features. A hook that raises contributes nothing rather than
    failing the run -- coverage is feedback, never a reason to abort a search.
    """
    if when == "step":
        fn = getattr(target, "step_coverage_features", None)
    else:
        fn = getattr(target, "run_coverage_features", None)
    if not callable(fn):
        return ()
    try:
        feats = fn()
    except Exception:  # noqa: BLE001 -- optional instrumentation is best-effort
        return ()
    return feats or ()


def behaviour_features(target: Any, sequence: list[Any]) -> tuple[list[int], Any, list[str]]:
    """Execute ``sequence`` and return (bitmap buckets, final state, violations).

    The target is driven step by step (rather than through ``run_sequence``) so
    each intermediate state contributes its own coverage -- a sequence that
    passes *through* a novel state is rewarded even if it ends somewhere already
    seen, which is what lets the corpus retain the useful *prefix* of a
    multi-step exploit.

    A step that raises is treated as a dead branch (the edge is still recorded),
    never as a crash: an invalid transaction is feedback, not a failure of the
    fuzzer.
    """
    state = target.reset()
    buckets: set[int] = set()
    prev_op: str | None = None
    for step in sequence:
        buckets.add(_hash_feature(("op", step.action)))
        if prev_op is not None:
            buckets.add(_hash_feature(("edge", prev_op, step.action)))
        buckets.add(_hash_feature(("actor_op", step.actor, step.action)))
        try:
            target.step(state, step.action, step.actor, dict(step.params))
        except Exception:  # noqa: BLE001 -- an invalid step is a dead branch, not a crash
            prev_op = step.action
            continue
        prev_op = step.action
        # The post-step state is part of the behaviour: a step that reaches a new
        # state is new coverage even if the operation itself is old.
        try:
            snap = target.snapshot(state)
        except Exception:  # noqa: BLE001
            snap = None
        for feat in _state_features(snap):
            buckets.add(_hash_feature(feat))
        # Real instrumentation the target opts into (e.g. EVM opcode/pc coverage).
        for feat in _target_coverage_features(target, "step"):
            buckets.add(_hash_feature(feat))

    for feat in _target_coverage_features(target, "run"):
        buckets.add(_hash_feature(feat))

    violated: list[str] = []
    for inv in target.invariants():
        try:
            if not inv.holds(state):
                violated.append(inv.inv_id)
        except Exception:  # noqa: BLE001 -- an un-evaluable predicate is not a hit
            continue
    return sorted(buckets), state, sorted(set(violated))


@dataclass
class CoverageMap:
    """A bitmap of buckets seen, plus the count of distinct features discovered.

    Mirrors AFL's ``trace_bits``: :meth:`merge` returns how many *new* buckets the
    candidate contributed, which is the "is this input interesting?" test.
    """

    bits: bytearray = field(default_factory=lambda: bytearray(BITMAP_BYTES))
    count: int = 0

    def merge(self, buckets: Iterable[int]) -> int:
        new = 0
        for b in buckets:
            byte, bit = divmod(b, 8)
            mask = 1 << bit
            if not self.bits[byte] & mask:
                self.bits[byte] |= mask
                self.count += 1
                new += 1
        return new

    def has(self, buckets: Iterable[int]) -> bool:
        for b in buckets:
            byte, bit = divmod(b, 8)
            if self.bits[byte] & (1 << bit):
                return True
        return False
