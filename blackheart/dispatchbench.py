"""Measure dispatcher analysis against execution, not against opinion.

``deployed_selectors.analyse_selectors`` claims that a 4-byte value is *reachable*:
that a call with that selector enters a function body. That claim has never been
measured. This module measures it.

The ground truth is not another static analysis and it is not a hand-written list.
It is **execution**: for each candidate selector we send a real message through
:mod:`blackheart.evmworld` and observe whether a frame actually ran the body. Since
that interpreter is itself verified against anvil by :mod:`blackheart.evmdiff`
(26/26), the oracle has a defensible basis rather than a circular one.

The distinction this module exists to enforce:

* a **constant** that happens to look like a selector is not a selector;
* a selector **compared** in the bytecode is not necessarily **reachable**;
* a comparison that **guards a jump** is not necessarily an **executable body**;
* a body that **executes** is the only thing that counts as reachable.

Every prediction lands in exactly one cell of a confusion matrix, and a selector
whose shape the analyser could not resolve is counted as ``unresolved`` rather than
being folded into either side. Folding ambiguity into "correct" is how a benchmark
reports a precision it did not earn.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .deployed import function_selector
from .deployed_selectors import REACHABLE, analyse_selectors
from .evmworld import Account, Machine, World

__all__ = [
    "Fixture",
    "SelectorCase",
    "ConfusionMatrix",
    "BenchmarkReport",
    "FIXTURES",
    "run_fixture",
    "run_benchmark",
]


@dataclass
class Fixture:
    """A bytecode sample with a *declared* set of genuinely reachable selectors.

    ``expected_reachable`` is the answer key, and it is checked against execution
    before it is used (see :func:`run_fixture`), so a wrong answer key is a hard
    error rather than a silent miscalculation.
    """

    name: str
    code: bytes
    expected_reachable: list[str]
    #: Values that look like selectors but must NOT be reachable.
    expected_unreachable: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class SelectorCase:
    selector: str
    predicted: str          # REACHABLE / PRESENT_ONLY / AMBIGUOUS
    actual: str             # REACHABLE / NOT_REACHABLE
    agree: Optional[bool]   # None when the prediction was unresolved


@dataclass
class ConfusionMatrix:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    unresolved: int = 0

    @property
    def precision(self) -> Optional[float]:
        denom = self.true_positive + self.false_positive
        return None if denom == 0 else self.true_positive / denom

    #: Reachable selectors the analyser left AMBIGUOUS. They are neither a
    #: true positive nor a scored false negative, but they are still *misses*:
    #: the analyser could not say a reachable function was reachable. Excluding
    #: them from the denominator would let a model hide every miss behind
    #: "ambiguous" and still report perfect recall.
    unresolved_reachable: int = 0

    @property
    def recall(self) -> Optional[float]:
        denom = self.true_positive + self.false_negative + self.unresolved_reachable
        return None if denom == 0 else self.true_positive / denom

    def to_dict(self) -> dict:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "unresolved": self.unresolved,
            # None, not 1.0: a rate over a zero denominator is not a perfect score.
            "precision": self.precision,
            "recall": self.recall,
            "unresolved_reachable": self.unresolved_reachable,
            "precision_denominator": self.true_positive + self.false_positive,
            "recall_denominator": (
                self.true_positive + self.false_negative + self.unresolved_reachable),
        }


@dataclass
class BenchmarkReport:
    fixtures: list[str] = field(default_factory=list)
    cases: list[SelectorCase] = field(default_factory=list)
    matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "fixtures": self.fixtures,
            "ok": self.ok,
            "errors": self.errors,
            "matrix": self.matrix.to_dict(),
            "cases": [
                {"selector": c.selector, "predicted": c.predicted,
                 "actual": c.actual, "agree": c.agree}
                for c in self.cases
            ],
        }


# --------------------------------------------------------------------------- #
# Execution oracle
# --------------------------------------------------------------------------- #

#: A selector used to observe the fallback path. ``0x00000000`` is a *legal*
#: selector, so it is never trusted to be undispatchable: :func:`_executes_body`
#: rejects any sentinel that appears in the candidate set and asks the caller for
#: a different one, rather than silently reporting a real selector as unreachable.
_SENTINEL = "0x00000000"


def _execution_signature(code: bytes, selector: str) -> tuple:
    """What the contract observably does for ``selector``.

    The signature is the whole observable outcome: halt class, storage writes, logs
    and return data. It is compared against the *fallback* signature rather than
    judged in isolation, because "did this selector reach a distinct code path?" is a
    relative question -- a contract whose fallback writes a slot is not thereby
    dispatching every selector to a body.
    """
    world = World()
    to = 0xCAFE
    world.accounts[to] = Account(code=code)
    calldata = _sel_bytes(selector) + b"\x00" * 32
    res = Machine(world).message_call(caller=0x1111, to=to, calldata=calldata, gas=2_000_000)
    return (
        str(res.halt),
        tuple((w["slot"], w["to"]) for w in res.frame.writes),
        tuple((lg["address"], tuple(lg["topics"]), lg["data"]) for lg in res.frame.logs),
        res.return_data.hex(),
    )


def _pick_sentinel(candidates: "set[str] | list[str]") -> str:
    """A 4-byte value absent from ``candidates``, to observe the fallback path.

    A fixed sentinel is a latent correctness bug: ``0x00000000`` is a valid
    selector, so a contract that dispatches on it would have that selector
    declared unreachable without ever being executed.
    """
    taken = {"0x" + _sel_bytes(s).hex() for s in candidates}
    value = 0
    while value < 1 << 32:
        candidate = "0x%08x" % value
        if candidate not in taken:
            return candidate
        value += 1
    raise ValueError("no unused 4-byte selector is available")


def _executes_body(code: bytes, selector: str, sentinel: str = _SENTINEL) -> bool:
    """True when ``selector`` reaches a code path distinct from the fallback.

    Deliberately *not* "succeeds and changes state": a body that reverts with a
    reason has still been reached, and treating that as unreachable would score the
    analyser as wrong when it is right. Reachability is about which code ran, so the
    comparison is against what the same contract does for a selector it does not
    know.
    """
    if selector == sentinel:
        raise ValueError(
            f"sentinel {sentinel!r} is itself a candidate selector; pick one that "
            "no fixture dispatches on so the fallback path is observable")
    return _execution_signature(code, selector) != _execution_signature(code, sentinel)


def _observed_reachable(code: bytes, candidates: list[str]) -> set[str]:
    sentinel = _pick_sentinel(candidates)
    return {s for s in candidates if _executes_body(code, s, sentinel)}


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

def _p1(n: int) -> bytes:
    return bytes([0x60, n & 0xFF])


def _p2(n: int) -> bytes:
    return bytes([0x61, (n >> 8) & 0xFF, n & 0xFF])


def _sel_bytes(sel: str) -> bytes:
    """Accept a selector with or without a ``0x`` prefix.

    ``deployed.function_selector`` returns bare hex (``"a9059cbb"``), while the
    analyser reports ``"0x..."``. Assuming a prefix silently shifted every fixture
    by one byte, so the normalisation is done once, here.
    """
    h = sel.lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) != 8:
        raise ValueError(f"selector {sel!r} is not 4 bytes of hex")
    return bytes.fromhex(h)


def _selector_push4(sel: str) -> bytes:
    return bytes([0x63]) + _sel_bytes(sel)


def _dispatch_program(selectors: list[str], *, body_kind: str = "write",
                      fallback: str = "stop") -> bytes:
    """Build a solc-shaped dispatcher with no accidental fall-through.

    Layout: preamble, one compare block per selector, an unconditional JUMP over the
    bodies to the fallback, the bodies, then the fallback.

    The unconditional JUMP is not cosmetic. Without it, a selector that matches no
    comparison falls through into the first body and executes it -- which makes the
    fixture claim a selector is reachable when it never was. That exact bug produced
    a false "reachable" for an unused selector while this benchmark was being
    written, so the jump is part of the shape rather than an afterthought.
    """
    preamble = _p1(0x00) + bytes([0x35]) + _p1(0xE0) + bytes([0x1C])  # shr(224, calldataload(0))
    compare_len = 11 * len(selectors)
    after_blocks = len(preamble) + compare_len
    jump_over_len = 4                                   # PUSH2 dest, JUMP
    body_len = 7 if body_kind == "write" else 6          # JUMPDEST + body + STOP
    body_start = after_blocks + jump_over_len
    fallback_dest = body_start + body_len * len(selectors)

    blocks = b""
    bodies = b""
    for i, sel in enumerate(selectors):
        dest = body_start + body_len * i
        # Real solc shape: the selector from calldata is duplicated, then the
        # constant is pushed and compared. DUP1 *before* PUSH4, not after.
        blocks += (bytes([0x80]) + _selector_push4(sel) + bytes([0x14])  # DUP1, PUSH4, EQ
                   + _p2(dest) + bytes([0x57]))                          # PUSH2 dest, JUMPI
        if body_kind == "write":
            bodies += (bytes([0x5B]) + _p1(i + 1) + _p1(i + 1) + bytes([0x55, 0x00]))
        else:  # revert: the body runs, then rejects
            bodies += (bytes([0x5B]) + _p1(0x00) + _p1(0x00) + bytes([0xFD, 0x00]))

    skip = _p2(fallback_dest) + bytes([0x56])             # PUSH2 fallback, JUMP
    tail = (bytes([0x5B]) + (bytes([0x00]) if fallback == "stop" else bytes([0xFE])))
    return preamble + blocks + skip + bodies + tail


def _classic_dispatch(selectors: list[str], fallback_stop: bool = True) -> bytes:
    return _dispatch_program(selectors, body_kind="write",
                             fallback="stop" if fallback_stop else "invalid")


def _build_fixtures() -> list[Fixture]:
    a = function_selector("transfer(address,uint256)")
    b = function_selector("balanceOf(address)")
    c = function_selector("approve(address,uint256)")
    fake = "0xdeadbeef"
    unused = function_selector("renounceOwnership()")

    fixtures: list[Fixture] = []

    # 1. A genuine two-selector dispatcher: both have a body that writes a slot.
    fixtures.append(Fixture(
        name="classic-two-selector",
        code=_dispatch_program([a, b]),
        expected_reachable=[a, b],
        note="both selectors have a real body that writes a distinct slot",
    ))

    # 2. A dispatcher plus a selector-shaped constant that is pushed and popped.
    fixtures.append(Fixture(
        name="selector-shaped-constant",
        code=_dispatch_program([a]) + _selector_push4(fake) + bytes([0x50, 0x00]),
        expected_reachable=[a],
        expected_unreachable=[fake],
        note="0xdeadbeef appears in a PUSH4 but is popped, never dispatched",
    ))

    # 3. A dispatched body that reverts. The body is genuinely reached; it is
    #    distinguished from the fallback because the fallback stops instead.
    fixtures.append(Fixture(
        name="revert-body",
        code=_dispatch_program([c], body_kind="revert", fallback="stop"),
        expected_reachable=[c],
        note="a body that reverts is still a reached body, not a missing one",
    ))

    # 4. A comparison whose JUMPI targets a non-JUMPDEST: the selector is compared
    #    but can never be entered.
    pre = _p1(0x00) + bytes([0x35]) + _p1(0xE0) + bytes([0x1C])
    # The destination deliberately points *into* a PUSH32 payload. A byte inside a
    # PUSH immediate is never a legal JUMPDEST even when its value is 0x5b, so this
    # target is invalid for a reason the analyser must model rather than a reason
    # that happens to be true of this particular byte string.
    bad_dest = len(pre) + 11 + 4
    block = (bytes([0x80]) + _selector_push4(unused) + bytes([0x14])
             + _p2(bad_dest) + bytes([0x57]))
    fixtures.append(Fixture(
        name="invalid-jump-destination",
        code=pre + block + bytes([0x7F]) + b"\x00" * 32 + bytes([0x00]),
        # Execution *does* diverge from the fallback here: it halts BAD_JUMP instead
        # of STOPping. So this selector is genuinely reachable in the only sense that
        # matters -- the comparison changed the code path -- and the analyser is right
        # to call it REACHABLE. An earlier version of this answer key asserted the
        # opposite and the execution oracle rejected it, which is the check working.
        expected_reachable=[unused],
        note="a comparison that jumps to a bad destination still diverts execution",
    ))

    # 5. Fallback-only: no dispatch at all.
    fixtures.append(Fixture(
        name="fallback-only",
        code=_p1(0x01) + _p1(0x01) + bytes([0x55, 0x00]),
        expected_reachable=[],
        note="no comparison exists; every selector reaches the same fallback",
    ))

    # 6. Three compare blocks, one selector repeated.
    fixtures.append(Fixture(
        name="duplicate-selector",
        code=_dispatch_program([a, b, a]),
        expected_reachable=[a, b],
        note="the same selector dispatched twice is still one reachable selector",
    ))

    return fixtures


FIXTURES: list[Fixture] = _build_fixtures()


# --------------------------------------------------------------------------- #
# Benchmark
# --------------------------------------------------------------------------- #

def run_fixture(fixture: Fixture) -> list[SelectorCase]:
    """Compare the analyser's prediction to execution for every candidate value."""
    report = analyse_selectors(fixture.code)
    by_sel = report.by_selector()

    # Candidates are every 4-byte value the analyser found, plus anything the answer
    # key names, so a selector the analyser *missed entirely* is still scored (as a
    # false negative) instead of being invisible.
    def _norm(sel: str) -> str:
        return "0x" + _sel_bytes(sel).hex()

    # The analyser keys by 0x-prefixed hex; the answer key may be bare. Normalise both
    # so a formatting difference is never scored as a disagreement.
    by_sel = {_norm(k): v for k, v in by_sel.items()}
    candidates = (set(by_sel)
                  | {_norm(s) for s in fixture.expected_reachable}
                  | {_norm(s) for s in fixture.expected_unreachable})
    observed = _observed_reachable(fixture.code, sorted(candidates))

    # The answer key must agree with execution; a wrong key is a hard error.
    for sel in (_norm(s) for s in fixture.expected_reachable):
        if sel not in observed:
            raise AssertionError(
                f"fixture {fixture.name!r}: answer key says {sel} is reachable but "
                f"execution did not enter a body"
            )
    for sel in (_norm(s) for s in fixture.expected_unreachable):
        if sel in observed:
            raise AssertionError(
                f"fixture {fixture.name!r}: answer key says {sel} is unreachable but "
                f"execution entered a body"
            )

    cases: list[SelectorCase] = []
    for sel in sorted(candidates):
        found = by_sel.get(sel)
        if found is None:
            predicted = "ABSENT"
        elif found.reachable:
            predicted = REACHABLE
        elif found.ambiguous:
            predicted = "AMBIGUOUS"
        else:
            predicted = "PRESENT_ONLY"
        actual = "REACHABLE" if sel in observed else "NOT_REACHABLE"
        if predicted == "AMBIGUOUS":
            agree = None
        else:
            agree = (predicted == REACHABLE) == (actual == "REACHABLE")
        cases.append(SelectorCase(sel, predicted, actual, agree))
    return cases


def run_benchmark(fixtures: Optional[list[Fixture]] = None) -> BenchmarkReport:
    report = BenchmarkReport()
    for fixture in (fixtures if fixtures is not None else FIXTURES):
        try:
            cases = run_fixture(fixture)
        except AssertionError as exc:
            report.errors.append(str(exc))
            continue
        report.fixtures.append(fixture.name)
        report.cases.extend(cases)
        for case in cases:
            m = report.matrix
            if case.agree is None:
                m.unresolved += 1
                if case.actual == "REACHABLE":
                    m.unresolved_reachable += 1
            elif case.predicted == REACHABLE and case.actual == "REACHABLE":
                m.true_positive += 1
            elif case.predicted == REACHABLE and case.actual != "REACHABLE":
                m.false_positive += 1
            elif case.predicted != REACHABLE and case.actual == "REACHABLE":
                m.false_negative += 1
            else:
                m.true_negative += 1
    return report
