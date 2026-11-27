"""Passive conformance checks for the documented HyperCore surfaces.

The Hyperliquid bounty page puts "any bug that would cause an outage or **logical
error** on nodes or API servers" in scope, and prohibits mainnet *testing*
(though reading public endpoints is not testing). This module encodes the
*logical invariants the documentation states* and checks live/passive reads
against them. A violation is a reproducible anomaly on an in-scope surface; it is
not, by itself, a confirmed vulnerability -- it must still pass the quality gates
(attacker control, impact, scope).

Invariants encoded (each cites its source):

1. ``borrowLendReserveState`` ledger identity
   (docs/for-developers/api/info-endpoint): ``balance + totalBorrowed`` should
   equal ``totalSupplied`` and ``utilization`` should equal
   ``totalBorrowed / totalSupplied``. A *negative* deviation
   (``balance + borrowed < supplied``) is a real solvency anomaly -- supplier
   claims exceed the assets the reserve can pay. A *positive* deviation is the
   benign direction (uncredited borrower interest sits in the pool) and is
   reported as INFO, not as a finding.

2. Merged outcome book (HIP-4 docs): "an order to buy Yes at price ``p`` is
   equivalent to an order to sell No at price ``1 - p``", so the Yes and No
   books are one merged book. The observable identity is
   ``no_best_ask == 1 - yes_best_bid`` and ``yes_best_ask == 1 - no_best_bid``.
   A crossed merged book (``yes_bid + no_bid > 1`` beyond tolerance) is a
   risk-free-arbitrage logical error.

3. Outcome settlement conservation (HIP-4 docs): Yes pays ``settleFraction`` and
   No pays ``1 - settleFraction``, so one Yes plus one No always redeems exactly
   one quote token.

4. Question negate/merge (HIP-4 docs): for a question of ``n`` outcomes where
   exactly one settles Yes, holding No on every outcome redeems exactly
   ``n - 1`` quote tokens.

The module is pure and network-free at its core (``audit_*`` functions take
already-fetched data); ``fetch_info`` is a thin, injectable transport used by the
CLI so the checks are unit-testable without a network.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

# A reserve whose supplier claims exceed its assets by more than this fraction is
# a real deficit worth reporting. Positive (benign) deviations are not findings.
LEDGER_DEFICIT_REL_TOL = 1e-3
LEDGER_DEFICIT_ABS_TOL = 1.0
# Price tolerance for the merged-book identity (prices are 2-decimal).
BOOK_TOL = 1e-9


@dataclass
class Anomaly:
    """A documented invariant that a passive read violated."""

    invariant: str
    surface: str
    severity: str          # "deficit" | "arbitrage" | "info"
    detail: str
    observed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "invariant": self.invariant,
            "surface": self.surface,
            "severity": self.severity,
            "detail": self.detail,
            "observed": self.observed,
        }


def fetch_info(base_url: str, body: dict, timeout: int = 25) -> Any:
    """POST a public ``info`` request. Read-only; never touches ``exchange``."""
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/info",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
        return json.load(resp)


# --------------------------------------------------------------------------- #
# 1. Borrow/lend reserve ledger identity
# --------------------------------------------------------------------------- #

def check_reserve_ledger(states: list, rel_tol: float = LEDGER_DEFICIT_REL_TOL,
                         abs_tol: float = LEDGER_DEFICIT_ABS_TOL) -> list[Anomaly]:
    out: list[Anomaly] = []
    for token, s in states:
        bal = float(s["balance"])
        borrowed = float(s["totalBorrowed"])
        supplied = float(s["totalSupplied"])
        deficit = supplied - (bal + borrowed)
        if supplied > 0 and deficit > max(abs_tol, rel_tol * supplied):
            out.append(Anomaly(
                invariant="reserve-fully-backed",
                surface=f"borrowLendReserveState token={token}",
                severity="deficit",
                detail=(f"supplier claims ({supplied}) exceed assets the reserve "
                        f"holds ({bal} idle + {borrowed} lent) by {deficit}"),
                observed={"balance": bal, "totalBorrowed": borrowed,
                          "totalSupplied": supplied, "deficit": deficit},
            ))
    return out


def check_reserve_utilization(states: list, tol: float = 1e-6) -> list[Anomaly]:
    out: list[Anomaly] = []
    for token, s in states:
        supplied = float(s["totalSupplied"])
        borrowed = float(s["totalBorrowed"])
        util = float(s["utilization"])
        expected = borrowed / supplied if supplied > 0 else 0.0
        if abs(util - expected) > tol:
            out.append(Anomaly(
                invariant="utilization-matches-ledger",
                surface=f"borrowLendReserveState token={token}",
                severity="info",
                detail=(f"reported utilization {util} != borrowed/supplied "
                        f"{expected}"),
                observed={"reported": util, "expected": expected},
            ))
    return out


# --------------------------------------------------------------------------- #
# 2. Merged outcome book identity
# --------------------------------------------------------------------------- #

def _best(levels: list, side: int) -> tuple[float, float] | None:
    """Return (price, size) of the top level on ``side`` (0=bids, 1=asks)."""
    try:
        book = levels[side]
    except (IndexError, TypeError):
        return None
    if not book:
        return None
    top = book[0]
    return float(top["px"]), float(top["sz"])


def check_merged_book(yes_book: dict, no_book: dict, tol: float = BOOK_TOL) -> list[Anomaly]:
    """Verify Yes and No share one merged book: buy Yes@p == sell No@(1-p)."""
    out: list[Anomaly] = []
    yb = _best(yes_book.get("levels", []), 0)
    ya = _best(yes_book.get("levels", []), 1)
    nb = _best(no_book.get("levels", []), 0)
    na = _best(no_book.get("levels", []), 1)
    if yb and na and abs(na[0] - (1.0 - yb[0])) > tol:
        out.append(Anomaly(
            invariant="merged-book-complementary",
            surface=f"l2Book {yes_book.get('coin')}/{no_book.get('coin')}",
            severity="info",
            detail=(f"No best ask {na[0]} != 1 - Yes best bid {yb[0]} "
                    f"(={1.0 - yb[0]:.4f})"),
            observed={"yes_bid": yb[0], "no_ask": na[0]},
        ))
    if ya and nb and abs(ya[0] - (1.0 - nb[0])) > tol:
        out.append(Anomaly(
            invariant="merged-book-complementary",
            surface=f"l2Book {yes_book.get('coin')}/{no_book.get('coin')}",
            severity="info",
            detail=(f"Yes best ask {ya[0]} != 1 - No best bid {nb[0]} "
                    f"(={1.0 - nb[0]:.4f})"),
            observed={"yes_ask": ya[0], "no_bid": nb[0]},
        ))
    # A crossed merged book: selling Yes and No together yields > 1 quote.
    if yb and nb and yb[0] + nb[0] > 1.0 + tol:
        out.append(Anomaly(
            invariant="merged-book-not-crossed",
            surface=f"l2Book {yes_book.get('coin')}/{no_book.get('coin')}",
            severity="arbitrage",
            detail=(f"Yes best bid {yb[0]} + No best bid {nb[0]} > 1: selling both "
                    f"legs returns more than the guaranteed 1 quote payout"),
            observed={"yes_bid": yb[0], "no_bid": nb[0], "sum": yb[0] + nb[0]},
        ))
    return out


# --------------------------------------------------------------------------- #
# 3 & 4. Settlement and question conservation (pure math, unit-tested)
# --------------------------------------------------------------------------- #

def outcome_settlement(settle_fraction: float, yes_shares: float, no_shares: float) -> float:
    """Documented payout: Yes -> settleFraction, No -> 1 - settleFraction."""
    return settle_fraction * yes_shares + (1.0 - settle_fraction) * no_shares


def settlement_conserves(settle_fraction: float, tol: float = 1e-12) -> bool:
    """One Yes + one No must always redeem exactly one quote token."""
    return abs(outcome_settlement(settle_fraction, 1.0, 1.0) - 1.0) <= tol


def question_no_set_redeems(n_outcomes: int) -> float:
    """Holding No on every outcome of an n-outcome question redeems n-1 quote."""
    return float(n_outcomes - 1)


def check_question_no_set(n_outcomes: int, redeemed: float, tol: float = 1e-9) -> Anomaly | None:
    expected = question_no_set_redeems(n_outcomes)
    if abs(redeemed - expected) > tol:
        return Anomaly(
            invariant="question-no-set-conserves",
            surface=f"question with {n_outcomes} outcomes",
            severity="arbitrage",
            detail=(f"a full No set redeemed {redeemed} quote but the documented "
                    f"value is {expected} (n-1)"),
            observed={"n_outcomes": n_outcomes, "redeemed": redeemed, "expected": expected},
        )
    return None


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

def audit_borrow_lend(fetch: Callable[[dict], Any]) -> list[Anomaly]:
    states = fetch({"type": "allBorrowLendReserveStates"})
    return check_reserve_ledger(states) + check_reserve_utilization(states)


def audit_outcome_books(fetch: Callable[[dict], Any], limit: int | None = None) -> list[Anomaly]:
    meta = fetch({"type": "outcomeMeta"}).get("outcomes", [])
    out: list[Anomaly] = []
    for o in (meta[:limit] if limit else meta):
        oid = o["outcome"]
        yes = fetch({"type": "l2Book", "coin": f"#{oid * 10 + 0}"})
        no = fetch({"type": "l2Book", "coin": f"#{oid * 10 + 1}"})
        if not yes or not no:
            continue
        out.extend(check_merged_book(yes, no))
    return out
