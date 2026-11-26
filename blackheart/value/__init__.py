"""Universal value and profitability engine.

A violated invariant is not yet a finding. The question BLACKHEART answers is an
*economic* one -- "receive more assets than I am entitled to, bypass a
restriction, or make another user's position absorb my loss" -- so the layer that
turns a broken property into a demonstrated financial impact is a first-class
capability, not a per-target afterthought.

This module is the single, target-agnostic answer to "did the attacker profit,
how much, and where did the value come from?". It is deliberately **structural**:
it carries no per-target table of field names. It classifies every field of a
target's own ``snapshot`` by *structure* (a mapping of ``actor -> int``, or a
nested ``actor -> {symbol: int}``) and by *name tokens*, so the same engine tracks
value on an ERC4626 vault, a lending market, a permit token, an options market,
and any future target -- including ones whose fields are named in ways this module
has never seen. That is what makes the capability universal: every caller
(discovery, the state-space search, the demonstrations pipeline, the CLI) reads
the same model instead of re-deriving it, so the accounting cannot drift between
engines. The priced account is also carried on every :class:`blackheart.models.Finding`
(``Finding.economic``) and rendered into every report, so it travels with a
finding through the campaign, engine and report layers rather than being
re-derived (or forgotten) per pipeline.

What it computes, per sequence:

  * the attacker's **net capital** before and after (owned assets minus
    obligations) and the realised **profit**;
  * **victim loss** -- value absorbed by every other participant, and
    **protocol loss** -- value that left the protocol itself;
  * a **conservation residual** -- the change in the sum of every actor's net
    capital. A positive residual is value created from nothing (unbacked minting);
    it is the unit-agnostic signature of the classic value-creation bug;
  * **repeatability** -- can the profitable sequence be run again from a fresh
    state (a one-shot extraction versus a repeatable drain).

Honesty rules, enforced in code:

  * never invent a balance -- only what the target's own ``snapshot`` exposes;
  * a permission (``allowance``) is not capital; an obligation (``debt``) is
    subtracted;
  * a step that reverts contributes no change and is never counted as profit;
  * a wraparound (``2**256``) value is an accounting artifact, not spendable
    value, and is excluded from realised profit;
  * a state change with no value movement is a *state manipulation*, not a
    demonstrated financial impact;
  * a snapshot that is not a mapping, or that exposes no attacker-identifiable
    balance, yields an explicitly untracked account -- never an assumed zero and
    never an assumed impact.

Nothing here decides exploitability. It quantifies the consequence of a violation
the search already found, so a theoretical inconsistency can be told apart from an
exploitable one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# --------------------------------------------------------------------------- #
# Field classification
# --------------------------------------------------------------------------- #

class FieldKind(str, Enum):
    """What a snapshot field means for value accounting."""

    ASSET = "asset"            # per-actor value the actor owns or can redeem
    LIABILITY = "liability"    # per-actor obligation, subtracted from capital
    PERMISSION = "permission"  # a grant (allowance); neither owned nor owed
    PROTOCOL = "protocol"      # protocol-held scalar value (not per-actor)
    OTHER = "other"            # prices, counters, flags -- not value


# Name tokens. The match is a lower-cased *substring*, so both singular and plural
# spellings ("balance"/"balances", "share"/"shares") classify identically; that is
# the fix for a field-name allow-list that missed the plural forms the real
# targets actually use. Order of the checks in ``classify_field`` makes a name
# that contains several tokens resolve deterministically.
_LIABILITY_TOKENS = ("debt", "borrow", "owe", "liab", "obligation")
_PERMISSION_TOKENS = ("allow", "approv", "authoriz", "permit")
_ASSET_TOKENS = (
    "balance", "wallet", "cash", "reserve", "collateral", "escrow", "refund",
    "credit", "paid", "share", "deposit", "owed", "seiz", "settl", "suppl",
    "position", "claim", "overpay", "vault", "redeem", "underlying", "fund",
    "quote", "idle", "asset", "locked",
)
# Fields that look value-like but are not tracked value: prices, flow counters,
# aggregate duplicates of per-actor sums, and *derived valuation views*. The last
# group matters for correctness, not just tidiness: a ``redeemable`` field is the
# redemption value of an actor's share balance -- the same holding expressed in
# the underlying unit -- so counting it *and* the share balance would double the
# actor's capital and fabricate a profit on an ordinary deposit.
_NON_VALUE_TOKENS = (
    "price", "rate", "fee", "count", "num_", "n_", "times", "round", "index",
    "total", "initialized", "owner", "flag", "seed", "nonce", "liquidations",
    "improper", "last_", "signed", "spent", "authorized", "reference", "redeem",
    "valuation", "worth",
)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _flatten_actor_map(value: Any) -> Optional[dict[str, int]]:
    """Return ``{actor: int}`` for a per-actor value field, else ``None``.

    Accepts a flat ``{actor: int}`` and a nested ``{actor: {symbol: int}}`` (a
    portfolio of holdings, summed per actor). Any other shape -- a bare int, a
    string, a list, an empty mapping -- is not a per-actor value map.
    """
    if not isinstance(value, dict) or not value:
        return None
    out: dict[str, int] = {}
    for actor, held in value.items():
        if _is_int(held):
            out[str(actor)] = held
        elif isinstance(held, dict) and held and all(_is_int(x) for x in held.values()):
            out[str(actor)] = sum(held.values())
        else:
            return None
    return out


def classify_field(name: str, value: Any = None) -> FieldKind:
    """Classify a snapshot field into a :class:`FieldKind`.

    Structure first: a field that is a mapping of actor -> number is per-actor
    value. Name tokens decide whether that value is owned (asset), owed
    (liability), or merely granted (permission), and whether a non-mapping value
    is a protocol scalar or a non-value field.

    An **empty** mapping is ambiguous by structure alone, so its name decides: a
    value-like name with an empty mapping is an asset map that is simply not yet
    populated (a vault whose shareholders appear only after the first deposit).
    Treating it as an asset map -- not a scalar -- is what lets the engine track a
    target whose holdings start empty and fill in as the sequence runs.
    """
    n = str(name).lower()
    is_map = isinstance(value, dict)
    per_actor = _flatten_actor_map(value) is not None
    if any(t in n for t in _LIABILITY_TOKENS):
        return FieldKind.LIABILITY if (per_actor or (is_map and not value)) else FieldKind.OTHER
    if any(t in n for t in _PERMISSION_TOKENS):
        # A permission is per-actor (an allowance granted to one account). A
        # scalar whose name merely contains the token (``total_authorized``) is a
        # counter, not a grant.
        return FieldKind.PERMISSION if (per_actor or (is_map and not value)) else FieldKind.OTHER
    if any(t in n for t in _NON_VALUE_TOKENS):
        return FieldKind.OTHER
    if any(t in n for t in _ASSET_TOKENS):
        if per_actor or (is_map and not value):
            return FieldKind.ASSET
        return FieldKind.PROTOCOL
    # No token matched. A populated per-actor numeric mapping is an asset by
    # structure -- the fallback that tracks a target whose value fields have names
    # this module has never seen (an options market's ``yes``/``no`` holdings).
    if per_actor:
        return FieldKind.ASSET
    return FieldKind.OTHER


# Actor names that denote the attacker. A campaign's adversary is ordinary and
# unprivileged; the model names it in the fixture. Recognising the *family*
# (``attacker``, ``attacker2``, ``user``, ``liquidator``, ...) is what makes the
# accounting work on targets that model several attacker-controlled accounts.
_ATTACKER_NAMES = frozenset(
    {"attacker", "user", "anonymous", "liquidator", "exploiter", "hacker", "eve"}
)
_ATTACKER_PREFIXES = ("attacker", "exploiter", "hacker")


def is_attacker_actor(name: str) -> bool:
    """True when an actor name denotes the attacker (or an attacker-controlled
    account). Conservative: a victim-like name never matches."""
    n = str(name).lower()
    if n in _ATTACKER_NAMES:
        return True
    return any(n.startswith(p) for p in _ATTACKER_PREFIXES)


# --------------------------------------------------------------------------- #
# The value model of one snapshot
# --------------------------------------------------------------------------- #

class ValueModel:
    """A structural read of one snapshot: which fields hold value, and for whom.

    Built once per snapshot and reused, so a caller can price the same state from
    several angles (attacker profit, victim loss, conservation) without
    re-classifying.
    """

    def __init__(self, snapshot: Any) -> None:
        self.kinds: dict[str, FieldKind] = {}
        self.actor_maps: dict[str, dict[str, int]] = {}
        self.scalars: dict[str, int] = {}
        if isinstance(snapshot, dict):
            for name, value in snapshot.items():
                kind = classify_field(name, value)
                self.kinds[str(name)] = kind
                if kind in (FieldKind.ASSET, FieldKind.LIABILITY, FieldKind.PERMISSION):
                    flat = _flatten_actor_map(value)
                    if flat is not None:
                        self.actor_maps[str(name)] = flat
                elif kind is FieldKind.PROTOCOL and _is_int(value):
                    self.scalars[str(name)] = int(value)

    # -- per-actor capital ------------------------------------------------ #
    def actors(self) -> set[str]:
        names: set[str] = set()
        for field_map in self.actor_maps.values():
            names.update(field_map)
        return names

    def net_capital(self, actor: str) -> int:
        """Owned assets minus obligations for one actor.

        A permission is neither, so it is not counted: this is what stops a
        doubled permit -- or a borrow that raises cash and debt equally -- from
        being reported as profit.
        """
        total = 0
        for name, kind in self.kinds.items():
            field_map = self.actor_maps.get(name)
            if field_map is None:
                continue
            if kind is FieldKind.ASSET:
                total += field_map.get(actor, 0)
            elif kind is FieldKind.LIABILITY:
                total -= field_map.get(actor, 0)
        return total

    def attacker_actor(self) -> Optional[str]:
        """The attacker's actor name among value-bearing fields, or ``None``.

        An actor that appears solely in a permission field has no capital to
        track, so it is not returned.
        """
        for name, field_map in self.actor_maps.items():
            if self.kinds.get(name) not in (FieldKind.ASSET, FieldKind.LIABILITY):
                continue
            for actor in field_map:
                if is_attacker_actor(actor):
                    return actor
        return None

    def system_total(self) -> int:
        """Sum of every actor's net capital -- conserved under pure transfers."""
        return sum(self.net_capital(a) for a in self.actors())

    def attacker_total(self) -> int:
        """Sum of net capital across every attacker-controlled account."""
        return sum(self.net_capital(a) for a in self.actors() if is_attacker_actor(a))

    def to_dict(self) -> dict:
        return {
            "fields": {k: v.value for k, v in self.kinds.items()},
            "actors": sorted(self.actors()),
        }


def victim_loss(start: ValueModel, end: ValueModel, attacker: str) -> int:
    """Value absorbed by non-attacker participants between two snapshots.

    Only *asset* fields count: a decrease in an obligation (debt) or in a
    permission (allowance) is a benefit, not a loss. The comparison is per field
    and per actor, so a fall in one asset is never netted against a rise in
    another.
    """
    loss = 0
    for name, kind in start.kinds.items():
        if kind is not FieldKind.ASSET:
            continue
        start_map = start.actor_maps.get(name, {})
        end_map = end.actor_maps.get(name, {})
        for actor, start_v in start_map.items():
            if actor == attacker or is_attacker_actor(actor):
                continue
            end_v = end_map.get(actor, start_v)
            if end_v < start_v:
                loss += start_v - end_v
    return loss


# --------------------------------------------------------------------------- #
# The account
# --------------------------------------------------------------------------- #

#: Values at or above this are outside the domain of any real balance and are the
#: signature of a wraparound (2**256 arithmetic). A wrapped balance is an
#: accounting artifact, not spendable value. The bound is 2**128: an 18-decimal
#: token with a total supply of 3.4e38 units is already absurd, while a 2**256
#: wraparound lands near 1.2e77, so this separates the two without ever flagging a
#: real amount.
_ARITH_BOUND = 2 ** 128


@dataclass
class ValueAccount:
    """The attacker's profit-and-loss account for one sequence."""

    case_id: str = ""
    invariant_id: str = ""
    sequence: list[dict] = field(default_factory=list)
    attacker: str = ""
    attacker_initial_capital: int = 0
    attacker_final_capital: int = 0
    attacker_profit: int = 0
    victim_loss: int = 0
    protocol_loss: int = 0
    per_step_profit: list[int] = field(default_factory=list)
    #: Change in the sum of every actor's net capital. Positive == value created.
    conservation_residual: int = 0
    #: Positive part of the residual: value created from nothing (unbacked).
    value_created: int = 0
    repeatable: bool = False
    max_extraction: int = 0
    profitable: bool = False
    state_changed: bool = False
    bounded_values: bool = False
    reverted_steps: int = 0
    financial_impact_established: bool = False
    tracked: bool = False
    field_kinds: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "invariant_id": self.invariant_id,
            "sequence": self.sequence,
            "attacker": self.attacker,
            "attacker_initial_capital": self.attacker_initial_capital,
            "attacker_final_capital": self.attacker_final_capital,
            "attacker_profit": self.attacker_profit,
            "victim_loss": self.victim_loss,
            "protocol_loss": self.protocol_loss,
            "per_step_profit": self.per_step_profit,
            "conservation_residual": self.conservation_residual,
            "value_created": self.value_created,
            "repeatable": self.repeatable,
            "max_extraction": self.max_extraction,
            "profitable": self.profitable,
            "state_changed": self.state_changed,
            "bounded_values": self.bounded_values,
            "reverted_steps": self.reverted_steps,
            "financial_impact_established": self.financial_impact_established,
            "tracked": self.tracked,
            "field_kinds": self.field_kinds,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def _snapshot(target: Any, state: Any) -> Optional[dict]:
    """Read a target's snapshot, tolerating a non-mapping or a raising target."""
    try:
        snap = target.snapshot(state)
    except Exception:  # noqa: BLE001 -- a target that cannot snapshot has no value
        return None
    return snap if isinstance(snap, dict) else None


def _has_unbounded(values: list[int]) -> bool:
    return any(abs(v) >= _ARITH_BOUND for v in values)


def analyse(target: Any, sequence: list[Any], invariant_id: str = "",
            case_id: str = "", *, repeat: int = 2) -> ValueAccount:
    """Quantify the economic consequence of a sequence.

    ``target`` implements the sequence-target protocol (``reset`` / ``step`` /
    ``snapshot``). The sequence is run from a fresh state; the attacker's capital
    is tracked per step, and the value flow between the attacker, the other
    participants, and the protocol is diffed from the target's own snapshots.
    """
    acct = ValueAccount(
        case_id=case_id or getattr(target, "name", ""),
        invariant_id=invariant_id,
        sequence=[s.to_dict() for s in sequence],
    )

    start_state = target.reset()
    start_snap = _snapshot(target, start_state)
    if start_snap is None:
        acct.notes.append("snapshot is not a mapping; value not tracked")
        return acct

    start_model = ValueModel(start_snap)
    acct.field_kinds = {k: v.value for k, v in start_model.kinds.items()}

    # Run the sequence once, tracking the attacker's capital after each step. A
    # step that reverts (raises) contributes no change and is not counted.
    state = target.reset()
    per_step_models: list[ValueModel] = [start_model]
    reverted = 0
    for step in sequence:
        try:
            target.step(state, step.action, step.actor, dict(step.params))
        except Exception:  # noqa: BLE001 -- an invalid step is feedback, not a crash
            reverted += 1
            per_step_models.append(per_step_models[-1])
            continue
        per_step_models.append(ValueModel(_snapshot(target, state) or {}))

    end_snap = _snapshot(target, state)
    if end_snap is None:
        acct.notes.append("final snapshot is not a mapping; value not tracked")
        return acct
    end_model = ValueModel(end_snap)
    acct.reverted_steps = reverted

    # Identify the attacker from every state the sequence passed through. A target
    # may start with empty holdings (a vault whose shareholders appear only after
    # the first deposit), so the attacker is often identifiable only once the
    # sequence has run -- never declare the account untracked while the end state
    # names an attacker.
    attacker = start_model.attacker_actor() or end_model.attacker_actor()
    if attacker is None:
        for m in per_step_models:
            attacker = m.attacker_actor()
            if attacker is not None:
                break
    if attacker is None:
        acct.notes.append("no attacker-identifiable balance in snapshot; capital not tracked")
        return acct

    acct.tracked = True
    acct.attacker = attacker
    acct.attacker_initial_capital = start_model.attacker_total()

    # Per-step profit from the recorded states. A reverted step appends the
    # previous model unchanged, so its delta is naturally zero.
    prev = per_step_models[0].attacker_total()
    for model in per_step_models[1:]:
        now = model.attacker_total()
        acct.per_step_profit.append(now - prev)
        prev = now

    acct.attacker_final_capital = end_model.attacker_total()
    acct.attacker_profit = acct.attacker_final_capital - acct.attacker_initial_capital
    acct.victim_loss = victim_loss(start_model, end_model, attacker)

    # Protocol loss: protocol-held scalar value that decreased (value that left
    # the protocol itself, e.g. a reserve going negative).
    protocol_loss = 0
    for k, start_v in start_model.scalars.items():
        end_v = end_model.scalars.get(k, start_v)
        if end_v < start_v:
            protocol_loss += start_v - end_v
    acct.protocol_loss = protocol_loss

    # Conservation residual: the change in the sum of every actor's net capital.
    # A pure transfer conserves it; value created from nothing raises it. This is
    # the unit-agnostic signature of unbacked minting, and it is what catches a
    # value-creation bug the attacker's own balance delta may not show.
    acct.conservation_residual = end_model.system_total() - start_model.system_total()
    acct.value_created = max(0, acct.conservation_residual)

    # A wraparound/overflow is an accounting artifact, not spendable value: flag
    # it and refuse to treat it as realised profit.
    tracked = (list(acct.per_step_profit)
               + [acct.attacker_initial_capital, acct.attacker_final_capital,
                  acct.attacker_profit, acct.victim_loss, acct.protocol_loss,
                  acct.conservation_residual])
    if _has_unbounded(tracked):
        acct.bounded_values = True
        acct.notes.append("unbounded value present (overflow/wraparound); "
                          "profit not counted as realized")
        acct.attacker_profit = 0
        acct.value_created = 0

    # Did the sequence change observable state at all? A "profitable" verdict is
    # only meaningful if something moved.
    acct.state_changed = start_snap != end_snap

    # Repeatability: run the same sequence again; if the attacker profits both
    # times, the extraction is repeatable.
    profits: list[int] = []
    for _ in range(max(1, repeat)):
        s2 = target.reset()
        for step in sequence:
            try:
                target.step(s2, step.action, step.actor, dict(step.params))
            except Exception:  # noqa: BLE001
                continue
        snap2 = _snapshot(target, s2) or {}
        profits.append(ValueModel(snap2).attacker_total() - acct.attacker_initial_capital)
    acct.repeatable = bool(profits) and all(p > 0 for p in profits)
    acct.max_extraction = max(profits) if profits else 0

    acct.profitable = acct.attacker_profit > 0
    if acct.profitable and not acct.repeatable:
        acct.notes.append("profitable but not repeatable from a fresh state (one-shot)")
    if acct.attacker_profit > 0 and acct.victim_loss == 0 and acct.protocol_loss == 0:
        acct.notes.append("attacker gain not matched by any tracked loss (unbacked value)")

    # A demonstrated financial impact requires value to actually move between
    # parties: the attacker nets a gain, a counterparty takes a loss, or the
    # protocol loses value. The conservation residual is reported as a *diagnostic*
    # but does not by itself establish impact: a snapshot may expose a cumulative
    # flow counter (``deposited``) alongside real holdings, so a positive residual
    # is a signal to investigate, not proof of value creation. A sequence that only
    # flips a flag or doubles a permission is a state manipulation, not a
    # demonstrated financial impact.
    acct.financial_impact_established = bool(
        acct.attacker_profit > 0 or acct.victim_loss > 0 or acct.protocol_loss > 0)
    if acct.value_created > 0 and not acct.financial_impact_established:
        acct.notes.append("summed value fields grew but no party was shown to gain or "
                          "lose; treat the conservation residual as a lead, not impact")
    if acct.state_changed and not acct.financial_impact_established:
        acct.notes.append("state changed with no established value movement "
                          "(state manipulation, not a demonstrated financial impact)")
    return acct


def profit_of(target: Any, sequence: list[Any]) -> int:
    """The attacker's realised net profit for a sequence (cheap, single run).

    The search uses this as a ranking signal: a sequence that moves value toward
    the attacker is worth exploring further, regardless of which invariant it
    happened to break.
    """
    start = _snapshot(target, target.reset())
    if start is None:
        return 0
    model = ValueModel(start)
    if model.attacker_actor() is None:
        return 0
    before = model.attacker_total()
    state = target.reset()
    for step in sequence:
        try:
            target.step(state, step.action, step.actor, dict(step.params))
        except Exception:  # noqa: BLE001
            continue
    end = _snapshot(target, state)
    if end is None:
        return 0
    return ValueModel(end).attacker_total() - before


__all__ = [
    "FieldKind",
    "ValueAccount",
    "ValueModel",
    "analyse",
    "classify_field",
    "is_attacker_actor",
    "profit_of",
    "victim_loss",
]
