"""Category-linked rules over a Rust / Substrate or Solana / Anchor surface.

Every rule answers the same question the Solidity rules do, in a different
environment: what can an ordinary signed account do here that it should not?
Only *dispatchables* (functions inside ``#[pallet::call]``) are judged, because
that is the attacker-reachable surface -- a ``pub fn`` on ``Pallet<T>`` that no
dispatchable calls is not reachable by an unprivileged account, and claiming
otherwise would be a false lead.

A flag is a lead, never a finding. Each rule carries the question that would
turn it into one, so the next step is always a test, not a report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from ..objectives import _OBJECTIVE_CATALOG
from .flags import CandidateFlag
from .rust import RustFunction, RustModule, RustSurfaceReport


@dataclass(frozen=True)
class RustRule:
    name: str
    category: str
    severity: str
    rationale: str
    question: str
    test: Callable[[RustModule, RustFunction], Optional[str]]


def _snippet(func: RustFunction, pattern: str, width: int = 110) -> Optional[str]:
    m = re.search(pattern, func.body)
    if not m:
        return None
    start = max(0, m.start() - 30)
    return " ".join(func.body[start:start + width].split())


def _has(body: str, pattern: str) -> bool:
    return re.search(pattern, body) is not None


def _panic_in_dispatchable(m: RustModule, f: RustFunction) -> Optional[str]:
    return _snippet(f, r"\.unwrap\(\)|\.expect\(|panic!|todo!|unimplemented!|unreachable!")


def _unbounded_storage_iteration(m: RustModule, f: RustFunction) -> Optional[str]:
    # `::iter()` is as common as `.iter()`: a storage map is iterated through its
    # own path, not through a value.
    return _snippet(f, r"(\.|::)(iter|iter_keys|iter_values)\(\)|for\s+\w+\s+in\s+Self::")


def _saturating_arithmetic(m: RustModule, f: RustFunction) -> Optional[str]:
    if not _has(f.body, r"balance|amount|transfer|reserve|deposit|withdraw|issuance"):
        return None
    return _snippet(f, r"\.saturating_(add|sub|mul|div|accrue|reduce)")


def _unchecked_cast(m: RustModule, f: RustFunction) -> Optional[str]:
    return _snippet(f, r"\bas\s+(u8|u16|u32|u64|u128|i8|i16|i32|i64|i128|BalanceOf<T>)\b")


def _multiplication_without_checked(m: RustModule, f: RustFunction) -> Optional[str]:
    if _has(f.body, r"checked_mul|saturating_mul|const\s*\*"):
        return None
    m = re.search(r"([A-Za-z_][\w.\[\]]*)\s*\*\s*([A-Za-z_][\w.\[\]]*)", f.body)
    if not m:
        return None
    start = max(0, m.start() - 30)
    return " ".join(f.body[start:start + 110].split())


def _no_origin_check(m: RustModule, f: RustFunction) -> Optional[str]:
    # Anchor's authorization lives in the Accounts struct (`Signer`, `has_one`,
    # `constraint`), not in the handler body. Judging the body would flag every
    # Anchor instruction with a false "no origin check".
    if m.anchor:
        return None
    if _has(f.body, r"ensure!|Signed|Root|NoPermission|BadOrigin|ok_or\(|has_role|who\s*==|origin"):
        return None
    return "dispatchable body has no origin, signature or permission check"


def _missing_weight_annotation(m: RustModule, f: RustFunction) -> Optional[str]:
    if m.anchor:
        return None  # Anchor has no FRAME weights; compute is charged by the runtime
    if f.weight:
        return None
    return "dispatchable declares no #[pallet::weight(...)]"


def _event_before_state_change(m: RustModule, f: RustFunction) -> Optional[str]:
    event = f.body.find("deposit_event")
    if event == -1:
        return None
    write = re.search(r"::<T, I>::(insert|mutate|put|remove|kill)|::<T>::(insert|mutate|put|remove)", f.body)
    if write is None or write.start() < event:
        return None
    return " ".join(f.body[event:event + 110].split())


def _time_window_comparison(m: RustModule, f: RustFunction) -> Optional[str]:
    return _snippet(f, r"(now\(\)|timestamp|block_number\(\))[^;\n]{0,40}(<|>|<=|>=|\+|-)")


def _unchecked_transfer_result(m: RustModule, f: RustFunction) -> Optional[str]:
    m = re.search(r"(let\s+_\s*=\s*[^;\n]*transfer|\.transfer\([^;\n]*\)\s*\.ok\(\))", f.body)
    if not m:
        return None
    start = max(0, m.start() - 30)
    return " ".join(f.body[start:start + 110].split())


# ---------------------------------------------------------------------------
# Solana / Anchor
# ---------------------------------------------------------------------------

#: Account types Anchor does not validate by itself: the handler must check the
#: owner, address or seeds, or an unprivileged caller chooses what is written.
_ANCHOR_UNCHECKED_TYPES = ("UncheckedAccount", "AccountInfo")

#: Constraints that bind an account to a known address, owner or PDA. Anchor's
#: own typed wrappers (AccountLoader, Account, Signer, SystemAccount) carry
#: their own owner/initialisation checks, so only the raw types are judged.
_ANCHOR_BINDINGS = (
    "address",
    "owner",
    "seeds",
    "has_one",
    "constraint",
    "executable",
    "token::mint",
    "token::authority",
    "associated_token::",
    "sysvar::",
)


def _anchor_fields(m: RustModule, f: RustFunction):
    if not f.accounts_struct:
        return ()
    accounts = m.accounts_for(f.accounts_struct)
    return accounts.fields if accounts else ()


def anchor_unbound_writable(m: RustModule, f: RustFunction) -> tuple[str, ...]:
    """Writable raw accounts of an Anchor handler that no field binds.

    Anchor binds a field through its own ``#[account(...)]`` or through
    *another* field's ``has_one = <name>`` (``DriftDeposit`` pins the raw
    ``integration_acc_3`` via the ``bank`` field). A ``/// CHECK:`` comment is
    stripped and is an assertion, not a check, so it never clears a field.
    """
    fields = _anchor_fields(m, f)
    bound = {
        name
        for other in fields
        for name in re.findall(r"has_one\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", other.attrs)
    }
    out: list[str] = []
    for field in fields:
        if field.name in bound:
            continue
        if not re.search(r"\bmut\b", field.attrs):
            continue
        if not any(t in field.type for t in _ANCHOR_UNCHECKED_TYPES):
            continue
        if any(b in field.attrs for b in _ANCHOR_BINDINGS):
            continue
        out.append(
            f"`{field.name}: {field.type}` is writable and carries no "
            f"address/owner/seeds/has_one/constraint check"
        )
    return tuple(out)


def _anchor_unchecked_writable(m: RustModule, f: RustFunction) -> Optional[str]:
    evidence = anchor_unbound_writable(m, f)
    return evidence[0] if evidence else None


def _anchor_unchecked_cpi(m: RustModule, f: RustFunction) -> Optional[str]:
    if not re.search(r"\binvoke(_signed)?\s*\(", f.body):
        return None
    if re.search(r"\.key\(\)\s*==|program_id\s*\(\)\s*==|address\s*=", f.body):
        return None
    return _snippet(f, r"\binvoke(_signed)?\s*\(")


RUST_RULES: tuple[RustRule, ...] = (
    RustRule(
        "panic-in-dispatchable", "denial-of-service", "medium",
        "A panic aborts the block author's work. If any signed account can trigger it, "
        "it is a cheap way to fill blocks or halt a pallet.",
        "Can I make this dispatchable panic with an input any signed account can supply?",
        _panic_in_dispatchable,
    ),
    RustRule(
        "unbounded-storage-iteration", "denial-of-service", "medium",
        "Iterating a storage collection inside a dispatchable makes the cost depend on "
        "state an attacker may be able to grow.",
        "Can I grow this collection until the dispatchable exceeds the block weight?",
        _unbounded_storage_iteration,
    ),
    RustRule(
        "saturating-arithmetic-in-value-path", "accounting-manipulation", "medium",
        "Saturating arithmetic silently clamps. In a value path the clamp is either an "
        "unbacked credit or a debit that vanished.",
        "If this clamps, who receives the difference and who loses it?",
        _saturating_arithmetic,
    ),
    RustRule(
        "unchecked-cast", "accounting-manipulation", "medium",
        "`as` truncates. A cast in a value path lets the caller pick an amount whose "
        "narrowed value is not the value that moved.",
        "Can I choose an amount whose cast wraps, and does the wrapped value move funds?",
        _unchecked_cast,
    ),
    RustRule(
        "multiplication-without-checked", "accounting-manipulation", "low",
        "An unchecked multiplication can overflow before the result is bounded.",
        "Can I overflow this multiplication before it is checked?",
        _multiplication_without_checked,
    ),
    RustRule(
        "no-origin-check", "access-control", "medium",
        "A dispatchable with no origin, signature or permission check is callable by "
        "every signed account.",
        "What stops any signed account from calling this?",
        _no_origin_check,
    ),
    RustRule(
        "missing-weight-annotation", "denial-of-service", "low",
        "A dispatchable with no declared weight under-charges its own execution.",
        "Can I make this dispatchable cost more than it declares?",
        _missing_weight_annotation,
    ),
    RustRule(
        "event-before-state-change", "state-inconsistency", "low",
        "Emitting before the state write lets an abort leave an indexer with a record "
        "the chain never committed.",
        "If this aborts after the event, what does an indexer believe that is not true?",
        _event_before_state_change,
    ),
    RustRule(
        "time-window-comparison", "ordering-timing", "low",
        "A time or block window decides eligibility; the caller chooses when to land.",
        "Can I choose the block at which this window opens or closes?",
        _time_window_comparison,
    ),
    RustRule(
        "unchecked-transfer-result", "silent-transfer-failure", "medium",
        "Discarding a transfer result records success for a transfer that failed.",
        "If this transfer returns Err, does the state still record it as done?",
        _unchecked_transfer_result,
    ),
    RustRule(
        "anchor-unchecked-writable-account", "access-control", "medium",
        "An Anchor instruction whose Accounts struct carries a raw writable account "
        "with no address/owner/seeds/has_one/constraint lets the caller choose what "
        "the program writes to, and the handler may not re-check it.",
        "Is this account validated in the handler body before it is written, and can "
        "an unprivileged caller substitute an account they control?",
        _anchor_unchecked_writable,
    ),
    RustRule(
        "anchor-unchecked-cpi", "access-control", "medium",
        "A CPI to a program id taken from an account lets the caller route the call to "
        "a program they control unless the id is checked against a known program.",
        "Is the invoked program id constrained to the expected program, or can I pass "
        "my own program and have it return success?",
        _anchor_unchecked_cpi,
    ),
)

# Linkage invariant: every rule's category must exist in the objective catalog.
_UNKNOWN = sorted({r.category for r in RUST_RULES} - set(_OBJECTIVE_CATALOG))
if _UNKNOWN:  # pragma: no cover - import-time contract violation
    raise RuntimeError(f"rust ingest rules reference unknown objective categories: {_UNKNOWN}")


def evaluate_rust(report: RustSurfaceReport) -> tuple[CandidateFlag, ...]:
    """Run every rule over every dispatchable and return the flags, most severe first."""
    flags: list[CandidateFlag] = []
    for module in report.modules:
        for func in module.dispatchables:
            for rule in RUST_RULES:
                evidence = rule.test(module, func)
                if evidence is None:
                    continue
                flags.append(
                    CandidateFlag(
                        rule=rule.name,
                        category=rule.category,
                        severity_hint=rule.severity,
                        contract=module.name,
                        function=func.name,
                        path=module.path,
                        line=func.line,
                        evidence=evidence,
                        rationale=rule.rationale,
                        question=rule.question,
                    )
                )
    order = {s: i for i, s in enumerate(("medium", "low", "info"))}
    flags.sort(key=lambda f: (order[f.severity_hint], f.path, f.line, f.rule))
    return tuple(flags)
