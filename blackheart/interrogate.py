"""Interrogation: turn what the code claims into claims, then try to break them.

Every other engine here starts from a *suspicion* (a rule matched, a class is
modelled) and looks for a witness. This one starts from the opposite direction:
it reads the code's own promises and tries to falsify each one.

A claim is something the source asserts, explicitly or by structure:

* "only an authorized caller can reach this function"
* "every transfer conserves supply"
* "this loop terminates"
* "state is consistent across an external call"
* "initialization happens once"

Each claim is then attacked. The result is never "clean": it is one of

* ``FALSIFIED`` -- a concrete reason the claim does not hold, at ``file:line``;
* ``SURVIVED`` -- this specific check found no counterexample, together with
  what the check could not see;
* ``UNTESTABLE`` -- the claim cannot be decided from the source that was read.

That third state is the point. A claim that is neither broken nor bounded is a
blind spot, and it is written down instead of being quietly dropped. This is the
same discipline ``assure`` applies to searches, applied to assumptions.

Nothing here executes the target: every verdict names its method and its limit,
because a static "survived" is not a proof and must never be read as one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .ingest.rust_flags import anchor_unbound_writable

FALSIFIED = "FALSIFIED"
SURVIVED = "SURVIVED"
UNTESTABLE = "UNTESTABLE"

#: Patterns that mean "the caller was authenticated" in a Solidity function.
#: A bare `msg.sender` is *not* one: `balanceOf[msg.sender]` is the subject of
#: the operation, not a check on it. Counting it as a guard hid the public
#: withdrawal in the very first fixture this engine ran against.
_AUTH_PATTERNS = (
    r"only\w*(owner|admin|role|governance|authoriz|minter|keeper|operator)",
    r"require\s*\(\s*_?msg\.?sender\(?\)?\s*==",
    r"if\s*\(\s*_?msg\.?sender\(?\)?\s*!=",
    r"_checkrole|hasrole|_checkowner|requiresauth|authority\.cancall|isauthorized",
)


def _solidity_guard(func) -> bool:
    """Does this function actually check *who* is calling?"""
    if func.modifiers:
        return True
    body = func.body
    return any(re.search(pattern, body, re.IGNORECASE) for pattern in _AUTH_PATTERNS)

#: Tokens that mean "the origin was authenticated" in a Substrate dispatchable.
#: A bare `ensure!` is *not* one of them: `ensure!(amount > 0)` is a range check,
#: and counting it as authorization would hide exactly the bug this looks for.
_ORIGIN_TOKENS = (
    "ensure_signed", "ensure_root", "ensure_origin", "ensure_none",
    "ensure_signed_or_root", "forceorigin", "nopermission", "badorigin",
    "has_role(", "signedby", "ensure_authorized", "from_runtime_origin",
)

#: Any `ensure_<name>(...)` call is a guard in FRAME's own convention, and pallets
#: use plenty of them: `ensure_sudo`, `ensure_psm_admin`, `ensure_eth_signed`,
#: `ensure_non_contract_if_signed`. A fixed name list missed all of those and
#: reported pallet-sudo's `sudo` as unguarded -- the single worst false positive
#: this check can produce, because it is the one call that must never be open.
#: `ensure!` is a macro and is deliberately not matched.
_ORIGIN_GUARD_CALL = re.compile(r"\bensure_[a-z0-9_]+\s*\(", re.IGNORECASE)

#: An `ensure!` that compares an identity, which *is* an authorization check.
_IDENTITY_ENSURE = re.compile(
    r"ensure!\([^;]{0,160}?(origin|caller|sender|who|admin|owner|account|signer)",
    re.IGNORECASE,
)


def _rust_origin_guard(body: str) -> bool:
    lower = body.lower()
    if any(token in lower for token in _ORIGIN_TOKENS):
        return True
    if _ORIGIN_GUARD_CALL.search(body):
        return True
    return _IDENTITY_ENSURE.search(body) is not None

_WRITE = re.compile(r"[A-Za-z_][\w.\[\]]*\s*(\+=|-=|\*=|/=|=)(?!=)")
_EXTERNAL_CALL = re.compile(
    r"\.call\{|\.call\(|\.delegatecall\(|\.send\(|\.transfer\(|\.staticcall\(|"
    r"\bI[A-Z]\w*\([^)]*\)\.\w+\("
)


@dataclass(frozen=True)
class Claim:
    key: str
    subject: str
    statement: str
    location: str
    question: str


@dataclass(frozen=True)
class Verdict:
    claim: Claim
    status: str
    method: str
    evidence: str = ""
    counterexample: str = ""
    blind_spot: str = ""

    def as_dict(self) -> dict:
        return {
            "claim": self.claim.statement,
            "subject": self.claim.subject,
            "location": self.claim.location,
            "status": self.status,
            "method": self.method,
            "evidence": self.evidence,
            "counterexample": self.counterexample,
            "blind_spot": self.blind_spot,
            "question": self.claim.question,
        }


def _first_line(text: str, pattern: str, width: int = 120) -> Optional[str]:
    m = re.search(pattern, text)
    if not m:
        return None
    start = max(0, m.start() - 30)
    return " ".join(text[start:start + width].split())


# --------------------------------------------------------------------------- #
# Solidity claims
# --------------------------------------------------------------------------- #
def _solidity_claims(report) -> list[Verdict]:
    verdicts: list[Verdict] = []
    for contract in report.contracts:
        for func in contract.functions:
            if not (func.externally_callable and func.state_changing):
                continue
            location = f"{contract.path}:{func.line}"
            guarded = _solidity_guard(func)
            claim = Claim(
                key=f"authorization:{contract.name}.{func.name}",
                subject=f"{contract.name}.{func.name}",
                statement=f"only an authorized caller can change state through {func.name}",
                location=location,
                question=(
                    f"What stops an unprivileged account from calling {func.name} "
                    "and changing state?"
                ),
            )
            if not guarded:
                verdicts.append(
                    Verdict(
                        claim=claim,
                        status=FALSIFIED,
                        method="static: externally callable, state-changing, no guard token",
                        evidence=_first_line(func.body, r"\w+") or func.signature,
                        counterexample=(
                            f"any account can call {func.name} and reach "
                            f"`{' '.join(func.body.split())[:80]}`"
                        ),
                        blind_spot=(
                            "an internal modifier this scanner does not resolve could "
                            "still gate the function; check the modifier body"
                        ),
                    )
                )
            else:
                verdicts.append(
                    Verdict(
                        claim=claim,
                        status=SURVIVED,
                        method="static: guard token present in modifiers or body",
                        evidence=", ".join(func.modifiers) or "guard token in body",
                        blind_spot=(
                            "a guard that checks the wrong dimension (a role that can be "
                            "self-granted, a signature without a nonce) passes this check"
                        ),
                    )
                )

            # Loop termination.
            loop = _first_line(func.body, r"\b(while|for)\s*\(")
            if loop:
                unbounded = re.search(r"while\s*\(\s*true\s*\)", func.body) or re.search(
                    r"for\s*\([^;]*;[^;]*;\s*[^)]*\.push\(", func.body
                )
                verdicts.append(
                    Verdict(
                        claim=Claim(
                            key=f"termination:{contract.name}.{func.name}",
                            subject=f"{contract.name}.{func.name}",
                            statement=f"loops in {func.name} terminate within the block gas limit",
                            location=location,
                            question=(
                                f"Can I grow the input until the loop in {func.name} "
                                "exceeds the block gas limit?"
                            ),
                        ),
                        status=FALSIFIED if unbounded else UNTESTABLE,
                        method="static: loop shape inspection",
                        evidence=loop,
                        counterexample="a loop whose bound grows inside its own body" if unbounded else "",
                        blind_spot=(
                            "a loop bounded by a storage array is only safe if the array "
                            "cannot be grown by an attacker; that is a different check"
                        ),
                    )
                )

            # Reentrancy ordering.
            ext = _EXTERNAL_CALL.search(func.body)
            if ext:
                write = _WRITE.search(func.body)
                before = write is not None and write.start() < ext.start()
                verdicts.append(
                    Verdict(
                        claim=Claim(
                            key=f"ordering:{contract.name}.{func.name}",
                            subject=f"{contract.name}.{func.name}",
                            statement=f"state is written before any external call in {func.name}",
                            location=location,
                            question=(
                                f"What can the callee do to {contract.name}'s state "
                                f"before {func.name} finishes writing it?"
                            ),
                        ),
                        status=FALSIFIED if not before else SURVIVED,
                        method="static: first write offset vs first external call offset",
                        evidence=" ".join(func.body[ext.start():ext.start() + 90].split()),
                        counterexample="" if before else "external call precedes the first state write",
                        blind_spot=(
                            "reentrancy through a second contract, a callback hook, or a "
                            "token with transfer hooks is not visible here"
                        ),
                    )
                )

        # Value conservation, per contract.
        mints = [
            f for f in contract.functions
            if re.search(r"_mint\(|totalSupply\s*\+=", f.body) and f.externally_callable
        ]
        burns = [
            f for f in contract.functions
            if re.search(r"_burn\(|totalSupply\s*-=", f.body) and f.externally_callable
        ]
        if mints or burns:
            guarded_mint = all(_solidity_guard(f) for f in mints)
            verdicts.append(
                Verdict(
                    claim=Claim(
                        key=f"conservation:{contract.name}",
                        subject=contract.name,
                        statement=f"external calls to {contract.name} conserve total supply",
                        location=f"{contract.path}:{contract.line}",
                        question=(
                            f"Who can mint or burn {contract.name}'s supply, and what do "
                            "they pay for it?"
                        ),
                    ),
                    status=FALSIFIED if not guarded_mint else SURVIVED,
                    method="static: mint/burn reachability from an external function",
                    evidence=", ".join(f.name for f in (mints + burns)[:6]),
                    counterexample=(
                        "an externally callable mint with no authorization token"
                        if not guarded_mint else ""
                    ),
                    blind_spot=(
                        "supply can also drift through accounting that is not a mint/burn "
                        "(a fee taken from a balance, a rounding direction)"
                    ),
                )
            )

        # Initialization.
        for func in contract.functions:
            if not re.match(r"init|initialize|init_", func.name, re.I):
                continue
            guarded = bool(func.modifiers) or re.search(
                r"initialized|initializer|_disableInitializers", func.body
            )
            verdicts.append(
                Verdict(
                    claim=Claim(
                        key=f"initialization:{contract.name}.{func.name}",
                        subject=f"{contract.name}.{func.name}",
                        statement=f"{func.name} can only succeed once",
                        location=f"{contract.path}:{func.line}",
                        question=f"Can I call {func.name} again and re-own the contract?",
                    ),
                    status=SURVIVED if guarded else FALSIFIED,
                    method="static: initializer guard token",
                    evidence=_first_line(func.body, r"initializ\w*|onlyInitializing") or "",
                    counterexample="" if guarded else "no initialized flag or initializer modifier",
                    blind_spot=(
                        "a guard that can be reset, or an implementation left uninitialized "
                        "behind a proxy, is not visible here"
                    ),
                )
            )
    return verdicts


# --------------------------------------------------------------------------- #
# Rust / Substrate claims
# --------------------------------------------------------------------------- #
def _anchor_authorization(module, func) -> tuple[str, str, str, str, str]:
    """Judge an Anchor instruction by its Accounts struct, not its body.

    Anchor's authorization is the ``Signer`` plus the ``has_one``/``constraint``/
    ``address``/``seeds`` binding in the ``#[derive(Accounts)]`` struct. Reading
    the handler body for a Substrate ``ensure_signed`` would mark every Anchor
    instruction FALSIFIED, which is a false claim, not a finding. The four
    answers below are the honest ones: a binding exists, a signer has no binding,
    the instruction has no signer (possibly permissionless by design), or the
    Accounts struct is not in the scanned file.
    """
    accounts = None
    lookup = getattr(module, "accounts_for", None)
    if lookup is not None and getattr(func, "accounts_struct", ""):
        accounts = lookup(func.accounts_struct)
    fields = accounts.fields if accounts else ()
    unbound = anchor_unbound_writable(module, func)
    if unbound:
        return (
            FALSIFIED,
            "static: unbound writable account in the Anchor Accounts struct",
            unbound[0],
            unbound[0],
            "a `/// CHECK:` comment or a check in the handler body may still validate "
            "it; the account list alone is not proof of a bug",
        )
    if accounts is None:
        return (
            UNTESTABLE,
            "static: the Accounts struct is not defined in this file",
            "",
            "",
            "the handler takes a `Context<T>` whose Accounts struct lives elsewhere; "
            "this file cannot decide what it binds",
        )
    signers = [f for f in fields if "Signer" in f.type]
    if not signers:
        return (
            UNTESTABLE,
            "static: the Anchor Accounts struct has no Signer",
            ", ".join(f.name for f in fields[:6]),
            "",
            "a permissionless instruction is by design; the question is what state an "
            "unprivileged caller can move, not who may call it",
        )
    bound = any(
        any(token in f.attrs for token in ("has_one", "constraint", "address", "seeds", "owner"))
        for f in fields
    )
    if not bound:
        return (
            UNTESTABLE,
            "static: the Anchor Accounts struct has a Signer but no binding",
            ", ".join(f.name for f in signers),
            "",
            "a Signer proves who signed, not what they may do; the handler body may "
            "still authorize them and that check is not visible here",
        )
    return (
        SURVIVED,
        "static: the Anchor Accounts struct binds its accounts",
        ", ".join(f.name for f in fields),
        "",
        "the binding proves the keys match stored state, not that the stored state is "
        "the right authority; a field bound by another field's has_one is only as "
        "strong as that field",
    )


def _rust_claims(report) -> list[Verdict]:
    verdicts: list[Verdict] = []
    for module in report.modules:
        for func in module.dispatchables:
            location = f"{module.path}:{func.line}"
            body = func.body
            _lower = body.lower()

            if getattr(module, "anchor", False):
                status, method, evidence, counterexample, blind_spot = _anchor_authorization(
                    module, func
                )
                statement = f"the Accounts struct validates the accounts {func.name} acts on"
                question = (
                    f"Can an unprivileged caller substitute an account in "
                    f"{func.name}'s Accounts struct?"
                )
            else:
                guarded = _rust_origin_guard(body)
                status = SURVIVED if guarded else FALSIFIED
                method = "static: origin/signature/permission token in the dispatchable body"
                evidence = _first_line(body, r"ensure_\w+|ensure!") or ""
                counterexample = "" if guarded else "no origin check in the dispatchable body"
                blind_spot = (
                    "a check on the wrong dimension (a caller who can self-grant the "
                    "role, a signature without a nonce or domain) passes this check"
                )
                statement = f"only an authorized origin can call dispatchable {func.name}"
                question = f"What stops any signed account from calling {func.name}?"
            verdicts.append(
                Verdict(
                    claim=Claim(
                        key=f"authorization:{module.name}.{func.name}",
                        subject=f"{module.name}.{func.name}",
                        statement=statement,
                        location=location,
                        question=question,
                    ),
                    status=status,
                    method=method,
                    evidence=evidence,
                    counterexample=counterexample,
                    blind_spot=blind_spot,
                )
            )

            panic = _first_line(body, r"\.unwrap\(\)|\.expect\(|panic!|todo!|unimplemented!")
            verdicts.append(
                Verdict(
                    claim=Claim(
                        key=f"no-panic:{module.name}.{func.name}",
                        subject=f"{module.name}.{func.name}",
                        statement=f"dispatchable {func.name} cannot be made to panic",
                        location=location,
                        question=(
                            f"Can I make {func.name} panic with an input any signed "
                            "account can supply?"
                        ),
                    ),
                    status=FALSIFIED if panic else SURVIVED,
                    method="static: panic-capable token scan",
                    evidence=panic or "",
                    counterexample=panic or "",
                    blind_spot=(
                        "a panic inside a called function, a slice index, or an arithmetic "
                        "overflow in debug builds is not visible from this body"
                    ),
                )
            )

            iteration = _first_line(body, r"(\.|::)(iter|iter_keys|iter_values)\(\)|for\s+\w+\s+in\s+Self::")
            verdicts.append(
                Verdict(
                    claim=Claim(
                        key=f"bounded-work:{module.name}.{func.name}",
                        subject=f"{module.name}.{func.name}",
                        statement=f"the work in {func.name} is bounded independently of stored state",
                        location=location,
                        question=(
                            f"Can I grow stored state until {func.name} exceeds the block weight?"
                        ),
                    ),
                    status=FALSIFIED if iteration else SURVIVED,
                    method="static: storage iteration in a dispatchable",
                    evidence=iteration or "",
                    counterexample=iteration or "",
                    blind_spot=(
                        "a loop over a bounded vector still depends on the bound chosen at "
                        "write time; check that the bound is enforced on insert"
                    ),
                )
            )

            if not getattr(module, "anchor", False):
                verdicts.append(
                    Verdict(
                        claim=Claim(
                            key=f"weighted:{module.name}.{func.name}",
                            subject=f"{module.name}.{func.name}",
                            statement=f"dispatchable {func.name} declares the weight it can consume",
                            location=location,
                            question=f"Can I make {func.name} cost more than it declares?",
                        ),
                        status=SURVIVED if func.weight else FALSIFIED,
                        method="static: #[pallet::weight] annotation",
                        evidence=func.weight or "",
                        counterexample="" if func.weight else "no weight annotation",
                        blind_spot=(
                            "a declared weight is a claim about the worst case; it is only true "
                            "if the weight function matches the code path"
                        ),
                    )
                )
    return verdicts




# --------------------------------------------------------------------------- #
# Go / Cosmos claims
# --------------------------------------------------------------------------- #
def _go_message_handler(func) -> bool:
    if func.stub or func.is_consensus:
        return False
    return func.is_handler


def _go_claims(report) -> list[Verdict]:
    """Derive the claims a Go / Cosmos surface makes and try to falsify them."""
    verdicts: list[Verdict] = []
    for func in report.functions:
        if func.stub or func.path.endswith(".pb.go"):
            continue
        if not (func.is_handler or func.is_consensus):
            continue
        location = f"{func.path}:{func.line}"
        subject = f"{func.receiver + '.' if func.receiver else ''}{func.name}"

        if _go_message_handler(func):
            writes = re.search(
                r"\.Set\(|\.SetParams\(|SendCoins|MintCoins|BurnCoins|Delegate\(|"
                r"Undelegate\(|SetValidator|SetAccount", func.body)
            guarded = re.search(
                r"(?:if|require|ensure)[^;]{0,240}(?:Authority|GetSigners|Sender|"
                r"Creator|Owner|FromAddress|GetAuthority)|ValidateBasic|GetSigners|"
                r"authz|CheckAuthority",
                func.body)
            claim = Claim(
                key=f"authorization:{subject}",
                subject=subject,
                statement=f"only an authorized caller can change state through {subject}",
                location=location,
                question=f"What stops an unprivileged account from calling {subject}?",
            )
            if writes and not guarded:
                verdicts.append(Verdict(
                    claim=claim, status=FALSIFIED,
                    method="static: message handler writes state with no signer/authority token",
                    evidence=_first_line(func.body, r"\.Set\(|SendCoins|MintCoins|Delegate\(") or func.signature,
                    counterexample=f"{subject} reaches a state write without an authority check",
                    blind_spot=("the write may be reached only through a caller that already "
                                "checked the signer; confirm the call path"),
                ))
            else:
                verdicts.append(Verdict(
                    claim=claim, status=SURVIVED,
                    method="static: signer/authority token present or no direct write",
                    evidence="authority/signer token" if guarded else "no direct state write",
                    blind_spot=("a check on the wrong identity, or an authority field the "
                                "message itself supplies, passes this check"),
                ))

        panic = _first_line(func.body, r"\bpanic\(|\bMust[A-Z]\w*\(")
        panic_reachable = _go_message_handler(func) or func.name == "AnteHandle"
        if panic and not panic_reachable:
            panic_status = UNTESTABLE
            panic_blind = ("genesis/export data is not an unprivileged transaction input; "
                           "this panic is not reachable by the attacker this check models")
        else:
            panic_status = FALSIFIED if panic else SURVIVED
            panic_blind = ("a nil map, nil pointer or out-of-range index can panic without a "
                           "panic call; this check does not prove absence")
        verdicts.append(Verdict(
            claim=Claim(
                key=f"no-panic:{subject}", subject=subject,
                statement=f"{subject} cannot be made to panic by an unprivileged caller",
                location=location,
                question=f"Can I make {subject} panic with an input any signed account can supply?",
            ),
            status=panic_status,
            method="static: panic/Must scan",
            evidence=panic or "",
            counterexample=panic if panic_status == FALSIFIED else "",
            blind_spot=panic_blind,
        ))

        if func.is_consensus:
            map_iter = _first_line(
                func.body,
                r"for\s+[^;{\n]*range\s+[^\s{]+",
            )
            expr_m = re.search(r"for\s+[^;{\n]*range\s+([^\s{]+)\s*\{", func.body)
            is_map = bool(expr_m and ("map[" in func.body or re.search(
                r"map|Map|entries|signers|scores|validators|votes", expr_m.group(1))))
            verdicts.append(Verdict(
                claim=Claim(
                    key=f"deterministic:{subject}", subject=subject,
                    statement=f"{subject} reaches the same state on every validator",
                    location=location,
                    question="Does this consensus path depend on map order or wall-clock time?",
                ),
                status=FALSIFIED if (map_iter and is_map) or re.search(
                    r"\btime\.(?:Now|Since|Until)\(", func.body) else SURVIVED,
                method="static: map-range and wall-clock scan",
                evidence=map_iter or _first_line(func.body, r"\btime\.(?:Now|Since|Until)\(") or "",
                counterexample=(map_iter or "wall-clock call") if (map_iter and is_map) or
                re.search(r"\btime\.(?:Now|Since|Until)\(", func.body) else "",
                blind_spot=("a deterministic-looking loop can still depend on a map through "
                            "a helper; this is a local check"),
            ))

        bounded = (None if func.name in ("InitGenesis", "ExportGenesis") else _first_line(
            func.body,
            r"for\s+[^;{\n]*range\s+[^\n{]*(?:GetAll|Iterate|Iterator|Walk|PrefixIterator)",
        ))
        verdicts.append(Verdict(
            claim=Claim(
                key=f"bounded-work:{subject}", subject=subject,
                statement=f"the work in {subject} is bounded independently of stored state",
                location=location,
                question=f"Can I grow stored state until {subject} exceeds its declared cost?",
            ),
            status=FALSIFIED if bounded else SURVIVED,
            method="static: store iteration in a handler/consensus path",
            evidence=bounded or "",
            counterexample=bounded or "",
            blind_spot=("a loop over a bounded vector still depends on the bound chosen at "
                        "write time; check that the bound is enforced on insert"),
        ))

        unchecked = _first_line(
            func.body,
            r"(?:_\s*=\s*|[A-Za-z_]\w*\s*,\s*_\s*:?=\s*)[^\n;]*"
            r"(?:SendCoins|MintCoins|BurnCoins|Delegate|Undelegate|Transfer)\(",
        )
        verdicts.append(Verdict(
            claim=Claim(
                key=f"error-propagation:{subject}", subject=subject,
                statement=f"{subject} does not record a value transfer that failed",
                location=location,
                question="If this transfer returns an error, does the state still record it as done?",
            ),
            status=FALSIFIED if unchecked else SURVIVED,
            method="static: discarded bank/staking result",
            evidence=unchecked or "",
            counterexample=unchecked or "",
            blind_spot=("a transfer that returns an error but is checked by a later balance "
                        "read is not caught here"),
        ))
    return verdicts


def interrogate(path: str, language: str = "auto") -> tuple[list[Verdict], str, tuple[str, ...]]:
    """Derive the claims a tree makes and attempt to falsify each one.

    Returns ``(verdicts, language, errors)``. ``errors`` is what the scanner
    could not read: a claim derived from a partial surface is weaker, and the
    caller must be able to say so.
    """
    from .ingest import detect_language

    resolved = language
    if resolved == "auto":
        resolved = detect_language(path)

    if resolved == "rust":
        from .ingest.rust import ingest_rust

        report = ingest_rust(path)
        return _rust_claims(report), "rust", report.errors
    if resolved == "solidity":
        from .ingest.solidity import ingest

        report = ingest(path)
        return _solidity_claims(report), "solidity", report.errors
    if resolved == "go":
        from .ingest.golang import ingest_go

        report = ingest_go(path)
        return _go_claims(report), "go", report.errors
    from .ingest import language_census

    census = language_census(path)
    if census:
        found = ", ".join(f"{n} {lang}" for lang, n in sorted(census.items()))
        return [], resolved, (
            f"ambiguous tree ({found}); pass --language solidity, rust, vyper or go "
            "to interrogate one, then the others",
        )
    return [], resolved, (f"no scannable source found under {path!r}",)


def summarise(verdicts: Iterable[Verdict]) -> dict:
    counts = {FALSIFIED: 0, SURVIVED: 0, UNTESTABLE: 0}
    for verdict in verdicts:
        counts[verdict.status] = counts.get(verdict.status, 0) + 1
    return counts


def as_dict(verdicts: list[Verdict], language: str, errors: tuple[str, ...]) -> dict:
    return {
        "language": language,
        "claims": len(verdicts),
        "summary": summarise(verdicts),
        "errors": list(errors),
        "verdicts": [v.as_dict() for v in verdicts],
        "discipline": (
            "SURVIVED means this check found no counterexample. It is not a proof, "
            "and each verdict names what it could not see."
        ),
    }


def render_markdown(verdicts: list[Verdict], language: str, errors: tuple[str, ...]) -> str:
    counts = summarise(verdicts)
    lines = ["# Interrogation ledger", ""]
    lines.append(f"- language: {language}")
    lines.append(f"- claims tested: {len(verdicts)}")
    lines.append(f"- falsified: {counts.get(FALSIFIED, 0)}")
    lines.append(f"- survived (within this check): {counts.get(SURVIVED, 0)}")
    lines.append(f"- untestable: {counts.get(UNTESTABLE, 0)}")
    lines.append("")

    falsified = [v for v in verdicts if v.status == FALSIFIED]
    if falsified:
        lines.append("## Falsified claims")
        lines.append("")
        for v in falsified:
            lines.append(f"### {v.claim.statement}")
            lines.append("")
            lines.append(f"- location: `{v.claim.location}`")
            lines.append(f"- method: {v.method}")
            lines.append(f"- evidence: `{v.evidence}`")
            lines.append(f"- counterexample: {v.counterexample}")
            lines.append(f"- blind spot: {v.blind_spot}")
            lines.append(f"- question: {v.claim.question}")
            lines.append("")

    survived = [v for v in verdicts if v.status == SURVIVED]
    if survived:
        lines.append("## Claims that survived this check")
        lines.append("")
        lines.append("| claim | location | method | could not see |")
        lines.append("|---|---|---|---|")
        for v in survived:
            lines.append(
                f"| {v.claim.statement} | {v.claim.location} | {v.method} | {v.blind_spot} |"
            )
        lines.append("")

    untestable = [v for v in verdicts if v.status == UNTESTABLE]
    if untestable:
        lines.append("## Claims this scan could not decide")
        lines.append("")
        for v in untestable:
            lines.append(f"- {v.claim.statement} ({v.claim.location}) — {v.blind_spot}")
        lines.append("")

    if errors:
        lines.append("## What the scanner could not read")
        lines.append("")
        for error in errors:
            lines.append(f"- {error}")
        lines.append("")

    lines.append(
        "> A falsified claim is a lead, not a finding: it names where the code "
        "does not do what it says, and the next step is a reproduction under scope."
    )
    lines.append("")
    return "\n".join(lines)
