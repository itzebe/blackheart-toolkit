"""Attacker objective engine (mission section 2A).

Before reviewing any individual function, the engine enumerates *what an attacker
wants* against a target. Objectives are generated from a target profile (a
description of the system's entry points, trust boundaries, and assets), not from
a list of known CVEs -- so the search is not limited to documented checklists.

Each objective is expanded into attacker capabilities, preconditions, assets at
risk, entry points, trust boundaries, the invariant it would violate, a candidate
attack sequence, and a safe place to test it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Objective
from ..mindset import apply_lens, frame_rationale

# --------------------------------------------------------------------------- #
# Target profile
# --------------------------------------------------------------------------- #

@dataclass
class TargetProfile:
    """A structured description of the system under review."""

    name: str
    kind: str = "smart-contract"          # smart-contract | web | api | infra | mobile
    assets: list[str] = field(default_factory=list)          # valuable things
    entry_points: list[str] = field(default_factory=list)    # external surfaces
    trust_boundaries: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)           # actors / privileges
    external_deps: list[str] = field(default_factory=list)   # oracles, bridges, etc.
    notes: str = ""


# --------------------------------------------------------------------------- #
# Objective catalogues
# --------------------------------------------------------------------------- #

# Category -> (title, description, capabilities, preconditions, invariant)
_OBJECTIVE_CATALOG: dict[str, dict] = {
    "asset-theft": {
        "title": "Steal or withdraw assets without authorization",
        "description": "Extract value from the system without a valid right to it.",
        "capabilities": ["call public functions", "supply arbitrary calldata", "be an unprivileged account"],
        "preconditions": ["a withdrawal/transfer path exists", "the caller check can be bypassed or spoofed"],
        "invariant": "no actor can increase their own asset balance without paying in equal value",
    },
    "unbacked-debt": {
        "title": "Create unbacked debt or credit",
        "description": "Mint credit/liabilities that are not backed by real collateral.",
        "capabilities": ["open positions", "manipulate reported collateral", "sequence calls"],
        "preconditions": ["collateral accounting reads attacker-influenced state"],
        "invariant": "outstanding credit never exceeds properly backed collateral",
    },
    "auth-bypass": {
        "title": "Bypass authentication or authorization",
        "description": "Reach a protected operation without the required privilege.",
        "capabilities": ["craft requests", "replay tokens", "omit or forge credentials"],
        "preconditions": ["a privileged entry point exists", "the check is on the wrong dimension"],
        "invariant": "protected state changes only through an authorized caller",
    },
    "privilege-escalation": {
        "title": "Escalate privileges",
        "description": "Turn a low-privilege position into an owner/admin position.",
        "capabilities": ["hold a low role", "trigger role transitions"],
        "preconditions": ["role transitions exist with weak gating"],
        "invariant": "roles only change through authorized, intended transitions",
    },
    "accounting-manipulation": {
        "title": "Manipulate accounting or settlement",
        "description": "Desynchronise internal bookkeeping from real balances.",
        "capabilities": ["deposit/withdraw", "donate", "trigger accrual"],
        "preconditions": ["accounting mixes external balances with internal shares"],
        "invariant": "internal accounting equals redeemable external value",
    },
    "replay-forgery": {
        "title": "Replay or forge authorization",
        "description": "Reuse or fabricate a signature/permit to act twice.",
        "capabilities": ["observe signed messages", "resubmit transactions"],
        "preconditions": ["signatures lack a nonce, domain, or chain binding"],
        "invariant": "each authorization is usable exactly once for its intended operation",
    },
    "signature-bypass": {
        "title": "Bypass signature verification",
        "description": "Make an invalid signature verify as valid.",
        "capabilities": ["supply arbitrary (v,r,s)", "choose the message"],
        "preconditions": ["verification uses ecrecover without malleability checks"],
        "invariant": "only a signature from the true key authorizes the action",
    },
    "state-inconsistency": {
        "title": "Cause inconsistent contract state",
        "description": "Leave state partially updated or mutually contradictory.",
        "capabilities": ["cause reverts mid-operation", "reenter", "use callbacks"],
        "preconditions": ["state updates are not atomic across a callback"],
        "invariant": "failed operations leave no partially committed state",
    },
    "oracle-manipulation": {
        "title": "Manipulate collateral valuations",
        "description": "Move a price feed so the system mis-values collateral.",
        "capabilities": ["trade on the underlying venue", "flash-borrow", "time the read"],
        "preconditions": ["valuation trusts a spot price or a single venue"],
        "invariant": "valuations reflect manipulation-resistant prices",
    },
    "rounding-precision": {
        "title": "Exploit rounding or precision differences",
        "description": "Amplify a rounding error across repeated conversions.",
        "capabilities": ["perform many small operations", "choose decimals"],
        "preconditions": ["share math rounds in the attacker's favour on one side"],
        "invariant": "no sequence of conversions yields net value creation",
    },
    "liquidation-bypass": {
        "title": "Circumvent liquidation or risk controls",
        "description": "Avoid liquidation when unhealthy, or liquidate a healthy position.",
        "capabilities": ["time transactions", "manipulate the health metric"],
        "preconditions": ["health check is manipulable or off-by-one"],
        "invariant": "liquidation only seizes genuinely unhealthy positions",
    },
    "cross-protocol-trust": {
        "title": "Exploit trust between external protocols",
        "description": "Abuse an integration where a peer is trusted blindly.",
        "capabilities": ["control or impersonate a peer", "return hostile data"],
        "preconditions": ["a callback/return value from a peer is trusted"],
        "invariant": "no external peer can cause unauthorized state or value change",
    },
    "info-disclosure": {
        "title": "Obtain unauthorized access to protected information",
        "description": "Read data that should be restricted to other principals.",
        "capabilities": ["enumerate identifiers", "access endpoints directly"],
        "preconditions": ["object-level authorization is missing"],
        "invariant": "protected data is only readable by its owner",
    },
    "ordering-timing": {
        "title": "Manipulate state through transaction ordering or timing",
        "description": "Exploit mempool ordering, deadlines, or timing windows.",
        "capabilities": ["front/back-run", "choose block position", "delay"],
        "preconditions": ["an operation depends on order or an expiry that can be raced"],
        "invariant": "outcomes do not depend on attacker-controlled ordering",
    },
    "cross-contract": {
        "title": "Exploit cross-contract interactions",
        "description": "Compose multiple contracts to violate an invariant.",
        "capabilities": ["deploy helper contracts", "chain calls"],
        "preconditions": ["two contracts share state or trust assumptions"],
        "invariant": "composed interactions preserve each contract's invariants",
    },
    "callback-reentrancy": {
        "title": "Re-enter through a callback before state is finalised",
        "description": "Exploit an external call/callback that runs before state updates commit.",
        "capabilities": ["supply a hostile callback target", "reenter the calling contract"],
        "preconditions": ["an external call happens before effects are written"],
        "invariant": "an external callback cannot observe or act on partially-updated state",
    },
    "access-control": {
        "title": "Call a privileged operation without the required role",
        "description": "Reach an owner/admin-gated operation as an unprivileged caller.",
        "capabilities": ["call public functions", "supply arbitrary calldata"],
        "preconditions": ["a privileged operation exists with weak or missing gating"],
        "invariant": "privileged state changes only through an authorized caller",
    },
    "cross-chain-replay": {
        "title": "Replay or misdirect a cross-domain message",
        "description": "Execute an authorized bridge message twice, or on the wrong chain.",
        "capabilities": ["observe an authorized message", "resubmit it", "choose the domain"],
        "preconditions": ["a message lacks an executed-marker or a destination binding"],
        "invariant": "each cross-domain message executes at most once, on its destination",
    },
    "slippage-manipulation": {
        "title": "Extract value through AMM price/slippage math",
        "description": "Exploit a swap formula or slippage check to trade at a stale/incorrect price.",
        "capabilities": ["swap", "choose size and direction", "compose a round trip"],
        "preconditions": ["the swap output uses the wrong reserve or omits the input"],
        "invariant": "the pool invariant never decreases; a swap never pays out more than the math allows",
    },
    "silent-transfer-failure": {
        "title": "Credit value when the transfer silently failed",
        "description": "Rely on a transfer that returned false or moved nothing (non-standard token).",
        "capabilities": ["use a non-standard token", "deposit above a cap"],
        "preconditions": ["the return value of a transfer is unchecked"],
        "invariant": "credited balances never exceed the funds actually held",
    },
    "governance-manipulation": {
        "title": "Manipulate governance with transient voting power",
        "description": "Flash-borrow voting power to pass a proposal you do not hold.",
        "capabilities": ["flash-borrow", "vote", "repay in one transaction"],
        "preconditions": ["voting power is read from the current balance, not a snapshot"],
        "invariant": "a proposal only passes with power held at the snapshot",
    },
    "denial-of-service": {
        "title": "Grief a critical path into a permanent halt",
        "description": "Block liquidations, withdrawals, or settlement for everyone at low cost.",
        "capabilities": ["create a position/state", "trigger the shared path"],
        "preconditions": ["one actor's state can block an operation for all actors"],
        "invariant": "no single actor can permanently block a critical path",
    },
    "reward-manipulation": {
        "title": "Claim rewards that were never accrued",
        "description": "Exploit a missing checkpoint to claim rewards distributed before joining.",
        "capabilities": ["stake", "wait for a distribution", "claim"],
        "preconditions": ["the staker's reward debt is not checkpointed on stake"],
        "invariant": "the pool never pays out more rewards than it has distributed",
    },
    "storage-collision": {
        "title": "Overwrite reserved storage through a proxy",
        "description": "Write the proxy's admin slot from unprivileged implementation logic.",
        "capabilities": ["call implementation logic", "choose the storage slot"],
        "preconditions": ["a proxy slot is not reserved against implementation writes"],
        "invariant": "implementation logic can never overwrite the proxy's admin slot",
    },
    "decimals-mismatch": {
        "title": "Exploit a token-decimals assumption",
        "description": "Deposit a token whose decimals differ from the assumed value.",
        "capabilities": ["choose the token", "choose the amount"],
        "preconditions": ["amounts are scaled by a hard-coded decimals value"],
        "invariant": "credited value never exceeds the value actually deposited",
    },
    "cors-credential-leak": {
        "title": "Read authenticated cross-origin responses",
        "description": "Exploit a reflected Origin paired with allow-credentials to read a "
                       "user's authenticated response from an attacker page.",
        "capabilities": ["host a web origin", "get the victim's browser to load it",
                         "use a sandboxed iframe (Origin: null)"],
        "preconditions": ["the resource reflects Origin into Access-Control-Allow-Origin",
                          "the response allows credentials"],
        "invariant": "no origin outside the allowlist can read an authenticated response",
    },
    "token-audience-confusion": {
        "title": "Reuse a token against the wrong resource or tenant",
        "description": "Present a bearer token to a resource or tenant it was not minted "
                       "for, because the verifier checks signature but not audience/tenant.",
        "capabilities": ["obtain a token for one resource/tenant", "present it to another"],
        "preconditions": ["two resources or issuers coexist (e.g. a legacy and a current "
                          "version)", "the verifier does not bind audience and tenant"],
        "invariant": "a token is only accepted by the resource and tenant it was minted for",
    },
    "mcp-cross-tenant-disclosure": {
        "title": "Read another tenant's data through MCP tool calls",
        "description": "Use a tool that resolves data by an attacker-supplied cloudId or "
                       "identifier instead of the token's bound tenant.",
        "capabilities": ["call tools", "supply a cloudId or object id"],
        "preconditions": ["a tool trusts a caller-supplied tenant identifier",
                          "object-level authorization is not re-checked"],
        "invariant": "a tool only returns data from the tenant bound to the token",
    },
    "mcp-scope-overreach": {
        "title": "Reach data beyond a granted scope",
        "description": "Use a granted scope to read or write a resource the scope should not "
                       "cover (e.g. search: returns titles of unreadable documents).",
        "capabilities": ["hold one narrow scope", "call tools that fan out across apps"],
        "preconditions": ["a tool enforces the scope name but not the underlying permission"],
        "invariant": "no response contains content the caller cannot read at the source",
    },
    "mcp-consent-bypass": {
        "title": "Obtain or escalate a grant without informed consent",
        "description": "Cause a grant, a scope, or a tenant binding to be issued that the "
                       "user did not knowingly authorize.",
        "capabilities": ["drive the authorization flow", "control a redirect or client"],
        "preconditions": ["the consent screen omits the granted tenant or scopes",
                          "a redirect or client binding is not enforced"],
        "invariant": "a grant covers only what the user saw and approved",
    },
}

# Keyword -> objective categories, used to select relevant objectives per target.
_KIND_DEFAULTS: dict[str, list[str]] = {
    "smart-contract": [
        "asset-theft", "unbacked-debt", "auth-bypass", "accounting-manipulation",
        "replay-forgery", "signature-bypass", "state-inconsistency", "oracle-manipulation",
        "rounding-precision", "liquidation-bypass", "cross-protocol-trust",
        "ordering-timing", "cross-contract", "callback-reentrancy", "access-control",
        "cross-chain-replay", "slippage-manipulation", "silent-transfer-failure",
        "governance-manipulation", "denial-of-service", "reward-manipulation",
        "storage-collision", "decimals-mismatch",
    ],
    "web": ["auth-bypass", "privilege-escalation", "info-disclosure", "state-inconsistency",
            "ordering-timing", "denial-of-service"],
    "api": ["auth-bypass", "privilege-escalation", "info-disclosure", "replay-forgery",
            "ordering-timing", "denial-of-service"],
    "infra": ["auth-bypass", "privilege-escalation", "info-disclosure", "denial-of-service"],
    "mobile": ["auth-bypass", "info-disclosure", "replay-forgery", "signature-bypass"],
    "mcp": ["auth-bypass", "info-disclosure", "cors-credential-leak",
            "token-audience-confusion", "mcp-cross-tenant-disclosure",
            "mcp-scope-overreach", "mcp-consent-bypass", "privilege-escalation",
            "denial-of-service"],
}


def available_categories() -> list[str]:
    return sorted(_OBJECTIVE_CATALOG)


def _categories_for(profile: TargetProfile) -> list[str]:
    cats = list(_KIND_DEFAULTS.get(profile.kind, _KIND_DEFAULTS["smart-contract"]))
    text = " ".join(
        [profile.name, profile.notes, *profile.assets, *profile.external_deps]
    ).lower()
    # A keyword may imply several objectives (a "proxy" is both a privilege-
    # escalation and a storage-collision surface; a "bridge" is both an external
    # trust and a cross-domain replay surface).
    keyword_map: dict[str, list[str]] = {
        "oracle": ["oracle-manipulation"],
        "price": ["oracle-manipulation"],
        "bridge": ["cross-protocol-trust", "cross-chain-replay"],
        "vault": ["accounting-manipulation"],
        "share": ["rounding-precision"],
        "aToken": ["accounting-manipulation"],
        "wrapper": ["accounting-manipulation"],
        "signature": ["signature-bypass"],
        "permit": ["replay-forgery"],
        "liquidation": ["liquidation-bypass"],
        "collateral": ["unbacked-debt"],
        "upgrade": ["privilege-escalation", "storage-collision"],
        "proxy": ["privilege-escalation", "storage-collision"],
        "callback": ["callback-reentrancy"],
        "hook": ["callback-reentrancy"],
        "reentran": ["callback-reentrancy"],
        "flashloan": ["callback-reentrancy", "governance-manipulation"],
        "owner": ["access-control"],
        "admin": ["access-control"],
        "role": ["access-control"],
        "privileg": ["access-control"],
        "cross-chain": ["cross-chain-replay"],
        "message": ["cross-chain-replay"],
        "amm": ["slippage-manipulation"],
        "swap": ["slippage-manipulation"],
        "slippage": ["slippage-manipulation"],
        "liquidity": ["slippage-manipulation"],
        "token": ["silent-transfer-failure"],
        "erc20": ["silent-transfer-failure"],
        "govern": ["governance-manipulation"],
        "vote": ["governance-manipulation"],
        "proposal": ["governance-manipulation"],
        "dao": ["governance-manipulation"],
        "dos": ["denial-of-service"],
        "grief": ["denial-of-service"],
        "pause": ["denial-of-service"],
        "reward": ["reward-manipulation"],
        "stake": ["reward-manipulation"],
        "emission": ["reward-manipulation"],
        "delegatecall": ["storage-collision"],
        "decimals": ["decimals-mismatch"],
    }
    for kw, mapped in keyword_map.items():
        if kw.lower() in text:
            for cat in mapped:
                if cat not in cats:
                    cats.append(cat)
    return cats


def _priority_for(category: str, profile: TargetProfile) -> int:
    """Rank objectives by potential impact and attacker accessibility."""
    high_impact = {"asset-theft", "unbacked-debt", "accounting-manipulation", "signature-bypass"}
    medium = {"oracle-manipulation", "cross-protocol-trust", "privilege-escalation",
              "liquidation-bypass", "callback-reentrancy", "access-control"}
    base = 90 if category in high_impact else 70 if category in medium else 50
    # Assets mentioning funds push the priority up.
    if any(a.lower() in {"funds", "collateral", "shares", "tokens", "eth"} for a in profile.assets):
        base += 5
    return base


def generate_objectives(profile: TargetProfile) -> list[Objective]:
    """Generate attacker objectives for a target profile, highest priority first."""
    objectives: list[Objective] = []
    for i, cat in enumerate(_categories_for(profile)):
        spec = _OBJECTIVE_CATALOG[cat]
        lens = apply_lens(cat, texts=(spec["title"], spec["description"],
                                      spec["invariant"], *spec["capabilities"],
                                      *profile.assets, *profile.trust_boundaries))
        obj = Objective(
            obj_id=f"{profile.name}:{cat}",
            title=spec["title"],
            category=cat,
            description=spec["description"],
            attacker_capabilities=list(spec["capabilities"]),
            preconditions=list(spec["preconditions"]),
            assets_at_risk=list(profile.assets),
            entry_points=list(profile.entry_points),
            trust_boundaries=list(profile.trust_boundaries),
            expected_invariant=spec["invariant"],
            attack_sequence=[],
            safe_environment=(
                "local fork / anvil / isolated test deployment; never production"
            ),
            priority=_priority_for(cat, profile),
            rationale=frame_rationale(
                f"Category '{cat}' is applicable to a {profile.kind} target with "
                f"assets {profile.assets or '[unspecified]'}.",
                cat,
                texts=(spec["title"], spec["description"], spec["invariant"],
                       *spec["capabilities"], *profile.assets,
                       *profile.trust_boundaries),
            ),
            attacker_outcome=lens.outcome,
            attacker_levers=list(lens.levers),
        )
        objectives.append(obj)
    objectives.sort(key=lambda o: (-o.priority, o.category))
    return objectives
