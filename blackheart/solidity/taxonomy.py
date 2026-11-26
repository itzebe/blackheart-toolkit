"""Heuristics that map Solidity declarations to the model vocabulary.

These are *classifiers*, not truth: they take a function or variable name and a
small amount of structure and return the most likely category / asset / role.
Every classifier returns a value *and* the evidence for it, so a reviewer can see
why the extractor reached its conclusion and override it. Where the evidence is
absent the classifier returns a neutral default rather than a confident guess --
the extractor's contract is to propose, never to invent.
"""

from __future__ import annotations

# Objective categories the model vocabulary uses (kept aligned with
# blackheart.objectives). A classifier names one of these or "" (unknown).
CATEGORY_HINTS: dict[str, tuple[str, ...]] = {
    "oracle-manipulation": ("oracle", "price", "getprice", "twap", "latestanswer", "spot"),
    "access-control": ("admin", "owner", "role", "grant", "revoke", "setadmin", "setowner"),
    "auth-bypass": ("auth", "login", "session", "token", "apikey", "credential"),
    "privilege-escalation": ("upgrade", "delegate", "implementation", "setimpl", "transferownership"),
    "reentrancy": ("withdraw", "redeem", "claim", "callback", "onflashloan", "receive"),
    "accounting-manipulation": ("deposit", "mint", "burn", "account", "balance", "supply", "shares"),
    "rounding-precision": ("convert", "preview", "shares", "assets", "round"),
    "slippage-manipulation": ("swap", "slippage", "minout", "amountout", "reserve"),
    "liquidation-bypass": ("liquidat", "health", "collateral", "threshold"),
    "governance-manipulation": ("propose", "vote", "quorum", "timelock", "execute"),
    "reward-manipulation": ("reward", "stake", "unstake", "accrue", "harvest", "claim"),
    "replay-forgery": ("nonce", "permit", "signature", "ecrecover", "replay"),
    "signature-bypass": ("permit", "ecrecover", "signature", "eip712", "domain"),
    "denial-of-service": ("pause", "freeze", "block", "halt", "emergency"),
    "info-disclosure": ("get", "view", "read", "reveal", "secret", "private"),
    "cross-chain-replay": ("bridge", "message", "relay", "domain", "lzreceive", "onmessage"),
    "state-inconsistency": ("update", "set", "sync", "refresh", "checkpoint"),
    "cross-contract": ("call", "delegatecall", "hook", "external"),
}

# Asset/property a function touches, by name hint.
ASSET_HINTS: tuple[tuple[str, str], ...] = (
    ("withdraw", "assets"), ("redeem", "assets"), ("deposit", "assets"),
    ("mint", "shares"), ("burn", "shares"), ("balance", "balance"),
    ("supply", "totalSupply"), ("transfer", "assets"), ("swap", "reserves"),
    ("liquidat", "collateral"), ("vote", "votingPower"), ("reward", "rewards"),
    ("permit", "allowance"), ("approve", "allowance"), ("stake", "stake"),
)

# Function-name prefixes that signal a privileged operation.
_PRIVILEGED_PREFIXES = (
    "set", "update", "upgrade", "grant", "revoke", "pause", "unpause",
    "initialize", "init", "configure", "enable", "disable", "rescue",
    "sweep", "withdrawfees", "mintto", "burnfrom", "force",
)


def infer_category(name: str) -> tuple[str, str]:
    """Return ``(category, evidence)`` for a function name, or ``("", "")``."""
    low = name.lower()
    best = ("", "")
    for category, hints in CATEGORY_HINTS.items():
        for hint in hints:
            if hint in low:
                # Prefer the longest matching hint as the strongest evidence.
                if len(hint) > len(best[1]):
                    best = (category, hint)
    return best


def infer_asset(name: str) -> str:
    low = name.lower()
    for hint, asset in ASSET_HINTS:
        if hint in low:
            return asset
    return ""


def is_privileged(name: str, *, has_role_modifier: bool) -> bool:
    """A function is privileged if a role-bearing modifier guards it, or its name
    reads like an administrative setter. This is a *heuristic* for the model's
    ``sensitive`` flag; the runtime validation step is what makes it trustworthy."""
    if has_role_modifier:
        return True
    low = name.lower()
    return any(low.startswith(p) for p in _PRIVILEGED_PREFIXES)


def is_sensitive(name: str, *, mutating: bool, category: str) -> bool:
    """Does this operation mutate a protected asset? Conservative: a mutating
    function that touches an asset hint, or whose category is value-bearing."""
    if not mutating:
        return False
    if infer_asset(name):
        return True
    return category in {
        "accounting-manipulation", "asset-theft", "rounding-precision",
        "slippage-manipulation", "liquidation-bypass", "reward-manipulation",
        "oracle-manipulation", "cross-chain-replay",
    }


def infer_guard_roles(modifier_names: list[str], contract_name: str = "") -> tuple[str, ...]:
    """Map role-bearing modifier names to a small role vocabulary.

    ``onlyOwner`` -> ``("owner",)``; ``onlyRole(MINTER_ROLE)`` -> ``("minter",)``.
    Unknown modifiers yield no role rather than a guessed one.
    """
    roles: list[str] = []
    for m in modifier_names:
        low = m.lower()
        if low.startswith("only"):
            role = low[4:]
            if role:
                roles.append(role)
        elif low.startswith("requires"):
            roles.append(low[8:] or "authorized")
        elif "role" in low:
            roles.append(low.replace("role", "").strip("_") or "role")
    seen: list[str] = []
    for r in roles:
        if r and r not in seen:
            seen.append(r)
    return tuple(seen)
