"""Attack-chain generator (mission section 2B).

An attack chain combines several operations -- often across contracts, roles, and
transactions -- into a hypothesis about how a composite of behaviours might
violate an invariant that no single call does.

Chains here are *hypotheses*. Nothing in this module claims a target is
vulnerable; it produces structured sequences that the exploit engine can attempt
to execute and that the verification agent can attempt to falsify.
"""

from __future__ import annotations

from ..models import AttackChain, AttackStep, Objective


# --------------------------------------------------------------------------- #
# Chain templates
# --------------------------------------------------------------------------- #

# Each template is a named recipe: (title, actors, steps, invariants, note).
# A step is (actor, action, params, target, expected_effect).
_TEMPLATES: dict[str, dict] = {
    "deposit-borrow-transfer-withdraw": {
        "title": "Deposit -> borrow -> transfer -> withdraw",
        "actors": ["attacker", "victim"],
        "invariants": ["outstanding credit never exceeds properly backed collateral"],
        "steps": [
            ("attacker", "deposit", {"amount": "A"}, "vault", "obtain shares"),
            ("attacker", "borrow", {"amount": "B"}, "pool", "increase debt"),
            ("attacker", "transfer", {"to": "helper"}, "shares", "move shares"),
            ("attacker", "withdraw", {"amount": "A"}, "vault", "recover collateral"),
        ],
        "note": "Classic over-borrow via share/balance desync.",
    },
    "approve-callback-state": {
        "title": "Approve -> callback -> external interaction -> state update",
        "actors": ["attacker", "victim"],
        "invariants": ["failed operations leave no partially committed state"],
        "steps": [
            ("victim", "approve", {"spender": "attacker"}, "token", "grant allowance"),
            ("attacker", "call", {"hook": "malicious"}, "victim", "trigger callback"),
            ("attacker", "reenter", {"fn": "withdraw"}, "vault", "drain before update"),
            ("attacker", "return", {}, "vault", "let state update run late"),
        ],
        "note": "Reentrancy across a callback boundary.",
    },
    "authz-change-replay": {
        "title": "Create authorization -> change state -> replay authorization",
        "actors": ["attacker"],
        "invariants": ["each authorization is usable exactly once for its intended operation"],
        "steps": [
            ("attacker", "sign", {"msg": "permit"}, "token", "create authorization"),
            ("attacker", "change_state", {}, "token", "invalidate the intent"),
            ("attacker", "replay", {"sig": "same"}, "token", "reuse the authorization"),
        ],
        "note": "Signature replay without nonce/domain binding.",
    },
    "collateral-liquidation-accounting": {
        "title": "Modify collateral -> trigger liquidation -> exploit accounting",
        "actors": ["attacker", "victim"],
        "invariants": ["liquidation only seizes genuinely unhealthy positions"],
        "steps": [
            ("attacker", "manipulate", {"asset": "collateral"}, "oracle", "move valuation"),
            ("attacker", "liquidate", {"victim": "v"}, "pool", "seize collateral"),
            ("attacker", "restore", {"asset": "collateral"}, "oracle", "undo the move"),
            ("attacker", "withdraw", {}, "pool", "extract profit"),
        ],
        "note": "Oracle-timed liquidation with accounting residue.",
    },
    "bridge-settle-replay": {
        "title": "Bridge or teleport -> settle -> reverse or replay",
        "actors": ["attacker"],
        "invariants": ["replayed requests cannot create duplicate settlements"],
        "steps": [
            ("attacker", "bridge", {"to": "dest"}, "bridge", "initiate transfer"),
            ("attacker", "settle", {}, "bridge", "settle on destination"),
            ("attacker", "replay", {"same": "message"}, "bridge", "duplicate settlement"),
        ],
        "note": "Message replay across a bridge.",
    },
    "upgrade-init-privileged": {
        "title": "Upgrade -> initialize -> exercise privileged functionality",
        "actors": ["attacker"],
        "invariants": ["protected state changes only through an authorized caller"],
        "steps": [
            ("attacker", "upgrade", {"impl": "malicious"}, "proxy", "swap implementation"),
            ("attacker", "initialize", {"owner": "attacker"}, "proxy", "reinit to attacker"),
            ("attacker", "sweep", {}, "proxy", "exercise privileged fn"),
        ],
        "note": "Unprotected initializer after upgrade.",
    },
    "oracle-move-borrow-restore": {
        "title": "Change oracle state -> borrow -> restore oracle state",
        "actors": ["attacker"],
        "invariants": ["valuations reflect manipulation-resistant prices"],
        "steps": [
            ("attacker", "flash_borrow", {"asset": "A"}, "venue", "obtain size"),
            ("attacker", "move_price", {"down": True}, "venue", "depress collateral price"),
            ("attacker", "borrow", {"max": True}, "pool", "borrow against stale price"),
            ("attacker", "restore_price", {}, "venue", "avoid liquidation"),
        ],
        "note": "Spot-price oracle manipulation.",
    },
    "share-roundtrip-multiuser": {
        "title": "Repeated share conversions across users and decimals",
        "actors": ["attacker", "victim", "victim2"],
        "invariants": ["no sequence of conversions yields net value creation"],
        "steps": [
            ("victim", "deposit", {"amount": "x"}, "vault", "seed the pool"),
            ("attacker", "donate", {"amount": "d"}, "vault", "inflate share price"),
            ("victim2", "deposit", {"amount": "y"}, "vault", "enter at inflated price"),
            ("attacker", "withdraw", {"all": True}, "vault", "extract rounding gain"),
        ],
        "note": "ERC4626-style share inflation / rounding extraction.",
    },
    "wrapper-accounting-divergence": {
        "title": "Wrapper share vs underlying aToken accounting divergence",
        "actors": ["attacker", "victim"],
        "invariants": ["internal accounting equals redeemable external value"],
        "steps": [
            ("victim", "deposit_underlying", {"amount": "u"}, "aToken", "mint aTokens"),
            ("victim", "wrap", {"shares": "s"}, "wrapper", "mint wrapper shares"),
            ("attacker", "accrue_yield", {}, "aToken", "rebase aToken balance"),
            ("attacker", "unwrap", {"shares": "s"}, "wrapper", "redeem at stale rate"),
        ],
        "note": "Priority Twyne hypothesis: aToken/wrapper-share exchange-rate drift.",
    },
    "timing-frontrun-deadline": {
        "title": "Front-run / back-run around a deadline or ordering window",
        "actors": ["attacker", "victim"],
        "invariants": "outcomes do not depend on attacker-controlled ordering",
        "steps": [
            ("victim", "submit", {"op": "trade"}, "venue", "queue a transaction"),
            ("attacker", "frontrun", {"same": "op"}, "venue", "act before victim"),
            ("victim", "exec", {}, "venue", "victim executes at worse terms"),
            ("attacker", "backrun", {}, "venue", "capture the difference"),
        ],
        "note": "Ordering-dependence hypothesis.",
    },
    "callback-reentrancy-drain": {
        "title": "Deposit -> hostile callback re-enters withdraw before state update",
        "actors": ["attacker"],
        "invariants": ["an external callback cannot observe or act on partially-updated state"],
        "steps": [
            ("attacker", "deposit", {"amount": "A"}, "vault", "enter the vault"),
            ("attacker", "set_callback", {"target": "hostile"}, "vault", "arm the callback"),
            ("attacker", "withdraw", {"amount": "A"}, "vault", "trigger external call before update"),
            ("attacker", "reenter", {"fn": "withdraw"}, "vault", "drain before balance is written"),
        ],
        "note": "Checks-effects-interactions violation via a callback.",
    },
    "access-control-privileged-call": {
        "title": "Unprivileged caller invokes a privileged setter",
        "actors": ["attacker"],
        "invariants": ["privileged state changes only through an authorized caller"],
        "steps": [
            ("attacker", "call_privileged", {"fn": "setOwner", "arg": "attacker"}, "target", "reach a gated fn"),
            ("attacker", "sweep", {"to": "attacker"}, "target", "exercise the escalated privilege"),
        ],
        "note": "Missing or wrong-dimension authorization check.",
    },
}


def available_templates() -> list[str]:
    return sorted(_TEMPLATES)


def _select_templates(objective: Objective, profile_kind: str) -> list[str]:
    """Choose chain templates relevant to an objective's category."""
    by_category = {
        "asset-theft": ["deposit-borrow-transfer-withdraw", "approve-callback-state"],
        "unbacked-debt": ["deposit-borrow-transfer-withdraw", "oracle-move-borrow-restore"],
        "auth-bypass": ["upgrade-init-privileged", "authz-change-replay"],
        "privilege-escalation": ["upgrade-init-privileged"],
        "accounting-manipulation": [
            "wrapper-accounting-divergence", "share-roundtrip-multiuser",
            "deposit-borrow-transfer-withdraw",
        ],
        "replay-forgery": ["authz-change-replay", "bridge-settle-replay"],
        "signature-bypass": ["authz-change-replay"],
        "state-inconsistency": ["approve-callback-state"],
        "oracle-manipulation": ["oracle-move-borrow-restore", "collateral-liquidation-accounting"],
        "rounding-precision": ["share-roundtrip-multiuser", "wrapper-accounting-divergence"],
        "liquidation-bypass": ["collateral-liquidation-accounting", "oracle-move-borrow-restore"],
        "cross-protocol-trust": ["bridge-settle-replay", "approve-callback-state"],
        "ordering-timing": ["timing-frontrun-deadline"],
        "cross-contract": ["approve-callback-state", "deposit-borrow-transfer-withdraw"],
        "callback-reentrancy": ["callback-reentrancy-drain", "approve-callback-state"],
        "access-control": ["access-control-privileged-call"],
    }
    names = by_category.get(objective.category, [])
    if profile_kind in {"web", "api", "infra", "mobile"}:
        # Only keep chains that make sense without an on-chain target.
        names = [n for n in names if n in {"approve-callback-state", "timing-frontrun-deadline", "authz-change-replay"}]
    return names


def generate_chains(objective: Objective, profile_kind: str = "smart-contract") -> list[AttackChain]:
    """Generate attack-chain hypotheses for an objective."""
    chains: list[AttackChain] = []
    for name in _select_templates(objective, profile_kind):
        tpl = _TEMPLATES[name]
        steps = [
            AttackStep(
                index=i,
                actor=s[0],
                action=s[1],
                params=dict(s[2]),
                target_contract=s[3],
                expected_effect=s[4],
            )
            for i, s in enumerate(tpl["steps"])
        ]
        invs = tpl["invariants"]
        if isinstance(invs, str):
            invs = [invs]
        chains.append(
            AttackChain(
                chain_id=f"{objective.obj_id}::{name}",
                title=tpl["title"],
                objective_id=objective.obj_id,
                steps=steps,
                invariants_targeted=list(invs),
                contracts_involved=sorted({s[3] for s in tpl["steps"]}),
                actors=list(tpl["actors"]),
                hypothesis=tpl["note"],
                priority=objective.priority,
            )
        )
    return chains
