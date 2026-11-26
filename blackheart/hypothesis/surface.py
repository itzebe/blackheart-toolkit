"""Target-surface applicability model (mission Part 3.1, Phase 6).

The baseline hypothesis strategy scores every vulnerability class from static
per-class constants. Measured against the ranking benchmark, that strategy ranks
the same class first for *every* target -- it never asks whether the target even
exposes the surface a class needs. A vault with no oracle is scored the same as a
lending market with one.

This module reads the target's *actual surface* -- entry points, trust boundaries,
roles, external dependencies, and notes -- and derives which attack classes are
applicable, questionable, or implausible. The hypothesis engine multiplies its
class score by this factor, so effort flows to classes the target can actually
exhibit.

The detectors are keyword/surface rules over the profile, not per-target special
cases, so they generalise: they are the same rules the negative (anti-overfitting)
corpus exercises from the other direction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..objectives import TargetProfile

# --------------------------------------------------------------------------- #
# Surface detectors
# --------------------------------------------------------------------------- #

_ORACLE_TERMS = ("oracle", "price", "feed", "valuation", "twap", "chainlink", "quote")
_SIGNATURE_TERMS = ("permit", "signature", "ecrecover", "eip712", "eip-712", "sig",
                    "nonce", "relayer", "sign", "signed", "v,r,s")
_PROXY_TERMS = ("proxy", "upgrade", "initialize", "delegatecall", "implementation", "uups")
_CALLBACK_TERMS = ("callback", "hook", "onflashloan", "onerc", "receive(", "fallback",
                   "reentran", "flashloan", "oncall")
_SHARE_TERMS = ("share", "vault", "erc4626", "redeem", "deposit", "atoken", "wrapper",
                "convert", "round")
_ACCESS_TERMS = ("owner", "admin", "role", "onlyowner", "privileg", "govern", "manager",
                 "authority", "guardian")
_BRIDGE_TERMS = ("bridge", "settle", "message", "teleport", "crosschain", "cross-chain")


def _split_camel(name: str) -> str:
    """Split CamelCase so a negation prefix stays adjacent to its term.

    ``VaultNoOracle`` must tokenise to ``Vault No Oracle``; otherwise the substring
    ``"no "`` never appears before ``oracle`` and the negation is missed.
    """
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)


def _haystack(profile: TargetProfile) -> str:
    return " ".join(
        [
            _split_camel(profile.name),
            profile.notes,
            *profile.assets,
            *profile.entry_points,
            *profile.trust_boundaries,
            *profile.roles,
            *profile.external_deps,
        ]
    ).lower()


# Cues that negate a surface term appearing shortly after them. Profiles routinely
# say "no external price dependency" or "non-upgradeable"; counting those as the
# surface being present inverted the ranking on the negative corpus.
_NEGATION_CUES = ("no ", "not ", "without ", "non-", "lacks ", "free of ", "absent",
                  "never ")
_NEGATION_WINDOW = 18


def _term_present(text: str, term: str) -> bool:
    """True when ``term`` appears at least once NOT preceded by a negation cue."""
    start = 0
    while True:
        idx = text.find(term, start)
        if idx == -1:
            return False
        window = text[max(0, idx - _NEGATION_WINDOW):idx]
        if not any(cue in window for cue in _NEGATION_CUES):
            return True
        start = idx + len(term)


def _any(text: str, terms: tuple[str, ...]) -> bool:
    return any(_term_present(text, t) for t in terms)


@dataclass
class Surface:
    """Which attack surfaces a target actually exposes."""

    has_oracle: bool = False
    has_signature: bool = False
    has_proxy: bool = False
    has_callback: bool = False
    has_shares: bool = False
    has_access_control: bool = False
    has_bridge: bool = False

    def to_dict(self) -> dict:
        return {
            "oracle": self.has_oracle,
            "signature": self.has_signature,
            "proxy": self.has_proxy,
            "callback": self.has_callback,
            "shares": self.has_shares,
            "access_control": self.has_access_control,
            "bridge": self.has_bridge,
        }


def detect_surface(profile: TargetProfile) -> Surface:
    text = _haystack(profile)
    return Surface(
        has_oracle=_any(text, _ORACLE_TERMS),
        has_signature=_any(text, _SIGNATURE_TERMS),
        has_proxy=_any(text, _PROXY_TERMS),
        has_callback=_any(text, _CALLBACK_TERMS),
        has_shares=_any(text, _SHARE_TERMS),
        has_access_control=_any(text, _ACCESS_TERMS),
        has_bridge=_any(text, _BRIDGE_TERMS),
    )


# --------------------------------------------------------------------------- #
# Class -> required surface
# --------------------------------------------------------------------------- #

# Each entry: the Surface attribute a class depends on, and how strongly. A
# dependency that is ABSENT damps the class; one that is PRESENT boosts it. The
# boost is smaller than the damp so absence dominates presence (a class is only
# promoted when its surface is genuinely there).
@dataclass(frozen=True)
class SurfaceRule:
    attr: str
    present_boost: float = 1.6
    absent_damp: float = 0.25


_CLASS_SURFACE: dict[str, SurfaceRule] = {
    "oracle-manipulation": SurfaceRule("has_oracle", 1.8, 0.2),
    "liquidation-bypass": SurfaceRule("has_oracle", 1.4, 0.45),
    "replay-forgery": SurfaceRule("has_signature", 1.9, 0.25),
    "signature-bypass": SurfaceRule("has_signature", 1.9, 0.25),
    "proxy-initializer": SurfaceRule("has_proxy", 1.9, 0.3),
    "privilege-escalation": SurfaceRule("has_proxy", 1.5, 0.5),
    "callback-reentrancy": SurfaceRule("has_callback", 1.8, 0.35),
    "state-inconsistency": SurfaceRule("has_callback", 1.5, 0.6),
    "rounding-precision": SurfaceRule("has_shares", 1.7, 0.5),
    "accounting-manipulation": SurfaceRule("has_shares", 1.6, 0.5),
    "cross-protocol-trust": SurfaceRule("has_bridge", 1.6, 0.7),
    "access-control": SurfaceRule("has_access_control", 1.6, 0.7),
    "asset-theft": SurfaceRule("has_shares", 1.3, 0.8),
}


@dataclass
class Applicability:
    """The multiplier a class earns, plus why (for the rationale string)."""

    multiplier: float = 1.0
    reason: str = "no surface dependency"

    def to_dict(self) -> dict:
        return {"multiplier": round(self.multiplier, 4), "reason": self.reason}


def applicability(vulnerability_class: str, surface: Surface) -> Applicability:
    """Return the surface multiplier for a class given a target's surface."""
    rule = _CLASS_SURFACE.get(vulnerability_class)
    if rule is None:
        return Applicability(1.0, "class has no declared surface dependency")
    present = getattr(surface, rule.attr)
    label = rule.attr.removeprefix("has_")
    if present:
        return Applicability(rule.present_boost, f"surface '{label}' is present -> boosted")
    return Applicability(rule.absent_damp, f"surface '{label}' is absent -> damped")


def surface_summary(profile: TargetProfile) -> str:
    s = detect_surface(profile)
    present = [k for k, v in s.to_dict().items() if v]
    return "surfaces: " + (", ".join(present) if present else "none detected")
