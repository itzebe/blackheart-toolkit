"""Target-aware applicability: which vulnerability classes can this target exhibit?

Not every class applies to every target. A vault with no oracle cannot suffer
oracle manipulation; a stateless HTTP echo service has no state machine to violate.
Treating every class as applicable wastes effort and, worse, produces a coverage
ledger that claims work it never did.

This module reads the target's *actual surface* -- its components, entry points,
roles, assets, dependencies, and notes -- detects which surface tokens it exposes
(:data:`SURFACES`), and classifies each taxonomy class as applicable, inapplicable
(with a reason), or unresolved (visible as a gap).

The detectors are general keyword/surface rules over the profile, not per-target
special cases, so they generalise to any target the operator describes. A profile
that does not mention a surface does not *prove* the surface is absent; the engine
is honest about that: a class is only marked inapplicable when the profile
positively lacks its surface, otherwise it stays ``UNRESOLVED``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..objectives import TargetProfile
from .record import CoverageState
from .taxonomy import Taxonomy, VulnClass

#: Surface token -> cue substrings that indicate the target exposes it.
_SURFACE_CUES: dict[str, tuple[str, ...]] = {
    "auth": ("auth", "login", "session", "token", "password", "credential", "sso",
             "oauth", "jwt", "sign-in", "signin"),
    "authorization": ("role", "permission", "access", "admin", "owner", "privilege",
                      "acl", "scope", "grant", "policy"),
    "business-logic": ("workflow", "order", "checkout", "state", "step", "process",
                       "approve", "claim", "redeem", "invoice", "settle"),
    "input": ("input", "parameter", "param", "body", "query", "form", "upload",
              "deserialize", "parse", "request"),
    "state-machine": ("state", "transition", "status", "phase", "lifecycle"),
    "financial": ("balance", "transfer", "payment", "deposit", "withdraw", "vault",
                  "share", "asset", "collateral", "loan", "debt", "fee", "reward",
                  "fund", "token", "settle", "accounting"),
    "arithmetic": ("math", "arithmetic", "round", "precision", "decimal", "scale",
                   "mul", "div", "interest", "rate", "price"),
    "concurrency": ("concurrent", "race", "thread", "async", "lock", "mutex",
                    "parallel", "timeout", "ordering", "mempool", "stale"),
    "signature": ("signature", "permit", "nonce", "ecrecover", "eip-712", "eip712",
                  "sig", "sign", "vault-proof", "attestation"),
    "crypto": ("crypto", "hash", "cipher", "encrypt", "decrypt", "hmac", "random",
               "kdf", "keccak", "aes", "rsa", "curve"),
    "resource": ("gas", "cpu", "memory", "quota", "limit", "rate-limit", "ratelimit",
                 "loop", "unbounded", "exhaust", "recursion"),
    # Deliberately excludes generic words like "service"/"external": those appear in
    # almost any target and would make every cross-component class falsely applicable.
    "cross-component": ("bridge", "oracle", "callback", "hook", "integration",
                        "upstream", "inter-contract", "multi-contract", "queue",
                        "webhook", "dependency", "reentrancy"),
    "api": ("api", "http", "rest", "graphql", "endpoint", "rpc", "grpc", "route",
            "webhook"),
    "config": ("config", "environment", "deploy", "setting", "feature-flag", "env"),
    "upgrade": ("proxy", "upgrade", "initialize", "implementation", "uups",
                "governance", "vote", "timelock", "admin"),
    "supply-chain": ("dependency", "package", "npm", "pip", "cargo", "vendor",
                     "lockfile"),
    "data-isolation": ("tenant", "account", "user", "owner", "namespace",
                       "isolation", "idor", "permission"),
    "compositional": ("multi-step", "multi step", "combined", "chain", "sequence",
                      "cross-protocol", "compositional"),
}


def _split_camel(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)


def _haystack(profile: TargetProfile) -> str:
    return _split_camel(" ".join([
        profile.name, profile.kind, profile.notes,
        *profile.assets, *profile.entry_points, *profile.trust_boundaries,
        *profile.roles, *profile.external_deps,
    ])).lower()


@dataclass
class SurfaceReport:
    """Which surface tokens the target exposes, and the cue that revealed each."""

    detected: dict[str, str] = field(default_factory=dict)   # token -> first cue
    #: True when the profile was too thin to detect anything meaningful; every
    #: class then stays UNRESOLVED rather than being guessed inapplicable.
    thin_profile: bool = False

    def tokens(self) -> set[str]:
        return set(self.detected)

    def to_dict(self) -> dict:
        return {"detected": dict(self.detected), "thin_profile": self.thin_profile}


@dataclass
class ClassVerdict:
    """The applicability verdict for one taxonomy class on one target."""

    key: str
    title: str
    state: CoverageState
    reason: str
    #: For an applicable class, the surface(s) that made it applicable.
    matched_surfaces: list[str] = field(default_factory=list)
    #: When a model exists, note it so the operator knows the class is breakable.
    has_model: bool = False

    def to_dict(self) -> dict:
        return {
            "key": self.key, "title": self.title, "state": self.state.value,
            "reason": self.reason, "matched_surfaces": list(self.matched_surfaces),
            "has_model": self.has_model,
        }


@dataclass
class ApplicabilityResult:
    target: str
    surfaces: SurfaceReport
    verdicts: list[ClassVerdict] = field(default_factory=list)

    def applicable(self) -> list[ClassVerdict]:
        return [v for v in self.verdicts
                if v.state in (CoverageState.APPLICABLE, CoverageState.NOT_ASSESSED)]

    def inapplicable(self) -> list[ClassVerdict]:
        return [v for v in self.verdicts if v.state is CoverageState.INAPPLICABLE]

    def unresolved(self) -> list[ClassVerdict]:
        return [v for v in self.verdicts if v.state is CoverageState.UNRESOLVED]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "surfaces": self.surfaces.to_dict(),
            "counts": {
                "applicable": len(self.applicable()),
                "inapplicable": len(self.inapplicable()),
                "unresolved": len(self.unresolved()),
            },
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


class ApplicabilityEngine:
    """Classify taxonomy classes against a target's real surface."""

    def __init__(self, taxonomy: Taxonomy):
        self.taxonomy = taxonomy

    def detect_surfaces(self, profile: TargetProfile) -> SurfaceReport:
        hay = _haystack(profile)
        report = SurfaceReport()
        for token, cues in _SURFACE_CUES.items():
            for cue in cues:
                if cue in hay:
                    report.detected[token] = cue
                    break
        # A profile with no assets/entry-points/roles carries no real signal; do not
        # pretend the absence of a cue means the surface is inapplicable.
        meaningful = bool(profile.assets or profile.entry_points or profile.roles
                          or profile.external_deps or profile.notes.strip())
        report.thin_profile = not meaningful and not report.detected
        return report

    def _verdict(self, cls: VulnClass, surfaces: set[str], thin: bool) -> ClassVerdict:
        has_model = bool(cls.objective_category)
        if thin:
            return ClassVerdict(
                cls.key, cls.title, CoverageState.UNRESOLVED,
                "target profile carries no surface signal; applicability cannot be "
                "decided without inventing facts",
                has_model=has_model,
            )
        if cls.needs_any(surfaces):
            matched = sorted(set(cls.requires) & surfaces)
            reason = (
                f"target exposes {', '.join(matched)}"
                if matched else "class applies to any target"
            )
            return ClassVerdict(cls.key, cls.title, CoverageState.APPLICABLE, reason,
                                matched_surfaces=matched, has_model=has_model)
        # The class requires a surface the target does not expose. Inapplicable WITH
        # a reason, never a silent skip.
        return ClassVerdict(
            cls.key, cls.title, CoverageState.INAPPLICABLE,
            f"target exposes none of the surfaces this class requires "
            f"({', '.join(cls.requires)})",
            has_model=has_model,
        )

    def classify(self, profile: TargetProfile) -> ApplicabilityResult:
        report = self.detect_surfaces(profile)
        surfaces = report.tokens()
        result = ApplicabilityResult(target=profile.name, surfaces=report)
        for cls in self.taxonomy:
            result.verdicts.append(self._verdict(cls, surfaces, report.thin_profile))
        return result


def seed_record(result: ApplicabilityResult):
    """Seed a :class:`CoverageRecord` from an applicability result.

    Applicable classes become ``APPLICABLE``; inapplicable classes become
    ``INAPPLICABLE`` with their reason; unresolved classes stay ``UNRESOLVED``. No
    class is left out, so an untouched class is always visible.
    """
    from .record import CoverageRecord

    rec = CoverageRecord(result.target, [(v.key, v.title) for v in result.verdicts])
    rec.surfaces = sorted(result.surfaces.tokens())
    for v in result.verdicts:
        if v.state is CoverageState.INAPPLICABLE:
            rec.set_state(v.key, CoverageState.INAPPLICABLE, reason=v.reason)
        elif v.state is CoverageState.UNRESOLVED:
            rec.set_state(v.key, CoverageState.UNRESOLVED, reason=v.reason)
        else:
            rec.set_state(v.key, CoverageState.APPLICABLE, reason=v.reason)
    return rec
