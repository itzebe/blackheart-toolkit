"""Bridge a program's policy into the coverage engine's eligibility predicate.

The coverage engine orders work partly by *program eligibility*, but it must never
invent that eligibility. This bridge supplies the predicate the controller calls:
given a class key, it returns ``True``/``False``/``None`` from the normalized policy
-- and ``None`` (unknown) is passed through as unknown, never coerced to eligible.

Two mappings make a free-text program policy usable against the taxonomy:

  * an exact class-key rule the program stated (``class_rules`` keyed by key), and
  * a synonym match against the taxonomy class's title/description, because a
    program says "reentrancy" or "IDOR", not our internal keys.

When neither matches, the answer is ``None`` -- not ``False`` (the program may pay)
and not ``True`` (the program may not). The controller treats ``None`` as "still
worth work but below a confirmed-ineligible class", so an unstated rule never
silently drops a class.
"""

from __future__ import annotations

import re
from typing import Optional

from ..coverage_engine.taxonomy import Taxonomy, VulnClass
from .policy import Band, NormalizedPolicy

#: Words too generic to establish a class match.
_STOP = {"the", "a", "an", "of", "and", "or", "to", "in", "on", "for", "with", "by"}


def _tokens(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]+", text.lower()) if w not in _STOP and len(w) > 2}


def _alias_match(cls: VulnClass, rule_text: str) -> bool:
    """True when a program's free-text class statement clearly names taxonomy class."""
    rule_tokens = _tokens(rule_text)
    if not rule_tokens:
        return False
    # Require the class's distinctive title token to appear, so "injection" matches
    # injection but "input" alone does not match everything.
    title_tokens = _tokens(cls.title)
    distinctive = {t for t in title_tokens if len(t) > 4}
    return bool(distinctive & rule_tokens) or cls.key in rule_text.lower()


class PolicyEligibility:
    """A callable eligibility predicate built from one normalized program policy."""

    def __init__(self, policy: NormalizedPolicy, taxonomy: Taxonomy):
        self.policy = policy
        self.taxonomy = taxonomy
        # Pre-compute exact rules: key -> eligible.
        self._exact: dict[str, Optional[bool]] = {
            r.class_key: r.eligible for r in policy.class_rules
        }

    def __call__(self, class_key: str) -> Optional[bool]:
        # 1. An exact rule the program stated for this key.
        if class_key in self._exact and self._exact[class_key] is not None:
            return self._exact[class_key]
        cls = self.taxonomy.get(class_key)
        if cls is None:
            return None
        # 2. A synonym match against the class's title.
        for rule in self.policy.class_rules:
            if rule.eligible is None:
                continue
            if _alias_match(cls, rule.original_text or rule.class_key):
                return rule.eligible
        # 3. Nothing stated: unknown (never a silent False/True).
        return None

    def band_for(self, class_key: str) -> Band:
        """The band the program assigned this class, or the class's default band."""
        for rule in self.policy.class_rules:
            cls = self.taxonomy.get(class_key)
            if cls and _alias_match(cls, rule.original_text or rule.class_key):
                if rule.band is not Band.UNKNOWN:
                    return rule.band
        cls = self.taxonomy.get(class_key)
        if cls is not None:
            return Band(cls.default_band.value)
        return Band.UNKNOWN

    def explanation(self, class_key: str) -> dict:
        verdict = self(class_key)
        return {
            "class_key": class_key,
            "eligible": verdict,
            "basis": (
                "stated by program" if verdict is not None
                else "not stated by program (unknown, not assumed ineligible)"
            ),
            "minimum_band": self.policy.minimum_eligible_band().value,
            "policy_version": self.policy.version,
            "policy_sha256": self.policy.source_sha256 if self.policy.is_verified() else "",
        }
