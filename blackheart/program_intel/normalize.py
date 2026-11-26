"""Normalize a program's published policy from heterogeneous formats.

Different platforms (Immunefi, HackerOne, Bugcrowd, a bespoke page, a markdown
scope file) publish the same *kinds* of rule in different shapes. This module reads
the ones it can recognize from plain text and records everything it could not
establish as an uncertainty.

The rule is absolute: **never invent a policy rule.** A line that does not
confidently parse as a scope entry, a class rule, a severity floor, or a restriction
becomes an uncertainty (or is preserved verbatim in the source text), not a guess.
This is what keeps the engine from promising a payout a program never offered.

The parser is deliberately conservative and format-tolerant rather than
platform-specific: a caller passes the raw text (with its source URL and time) and
the normalizer extracts what the markers actually say.
"""

from __future__ import annotations

import re
from typing import Optional

from ..models import utcnow
from .policy import (
    _BAND_ORDER,
    AssetClass,
    Band,
    ClassRule,
    NormalizedPolicy,
    ScopeEntry,
    coerce_band,
)

#: Heading cues that introduce each section. Matched case-insensitively.
_SECTION_CUES = {
    "in_scope": ("in scope", "in-scope", "assets in scope", "scope"),
    "out_of_scope": ("out of scope", "out-of-scope", "not in scope",
                     "out of scope assets", "excluded assets"),
    "severity": ("severity", "severity classification", "severity levels",
                 "impact"),
    "payout": ("payout", "reward", "bounty", "payouts", "rewards",
               "severity and rewards", "reward tiers"),
    "restrictions": ("restriction", "rules", "prohibited", "do not", "testing rules",
                     "out of scope activities", "reporting", "disclosure",
                     "safe harbour", "safe harbor", "how a report travels"),
    "known": ("known issue", "known issues", "already known", "duplicate"),
    "poc": ("proof of concept", "poc", "proof-of-concept"),
    "rate": ("rate limit", "rate-limit", "requests per", "rps"),
}

#: Class-eligibility cues.
_EXCLUDE_CUES = ("not eligible", "ineligible", "out of scope", "excluded",
                 "will not be rewarded", "not accepted", "won't be rewarded")
_INCLUDE_CUES = ("eligible", "in scope", "accepted", "will be rewarded", "payable")

#: A markdown/text bullet or a `-`-prefixed scope line.
_BULLET = re.compile(r"^\s*(?:[-*+\u2022]|\d+[.)])\s+(.*\S)\s*$")
# A URL, an address, or a bare hostname with a known TLD. The TLD list keeps a
# class name like "Self-XSS" from being mistaken for an asset.
_URLISH = re.compile(
    r"https?://|0x[0-9a-fA-F]{6,}|"
    r"\b[\w-]+(?:\.[\w-]+)*\.(?:com|io|org|net|finance|xyz|fi|exchange|dev|app|"
    r"co|ai|so|gg|finance|network)\b",
    re.IGNORECASE,
)


def _lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in text.splitlines()]


def _current_section(line: str, current: str) -> tuple[str, str]:
    """Split a heading-like line into ``(new_section, inline_content)``.

    A policy is often written with the heading and its value on one line --
    ``In scope: api.example.com`` or ``In scope from 1 September``. Treating
    that whole line as a heading would silently discard the value, which is
    exactly the kind of quiet data loss this parser must not do. The value after
    the heading is returned so the caller can absorb it under the new section.
    """
    stripped = line.strip().strip("#").strip()
    low = stripped.lower().strip(": ")
    if not low or len(low) > 160:
        return current, ""
    for section, cues in _SECTION_CUES.items():
        for cue in sorted(cues, key=len, reverse=True):
            if low == cue:
                return section, ""
            if low.startswith(cue):
                remainder = stripped[len(cue):]
                # A real separator ("In scope: x", "In scope - x") leaves content.
                if remainder[:1] in (":", "\u2013", "\u2014", "-"):
                    return section, remainder.lstrip(": \u2013\u2014-").strip()
                # A heading phrase also carries a value: "In scope from 1 September",
                # "Proof of concept required", "Severity and rewards". Only accept
                # it at a word boundary, so "scoped" is not a heading.
                if remainder[:1].isspace() and len(remainder.split()) <= 12:
                    return section, remainder.strip()
                return current, ""
    return current, ""


_HEADING_FILLER = frozenset({
    "activities", "and rewards", "classification", "definitions", "details",
    "levels", "notes", "overview", "policy", "required", "rules", "scope",
})
_REPORTING_CUES = (
    "report privately", "acknowledgement", "triage decision", "payment",
    "disclosure", "safe harbour", "safe harbor", "how a report travels",
    "write to security@", "do not open a public",
)


def _looks_like_asset(line: str) -> bool:
    if len(line) > 400:
        return False
    return bool(_URLISH.search(line)) or "contract" in line.lower()


def _looks_like_scope_phrase(line: str) -> bool:
    """A published scope bullet is an asset even when it names no URL.

    A Cosmos chain's scope is prose: "consensus and block production", "the ML-DSA-87
    signing path". Dropping it because it is not a hostname is the quiet data loss
    this parser must not commit. The filters keep reporting instructions and
    heading filler out.
    """
    low = line.lower().strip().rstrip(".")
    if len(line) > 260 or len(line.split()) < 2:
        return False
    if low in _HEADING_FILLER:
        return False
    if any(cue in low for cue in _REPORTING_CUES):
        return False
    if "proof of concept" in low and len(line.split()) <= 8:
        return False
    return True


def _staged_components(text: str) -> tuple[str, ...]:
    after = text.split(":", 1)[1] if ":" in text else text
    parts = re.split(r",|\band\b", after)
    out: list[str] = []
    for part in parts:
        name = re.sub(r"^(?:the|a|an)\s+", "", part.strip(" .;"), flags=re.I)
        name = name.strip(" .;")
        if name and len(name) <= 100 and not name.lower().startswith("each one"):
            out.append(name)
    return tuple(out)


def _asset_name(line: str) -> str:
    """The asset identity from a scope line: drop a parenthetical or dash suffix."""
    name = line.split("(")[0]
    name = re.split(r"\s+-\s+", name)[0]
    return name.strip().rstrip(",.;")


class PolicyNormalizer:
    """Parse raw policy text into a :class:`NormalizedPolicy`, honestly."""

    def __init__(self) -> None:
        self.uncertainties: list[str] = []

    def normalize(self, text: str, *, program: str, source_url: str,
                  program_id: str = "", version: str = "",
                  retrieved_at: Optional[str] = None) -> NormalizedPolicy:
        self.uncertainties = []
        policy = NormalizedPolicy(
            program=program, program_id=program_id, source_url=source_url,
            source_text=text, retrieved_at=retrieved_at or utcnow(), version=version,
        )
        if not text.strip():
            self.uncertainties.append("policy text was empty; nothing could be established")
            policy.uncertainties = list(self.uncertainties)
            return policy

        section = ""
        for raw in _lines(text):
            bullet = _BULLET.match(raw)
            line = bullet.group(1) if bullet else raw.strip()
            if not line:
                continue
            new_section, inline = _current_section(raw, section)
            if new_section != section:
                section = new_section
                if not inline:
                    continue
                # The heading carried a value on the same line: absorb it under
                # the new section rather than dropping it.
                self._absorb(policy, section, inline, raw, bool(bullet), inline=True)
                continue
            if inline:
                # Same section, heading repeated with a value ("Scope: x" twice).
                self._absorb(policy, section, inline, raw, bool(bullet), inline=True)
                continue
            self._absorb(policy, section, line, raw, bool(bullet))
        self._derive(policy)
        policy.uncertainties = list(self.uncertainties)
        return policy

    # -- absorption ----------------------------------------------------- #

    def _absorb(self, policy: NormalizedPolicy, section: str, line: str, raw: str,
                bullet: bool = False, inline: bool = False) -> None:
        low = line.lower().strip()
        if section == "in_scope":
            if low in _HEADING_FILLER:
                return
            if low.startswith("from ") or "effective from" in low or "in scope from" in low:
                policy.scope_effective_from = line.strip()
                return
            if "components under active remediation" in low:
                policy.special_conditions.append(line.strip())
                staged = _staged_components(line)
                if staged:
                    policy.staged_components.extend(staged)
                return
            if "remediation lands" in low or "added, with an announcement" in low:
                policy.special_conditions.append(line.strip())
                policy.staged_components.extend(_staged_components(line))
                return
            if any(c in low for c in _EXCLUDE_CUES) or any(c in low for c in _INCLUDE_CUES):
                # "Scope notes" is a heading, not an asset. A class-eligibility
                # statement under it is a class rule, never a scope entry.
                self._absorb_class_statement(policy, line, raw)
                return
            looks_asset = _looks_like_asset(line)
            # A prose bullet is an asset only when it reads like a named component
            # (capitalised, or a URL/contract). A lowercase meta-sentence such as
            # "this line is not obviously an asset" stays an uncertainty.
            prose_asset = (bullet or _looks_like_scope_phrase(line)) and (
                looks_asset or (line[:1].isupper() and not inline)
            )
            if looks_asset or prose_asset:
                policy.scope.append(ScopeEntry(
                    asset=_asset_name(line), original_text=raw.strip(),
                    classification=AssetClass.IN_SCOPE,
                    effective_from=policy.scope_effective_from,
                    component_status="active",
                ))
            else:
                self.uncertainties.append(f"unparsed in-scope line: {line[:80]}")
            return
        if section == "out_of_scope":
            if low in _HEADING_FILLER:
                return
            if inline and not _looks_like_asset(line):
                policy.class_rules.append(ClassRule(
                    class_key=line.strip(), eligible=False, original_text=raw.strip(),
                ))
                return
            short_class = (bullet and not _looks_like_asset(line)
                           and len(line.split()) <= 6)
            if short_class:
                policy.class_rules.append(ClassRule(
                    class_key=line.strip(), eligible=False, original_text=raw.strip(),
                ))
            elif _looks_like_asset(line) or _looks_like_scope_phrase(line):
                policy.scope.append(ScopeEntry(
                    asset=line.split("(")[0].strip(), original_text=raw.strip(),
                    classification=AssetClass.OUT_OF_SCOPE,
                    component_status="out_of_scope",
                ))
            else:
                # Could be an excluded *class* rather than an asset.
                policy.class_rules.append(ClassRule(
                    class_key=line.strip(), eligible=False, original_text=raw.strip(),
                ))
            return
        if section in ("severity", "payout"):
            self._absorb_severity(policy, line, raw)
            return
        if section == "restrictions":
            if low in _HEADING_FILLER:
                return
            policy.testing_restrictions.append(line)
            if any(c in low for c in ("rate limit", "requests per", "rps", "qps")):
                policy.rate_limits.append(line)
            if "components under active remediation" in low:
                policy.special_conditions.append(line.strip())
                policy.staged_components.extend(_staged_components(line))
            if "proof of concept" in low:
                policy.poc_standard = (policy.poc_standard + " " + line).strip()
            # A restriction may also state a class exclusion; capture it.
            if any(c in low for c in _EXCLUDE_CUES):
                self._absorb_class_statement(policy, line, raw)
            return
        if section == "rate":
            policy.rate_limits.append(line)
            return
        if section == "known":
            policy.known_issues.append(line)
            return
        if section == "poc":
            policy.poc_standard = (policy.poc_standard + " " + line).strip()
            return
        # No section yet: look for a class-eligibility statement anywhere.
        if any(c in low for c in _EXCLUDE_CUES) or any(c in low for c in _INCLUDE_CUES):
            self._absorb_class_statement(policy, line, raw)

    def _absorb_class_statement(self, policy: NormalizedPolicy, line: str, raw: str) -> None:
        low = line.lower()
        eligible = None
        if any(c in low for c in _EXCLUDE_CUES):
            eligible = False
        elif any(c in low for c in _INCLUDE_CUES):
            eligible = True
        if eligible is None:
            return
        band = coerce_band(line)
        policy.class_rules.append(ClassRule(
            class_key=_class_key_from(line), eligible=eligible, band=band,
            original_text=raw.strip(),
        ))

    def _absorb_severity(self, policy: NormalizedPolicy, line: str, raw: str) -> None:
        band = coerce_band(line)
        if band is Band.UNKNOWN:
            if "payout" in raw.lower() or "$" in line or "usd" in line.lower():
                policy.payouts[line.split(":")[0].strip()] = line
            return
        # "Critical: $10,000" or "High - up to $5000" -> payout/severity map.
        key = band.value
        if "$" in line or "usd" in line.lower() or "reward" in line.lower():
            policy.payouts[key] = line
        else:
            policy.severity_definitions[key] = line

    def _derive(self, policy: NormalizedPolicy) -> None:
        """Derive the minimum severity floor *only* from what the program stated."""
        floor = _stated_floor(policy.source_text)
        if floor is not Band.UNKNOWN:
            policy.minimum_severity = floor
        elif policy.class_rules:
            # Derive from the lowest eligible class band if any are known.
            policy.minimum_severity = policy.minimum_eligible_band()
        # If still unknown, leave UNKNOWN: do not assume a universal threshold.


def _stated_floor(text: str) -> Band:
    """Read an explicit minimum-severity statement, if the program made one."""
    patterns = (
        r"minimum[^\n]{0,40}(?:severity|reward|bounty)[^\n]{0,20}?(critical|high|medium|low|info)",
        r"(?:only|accept)\w*[^\n]{0,30}(critical|high|medium|low|info)[^\n]{0,30}(?:and above|or higher|or above)",
        r"(critical|high|medium|low|info)[^\n]{0,10}(?:and above|or higher|or above)",
    )
    low = text.lower()
    for pat in patterns:
        m = re.search(pat, low)
        if m:
            return coerce_band(m.group(1))
    # "Only Critical and High are accepted" -- an explicit *set*, so the floor is
    # the lowest band named in that statement.
    for line in low.splitlines():
        if re.search(r"\b(?:only|accept\w*)\b", line) and re.search(r"\b(?:accept|paid|eligible|reward)", line):
            named = [coerce_band(w) for w in re.findall(
                r"\b(critical|high|medium|low|info)\b", line)]
            named = [b for b in named if b is not Band.UNKNOWN]
            if named:
                return min(named, key=lambda b: _BAND_ORDER[b])
    return Band.UNKNOWN


def _class_key_from(line: str) -> str:
    """A stable key for a free-text class name (first few words, slugged)."""
    words = re.findall(r"[a-zA-Z]+", line.lower())[:4]
    return "-".join(words) or "unnamed-class"
