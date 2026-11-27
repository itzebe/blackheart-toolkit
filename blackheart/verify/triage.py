"""Deterministic weak-finding gate (triage kill signals).

This module is an **adapted port** of the triage knowledge in
Agentic-Bug-Hunter (https://github.com/awarexone/Agentic-Bug-Hunter,
``skills/triage-validation/SKILL.md`` and ``bughunter/tools/lead_board.py``,
MIT License, Copyright (c) 2026 Claude Bug Bounty Hunter Contributors). See
``THIRD_PARTY_NOTICES.md``. The upstream tables ("KILL SIGNALS", "NEVER SUBMIT",
"CHAIN REQUIRED") are encoded here as data plus a deterministic gate, and adapted
to BLACKHEART's classification model.

Why BLACKHEART needed it: its :class:`~blackheart.verify.IndependentVerifier`
adjudicates a finding through seven *evidence* gates, but it has no encoded
knowledge of the *classes* that are routinely rejected as N/A by bounty triagers
(reflected XSS with no session theft, SSRF with only a DNS callback, CORS
wildcard with no credentialed exfiltration, and so on). This gate rejects those
weak classes *before* they consume verification effort, and marks the classes
that are only valid with a demonstrated chain. It complements the verifier; it
does not replace it.

Design: a finding is described by its ``category`` and the set of **evidence
tags** the hunter has actually established. Each rule states the tags its
category *requires*; a missing required tag is a kill signal. Rules are pure
data, so they are auditable and easy to extend, and the gate is deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Evidence tags: the facts a hunter can establish about a finding.
# --------------------------------------------------------------------------- #

class Evidence:
    """The evidence tags a finding may carry.

    A tag is present only when the hunter has actually demonstrated that fact
    (with a real request/response, not an assumption). The gate treats an absent
    tag as "not established", which is the fail-closed direction.
    """

    REPRODUCED = "reproduced"                  # reproducible from a fresh session
    IN_SCOPE = "in-scope"                     # asset is on the official scope list
    IMPACT_BEYOND_INFO = "impact-beyond-info"
    CROSS_IDENTITY = "cross-identity"         # attacker reads a *different* identity's data
    INTERNAL_DATA = "internal-data"           # SSRF reached an internal service AND got data
    EXECUTION = "execution"                   # XSS actually ran with session/cookie access
    DATA_EXFIL = "data-exfil"                 # SQLi returned real rows, not an error string
    CREDENTIALED_EXFIL = "credentialed-exfil"  # CORS: a credentialed request exfiltrated PII
    SENSITIVE_ACTION = "sensitive-action"     # clickjacking/CSRF: funds, email, delete
    AUTH_CODE_THEFT = "auth-code-theft"       # open redirect chained to OAuth code theft
    PASSWORD_RESET_POISONED = "password-reset-poisoned"
    OTP_BRUTE_FORCED = "otp-brute-forced"
    AUTH_BYPASS = "auth-bypass"               # graphql: an auth-bypass mutation
    IDOR_PROVEN = "idor-proven"               # graphql: node() IDOR proven
    CVE_EXPLOITED = "cve-exploited"           # a working CVE exploit, not a banner
    NO_AUTH_REQUIRED = "no-auth-required"     # works with no valid session
    PRIV_ESC = "priv-esc"                     # low-priv reads high-priv data
    SESSION_THEFT = "session-theft"           # XSS: cookie/session exfiltrated
    CSRF_TRIGGERED = "csrf-triggered"         # self-XSS triggered on the victim
    SUBDOMAIN_TAKEOVER = "subdomain-takeover"


@dataclass
class TriageRule:
    """One class-specific requirement.

    ``applies_to`` names the categories the rule governs (``"*"`` for all).
    ``requires`` are the evidence tags that must all be present; a missing one
    is the kill signal. ``chain_required`` marks a class that is only valid with
    a demonstrated chain (see :data:`CHAIN_REQUIRED`).
    """

    id: str
    applies_to: tuple[str, ...]
    requires: tuple[str, ...]
    reason: str
    chain_required: bool = False
    upstream: str = ""


# --------------------------------------------------------------------------- #
# Kill signals (from ABH "KILL SIGNALS" and "NEVER SUBMIT" tables)
# --------------------------------------------------------------------------- #

#: Classes that are rejected outright unless a chain is demonstrated.
CHAIN_REQUIRED: dict[str, str] = {
    "open-redirect": "OAuth redirect_uri -> auth code theft (ATO)",
    "clickjacking": "a sensitive action with a working PoC",
    "cors-wildcard": "a credentialed request that exfiltrates user data",
    "csrf": "a sensitive action (transfer funds, change email, delete account)",
    "rate-limit": "OTP/reset-token brute force that actually succeeds",
    "ssrf": "internal service access that returns data",
    "host-header-injection": "a password-reset email that uses the injected host",
    "prompt-injection": "reads another user's data (IDOR)",
    "s3-bucket-listing": "JS bundles containing API keys or OAuth secrets",
    "self-xss": "CSRF that triggers it on the victim",
    "subdomain-takeover": "an OAuth redirect_uri registered at that subdomain",
    "graphql-introspection": "an auth-bypass mutation or IDOR on node()",
}

#: Classes that should never be submitted as a standalone finding.
NEVER_SUBMIT: tuple[str, ...] = (
    "missing-csp", "missing-hsts", "missing-security-headers", "missing-spf",
    "missing-dkim", "missing-dmarc", "tabnabbing", "csv-injection",
    "logout-csrf", "mixed-content", "ssl-weak-ciphers",
    "missing-httponly", "missing-secure-cookie", "autocomplete-password",
    "broken-external-link", "session-not-invalidated", "concurrent-sessions",
    "internal-ip-in-error", "pre-account-takeover",
)

#: Class-specific kill signals: the evidence the class requires to be real.
KILL_SIGNALS: tuple[TriageRule, ...] = (
    TriageRule(
        id="xss-no-execution", applies_to=("xss", "reflected-xss", "stored-xss"),
        requires=(Evidence.EXECUTION,),
        reason="XSS without demonstrated execution/session access (e.g. only "
               "alert(1) or a domain popup) is not proof of impact",
        upstream="KILL SIGNALS: XSS via alert(document.domain)",
    ),
    TriageRule(
        id="ssrf-dns-only", applies_to=("ssrf",),
        requires=(Evidence.INTERNAL_DATA,),
        reason="SSRF with only a DNS callback reached no internal service or data; "
               "it needs an internal-service chain that returns data",
        chain_required=True,
        upstream="KILL SIGNALS / CHAIN REQUIRED: SSRF -- DNS callback only",
    ),
    TriageRule(
        id="idor-own-data", applies_to=("idor", "bola"),
        requires=(Evidence.CROSS_IDENTITY,),
        reason="IDOR where the attacker reads their own data proves no boundary "
               "crossing (that is 'missing auth', a different bug)",
        upstream="KILL SIGNALS: IDOR -- own data only",
    ),
    TriageRule(
        id="sqli-error-only", applies_to=("sqli",),
        requires=(Evidence.DATA_EXFIL,),
        reason="SQLi shown only by a database error string exfiltrated no data",
        upstream="KILL SIGNALS: SQLi -- error message only",
    ),
    TriageRule(
        id="cors-no-credentialed-exfil", applies_to=("cors-wildcard", "cors"),
        requires=(Evidence.CREDENTIALED_EXFIL,),
        reason="a CORS wildcard without a credentialed exfiltration of data is "
               "not exploitable (the wildcard blocks credentials); it needs a "
               "credentialed-exfil chain",
        chain_required=True,
        upstream="KILL SIGNALS / CHAIN REQUIRED: CORS wildcard *",
    ),
    TriageRule(
        id="rate-limit-nonsensitive", applies_to=("rate-limit",),
        requires=(Evidence.SENSITIVE_ACTION,),
        reason="a missing rate limit on a non-sensitive endpoint is not payable; "
               "it needs an OTP/reset-token brute-force chain",
        chain_required=True,
        upstream="KILL SIGNALS / CHAIN REQUIRED: Rate limit missing",
    ),
    TriageRule(
        id="banner-no-cve", applies_to=("info-disclosure", "banner-disclosure",
                                         "nuclei-info"),
        requires=(Evidence.CVE_EXPLOITED,),
        reason="version/banner disclosure without a working CVE exploit is info",
        upstream="KILL SIGNALS: Nuclei info template match",
    ),
    TriageRule(
        id="open-redirect-alone", applies_to=("open-redirect",),
        requires=(Evidence.AUTH_CODE_THEFT,),
        reason="an open redirect alone is informational; it needs a token/auth-code "
               "theft chain",
        chain_required=True,
        upstream="CHAIN REQUIRED: Open redirect",
    ),
    TriageRule(
        id="clickjacking-nonsensitive", applies_to=("clickjacking",),
        requires=(Evidence.SENSITIVE_ACTION,),
        reason="clickjacking on a non-sensitive page has no impact without a "
               "sensitive action PoC",
        chain_required=True,
        upstream="CHAIN REQUIRED: Clickjacking",
    ),
    TriageRule(
        id="graphql-introspection-alone",
        applies_to=("graphql-introspection",),
        requires=(Evidence.AUTH_BYPASS, Evidence.IDOR_PROVEN),
        reason="GraphQL introspection alone (no auth bypass, no IDOR) is not a bug",
        chain_required=True,
        upstream="NEVER SUBMIT / CHAIN REQUIRED: GraphQL introspection",
    ),
    TriageRule(
        id="self-xss-alone", applies_to=("self-xss",),
        requires=(Evidence.CSRF_TRIGGERED,),
        reason="self-XSS only exploits your own account without a CSRF trigger",
        chain_required=True,
        upstream="NEVER SUBMIT: Self-XSS",
    ),
    TriageRule(
        id="host-header-alone", applies_to=("host-header-injection",),
        requires=(Evidence.PASSWORD_RESET_POISONED,),
        reason="host header injection alone needs a password-reset poisoning PoC",
        chain_required=True,
        upstream="CHAIN REQUIRED: Host header injection",
    ),
    TriageRule(
        id="subdomain-takeover-alone", applies_to=("subdomain-takeover",),
        requires=(Evidence.SUBDOMAIN_TAKEOVER,),
        reason="subdomain takeover needs a chain (e.g. OAuth redirect_uri at that host)",
        chain_required=True,
        upstream="CHAIN REQUIRED: Subdomain takeover",
    ),
    TriageRule(
        id="auth-bypass-admin-precondition", applies_to=("auth-bypass",),
        requires=(Evidence.NO_AUTH_REQUIRED,),
        reason="an 'auth bypass' that requires an admin precondition is not a "
               "bypass; the attacker must already be admin",
        upstream="KILL SIGNALS: Auth bypass -- admin precondition",
    ),
)

#: Universal requirements: every finding, of any class, must carry these.
UNIVERSAL_REQUIRED: tuple[str, ...] = (Evidence.REPRODUCED, Evidence.IN_SCOPE)


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #

@dataclass
class TriageVerdict:
    """The gate's decision.

    ``reject`` means a kill signal fired: do not report (the finding is a known
    weak/never-submit class or is missing its required evidence). ``downgrade``
    means the class is only valid with a chain that has not been demonstrated.
    ``ok`` means it passed the gate (the verifier still decides the outcome).
    """

    category: str
    reject: bool
    downgrade: bool
    kill_signals: list[dict] = field(default_factory=list)
    chain_required: str = ""
    reasons: list[str] = field(default_factory=list)

    @property
    def weak(self) -> bool:
        return self.reject or self.downgrade

    @property
    def disposition(self) -> str:
        if self.reject:
            return "REJECT"
        if self.downgrade:
            return "DOWNGRADE"
        return "PASS"

    def to_dict(self) -> dict:
        return {
            "category": self.category, "disposition": self.disposition,
            "reject": self.reject, "downgrade": self.downgrade,
            "kill_signals": list(self.kill_signals),
            "chain_required": self.chain_required, "reasons": list(self.reasons),
        }


def _norm(category: str) -> str:
    return (category or "").strip().lower().replace("_", "-").replace(" ", "-")


class TriageGate:
    """Deterministic weak-finding gate (port of ABH's triage tables)."""

    def __init__(self, *, rules: Iterable[TriageRule] = KILL_SIGNALS) -> None:
        self._rules = tuple(rules)

    def evaluate(
        self,
        category: str,
        evidence: Iterable[str],
        *,
        chain_demonstrated: bool = False,
    ) -> TriageVerdict:
        """Adjudicate one finding by class and evidence tags.

        Args:
            category: the finding's class (e.g. ``"idor"``, ``"reflected-xss"``).
            evidence: the evidence tags actually established (see
                :class:`Evidence`).
            chain_demonstrated: whether a required chain has been proven end to
                end. Only consulted for chain-required classes.
        """
        cat = _norm(category)
        have = {str(e) for e in evidence}
        signals: list[dict] = []

        def add(sig: dict, *, hard: bool) -> None:
            sig["hard"] = hard
            signals.append(sig)

        # Universal requirements apply to every class and are always hard.
        for tag in UNIVERSAL_REQUIRED:
            if tag not in have:
                add({"id": f"universal-{tag}",
                     "reason": f"finding is not {tag.replace('_', ' ')}",
                     "upstream": "Gate 0: Reality Check"}, hard=True)

        # Never-submit classes are rejected outright unless a chain is shown.
        if cat in NEVER_SUBMIT and not chain_demonstrated:
            add({"id": f"never-submit-{cat}",
                 "reason": f"'{cat}' is on the never-submit list without a chain",
                 "upstream": "NEVER SUBMIT LIST"}, hard=True)

        chain_note = ""
        for rule in self._rules:
            if "*" not in rule.applies_to and cat not in rule.applies_to:
                continue
            missing = [t for t in rule.requires if t not in have]
            if not missing:
                continue
            if rule.chain_required and chain_demonstrated:
                continue  # the demonstrated chain supplies the missing evidence
            add({"id": rule.id, "reason": rule.reason,
                 "missing_evidence": missing, "upstream": rule.upstream},
                hard=not rule.chain_required)
            if rule.chain_required:
                chain_note = CHAIN_REQUIRED.get(cat, "")

        hard = any(s["hard"] for s in signals)
        chain_only = any(not s["hard"] for s in signals)
        return TriageVerdict(
            category=cat,
            reject=hard,
            downgrade=chain_only and not hard,
            kill_signals=signals,
            chain_required=chain_note,
            reasons=[s["reason"] for s in signals],
        )
