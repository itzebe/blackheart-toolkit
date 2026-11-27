"""The BLACKHEART operational doctrine -- the authoritative mission definition.

This module is the machine-readable statement of *how BLACKHEART operates*. It
does not replace any engine: it names the identity, the research lifecycle, the
attack surfaces, the shape a hypothesis must take, the investigation methods, the
validation requirements and verdict classes, the independent-review questions,
the prioritisation model, the logical research responsibilities, and the
non-negotiable security invariants -- and it maps each of them onto the module
that already implements it.

Why a doctrine module and not just prose in a docstring: the mission requires the
orchestrator to *expose* its doctrine, and requires that every phase, gate, and
rule is one value that the rest of the system reads rather than restates. Keeping
it here means the lifecycle cannot drift between the document, the CLI, the role
prompts, and the code -- the same reason the attacker mindset lives in
``blackheart.mindset``.

It builds on :mod:`blackheart.mindset` (the persona and the one question) and
does not duplicate it: the mindset is *who we are and what we ask*; this is *how
the operation is run*. Nothing here asserts a vulnerability; the invariant engine,
the investigation workflow, and the independent verifier still decide what is real.
"""

from __future__ import annotations

from dataclasses import dataclass

from .mindset import (
    ATTACKER_QUESTION,
    BLACKHEART_PERSONA,
    PERSONA_TRAITS,
    TOOLING_DOCTRINE,
)

# --------------------------------------------------------------------------- #
# Operational identity
# --------------------------------------------------------------------------- #

# The authoritative mission definition (mission section 2). This is the sentence
# every mission is measured against, and it is deliberately about *quality of
# findings*, not count.
OPERATIONAL_IDENTITY = (
    "BLACKHEART is an intelligence-led offensive security research operation that "
    "systematically investigates, challenges, reproduces, and validates weaknesses "
    "in real-world technology. Its purpose is to uncover security failures that "
    "conventional testing may overlook, establish their actual consequences, and "
    "produce independently verifiable evidence. BLACKHEART thinks adversarially, "
    "investigates scientifically, verifies independently, and documents "
    "professionally. Its success is measured by the quality, reproducibility, "
    "technical significance, and impact of its findings -- not the number of "
    "vulnerabilities it claims to discover."
)

# The four dispositions (mission section 2) as behaviours.
DISPOSITIONS: tuple[str, ...] = (
    "Think adversarially: hold the attacker's position, not the auditor's.",
    "Investigate scientifically: state the assumption, the test, and the "
    "falsification condition before running anything.",
    "Verify independently: a finding is not real until a separate agent fails to "
    "break it.",
    "Document professionally: every conclusion leaves a reproducible record.",
)

# The single success metric (mission section 2), stated so it can be quoted.
SUCCESS_METRIC = (
    "Success is the quality, reproducibility, technical significance, and impact "
    "of findings -- never the number of vulnerabilities claimed."
)


# --------------------------------------------------------------------------- #
# The research lifecycle (mission section 3)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Phase:
    """One phase of the research lifecycle.

    ``produces`` names the artefact the phase must emit; ``gate`` names the check
    that must pass before the next phase; ``modules`` names the existing code that
    implements it. The mapping is deliberate: the doctrine introduces no new
    engine, it points at the ones already built and tested.
    """

    number: int
    key: str
    name: str
    purpose: str
    questions: tuple[str, ...]
    produces: str
    gate: str
    modules: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "key": self.key,
            "name": self.name,
            "purpose": self.purpose,
            "questions": list(self.questions),
            "produces": self.produces,
            "gate": self.gate,
            "modules": list(self.modules),
        }


LIFECYCLE: tuple[Phase, ...] = (
    Phase(
        number=1,
        key="TARGET_INTELLIGENCE",
        name="Target intelligence",
        purpose="Establish what the target is before attacking it.",
        questions=(
            "What is the target and what technology does it use?",
            "What are its architecture and its security boundaries?",
            "What do its public source, docs, dependencies, and deployment say?",
            "Which authentication, authorization, cryptographic, infrastructure, "
            "and trust boundaries exist?",
            "Which security assumptions could fail?",
            "What is the research objective?",
        ),
        produces="a target intelligence record (confirmed facts vs assumptions vs unknowns)",
        gate="facts are distinguished from assumptions and unknowns",
        modules=("blackheart.objectives.TargetProfile", "blackheart.threatmodel"),
    ),
    Phase(
        number=2,
        key="ATTACK_SURFACE_DISCOVERY",
        name="Attack-surface discovery",
        purpose="Identify the surfaces that are actually relevant to this target.",
        questions=(
            "Which attack surfaces does this target actually expose?",
            "Which are most technically relevant and highest impact?",
        ),
        produces="a prioritised attack-surface list",
        gate="surfaces are prioritised by relevance and impact, not enumerated blindly",
        modules=("blackheart.hypothesis.surface", "blackheart.threatmodel"),
    ),
    Phase(
        number=3,
        key="ATTACK_HYPOTHESIS_DEVELOPMENT",
        name="Attack-hypothesis development",
        purpose="Turn each promising surface into an explicit, falsifiable hypothesis.",
        questions=(
            "What security assumption is being challenged?",
            "What is the suspected weakness and the attack mechanism?",
            "What evidence would confirm it, and what would disprove it?",
            "What authorization and testing boundaries apply?",
        ),
        produces="falsifiable hypotheses, each with a falsification condition",
        gate="every hypothesis carries the six required fields",
        modules=("blackheart.hypothesis.generation", "blackheart.chains"),
    ),
    Phase(
        number=4,
        key="ADVERSARIAL_INVESTIGATION",
        name="Adversarial investigation",
        purpose="Test the hypothesis with the most appropriate method.",
        questions=(
            "Which method can actually demonstrate (or refute) this?",
            "Is the test authorized, and is it reproducible locally?",
        ),
        produces="a reproduction (or a documented, honest non-reproduction)",
        gate="the authorization gate classifies the asset AUTHORIZED before any active test",
        modules=(
            "blackheart.investigation",
            "blackheart.invariants.engine",
            "blackheart.assurance",
            "blackheart.authz",
        ),
    ),
    Phase(
        number=5,
        key="EXPLOIT_VALIDATION",
        name="Exploit validation",
        purpose="Decide, on evidence, whether a suspicion is a real vulnerability.",
        questions=(
            "Is the weakness reproduced, with the precise root cause identified?",
            "Does the evidence show the violated security property?",
            "What are the realistic attack prerequisites?",
            "What alternative explanations exist?",
        ),
        produces="a verdict from the finding-verdict set, with evidence",
        gate="missing or invalid evidence cannot produce a confirmed vulnerability",
        modules=("blackheart.investigation", "blackheart.evidence", "blackheart.verify"),
    ),
    Phase(
        number=6,
        key="INDEPENDENT_ADVERSARIAL_REVIEW",
        name="Independent adversarial review",
        purpose="Have a separate agent try to break the conclusion, not approve it.",
        questions=(
            "Does the PoC actually demonstrate the claimed vulnerability?",
            "Is the issue exploitable under realistic conditions?",
            "Is the root cause correctly identified?",
            "Could the behaviour be intentional?",
            "Are there controls that invalidate the attack?",
            "Is the claimed impact exaggerated?",
            "Can an independent researcher reproduce the result?",
        ),
        produces="an independent verification result",
        gate="an unverified finding is never promoted to confirmed, however many agents agree",
        modules=("blackheart.verify", "blackheart.novelty", "blackheart.findings"),
    ),
)

PHASE_BY_KEY: dict[str, Phase] = {p.key: p for p in LIFECYCLE}


# --------------------------------------------------------------------------- #
# Attack surfaces (mission section 3, Phase 2)
# --------------------------------------------------------------------------- #

# The canonical surface catalogue. The mission is explicit that not every category
# applies to every target, so this is a *checklist to consider*, never a checklist
# to report. Each entry names what to look for.
ATTACK_SURFACES: tuple[str, ...] = (
    "authentication and identity management",
    "authorization and privilege boundaries",
    "session management",
    "API endpoints and integrations",
    "cryptographic implementations",
    "key management and signing operations",
    "data storage and encryption",
    "infrastructure and deployment configuration",
    "supply-chain dependencies",
    "smart contracts and blockchain integrations",
    "AI agents, tool permissions, and model-provider integrations",
    "recovery and migration mechanisms",
    "inter-service trust relationships",
)


# --------------------------------------------------------------------------- #
# Hypothesis shape (mission section 3, Phase 3)
# --------------------------------------------------------------------------- #

# Every hypothesis must contain these six elements or it is not a hypothesis.
HYPOTHESIS_REQUIRED_FIELDS: tuple[str, ...] = (
    "the security assumption being challenged",
    "the suspected weakness",
    "the proposed attack mechanism",
    "the expected evidence if the hypothesis is correct",
    "the conditions that would disprove it",
    "the required authorization and testing boundaries",
)

# The canonical example hypotheses the mission gives, kept as prompts so the
# engine always asks at least these.
HYPOTHESIS_PROMPTS: tuple[str, ...] = (
    "Can an attacker bypass an authorization boundary?",
    "Can an untrusted identity substitute a trusted identity?",
    "Can cryptographic key substitution undermine confidentiality?",
    "Can a recovery mechanism restore unauthorized privileges?",
    "Can malformed input violate a security invariant?",
    "Can a compromised component manipulate downstream trust?",
    "Can an agent execute operations beyond its granted permissions?",
)


# --------------------------------------------------------------------------- #
# Investigation methods (mission section 3, Phase 4)
# --------------------------------------------------------------------------- #

INVESTIGATION_METHODS: tuple[str, ...] = (
    "source-code analysis",
    "static analysis",
    "dependency analysis",
    "protocol analysis",
    "cryptographic review",
    "local adversarial testing",
    "controlled fault injection",
    "malicious-input testing",
    "boundary-condition testing",
    "property-based testing",
    "differential testing",
    "regression testing",
    "reproducible proof-of-concept development",
)

# The operations that are out of bounds, stated so they cannot be quietly added.
FORBIDDEN_OPERATIONS: tuple[str, ...] = (
    "destructive operations against live systems",
    "persistence",
    "credential theft",
    "data exfiltration",
    "unauthorized access",
)


# --------------------------------------------------------------------------- #
# Language-aware security research policy (mandatory)
# --------------------------------------------------------------------------- #

# The governing principle, in one line, so it can be quoted verbatim.
LANGUAGE_AWARE_PRINCIPLE = (
    "RESEARCH FIRST. IDENTIFY THE STACK. VERIFY COMPATIBILITY. TEST NATIVELY. "
    "REPRODUCE INDEPENDENTLY. REPORT HONESTLY."
)

# A. Repository reconnaissance comes first.
RECONNAISSANCE_REQUIREMENTS: tuple[str, ...] = (
    "verify repository, branch, commit and target scope",
    "identify every security-relevant implementation language",
    "inspect source files, manifests, compiler configurations, dependencies and "
    "build systems",
    "identify protocol architecture, framework, runtime and execution environment",
    "identify existing native test and exploit harnesses",
    "distinguish production code from tests, documentation, generated code and "
    "frontend code",
    "never infer the complete technology stack from README files or file "
    "extensions alone",
)

# B. Tool compatibility verification -- every item is checked against the target.
TOOL_COMPATIBILITY_REQUIREMENTS: tuple[str, ...] = (
    "supported language",
    "supported language version",
    "supported framework and runtime",
    "required compiler and build configuration",
    "instrumentation and execution requirements",
    "relevant vulnerability classes",
    "known limitations",
)

# C. Technology-native testing methods. Examples, never a ceiling: a language not
# listed here is researched, not skipped. The verified detail (tool versions,
# official documentation, known incompatibilities) lives in
# ``docs/SECURITY_TOOL_COMPATIBILITY.md`` and ``blackheart.toolchain``.
NATIVE_TESTING_METHODS: dict[str, tuple[str, ...]] = {
    "Solidity": ("Foundry", "Slither", "Echidna", "Medusa"),
    "Vyper": ("vyper", "Foundry", "Slither", "Titanoboa", "Hypothesis"),
    "Rust/Substrate": ("Cargo", "FRAME tests", "Rust integration harnesses",
                       "proptest", "cargo-fuzz"),
    "Python": ("pytest", "Hypothesis", "Bandit"),
    "Go": ("go test", "native fuzzing", "govulncheck"),
    "C/C++": ("compiler sanitizers", "libFuzzer", "AFL++"),
    "Move": ("native Move testing", "framework-specific Move tooling"),
    "Cairo": ("Cairo testing", "Starknet-specific tooling"),
    "JavaScript/TypeScript": ("native test frameworks", "property-based testing",
                              "compatible static analysis"),
}

# D. Mixed-language protocols: every security-relevant component is its own target.
MIXED_LANGUAGE_REQUIREMENTS: tuple[str, ...] = (
    "treat every security-relevant component independently",
    "map cross-component interactions: serialisation, message validation, "
    "signature verification, authorization, bridge operations and asset accounting",
    "never claim complete protocol coverage after examining only one language or "
    "component",
)

# E. The mandatory pre-execution compatibility gate: what must be documented
# before a security engine runs.
COMPATIBILITY_GATE_FIELDS: tuple[str, ...] = (
    "target component",
    "identified language and version",
    "framework and runtime",
    "selected tool",
    "official compatibility evidence",
    "reason for tool selection",
    "expected test coverage",
    "known limitations",
)

COMPATIBILITY_GATE_SMOKE_TEST = (
    "run a compatibility smoke test before full analysis; if compatibility cannot "
    "be established, BLOCK execution and research an appropriate alternative"
)

# F. Honest execution reporting -- the only four statuses, each with one meaning.
EXECUTION_STATUSES: dict[str, str] = {
    "PASS": "Analysis completed successfully",
    "BLOCKED": "Tool incompatible or required prerequisites unavailable",
    "INCOMPLETE": "Analysis started but did not complete or coverage is insufficient",
    "NO_FINDINGS": "Analysis completed successfully without identifying an issue",
}

HONEST_EXECUTION_RULES: tuple[str, ...] = (
    "a parser failure is not a vulnerability reproduction failure",
    "a successful build is not proof of security",
    "a clean scanner result is not proof that the protocol is secure",
    "never fabricate tool output, exploit results, test coverage or vulnerability "
    "confirmation",
)

# G. Research continuity -- a blocked tool never cancels a valid investigation.
RESEARCH_CONTINUITY_RULES: tuple[str, ...] = (
    "preserve the original vulnerability hypothesis and approved target scope",
    "never abandon a valid investigation because an inappropriate tool failed",
    "select the correct language-native testing method and continue from the last "
    "verified research state",
)

# H. Final acceptance criteria -- no investigation is complete until all hold.
COMPLETION_ACCEPTANCE: tuple[str, ...] = (
    "technology stack is documented",
    "tool compatibility is verified",
    "relevant security-critical components have been examined",
    "appropriate native tests have been performed",
    "vulnerability hypotheses have been independently assessed",
    "coverage gaps and untested components are disclosed",
)

#: The whole policy as one machine-readable value. The Markdown policy document
#: (``docs/SECURITY_TOOL_COMPATIBILITY.md``) is checked against this dict, and the
#: compatibility gate in :mod:`blackheart.toolchain` reads the field list and the
#: status set from here, so the policy cannot drift from what is enforced.
LANGUAGE_AWARE_POLICY: dict = {
    "principle": LANGUAGE_AWARE_PRINCIPLE,
    "repository_reconnaissance": list(RECONNAISSANCE_REQUIREMENTS),
    "tool_compatibility_verification": list(TOOL_COMPATIBILITY_REQUIREMENTS),
    "native_testing_methods": {k: list(v) for k, v in NATIVE_TESTING_METHODS.items()},
    "mixed_language_protocols": list(MIXED_LANGUAGE_REQUIREMENTS),
    "pre_execution_gate": {
        "fields": list(COMPATIBILITY_GATE_FIELDS),
        "smoke_test": COMPATIBILITY_GATE_SMOKE_TEST,
    },
    "execution_statuses": dict(EXECUTION_STATUSES),
    "honest_execution": list(HONEST_EXECUTION_RULES),
    "research_continuity": list(RESEARCH_CONTINUITY_RULES),
    "completion_acceptance": list(COMPLETION_ACCEPTANCE),
    "tooling_bar": list(TOOLING_DOCTRINE),
    "registry": "docs/SECURITY_TOOL_COMPATIBILITY.md",
    "enforced_by": [
        "blackheart.toolchain",
        "blackheart.toolchain.detect",
        "blackheart compat",
        "tests/test_tool_compatibility.py",
    ],
    "overrides": "generic tool-selection defaults",
}


# --------------------------------------------------------------------------- #
# Validation (mission section 3, Phase 5) and verdicts
# --------------------------------------------------------------------------- #

# What must be true before a suspicion may be called a confirmed vulnerability.
VALIDATION_REQUIREMENTS: tuple[str, ...] = (
    "reproduction of the suspected weakness",
    "identification of the precise root cause",
    "evidence demonstrating the violated security property",
    "confirmation of attacker capabilities",
    "analysis of realistic attack prerequisites",
    "examination of alternative explanations",
    "independent reproduction where feasible",
    "assessment of real-world security consequences",
)

# The verdict set. These are kept deliberately distinct; the mission forbids
# conflating them. A finding is always in exactly one of these states.
FINDING_VERDICTS: tuple[str, ...] = (
    "CONFIRMED",            # reproduced, root cause identified, independently verified
    "STRONGLY_SUPPORTED",   # strong evidence, not yet independently reproduced
    "UNCONFIRMED",          # a live suspicion without sufficient evidence
    "FALSE_POSITIVE",       # explained by benign behaviour or a non-discriminating PoC
    "INFORMATIONAL",        # real but not a vulnerability (intentional/documented)
    "NOT_REPRODUCIBLE",     # could not be reproduced on retry
    "OUT_OF_SCOPE",         # outside the authorized program scope
)

# The verdicts that may never be read back as "this is a real vulnerability".
NON_CONFIRMED_VERDICTS: tuple[str, ...] = tuple(
    v for v in FINDING_VERDICTS if v != "CONFIRMED"
)


# --------------------------------------------------------------------------- #
# Independent review (mission section 3, Phase 6)
# --------------------------------------------------------------------------- #

# The questions an independent reviewer must answer. These mirror the opt-in
# challenges in ``blackheart.verify``; the reviewer answers them from evidence.
REVIEW_QUESTIONS: tuple[str, ...] = (
    "Does the PoC actually demonstrate the claimed vulnerability?",
    "Is the issue exploitable under realistic conditions?",
    "Is the root cause correctly identified?",
    "Could the observed behaviour be intentional?",
    "Are there additional security controls that invalidate the attack?",
    "Is the claimed impact exaggerated?",
    "Can an independent researcher reproduce the result?",
)


# --------------------------------------------------------------------------- #
# Finding record sections (mission section 4)
# --------------------------------------------------------------------------- #

# The ten sections every finding must document. ``blackheart.findings``
# implements exactly these; this list is the contract the repository enforces.
@dataclass(frozen=True)
class FindingSection:
    letter: str
    name: str
    fields: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"letter": self.letter, "name": self.name, "fields": list(self.fields)}


FINDING_SECTIONS: tuple[FindingSection, ...] = (
    FindingSection("A", "Identification", (
        "finding_id", "title", "target", "component", "affected_version",
        "discovery_date", "researcher", "status",
    )),
    FindingSection("B", "Technical classification", (
        "category", "cwe", "cvss_score", "cvss_vector", "severity",
        "security_boundary", "attack_prerequisites",
    )),
    FindingSection("C", "Root cause", (
        "root_cause_file", "root_cause_location", "vulnerable_implementation",
        "design_mistake", "why_controls_failed",
    )),
    FindingSection("D", "Attack analysis", (
        "hypothesis", "attacker_assumptions", "attack_preconditions",
        "attack_sequence", "required_permissions", "exploitability",
        "consequences", "attack_scenarios",
    )),
    FindingSection("E", "Proof of concept", (
        "repro_environment", "repro_steps", "repro_commands", "poc_code",
        "expected_behavior", "observed_behavior", "execution_result",
        "repro_success_rate",
    )),
    FindingSection("F", "Evidence", (
        "evidence_ids", "logs", "source_refs", "traces", "before_after",
        "evidence_hashes",
    )),
    FindingSection("G", "Independent verification", (
        "verification_methodology", "reviewer", "verification_result",
        "alternative_explanations", "false_positive_analysis", "remaining_uncertainty",
    )),
    FindingSection("H", "Impact", (
        "confidentiality_impact", "integrity_impact", "availability_impact",
        "privilege_escalation", "affected_scope", "exploit_prerequisites",
        "severity_justification",
    )),
    FindingSection("I", "Remediation", (
        "recommended_fix", "affected_implementation", "invariants_to_restore",
        "regression_tests", "retest_result",
    )),
    FindingSection("J", "Disclosure", (
        "disclosure_policy", "reporting_channel", "report_status",
        "submission_status", "submission_reference", "org_response",
    )),
)

# The fields whose presence is *required* before a finding may be CONFIRMED: it
# must carry evidence and an independent verification result.
CONFIRMATION_REQUIRED_FIELDS: tuple[str, ...] = (
    "evidence_ids",
    "verification_result",
    "reviewer",
)


# --------------------------------------------------------------------------- #
# Prioritisation (mission section 7)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PriorityFactor:
    """One factor in the transparent prioritisation model.

    Each factor is scored 0.0..1.0 by the caller; the score is the weighted sum.
    The weights are a reviewable value, not a buried constant.
    """

    key: str
    weight: float
    description: str

    def to_dict(self) -> dict:
        return {"key": self.key, "weight": self.weight, "description": self.description}


PRIORITY_FACTORS: tuple[PriorityFactor, ...] = (
    PriorityFactor("security_impact", 0.28, "how serious the consequence is"),
    PriorityFactor("technical_plausibility", 0.18, "how likely the weakness is real"),
    PriorityFactor("novelty", 0.12, "how new the suspected weakness is"),
    PriorityFactor("exposure", 0.14, "how exposed the affected component is"),
    PriorityFactor("exploitability", 0.14, "how readily an attacker reaches it"),
    PriorityFactor("feasibility", 0.08, "whether the research can actually be done here"),
    PriorityFactor("reproducible_evidence", 0.06, "whether reproducible evidence is available"),
)

# Reward size is deliberately NOT a factor: the mission forbids prioritising a
# target merely because it advertises a large bounty.
PRIORITISATION_NON_FACTORS: tuple[str, ...] = (
    "advertised bounty size",
    "program popularity",
    "ease of report submission",
)


def priority_score(factors: dict[str, float]) -> float:
    """Transparent weighted score for one candidate, in ``[0.0, 1.0]``.

    Unknown factors contribute nothing (they are neither assumed good nor bad);
    the score is the weighted sum of the factors actually supplied. This keeps the
    model honest: a candidate is not penalised for an unmeasured dimension, and is
    never rewarded for a bounty size.
    """
    total = 0.0
    for f in PRIORITY_FACTORS:
        v = factors.get(f.key)
        if v is None:
            continue
        total += f.weight * max(0.0, min(1.0, float(v)))
    return round(total, 4)


def prioritize(candidates: list[dict], *, key: str = "factors") -> list[dict]:
    """Rank candidates by :func:`priority_score`, highest first.

    Each candidate is a dict carrying at least ``key`` -> {factor: value}. The
    original dicts are returned, each annotated with ``priority_score``, so a
    caller can show *why* an order was chosen.
    """
    ranked = []
    for c in candidates:
        item = dict(c)
        item["priority_score"] = priority_score(c.get(key, {}))
        ranked.append(item)
    ranked.sort(key=lambda c: c["priority_score"], reverse=True)
    return ranked


# --------------------------------------------------------------------------- #
# Bounty eligibility gate (the official policy is the sole authority)
# --------------------------------------------------------------------------- #

# The rule that governs every submission decision. Kept here, beside the
# prioritisation model it deliberately outranks, so the two can never be confused.
BOUNTY_GATE_RULE = (
    "The official, program-specific bug bounty policy is the sole authority on "
    "whether a vulnerability is eligible for submission. It decides the eligible "
    "assets, the exclusions, the qualifying classes, the required impact, the "
    "severity, the attacker prerequisites, the evidence bar, duplicate treatment, "
    "disclosure and reward conditions. No internal score, generic numeric "
    "threshold, or universal severity-to-payout assumption decides eligibility; "
    "internal scoring ranks research only. If the official policy cannot be "
    "retrieved or verified the answer is BLOCKED, never an invented decision."
)

#: The exact disposition when the official policy is unavailable. Single source:
#: ``blackheart.bounty.gate`` imports this rather than restating it.
BOUNTY_POLICY_UNVERIFIED = "BLOCKED — OFFICIAL BOUNTY POLICY NOT VERIFIED"


#: The rule that replaced invented numeric thresholds. Stated once, rendered in
#: the doctrine and in every bounty-report agent, so no mission can reintroduce a
#: generic 80/100 bar as if it were a program requirement.
BOUNTY_NO_THRESHOLD_RULE = (
    "No invented numeric threshold decides whether a candidate is submitted, "
    "critical, or eligible. A generic score (80/100, 90/100, or any other "
    "composite) is not a program requirement, not a severity definition and not a "
    "measure of exploitability, so it may not be used as one. If a program "
    "publishes its own scoring system, use that system exactly and cite its "
    "source; otherwise do not invent one. A mandatory gate failure cannot be "
    "compensated by strength in another gate, and a technically valid but "
    "ineligible finding is archived honestly rather than promoted."
)


@dataclass(frozen=True)
class BountyGate:
    """One of the seven mandatory gates every candidate must pass.

    The gates are independent and non-compensating: failing any one fixes the
    classification, whatever the others say.
    """

    letter: str
    name: str
    question: str
    records: tuple[str, ...]
    failure: str = ""

    def to_dict(self) -> dict:
        return {"letter": self.letter, "name": self.name,
                "question": self.question, "records": list(self.records),
                "failure": self.failure}


BOUNTY_GATES: tuple[BountyGate, ...] = (
    BountyGate(
        "1", "Deployment",
        "Is this exact code live, at a known address, on the chain the program covers?",
        ("exact deployed address", "verified implementation (proxy -> implementation slot)",
         "correct chain / chain id", "evidence of active deployment (state, balances, traffic)",
         "source identity: deployed bytecode against the repository at a pinned commit"),
        "no address, no implementation, no chain -> not a candidate",
    ),
    BountyGate(
        "2", "Eligibility",
        "Do the program's published rules include this asset and this class?",
        ("official program scope", "eligible asset",
         "no applicable exclusion (known issue, audit, duplicate, admin key, third party)",
         "the exact policy sections relied on, with retrieval date and text hash"),
        "out of scope or excluded -> C, valid but not payable",
    ),
    BountyGate(
        "3", "Reachability",
        "Can the stated attacker actually get there, without a privilege nobody granted them?",
        ("realistic attacker capabilities", "no undisclosed privileged assumption",
         "reproducible attack path", "preconditions, capital and cost"),
        "needs a role, key or whitelist -> not this attacker's path",
    ),
    BountyGate(
        "4", "Security violation",
        "What invariant is broken, and can an independent researcher reproduce it?",
        ("explicit security invariant", "demonstrated violation",
         "independent reproduction", "exact transaction sequence and observed state"),
        "no invariant and no reproduction -> D or F",
    ),
    BountyGate(
        "5", "Impact",
        "Who loses what, and does the attacker come out ahead?",
        ("actual affected asset or user", "quantified economic consequences",
         "realistic attacker economics (cost against gain, repeatability, liquidity)"),
        "no measurable loss and no attacker profit -> C",
    ),
    BountyGate(
        "6", "Novelty",
        "Is this already known, audited, fixed or acknowledged?",
        ("audit comparison", "existing issue and PR comparison", "known-fix comparison",
         "previously acknowledged behaviour excluded",
         "closest prior disclosure and the material difference"),
        "known or already fixed -> D",
    ),
    BountyGate(
        "7", "Reportability",
        "Can a triager act on this without asking us anything?",
        ("clear technical explanation", "reproducible PoC",
         "evidence sufficient for independent triage",
         "exact commands, addresses and block numbers"),
        "cannot be reproduced from the report -> F",
    ),
)

#: What a candidate *is*, in the program's own terms. Five classes, no sixth:
#: an "informational" observation is class C, because it fails Gate 5 (impact).
BOUNTY_CLASSIFICATIONS: tuple[tuple[str, str], ...] = (
    ("A", "PAYABLE CANDIDATE — all seven mandatory gates pass, with evidence "
          "supporting eligibility and the applicable impact category"),
    ("B", "POTENTIALLY PAYABLE — a technically convincing finding exists, but an "
          "explicitly identified external eligibility or deployment question remains "
          "unresolved"),
    ("C", "VALID, NOT PAYABLE — the technical defect exists, but a mandatory bounty "
          "requirement fails"),
    ("D", "REJECTED — the hypothesis is incorrect, non-reproducible or not exploitable"),
    ("F", "INCOMPLETE RESEARCH LEAD — a plausible technical hypothesis exists, but "
          "there is insufficient evidence to establish a vulnerability"),
)

#: The six process dispositions a gate run can end in. These are not the
#: classification: a disposition says what the process concluded, a classification
#: says what the candidate is. ``E`` (informational) reports as classification ``C``.
BOUNTY_DISPOSITIONS: tuple[tuple[str, str], ...] = (
    ("A", "submission-ready: meets verified technical and program eligibility requirements"),
    ("B", "potentially payable: plausible qualifying vulnerability with outstanding validation"),
    ("C", "valid but not payable: technically valid, but excluded or otherwise ineligible"),
    ("D", "invalid or disproven"),
    ("E", "informational: demonstrable observation without an established qualifying impact "
          "(reports as classification C)"),
    ("F", "not assessed: insufficient evidence to reach a conclusion"),
)

#: The four payment determinations a reassessment reports, and the disposition
#: each one comes from. ``PAYABLE`` has exactly one source, so no candidate can be
#: called payable without having passed every documented requirement.
PAYMENT_DETERMINATIONS: tuple[tuple[str, str], ...] = (
    ("PAYABLE", "from A: satisfies the program's documented requirements"),
    ("POTENTIALLY PAYABLE", "from B: credible eligibility argument, needs evidence"),
    ("NOT PAYABLE", "from C, D or E: excluded, disproven, or no qualifying impact"),
    ("UNRESOLVED", "from F: the official rules are ambiguous or the evidence is absent"),
)


# --------------------------------------------------------------------------- #
# Logical research responsibilities (mission section 6)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Responsibility:
    """One logical research responsibility and the existing agent that fills it.

    These are *responsibilities*, not new agents: the mission is explicit that
    they are logical and must reuse existing agents wherever possible.
    """

    key: str
    name: str
    duty: str
    agents: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "duty": self.duty,
                "agents": list(self.agents)}


RESPONSIBILITIES: tuple[Responsibility, ...] = (
    Responsibility("intelligence_analyst", "Intelligence Analyst",
                   "gathers target intelligence (phase 1)",
                   ("protocol-intelligence-agent",)),
    Responsibility("attack_surface_analyst", "Attack Surface Analyst",
                   "maps relevant security boundaries (phase 2)",
                   ("attack-surface-agent",)),
    Responsibility("hypothesis_researcher", "Hypothesis Researcher",
                   "develops falsifiable attack hypotheses (phase 3)",
                   ("attacker-strategy-agent",)),
    Responsibility("offensive_researcher", "Offensive Researcher",
                   "investigates weaknesses and develops PoCs (phase 4)",
                   ("smart-contract-exploit-agent", "web-exploit-agent",
                    "api-exploit-agent", "infrastructure-exploit-agent",
                    "cryptographic-protocol-agent", "supply-chain-agent",
                    "mobile-security-agent", "economic-attack-agent",
                    "exploit-chain-agent", "stateful-fuzzing-agent")),
    Responsibility("verification_researcher", "Verification Researcher",
                   "independently reproduces findings (phase 6)",
                   ("independent-verification-agent",)),
    Responsibility("adversarial_reviewer", "Adversarial Reviewer",
                   "challenges claims and finds false positives (phase 6)",
                   ("independent-verification-agent",)),
    Responsibility("impact_analyst", "Impact Analyst",
                   "establishes realistic security consequences (phase 5)",
                   ("economic-attack-agent", "protocol-intelligence-agent")),
    Responsibility("documentation_analyst", "Documentation Analyst",
                   "maintains complete research records (all phases)",
                   ("evidence-and-bounty-report-agent",)),
    Responsibility("disclosure_analyst", "Disclosure Analyst",
                   "prepares responsible disclosure material (post-verdict)",
                   ("evidence-and-bounty-report-agent",)),
)


# --------------------------------------------------------------------------- #
# Security invariants (mission section 9) -- non-negotiable
# --------------------------------------------------------------------------- #

# Each invariant is a rule the code enforces, named so a reviewer can check it.
SECURITY_INVARIANTS: tuple[str, ...] = (
    "authorization is fail-closed: an asset that is not AUTHORIZED cannot be tested",
    "target scope is enforced before any live testing",
    "every active action is written to an audit trail",
    "evidence provenance is preserved (content-addressed, hash-chained)",
    "simulated and real execution are kept separate and labelled",
    "findings and execution results are never fabricated",
    "a hypothesis is never promoted to a confirmed vulnerability without evidence",
    "reports are never submitted without explicit operator authorization",
    "sensitive findings are never disclosed publicly without authorization",
    "secrets are never written to logs or documentation",
    "security gates are never weakened to improve apparent autonomy",
    "human approval boundaries are explicit",
)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def doctrine_dict() -> dict:
    """The whole doctrine as a machine-readable dict (what the orchestrator exposes)."""
    return {
        "identity": OPERATIONAL_IDENTITY,
        "dispositions": list(DISPOSITIONS),
        "success_metric": SUCCESS_METRIC,
        "question": ATTACKER_QUESTION,
        "lifecycle": [p.to_dict() for p in LIFECYCLE],
        "attack_surfaces": list(ATTACK_SURFACES),
        "hypothesis_required_fields": list(HYPOTHESIS_REQUIRED_FIELDS),
        "hypothesis_prompts": list(HYPOTHESIS_PROMPTS),
        "investigation_methods": list(INVESTIGATION_METHODS),
        "forbidden_operations": list(FORBIDDEN_OPERATIONS),
        "language_aware_policy": LANGUAGE_AWARE_POLICY,
        "validation_requirements": list(VALIDATION_REQUIREMENTS),
        "finding_verdicts": list(FINDING_VERDICTS),
        "review_questions": list(REVIEW_QUESTIONS),
        "finding_sections": [s.to_dict() for s in FINDING_SECTIONS],
        "confirmation_required_fields": list(CONFIRMATION_REQUIRED_FIELDS),
        "priority_factors": [f.to_dict() for f in PRIORITY_FACTORS],
        "prioritisation_non_factors": list(PRIORITISATION_NON_FACTORS),
        "bounty_gate": {
            "rule": BOUNTY_GATE_RULE,
            "no_threshold_rule": BOUNTY_NO_THRESHOLD_RULE,
            "gates": [g.to_dict() for g in BOUNTY_GATES],
            "classifications": [{"key": k, "meaning": v} for k, v in BOUNTY_CLASSIFICATIONS],
            "dispositions": [{"key": k, "meaning": v} for k, v in BOUNTY_DISPOSITIONS],
            "payment_determinations": [
                {"determination": k, "source": v} for k, v in PAYMENT_DETERMINATIONS],
            "policy_unverified": BOUNTY_POLICY_UNVERIFIED,
            "implemented_by": ["blackheart/bounty/gate.py", "blackheart bounty gate"],
        },
        "responsibilities": [r.to_dict() for r in RESPONSIBILITIES],
        "security_invariants": list(SECURITY_INVARIANTS),
    }


def phase(key: str) -> Phase:
    """Look up a lifecycle phase by key (raises ``KeyError`` if unknown)."""
    return PHASE_BY_KEY[key]


def doctrine_prompt_block() -> str:
    """A compact doctrine block for an LLM system prompt.

    Kept short on purpose: the identity, the lifecycle phase names, and the hard
    rules. The full doctrine is available through ``blackheart doctrine``; this is
    what every role carries so the operation is run the same way everywhere.
    """
    phases = " -> ".join(p.name for p in LIFECYCLE)
    rules = "; ".join(SECURITY_INVARIANTS[:5])
    return (
        f"{OPERATIONAL_IDENTITY} "
        f"Run every mission through the lifecycle: {phases}. "
        "Never fabricate a finding or an execution result; never promote a "
        "hypothesis to a confirmed vulnerability without evidence and independent "
        "verification; never run an active test without a fail-closed "
        "authorization. Before running any tool, identify every implementation "
        "language from the source and build configuration, verify the tool's "
        "documented compatibility with that language and version, and smoke-test "
        "it; a tool is never assumed appropriate because it worked on another "
        "protocol, and an incompatible tool is BLOCKED, never substituted. "
        "Eligibility for submission is decided only by the target program's "
        "official bug bounty policy -- never by an internal score or a generic "
        "threshold; if that policy is not verified the answer is BLOCKED. "
        f"Non-negotiable: {rules}."
    )


def doctrine_document() -> str:
    """The full doctrine as a Markdown document."""
    lines: list[str] = []
    lines.append("# BLACKHEART operational doctrine")
    lines.append("")
    lines.append("> " + BLACKHEART_PERSONA)
    lines.append("")
    lines.append("## Operational identity")
    lines.append("")
    lines.append(OPERATIONAL_IDENTITY)
    lines.append("")
    lines.append("### Dispositions")
    lines.append("")
    for d in DISPOSITIONS:
        lines.append(f"- {d}")
    lines.append("")
    lines.append("### Success metric")
    lines.append("")
    lines.append(SUCCESS_METRIC)
    lines.append("")
    lines.append("### The question every mission answers")
    lines.append("")
    lines.append("> " + ATTACKER_QUESTION)
    lines.append("")
    lines.append("### The temperament")
    lines.append("")
    for t in PERSONA_TRAITS:
        lines.append(f"- {t}")
    lines.append("")
    lines.append("## The research lifecycle")
    lines.append("")
    for p in LIFECYCLE:
        lines.append(f"### Phase {p.number} -- {p.name}")
        lines.append("")
        lines.append(p.purpose)
        lines.append("")
        for q in p.questions:
            lines.append(f"- {q}")
        lines.append("")
        lines.append(f"- **Produces:** {p.produces}")
        lines.append(f"- **Gate:** {p.gate}")
        lines.append(f"- **Implemented by:** {', '.join('`' + m + '`' for m in p.modules)}")
        lines.append("")
    lines.append("## Attack surfaces to consider")
    lines.append("")
    for s in ATTACK_SURFACES:
        lines.append(f"- {s}")
    lines.append("")
    lines.append("## Hypothesis shape (all six are required)")
    lines.append("")
    for h in HYPOTHESIS_REQUIRED_FIELDS:
        lines.append(f"- {h}")
    lines.append("")
    lines.append("## Investigation methods")
    lines.append("")
    for m in INVESTIGATION_METHODS:
        lines.append(f"- {m}")
    lines.append("")
    lines.append("### Forbidden operations")
    lines.append("")
    for f in FORBIDDEN_OPERATIONS:
        lines.append(f"- {f}")
    lines.append("")
    lines.append("## Language-aware security research (mandatory)")
    lines.append("")
    lines.append("> " + LANGUAGE_AWARE_PRINCIPLE)
    lines.append("")
    lines.append("This policy overrides generic tool-selection defaults. The "
                 "verified tool registry, with official documentation and known "
                 "incompatibilities, is `docs/SECURITY_TOOL_COMPATIBILITY.md`; the "
                 "gate is enforced by `blackheart.toolchain` and `blackheart compat`, "
                 "and at the engine boundary by `blackheart/toolchain/enforce.py` -- "
                 "`hunt`, `campaign`, `engines run`, the state-space explorer and the "
                 "Python API take `--compatibility`/`compatibility=` and refuse a "
                 "target with no validated record bound to it.")
    lines.append("")
    lines.append("### A. Repository reconnaissance comes first")
    lines.append("")
    lines.append("Before selecting or executing security tools:")
    lines.append("")
    for r in RECONNAISSANCE_REQUIREMENTS:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("### B. Tool compatibility verification")
    lines.append("")
    lines.append("For every proposed tool, verify against the actual target:")
    lines.append("")
    for r in TOOL_COMPATIBILITY_REQUIREMENTS:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("Use official tool documentation and verify compatibility against "
                 "the actual target. Never assume a tool is appropriate because it "
                 "worked on a previous protocol.")
    lines.append("")
    lines.append("### C. Select technology-native testing methods")
    lines.append("")
    lines.append("| Language | Native tooling (examples, not exhaustive) |")
    lines.append("|---|---|")
    for language, tools in NATIVE_TESTING_METHODS.items():
        lines.append(f"| {language} | {', '.join(tools)} |")
    lines.append("")
    lines.append("Research additional languages and specialised frameworks whenever "
                 "encountered; this table is a starting point, not a ceiling.")
    lines.append("")
    lines.append("### D. Mixed-language protocols")
    lines.append("")
    for r in MIXED_LANGUAGE_REQUIREMENTS:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("### E. Mandatory pre-execution compatibility gate")
    lines.append("")
    lines.append("Before executing a security engine, document:")
    lines.append("")
    for r in COMPATIBILITY_GATE_FIELDS:
        lines.append(f"- {r}")
    lines.append("")
    lines.append(COMPATIBILITY_GATE_SMOKE_TEST + ".")
    lines.append("")
    lines.append("### F. Honest execution reporting")
    lines.append("")
    lines.append("Use these exact statuses:")
    lines.append("")
    for status, meaning in EXECUTION_STATUSES.items():
        lines.append(f"- `{status}` -- {meaning}.")
    lines.append("")
    for r in HONEST_EXECUTION_RULES:
        lines.append(f"- {r[0].upper() + r[1:]}.")
    lines.append("")
    lines.append("### G. Research continuity")
    lines.append("")
    for r in RESEARCH_CONTINUITY_RULES:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("### H. Final acceptance criteria")
    lines.append("")
    lines.append("No investigation can be marked complete until:")
    lines.append("")
    for r in COMPLETION_ACCEPTANCE:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("## Validation and verdicts")
    lines.append("")
    lines.append("A suspicion is a confirmed vulnerability only when all of these hold:")
    lines.append("")
    for v in VALIDATION_REQUIREMENTS:
        lines.append(f"- {v}")
    lines.append("")
    lines.append("The verdict set (kept distinct):")
    lines.append("")
    for v in FINDING_VERDICTS:
        lines.append(f"- `{v}`")
    lines.append("")
    lines.append("## Independent adversarial review")
    lines.append("")
    for q in REVIEW_QUESTIONS:
        lines.append(f"- {q}")
    lines.append("")
    lines.append("## Finding record sections")
    lines.append("")
    for s in FINDING_SECTIONS:
        lines.append(f"- **{s.letter}. {s.name}** -- {', '.join(s.fields)}")
    lines.append("")
    lines.append("## Prioritisation model")
    lines.append("")
    lines.append("| Factor | Weight | Meaning |")
    lines.append("|---|---|---|")
    for f in PRIORITY_FACTORS:
        lines.append(f"| {f.key} | {f.weight} | {f.description} |")
    lines.append("")
    lines.append("Deliberately not factors: " + ", ".join(PRIORITISATION_NON_FACTORS) + ".")
    lines.append("")
    lines.append("## Bounty eligibility gate (the official policy is the sole authority)")
    lines.append("")
    lines.append("> " + BOUNTY_GATE_RULE)
    lines.append("")
    lines.append("The priority score above orders research. It never decides "
                 "eligibility, and no candidate needs a minimum score to be "
                 "submitted.")
    lines.append("")
    lines.append("> " + BOUNTY_NO_THRESHOLD_RULE)
    lines.append("")
    lines.append("Every candidate passes these seven mandatory gates. They are "
                 "independent and non-compensating: a failure in one fixes the "
                 "classification, whatever the others say.")
    lines.append("")
    for g in BOUNTY_GATES:
        lines.append(f"### Gate {g.letter} -- {g.name}")
        lines.append("")
        lines.append(f"*{g.question}*")
        lines.append("")
        for r in g.records:
            lines.append(f"- {r}")
        if g.failure:
            lines.append("")
            lines.append(f"*If it fails:* {g.failure}")
        lines.append("")
    lines.append("### Classifications (what the candidate is)")
    lines.append("")
    for key, meaning in BOUNTY_CLASSIFICATIONS:
        lines.append(f"- **{key}** -- {meaning}")
    lines.append("")
    lines.append("### Gate dispositions (the process state, not the classification)")
    lines.append("")
    for key, meaning in BOUNTY_DISPOSITIONS:
        lines.append(f"- **{key}** -- {meaning}")
    lines.append("")
    lines.append("A reassessment reports one of four payment determinations, "
                 "derived from the disposition so the two can never disagree:")
    lines.append("")
    for determination, source in PAYMENT_DETERMINATIONS:
        lines.append(f"- **{determination}** -- {source}")
    lines.append("")
    lines.append("If the official policy cannot be retrieved or verified the "
                 f"disposition is `{BOUNTY_POLICY_UNVERIFIED}`; the technical "
                 "finding may stay documented while its bounty eligibility is "
                 "blocked or unassessed.")
    lines.append("")
    lines.append("Implemented by `blackheart/bounty/gate.py` "
                 "(`blackheart bounty gate --record <candidate.json>`), and "
                 "`blackheart.bounty.prepare_submission` carries the disposition "
                 "in every package.")
    lines.append("")
    lines.append("## Research responsibilities")
    lines.append("")
    for r in RESPONSIBILITIES:
        lines.append(f"- **{r.name}** -- {r.duty} ({', '.join(r.agents)})")
    lines.append("")
    lines.append("## Security invariants (non-negotiable)")
    lines.append("")
    for i in SECURITY_INVARIANTS:
        lines.append(f"- {i}")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "OPERATIONAL_IDENTITY", "DISPOSITIONS", "SUCCESS_METRIC",
    "Phase", "LIFECYCLE", "PHASE_BY_KEY", "phase",
    "ATTACK_SURFACES",
    "HYPOTHESIS_REQUIRED_FIELDS", "HYPOTHESIS_PROMPTS",
    "INVESTIGATION_METHODS", "FORBIDDEN_OPERATIONS",
    "LANGUAGE_AWARE_PRINCIPLE", "RECONNAISSANCE_REQUIREMENTS",
    "TOOL_COMPATIBILITY_REQUIREMENTS", "NATIVE_TESTING_METHODS",
    "MIXED_LANGUAGE_REQUIREMENTS", "COMPATIBILITY_GATE_FIELDS",
    "COMPATIBILITY_GATE_SMOKE_TEST", "EXECUTION_STATUSES",
    "HONEST_EXECUTION_RULES", "RESEARCH_CONTINUITY_RULES",
    "COMPLETION_ACCEPTANCE", "LANGUAGE_AWARE_POLICY",
    "VALIDATION_REQUIREMENTS", "FINDING_VERDICTS", "NON_CONFIRMED_VERDICTS",
    "REVIEW_QUESTIONS",
    "FindingSection", "FINDING_SECTIONS", "CONFIRMATION_REQUIRED_FIELDS",
    "PriorityFactor", "PRIORITY_FACTORS", "PRIORITISATION_NON_FACTORS",
    "priority_score", "prioritize",
    "BOUNTY_GATE_RULE", "BOUNTY_NO_THRESHOLD_RULE", "BOUNTY_POLICY_UNVERIFIED",
    "BountyGate", "BOUNTY_GATES", "BOUNTY_CLASSIFICATIONS",
    "BOUNTY_DISPOSITIONS", "PAYMENT_DETERMINATIONS",
    "Responsibility", "RESPONSIBILITIES",
    "SECURITY_INVARIANTS",
    "doctrine_dict", "doctrine_prompt_block", "doctrine_document",
]
