"""The human research loop as one honest agent: observe, orient, hypothesise,
test, decide, learn. It composes tested modules and introduces no new engine.

It *sees every stack*: a language blackheart cannot model is reported ``BLIND``
("seen, not modelled"), never "clean". A modelled stack is routed to the
``autohunt`` controller, which only surfaces proven, payable candidates. The
operator's only job remains independent review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .autohunt import (AutoHuntConfig, Target, bounty_grade, external_chain_runner,
                       run_autohunt)
from .ingest.coverage import SCANNER_FOR_LANGUAGE
from .toolchain.detect import detect_stack

PHASES: tuple[str, ...] = ("observe", "orient", "hypothesise", "test", "decide", "learn")

#: Languages blackheart can model end-to-end (a scanner plus the certifier).
MODELLED_LANGUAGES: frozenset[str] = frozenset(SCANNER_FOR_LANGUAGE)


@dataclass
class StackVerdict:
    language: str
    modelled: bool
    confirmed: bool
    production_files: int = 0
    manifests: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"language": self.language, "modelled": self.modelled,
                "confirmed": self.confirmed, "production_files": self.production_files,
                "manifests": list(self.manifests)}


@dataclass
class AgentResult:
    status: str                     # BLIND | EMPTY | BLOCKED | <hunt terminal reason>
    path: str
    stacks: list[StackVerdict] = field(default_factory=list)
    blind: list[str] = field(default_factory=list)
    reason: str = ""
    hunt: Optional[dict] = None
    surface: Optional[dict] = None

    def as_dict(self) -> dict:
        return {"status": self.status, "path": self.path,
                "stacks": [s.as_dict() for s in self.stacks],
                "blind": list(self.blind), "reason": self.reason,
                "hunt": self.hunt, "surface": self.surface,
                "phases": list(PHASES),
                "note": "BLIND is 'seen, not modelled' -- never 'clean'"}


def classify_stack(path: str) -> tuple[list[StackVerdict], list[str]]:
    """Every production language in the tree, marked modelled or blind."""
    report = detect_stack(path)
    verdicts: list[StackVerdict] = []
    blind: list[str] = []
    for ev in report.languages:
        if ev.production_files <= 0:
            continue
        modelled = ev.language in MODELLED_LANGUAGES
        verdicts.append(StackVerdict(ev.language, modelled, ev.confirmed,
                                     ev.production_files, list(ev.manifests)))
        if not modelled:
            blind.append(ev.language)
    return verdicts, blind


def run_agent(path: str, *, policy: Optional[dict] = None, compatibility: str = "",
              program: str = "", repository: str = "", commit: str = "",
              scanner: str = "semgrep", poc: bool = False,
              max_targets: int = 0,
              runner: Optional[Callable[[Target], dict]] = None,
              grader: Optional[Callable[[dict, Target], dict]] = None) -> AgentResult:
    """Observe, orient, then route: modelled stacks hunt; blind stacks say so."""
    verdicts, blind = classify_stack(path)
    if not verdicts:
        return AgentResult("EMPTY", path, reason="no production source found")
    if blind:
        if "TON FunC/Tact" in blind:
            from .ton.func import scan_func
            from .ton.tact import scan_tact

            surface = scan_tact(path)
            if not surface.handlers:
                surface = scan_func(path)
            if surface.handlers:
                unguarded = sum(1 for h in surface.handlers if not h.guarded)
                return AgentResult(
                    "SURFACE", path, stacks=verdicts, blind=blind,
                    reason=(f"TON surface recovered: {len(surface.handlers)} "
                            f"handler(s), {unguarded} unguarded (leads, not findings)"),
                    surface=surface.to_dict())
        return AgentResult("BLIND", path, stacks=verdicts, blind=blind,
                           reason="seen but not modelled: " + ", ".join(blind) +
                                  "; a lead, never 'clean'")
    if not compatibility:
        return AgentResult("BLOCKED", path, stacks=verdicts,
                           reason="modelled stack, but no --compatibility record to run")
    target = Target(component=Path(path).name or "target", path=path,
                    repository=repository, commit=commit, compatibility=compatibility)
    runner = runner or (lambda t: external_chain_runner(t, scanner=scanner, do_poc=poc))
    grader = grader or (lambda f, t: bounty_grade(f, t, policy=policy))
    result = run_autohunt(
        AutoHuntConfig(program=program, targets=[target], max_targets=max_targets,
                       stop_on_awaiting_review=True),
        runner=runner, grader=grader)
    return AgentResult(result.reason, path, stacks=verdicts,
                       reason=result.detail, hunt=result.as_dict())


__all__ = ["PHASES", "MODELLED_LANGUAGES", "StackVerdict", "AgentResult",
           "classify_stack", "run_agent"]
