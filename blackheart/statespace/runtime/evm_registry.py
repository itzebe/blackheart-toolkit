"""Unified registry of external-source EVM targets.

Three independently-maintained external applications are declared as EVM cases:

  * **Damn Vulnerable DeFi** v4.1.0 (``evm_cases``) -- the Mission 03 target.
  * **OpenZeppelin Ethernaut** (``evm_cases_ethernaut``) -- the Mission 04 second
    target, added to test generalization beyond a single application.
  * **Euler V1** (``evm_cases_euler``) -- the Mission 08 third target: a real,
    production DeFi protocol (a diamond-proxy lending market) rather than an
    educational suite, added to test generalization to an unfamiliar architecture.

Each registry owns its own cases and controls; this module is only a lookup and a
target catalogue, so the driver and the CLI do not need to know how many external
projects exist. It introduces no engine: every case is still a plain
:class:`~blackheart.statespace.runtime.evm.EvmCase` executed by the unchanged
:class:`~blackheart.statespace.runtime.evm.EvmExecutionAdapter`.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import evm_cases, evm_cases_ethernaut, evm_cases_euler
from .evm import EvmCase


@dataclass(frozen=True)
class ExternalTarget:
    """One external project's cases, controls and provenance."""

    key: str
    project: str
    repository: str
    commit: str
    tag: str
    note: str
    cases: dict
    controls: dict


TARGETS: tuple[ExternalTarget, ...] = (
    ExternalTarget(
        key="dvdf",
        project="Damn Vulnerable DeFi",
        repository="https://github.com/tinchoabbate/damn-vulnerable-defi",
        commit=evm_cases.DVDF_COMMIT,
        tag=evm_cases.DVDF_TAG,
        note="third-party, deliberately-vulnerable educational suite; "
             "a hit is a capability result, not a production vulnerability",
        cases=evm_cases.ALL_CASES,
        controls=evm_cases.CONTROL_CASES,
    ),
    ExternalTarget(
        key="ethernaut",
        project="OpenZeppelin Ethernaut",
        repository=evm_cases_ethernaut.ETHERNAUT_REPO,
        commit=evm_cases_ethernaut.ETHERNAUT_COMMIT,
        tag="",
        note="third-party, deliberately-vulnerable security-education CTF; "
             "a hit is a capability result, not a production vulnerability",
        cases=evm_cases_ethernaut.ALL_CASES,
        controls=evm_cases_ethernaut.ALL_CONTROL_CASES,
    ),
    ExternalTarget(
        key="euler",
        project="Euler V1",
        repository=evm_cases_euler.EULER_REPO,
        commit=evm_cases_euler.EULER_COMMIT,
        tag="",
        note="third-party, real production DeFi protocol (diamond-proxy lending "
             "market); the case reproduces a *documented, patched* historical flaw "
             "on a local fork to test generalization, not a live vulnerability",
        cases=evm_cases_euler.ALL_CASES,
        controls=evm_cases_euler.ALL_CONTROL_CASES,
    ),
)

#: case name -> its owning target
_BY_CASE: dict[str, ExternalTarget] = {}
for _t in TARGETS:
    for _name in _t.cases:
        _BY_CASE[_name] = _t

ALL_CASES = {name: t.cases[name] for name, t in _BY_CASE.items()}


def target_for(case: str) -> ExternalTarget:
    if case not in _BY_CASE:
        raise KeyError(f"unknown external case {case!r}; known: {sorted(ALL_CASES)}")
    return _BY_CASE[case]


def get_case(name: str, *, control: bool = False) -> EvmCase:
    target = target_for(name)
    if control:
        if name not in target.controls:
            raise KeyError(f"no control for {name!r}")
        return target.controls[name]()
    return target.cases[name]()


def has_control(name: str) -> bool:
    return name in target_for(name).controls


def catalogue() -> list[dict]:
    """A machine-readable description of every target and case, for the CLI."""
    out = []
    for t in TARGETS:
        for name in t.cases:
            c = t.cases[name]()
            out.append({
                "case": c.name, "target": t.project, "suite": c.suite,
                "description": c.description, "reference": c.reference,
                "has_control": name in t.controls,
            })
    return out
