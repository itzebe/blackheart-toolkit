"""Portable project provisioning for OpenHands discovery (mission section 11).

OpenHands discovers **project skills** at ``{workspace}/.openhands/skills/`` and
**project agents** at ``{workspace}/.openhands/agents/`` (verified on this
agent-server build). BLACKHEART keeps its canonical skills and agents at
``skills/`` and ``agents/`` -- the layout the repository's own tooling and tests
use -- so this module creates the discovery-layout links that point at them.

It uses **relative symlinks** where the filesystem allows and falls back to
copying the files where it does not (some mounted filesystems reject symlinks).
Both paths are idempotent: re-running repairs a broken link and never duplicates
content.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ProvisionResult:
    skills_link: str
    agents_link: str
    method: str
    copied: list[str] = field(default_factory=list)
    intelligence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "skills_link": self.skills_link,
            "agents_link": self.agents_link,
            "method": self.method,
            "copied": self.copied,
            "intelligence": self.intelligence,
        }


def _link_or_copy(src: Path, dest: Path) -> tuple[str, list[str]]:
    """Create ``dest`` as a relative symlink to ``src``; copy on failure.

    Returns ``(method, copied_paths)``. ``method`` is ``"symlink"`` or ``"copy"``.
    """
    if dest.is_symlink() or dest.exists():
        # Repair a stale link/dir: remove whatever is there first.
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    rel = os.path.relpath(src, dest.parent)
    try:
        os.symlink(rel, dest, target_is_directory=src.is_dir())
        return "symlink", []
    except (OSError, NotImplementedError):
        shutil.copytree(src, dest)
        copied = [str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()]
        return "copy", copied


def provision_project(root: str | os.PathLike) -> ProvisionResult:
    """Create the ``.openhands/{skills,agents}`` discovery layout under ``root``."""
    root = Path(root).resolve()
    openhands = root / ".openhands"
    openhands.mkdir(parents=True, exist_ok=True)

    skills_src = root / "skills"
    agents_src = root / "agents"
    if not skills_src.is_dir() or not agents_src.is_dir():
        raise FileNotFoundError(
            f"expected {skills_src} and {agents_src} to exist; run from the repository root"
        )

    methods: list[str] = []
    copied: list[str] = []
    m1, c1 = _link_or_copy(skills_src, openhands / "skills")
    methods.append(m1)
    copied += c1
    m2, c2 = _link_or_copy(agents_src, openhands / "agents")
    methods.append(m2)
    copied += c2

    method = "symlink" if methods == ["symlink", "symlink"] else "copy"

    # Also install the reusable external-intelligence configuration so a project
    # initialised through BLACKHEART inherits the capability (see
    # blackheart.intelligence.bootstrap). Best-effort: a failure here must not
    # break provisioning of skills/agents.
    intelligence: dict = {}
    try:
        from .intelligence.bootstrap import bootstrap_project

        intelligence = bootstrap_project(root).to_dict()
    except Exception as exc:  # noqa: BLE001 - provisioning must not fail on this
        intelligence = {"error": f"{type(exc).__name__}: {exc}"}

    return ProvisionResult(
        skills_link=str(openhands / "skills"),
        agents_link=str(openhands / "agents"),
        method=method,
        copied=copied,
        intelligence=intelligence,
    )
