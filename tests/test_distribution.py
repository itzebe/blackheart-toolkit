"""Acceptance bar for the distributable package, license and release workflow."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

import blackheart
from blackheart.cli import main

ROOT = Path(__file__).resolve().parent.parent


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_one_version_in_package_and_metadata() -> None:
    project = _pyproject()["project"]
    assert project["name"] == "blackheart"
    assert project["version"] == blackheart.__version__
    assert project["requires-python"] == ">=3.11"


def test_entry_point_target_is_importable() -> None:
    project = _pyproject()["project"]
    assert project["scripts"]["blackheart"] == "blackheart.cli:main"
    assert callable(main)


def test_package_metadata_is_complete() -> None:
    project = _pyproject()["project"]
    assert project["readme"] == "README.md"
    assert project["license"] == "Apache-2.0"
    assert project["dependencies"] == []
    assert project["urls"]["Repository"].endswith("/itzebe/blackheart")
    assert "build>=1.2" in project["optional-dependencies"]["dev"]


def test_license_and_notice_travel_with_the_project() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "BLACKHEART" in notice
    assert "THIRD_PARTY_NOTICES.md" in notice


def test_changelog_records_the_current_version() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{blackheart.__version__}]" in changelog
    assert "## [Unreleased]" in changelog


def test_release_workflow_builds_and_verifies_a_wheel() -> None:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )
    # `on` is parsed as the boolean True by YAML 1.1; accept either spelling.
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["push"]["tags"] == ["v*"]
    assert workflow["permissions"]["contents"] == "write"
    steps = workflow["jobs"]["build"]["steps"]
    run = "\n".join(step.get("run", "") for step in steps)
    assert "python -m build" in run
    assert "pip\" install dist/*.whl" in run
    assert "sha256sum" in run
    assert any(step.get("uses", "").startswith("softprops/action-gh-release") for step in steps)


def test_public_process_documents_exist() -> None:
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "RELEASE.md").read_text(encoding="utf-8")
    assert "pytest tests/ -q" in contributing
    assert "fails closed" in contributing.lower()
    assert "security/advisories/new" in security
    assert "does not grant permission" in security
    assert "SHA256SUMS" in release
