"""A relative run workspace must never cost an engine its report.

The engine is executed with ``cwd`` set to the *target*, so a relative workspace
makes the ``--json`` artifact path relative to the target while the adapter looks
for it relative to the process. The result is a scan that produced findings being
recorded as ``FAILED / no parseable artifact`` -- a silent loss of real results.
"""

from pathlib import Path

from blackheart.engines.solidity.slither import SlitherAdapter


def test_relative_workspace_is_resolved_to_absolute():
    adapter = SlitherAdapter("research/private/engines")
    assert adapter.workspace.is_absolute()
    assert adapter.workspace == Path("research/private/engines").resolve()


def test_scratch_dir_is_absolute_and_outside_the_target(tmp_path):
    adapter = SlitherAdapter("relative/workspace")
    scratch = adapter._scratch_dir()
    assert scratch.is_absolute()
    assert scratch.is_dir()
    assert adapter.name in scratch.name
    assert tmp_path not in scratch.parents


def test_scratch_dir_created_on_demand(tmp_path):
    adapter = SlitherAdapter(tmp_path / "fresh" / "ws")
    scratch = adapter._scratch_dir()
    assert scratch.is_dir()
    assert scratch == (tmp_path / "fresh" / "ws" / ".slither-scratch").resolve()
