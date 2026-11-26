# Release

BLACKHEART ships a standard Python sdist and wheel. The release is built from a
tag by `.github/workflows/release.yml`; nothing is published to PyPI until a
trusted publisher is configured for this repository.

## Versioning

- `blackheart/__init__.py` is the single source of truth for `__version__`.
- `pyproject.toml` carries the same version. Keep them equal; the release check
  below fails if they drift.
- Semantic versioning: a breaking CLI or record change is major, a new command
  or capability is minor, a fix is patch.
- `CHANGELOG.md` gets an entry before the tag.

## Cut a release

```bash
# 1. Update the version in both places
$EDITOR blackheart/__init__.py pyproject.toml

# 2. Update the changelog
$EDITOR CHANGELOG.md

# 3. Prove it locally
python3 -m pytest tests/ -m "not slow" -q
python3 -m blackheart differential
python3 -m blackheart coverage
python3 -m build
python3 -m venv /tmp/bh-release
/tmp/bh-release/bin/pip install dist/*.whl
/tmp/bh-release/bin/blackheart demo --dir /tmp/bh-demo --json

# 4. Commit, tag, push
git add -A
git commit -m "Release vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

The workflow builds the artifacts, installs the wheel in a clean environment,
runs `version`, `info`, `demo` and `init`, writes `SHA256SUMS`, and attaches the
artifacts and generated notes to the GitHub release.

## Verify a release

```bash
python3 -m venv /tmp/bh-verify
/tmp/bh-verify/bin/pip install \
  "https://github.com/itzebe/blackheart/releases/download/vX.Y.Z/blackheart-X.Y.Z-py3-none-any.whl"
/tmp/bh-verify/bin/blackheart --version
/tmp/bh-verify/bin/blackheart info --json
/tmp/bh-verify/bin/blackheart demo --dir /tmp/bh-verify-demo --json
```

Expected: `--version` prints `blackheart X.Y.Z`; `info` reports the same version,
the command count and `can_find_payable_bug_unaided: false`; `demo` returns
`ok: true`, `verdict: CONFIRMED`, `guarded_failures: 0`.

## What the release does not do

- It does not publish to PyPI.
- It does not run the external toolchain (Foundry, Slither, Echidna, Halmos).
  Those are operator-installed and gated by `blackheart doctor`.
- It does not claim a capability the engine does not have. The capability
  statement travels in the package.
