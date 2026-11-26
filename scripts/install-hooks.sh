#!/usr/bin/env sh
# Install the repo's git hooks (the free pre-push quality gate). No CI runner required.
set -eu
root=$(git rev-parse --show-toplevel)
git config core.hooksPath "$root/scripts/git-hooks"
chmod +x "$root/scripts/git-hooks/pre-push"
echo "installed pre-push hook (core.hooksPath=$root/scripts/git-hooks)"
echo "bypass once with: git push --no-verify"
