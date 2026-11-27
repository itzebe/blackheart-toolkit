#!/usr/bin/env sh
# Produce a toolkit-only public snapshot of BLACKHEART.
#
# It exports the tracked tree, removes the research payload (findings/, research/,
# .openhands/ -- PoCs, submission drafts, leads), and starts a FRESH git history
# (one commit). A fresh history is deliberate: the private repo's history contains
# that payload, and a public repo publishes its history, so nothing may be reused.
#
# usage: scripts/export-public.sh [OUT_DIR]   (default: ../blackheart-public)
set -eu
root=$(git rev-parse --show-toplevel)
out=${1:-"$root/../blackheart-public"}
rm -rf "$out"
mkdir -p "$out"
git -C "$root" archive HEAD | tar -x -C "$out"
rm -rf "$out/findings" "$out/research" "$out/.openhands"
cd "$out"
git init -q
git add -A
git -c user.name=openhands -c user.email=openhands@all-hands.dev \
    commit -qm "BLACKHEART toolkit - public snapshot"
git branch -M main
echo "public snapshot ready: $out"
echo "tracked files:   $(git ls-files | wc -l)"
echo "findings/ files: $(git ls-files | grep -c '^findings/' || true)"
echo "research/ files: $(git ls-files | grep -c '^research/' || true)"
echo "history:         $(git rev-list --count HEAD) commit (fresh)"
cat <<'EOS'

next (you own the flip):
  # create an EMPTY public repo on GitHub named e.g. blackheart, then:
  git remote add origin https://github.com/<you>/blackheart.git
  git push -u origin main

keep the private research repo (itzebe/blackheart) private -- it holds findings/,
research/ and the full history, and is your private research repo.
EOS
