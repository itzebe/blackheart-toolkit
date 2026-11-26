#!/usr/bin/env bash
# BLACKHEART portable installer.
#
# Installs a free, open-source exploit-research toolchain into a per-user prefix
# (~/.blackheart) plus standard locations, and then *functionally verifies* every
# tool. It never installs paid software and never requires an API key.
#
# Usage:
#   ./install.sh              # install + verify everything
#   ./install.sh --core       # Python package + Foundry only (fast path)
#   ./install.sh --no-rust    # skip the Rust toolchain (large, ~1.5 GB)
#   ./install.sh --verify     # verify the toolchain only (no installs)
#   ./install.sh --project    # also write local config under ./.openhands
#
# Design notes:
#   * Idempotent: re-running skips anything already present.
#   * Non-fatal per tool: a tool that cannot be installed in this environment is
#     reported as MISSING/UNSUPPORTED, never silently substituted.
#   * Everything installs into the user's home; `sudo` is only used when needed
#     for a system package (apt) and is skipped if unavailable.

set -uo pipefail

BLACKHEART_HOME="${BLACKHEART_HOME:-$HOME/.blackheart}"
BIN_DIR="$BLACKHEART_HOME/bin"
VENV_DIR="$BLACKHEART_HOME/venvs"
LOG_PREFIX="[blackheart-install]"

CORE_ONLY=0
VERIFY_ONLY=0
WRITE_PROJECT=0
NO_RUST=0
for arg in "$@"; do
  case "$arg" in
    --core) CORE_ONLY=1 ;;
    --verify) VERIFY_ONLY=1 ;;
    --project) WRITE_PROJECT=1 ;;
    --no-rust) NO_RUST=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac
done

mkdir -p "$BIN_DIR" "$VENV_DIR"
say() { printf '%s %s\n' "$LOG_PREFIX" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------- #
# PATH: make the installed toolchain visible for this run and future shells.
# --------------------------------------------------------------------------- #
export PATH="$PATH:$BIN_DIR:$HOME/.foundry/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:$HOME/.local/go/bin:/usr/local/go/bin"
add_path_line() {
  local line="$1" rc="$2"
  [ -f "$rc" ] || touch "$rc"
  grep -qF "$line" "$rc" 2>/dev/null || echo "$line" >> "$rc"
}
add_path_line 'export PATH="$PATH:$HOME/.blackheart/bin:$HOME/.foundry/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:$HOME/.local/go/bin:/usr/local/go/bin"' "$HOME/.bashrc"

# --------------------------------------------------------------------------- #
# OS / arch detection
# --------------------------------------------------------------------------- #
OS="$(uname -s)"; ARCH="$(uname -m)"
say "host: $OS $ARCH"
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) GOARCH=unknown ;;
esac

# --------------------------------------------------------------------------- #
# Python package + venvs
# --------------------------------------------------------------------------- #
install_python_pkg() {
  say "installing blackheart python package (editable)"
  python3 -m pip install -e "$(dirname "$0")" --quiet --disable-pip-version-check 2>&1 | tail -2 || \
    say "WARN: editable install failed; you can still run 'python3 -m blackheart' from the repo root"
}

install_solidity_engines() {
  # The Solidity analysis engines are installed from the pinned manifest, into
  # isolated venvs. Installing slither-analyzer into the system interpreter
  # would shadow this repository's tests/ directory with slither's own `tests`
  # package and break `pytest`, so it is never done here.
  say "installing Solidity engines from the pinned manifest (blackheart engines bootstrap)"
  python3 -m blackheart engines bootstrap || \
    say "WARN: some Solidity engines failed to install; run 'python3 -m blackheart engines doctor'"
}

install_python_tools() {
  [ "$CORE_ONLY" = 1 ] && return 0
  # Each Python tool gets its own venv under ~/.blackheart/venvs/<tool>. They pin
  # incompatible dependency sets (semgrep and sqlmap disagree on several), and a
  # system-wide install of semgrep also shadows this repository's `tests`
  # package. The tool registry resolves these venvs directly, so they never need
  # to be on PATH.
  local tool
  for tool in semgrep sqlmap wafw00f arjun; do
    if [ -x "$VENV_DIR/$tool/bin/$tool" ]; then say "$tool already present"; continue; fi
    say "installing $tool in its own venv"
    python3 -m venv "$VENV_DIR/$tool" 2>/dev/null && \
      "$VENV_DIR/$tool/bin/pip" install --quiet --disable-pip-version-check "$tool" 2>&1 | tail -1 || \
      say "WARN: $tool install failed"
  done

  install_solidity_engines

  # Mythril needs an isolated venv (it pins old eth-* versions that conflict).
  if [ ! -x "$VENV_DIR/mythril/bin/myth" ]; then
    say "installing mythril in an isolated venv"
    python3 -m venv "$VENV_DIR/mythril" 2>/dev/null && \
      "$VENV_DIR/mythril/bin/pip" install --quiet mythril 'setuptools<81' 2>&1 | tail -2 || \
      say "WARN: mythril install failed (optional)"
  fi

  # A default solc so slither/forge can compile without network per-run.
  # solc-select ships inside the slither venv, not the system interpreter.
  local solc_select="$VENV_DIR/slither/bin/solc-select"
  if [ -x "$solc_select" ]; then
    if "$solc_select" install 0.8.26 >/dev/null 2>&1 && \
       "$solc_select" use 0.8.26 >/dev/null 2>&1; then
      # The verifier resolves tools from ~/.blackheart/bin; expose the shim
      # there so "solc installed" means the same thing in every shell.
      [ -x "$VENV_DIR/slither/bin/solc" ] && \
        ln -sf "$VENV_DIR/slither/bin/solc" "$BIN_DIR/solc"
      say "solc 0.8.26 active"
    else
      say "WARN: could not activate solc 0.8.26; run 'solc-select install 0.8.26'"
    fi
  fi
}

# --------------------------------------------------------------------------- #
# Foundry
# --------------------------------------------------------------------------- #
install_foundry() {
  if have forge; then say "foundry already present: $(forge --version | head -1)"; return 0; fi
  say "installing foundry (forge/cast/anvil) via foundryup"
  curl -sL https://foundry.paradigm.xyz | bash >/dev/null 2>&1 || { say "WARN: foundry bootstrap failed"; return 0; }
  export PATH="$PATH:$HOME/.foundry/bin"
  foundryup >/dev/null 2>&1 || say "WARN: foundryup failed"
  have forge && say "foundry installed: $(forge --version | head -1)"
}

# --------------------------------------------------------------------------- #
# Prebuilt binaries (gitleaks, trivy)
# --------------------------------------------------------------------------- #
download_release() {
  local name="$1" url="$2" extract="$3" target="$4"
  if [ -x "$BIN_DIR/$name" ]; then say "$name already present"; return 0; fi
  [ "$ARCH" = "x86_64" ] || { say "$name: no prebuilt for $ARCH -> MISSING"; return 0; }
  say "downloading $name"
  local tmp; tmp="$(mktemp -d)"
  curl -sL -o "$tmp/pkg" "$url" || { say "WARN: $name download failed"; rm -rf "$tmp"; return 0; }
  ( cd "$tmp" && $extract pkg >/dev/null 2>&1 ) || { say "WARN: $name extract failed"; rm -rf "$tmp"; return 0; }
  local found; found="$(find "$tmp" -type f -name "$target" | head -1)"
  if [ -n "$found" ]; then cp "$found" "$BIN_DIR/$name" && chmod +x "$BIN_DIR/$name"; fi
  rm -rf "$tmp"
}

install_binaries() {
  [ "$CORE_ONLY" = 1 ] && return 0
  # echidna and medusa are installed by `blackheart engines bootstrap` from the
  # pinned manifest, so they are not downloaded again here. aderyn was removed:
  # upstream retired it and withdrew every download, so the old URL 404s.
  download_release gitleaks \
    "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz" \
    "tar xzf" gitleaks
  download_release trivy \
    "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz" \
    "tar xzf" trivy
}

# --------------------------------------------------------------------------- #
# Rust toolchain (Polkadot SDK / Substrate / Solana targets)
# --------------------------------------------------------------------------- #
install_rust() {
  [ "$CORE_ONLY" = 1 ] && return 0
  [ "$NO_RUST" = 1 ] && { say "skipping rust (--no-rust)"; return 0; }
  export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  if have rustc; then
    say "rust already present: $(rustc --version)"
  else
    say "installing rust (rustup, stable + nightly)"
    # Downloaded and inspected rather than piped into a shell: the same trust
    # decision the rest of this script makes for release tarballs.
    local tmp; tmp="$(mktemp -d)"
    curl -sSfL -o "$tmp/rustup.sh" https://sh.rustup.rs || { say "WARN: rustup download failed"; rm -rf "$tmp"; return 0; }
    sh "$tmp/rustup.sh" -y --profile minimal --default-toolchain stable --no-modify-path >/dev/null 2>&1 || \
      say "WARN: rustup install failed"
    rm -rf "$tmp"
  fi
  export PATH="$PATH:$CARGO_HOME/bin"
  have rustc || { say "rust unavailable -> rust targets BLOCKED"; return 0; }

  # Nightly is what cargo-fuzz and the sanitizer runtimes need; the runtime's own
  # pinned nightly may differ, which the compatibility record must state.
  rustup toolchain list 2>/dev/null | grep -q nightly || \
    rustup toolchain install nightly --profile minimal >/dev/null 2>&1 || \
    say "WARN: nightly toolchain install failed (cargo-fuzz will not run)"
  rustup component add clippy rustfmt --toolchain stable >/dev/null 2>&1 || \
    say "WARN: clippy/rustfmt component install failed"
}

install_cargo_tools() {
  [ "$CORE_ONLY" = 1 ] && return 0
  [ "$NO_RUST" = 1 ] && return 0
  have cargo || { say "cargo unavailable; skipping cargo-* tools"; return 0; }
  local tool
  for tool in cargo-fuzz cargo-audit cargo-deny; do
    if [ -x "$HOME/.cargo/bin/$tool" ]; then say "$tool already present"; continue; fi
    say "installing $tool (compiles from source; this takes a few minutes)"
    cargo install "$tool" --locked >/dev/null 2>&1 || say "WARN: $tool install failed"
  done
}

# --------------------------------------------------------------------------- #
# Go toolchain (needed to build the go-based recon/web tools)
# --------------------------------------------------------------------------- #
install_go() {
  [ "$CORE_ONLY" = 1 ] && return 0
  have go && { say "go already present: $(go version | awk '{print $3}')"; return 0; }
  [ "$ARCH" = "x86_64" ] || { say "go: no prebuilt for $ARCH -> go tools MISSING"; return 0; }
  local ver="1.27.4"
  say "installing go $ver"
  local tmp; tmp="$(mktemp -d)"
  curl -sL -o "$tmp/go.tgz" "https://go.dev/dl/go${ver}.linux-amd64.tar.gz" || { say "WARN: go download failed"; rm -rf "$tmp"; return 0; }
  if sudo -n true 2>/dev/null; then
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$tmp/go.tgz" && say "go installed to /usr/local/go"
  else
    mkdir -p "$HOME/.local" && tar -C "$HOME/.local" -xzf "$tmp/go.tgz" && say "go installed to ~/.local/go"
  fi
  rm -rf "$tmp"
  export PATH="$PATH:/usr/local/go/bin:$HOME/.local/go/bin"
}

# --------------------------------------------------------------------------- #
# Go tools (nuclei, httpx, subfinder, katana)
# --------------------------------------------------------------------------- #
install_go_tools() {
  [ "$CORE_ONLY" = 1 ] && return 0
  if ! have go; then
    say "go not found; skipping go-based tools (recon: nuclei/httpx/subfinder/katana/ffuf/gobuster/dnsx/dalfox/gau/waybackurls/naabu; scanners: gosec/govulncheck/staticcheck/osv-scanner/grype/syft/trivy)"
    return 0
  fi
  export GOBIN="$HOME/go/bin"
  for spec in \
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7" \
    "github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10" \
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7" \
    "github.com/projectdiscovery/katana/cmd/katana@v1.1.2" \
    "github.com/ffuf/ffuf/v2@v2.1.0" \
    "github.com/OJ/gobuster/v3@v3.6.0" \
    "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1" \
    "github.com/hahwul/dalfox/v2@v2.9.2" \
    "github.com/lc/gau/v2/cmd/gau@v2.2.3" \
    "github.com/tomnomnom/waybackurls@latest" \
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1" \
    "github.com/securego/gosec/v2/cmd/gosec@latest" \
    "golang.org/x/vuln/cmd/govulncheck@latest" \
    "honnef.co/go/tools/cmd/staticcheck@latest" \
    "github.com/google/osv-scanner/cmd/osv-scanner@latest" \
    "github.com/anchore/grype/cmd/grype@latest" \
    "github.com/anchore/syft/cmd/syft@latest" \
    "github.com/aquasecurity/trivy/cmd/trivy@latest"; do
    module="${spec%@*}"
    name="$(basename "$module")"
    case "$name" in
      v[0-9]*) name="$(basename "$(dirname "$module")")" ;;
    esac
    if [ -x "$GOBIN/$name" ]; then say "$name already present"; continue; fi
    say "installing $name via go"
    go install "$spec" >/dev/null 2>&1 || say "WARN: $name install failed"
  done
}

install_system_pkgs() {
  [ "$CORE_ONLY" = 1 ] && return 0
  have apt-get && sudo -n true 2>/dev/null || { say "no passwordless apt; skipping system packages (nmap, libpcap-dev)"; return 0; }
  local pkgs=()
  have nmap || pkgs+=(nmap)
  # libpcap is required by naabu's SYN scanner.
  dpkg -s libpcap-dev >/dev/null 2>&1 || pkgs+=(libpcap-dev)
  [ "${#pkgs[@]}" -eq 0 ] && { say "system packages already present"; return 0; }
  say "installing system packages: ${pkgs[*]}"
  sudo apt-get update -qq >/dev/null 2>&1
  sudo apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1 || say "WARN: system package install failed"
}

# --------------------------------------------------------------------------- #
# Foundry harness dependencies (forge-std)
# --------------------------------------------------------------------------- #
install_harness_deps() {
  [ "$CORE_ONLY" = 1 ] && return 0
  have forge || { say "forge not available; skipping harness deps"; return 0; }
  local repo_root; repo_root="$(cd "$(dirname "$0")" && pwd)"
  # Each Foundry harness imports forge-std, which is gitignored (harnesses/*/lib/)
  # and must be fetched per checkout. Provision every harness that needs it.
  local harness
  for harness in "$repo_root/harnesses/erc4626" "$repo_root/harnesses/dvdf"; do
    [ -d "$harness" ] || continue
    if [ -d "$harness/lib/forge-std" ]; then
      say "forge-std already present ($(basename "$harness"))"
      continue
    fi
    say "fetching forge-std for the $(basename "$harness") harness"
    ( cd "$harness" && git init -q 2>/dev/null; forge install foundry-rs/forge-std >/dev/null 2>&1 ) || \
      say "WARN: forge-std fetch failed; run 'forge install foundry-rs/forge-std' in $harness"
    rm -rf "$harness/.git" "$harness/.gitmodules" "$harness/foundry.lock" 2>/dev/null
    [ -d "$harness/lib/forge-std" ] && say "forge-std installed ($(basename "$harness"))"
  done
}

# --------------------------------------------------------------------------- #
# Verify
# --------------------------------------------------------------------------- #
verify_tools() {
  say "functionally verifying the toolchain"
  local repo_root; repo_root="$(cd "$(dirname "$0")" && pwd)"
  ( cd "$repo_root" && python3 -m blackheart tools verify --out "$BLACKHEART_HOME/tools/registry.json" ) || \
    say "WARN: tool registry verification could not run"
  # Report the external-scanner set honestly. A missing scanner is a WARN here
  # and a `missing` row in `blackheart external --doctor`; it is never read as
  # installed, and a clean scan is never read as proof of safety.
  ( cd "$repo_root" && python3 -m blackheart external --doctor ) || \
    say "WARN: some external scanners are not installed (see 'blackheart external --doctor')"
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
if [ "$VERIFY_ONLY" = 0 ]; then
  install_foundry
  install_harness_deps
  install_go
  install_system_pkgs
  install_rust
  install_cargo_tools
  install_binaries
  install_python_tools
  install_go_tools
  install_python_pkg
fi
verify_tools

if [ "$WRITE_PROJECT" = 1 ]; then
  say "writing project-local config under ./.openhands"
  mkdir -p .openhands
  cat > .openhands/blackheart.env <<EOF
# Generated by install.sh --project
export BLACKHEART_HOME="$BLACKHEART_HOME"
export PATH="\$PATH:$BIN_DIR:\$HOME/.foundry/bin:\$HOME/.local/bin:\$HOME/go/bin:\$HOME/.local/go/bin:/usr/local/go/bin"
EOF
  say "wrote .openhands/blackheart.env (source it to use the toolchain)"
  # Install the reusable external-intelligence config (MCP servers + env
  # template). No secret is written; the key is referenced as \${YDC_API_KEY}.
  python3 -m blackheart intel bootstrap --root . >/dev/null 2>&1 && \
    say "wrote .openhands/mcp.json (You.com MCP) + intelligence.env.example" || \
    say "WARN: could not write the intelligence config; run 'python3 -m blackheart intel bootstrap'"
fi

# Make the project's own skills and agents discoverable by OpenHands. The engine
# keeps them at skills/ and agents/; OpenHands looks under .openhands/. This is
# idempotent and only touches the discovery layout (never the canonical trees).
say "provisioning the .openhands skills/agents discovery layout"
python3 -m blackheart provision >/dev/null 2>&1 && \
  say "OpenHands can now discover this project's skills and agents" || \
  say "WARN: could not provision the discovery layout; run 'python3 -m blackheart provision'"

# Report the external-intelligence state honestly: configured or not. This never
# fails the install and never spends; it only tells the operator where to set
# YDC_API_KEY. The keyless fallbacks need no configuration.
say "external intelligence: You.com primary (set YDC_API_KEY) + keyless fallbacks (duckduckgo, wikipedia)"
python3 -m blackheart intel providers 2>/dev/null | sed 's/^/'"$LOG_PREFIX"'   /' || \
  say "WARN: could not read provider status; run 'python3 -m blackheart intel providers'"

say "done. Add to PATH for future shells:"
say "  export PATH=\"\$PATH:$BIN_DIR:\$HOME/.foundry/bin:\$HOME/.cargo/bin:\$HOME/.local/bin:\$HOME/go/bin:\$HOME/.local/go/bin:/usr/local/go/bin\""
