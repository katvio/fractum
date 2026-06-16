#!/usr/bin/env bash
set -euo pipefail

# Pinned Homebrew installer — verify SHA-256 before upgrading
# Update: curl -fsSL "$HOMEBREW_INSTALLER_URL" | sha256sum
HOMEBREW_INSTALLER_COMMIT="b953a44e39533dae3c3bb60bbd80138a73c360ec"
HOMEBREW_INSTALLER_URL="https://raw.githubusercontent.com/Homebrew/install/${HOMEBREW_INSTALLER_COMMIT}/install.sh"
HOMEBREW_INSTALLER_SHA256="2863708cb516c5d0bcdfff97dc13bffb61db93f7acc6ae559a5598a57ce11091"

# Verify offline packages before installation (M6)
verify_packages() {
  local pkg_dir="${1:-packages}"
  echo "→ Verifying package integrity..."

  if [ -f "${pkg_dir}/CHECKSUMS.sha256.asc" ]; then
    echo "→ Verifying GPG signature on packages (key D009F6290DCFDAB6)..."
    gpg --verify "${pkg_dir}/CHECKSUMS.sha256.asc" "${pkg_dir}/CHECKSUMS.sha256" \
      || { echo "ERROR: Invalid GPG signature on packages — installation aborted"; exit 1; }
    echo "  ✓ GPG signature valid"
  else
    echo "  WARNING: ${pkg_dir}/CHECKSUMS.sha256.asc not found — skipping GPG verification"
    echo "           For production use, obtain the .asc from a trusted Katvio release."
  fi

  echo "→ Verifying SHA-256 hashes..."
  (cd "${pkg_dir}" && shasum -a 256 --check CHECKSUMS.sha256 --strict --quiet) \
    || { echo "ERROR: Package hash mismatch — files may be corrupted or tampered"; exit 1; }
  echo "  ✓ Package hashes verified"
}

install_homebrew() {
  local tmp
  tmp=$(mktemp /tmp/brew-install.XXXXXX.sh)
  trap "rm -f '$tmp'" RETURN
  echo "→ Downloading Homebrew installer (commit ${HOMEBREW_INSTALLER_COMMIT:0:12})..."
  curl -fsSL -o "$tmp" "$HOMEBREW_INSTALLER_URL"
  echo "→ Verifying SHA-256..."
  echo "${HOMEBREW_INSTALLER_SHA256}  ${tmp}" | sha256sum --check --strict
  echo "→ Running Homebrew installer..."
  NONINTERACTIVE=1 bash "$tmp"
}

echo "==> fractum macOS bootstrap"
echo "Installs Xcode CLI, Homebrew, Python 3.12.11, creates .venv and installs fractum"

# 1) Xcode CLI Tools
echo "Step 1/5: Checking Xcode CLI Tools"
if ! xcode-select -p &>/dev/null; then
  echo "→ Installing Xcode CLI Tools..."
  xcode-select --install
  echo "Please install via the GUI that appears, then re-run this script."
  exit 0
else
  echo "→ Xcode CLI Tools already installed"
fi

# 2) Homebrew
echo "Step 2/5: Checking Homebrew"
if ! command -v brew &>/dev/null; then
  echo "→ Installing Homebrew..."
  install_homebrew
  echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.bash_profile
  eval "$(/opt/homebrew/bin/brew shellenv)"
else
  echo "→ Homebrew already installed"
fi

# 3) pyenv
echo "Step 3/5: Checking pyenv"
if ! command -v pyenv &>/dev/null; then
  echo "→ Installing pyenv..."
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew install pyenv
else
  echo "→ pyenv already installed"
fi

# 4) Python 3.12.11
echo "Step 4/5: Checking Python 3.12.11 via pyenv"
if ! pyenv versions | grep -q "3.12.11"; then
  echo "→ pyenv installing Python 3.12.11..."
  pyenv install 3.12.11
else
  echo "→ Python 3.12.11 already installed in pyenv"
fi
pyenv local 3.12.11
pyenv global 3.12.11
PY="$HOME/.pyenv/shims/python"

# Version check
VER=$($PY --version 2>&1 | awk '{print $2}')
if [[ "$VER" != "3.12.11" ]]; then
  echo "ERROR: Python 3.12.11 required (found $VER)" >&2
fi
echo "→ Using $PY ($VER)"

# 5) Virtualenv & install
echo "Step 5/5: Creating virtualenv at .venv and installing fractum"
if [[ ! -d .venv ]]; then
  $PY -m venv .venv
else
  echo "→ .venv already exists"
fi

# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip

if [ -f "packages/CHECKSUMS.sha256" ]; then
  verify_packages packages
  pip install --no-index --find-links=packages -e .
else
  pip install -e .
fi

echo "✅ macOS bootstrap complete!"
echo "👉 Run 'source .venv/bin/activate' to enter the environment."