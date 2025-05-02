#!/usr/bin/env bash
set -euo pipefail

echo "==> fractum macOS bootstrap"
echo "Installs Xcode CLI, Homebrew, Python 3.12.10, creates .venv and installs fractum"

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
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
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

# 4) Python 3.12.10
echo "Step 4/5: Checking Python 3.12.10 via pyenv"
if ! pyenv versions | grep -q "3.12.10"; then
  echo "→ pyenv installing Python 3.12.10..."
  pyenv install 3.12.10
else
  echo "→ Python 3.12.10 already installed in pyenv"
fi
pyenv local 3.12.10
pyenv global 3.12.10
PY="$HOME/.pyenv/shims/python"

# Version check
VER=$($PY --version 2>&1 | awk '{print $2}')
if [[ "$VER" != "3.12.10" ]]; then
  echo "ERROR: Python 3.12.10 required (found $VER)" >&2
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
pip install -e .

echo "✅ macOS bootstrap complete!"
echo "👉 Run 'source .venv/bin/activate' to enter the environment."