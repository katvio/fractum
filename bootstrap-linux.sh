#!/usr/bin/env bash
set -euo pipefail

# Pinned pyenv-installer — verify SHA-256 before upgrading
# Update: curl -fsSL "$PYENV_INSTALLER_URL" | sha256sum
PYENV_INSTALLER_COMMIT="63a9e6a216796aeba2535a3bac8e79ba5d95166d"
PYENV_INSTALLER_URL="https://github.com/pyenv/pyenv-installer/raw/${PYENV_INSTALLER_COMMIT}/bin/pyenv-installer"
PYENV_INSTALLER_SHA256="4b0adf623a6205727163eb98610b6c5e63f23b99183948b874d867cd9b30ef13"

install_pyenv_via_script() {
  local tmp
  tmp=$(mktemp /tmp/pyenv-installer.XXXXXX.sh)
  trap "rm -f '$tmp'" RETURN
  echo "→ Downloading pyenv-installer (commit ${PYENV_INSTALLER_COMMIT:0:12})..."
  curl -fsSL -o "$tmp" "$PYENV_INSTALLER_URL"
  echo "→ Verifying SHA-256..."
  echo "${PYENV_INSTALLER_SHA256}  ${tmp}" | sha256sum --check --strict
  echo "→ Running pyenv installer..."
  bash "$tmp"
}

echo "==> fractum Linux bootstrap"
echo "Installs Python 3.12.11, creates .venv and installs fractum"

# 1) System repositories and tools
if ! command -v git &>/dev/null \
   || ! command -v curl &>/dev/null \
   || ! command -v wget &>/dev/null \
   || ! command -v make &>/dev/null; then
  echo "Step 1/4: Installing system tools"
  sudo apt-get update
  sudo apt-get install -y git curl wget build-essential libssl-dev zlib1g-dev \
  libbz2-dev libreadline-dev libsqlite3-dev llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python3-openssl
else
  echo "Step 1/4: System tools already installed"
fi

# 2) pyenv installation (for exact Python version control)
echo "Step 2/4: Installing pyenv for exact Python 3.12.11 version"
PYENV_ROOT="$HOME/.pyenv"

if [[ -d "$PYENV_ROOT" ]]; then
  if [[ -x "$PYENV_ROOT/bin/pyenv" ]]; then
    echo "→ pyenv already installed"
  else
    echo "→ Found incomplete pyenv installation at $PYENV_ROOT"
    read -p "Do you want to remove and reinstall pyenv? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      rm -rf "$PYENV_ROOT"
      echo "→ Installing pyenv..."
      install_pyenv_via_script
    else
      echo "Please remove $PYENV_ROOT manually and run this script again."
      exit 1
    fi
  fi
else
  echo "→ Installing pyenv..."
  install_pyenv_via_script
fi

# Add pyenv to PATH for this session
export PYENV_ROOT="$HOME/.pyenv"
if [[ ! -d "$PYENV_ROOT" ]]; then
  echo "ERROR: pyenv installation failed. Please check error messages above."
  exit 1
fi

export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path 2>/dev/null || echo 'Failed to init pyenv path')"
eval "$(pyenv init - 2>/dev/null || echo 'Failed to init pyenv')"

# Add to .bashrc for future sessions
if ! grep -q 'pyenv init' ~/.bashrc; then
  echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
  echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
  echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
  echo 'eval "$(pyenv init -)"' >> ~/.bashrc
fi

# 3) Install Python 3.12.11 with pyenv
echo "Step 3/4: Installing Python 3.12.11 with pyenv"
if ! pyenv versions | grep -q "3.12.11"; then
  echo "→ Installing Python 3.12.11..."
  pyenv install 3.12.11
else
  echo "→ Python 3.12.11 already installed via pyenv"
fi

# Use Python 3.12.11 for this project
pyenv local 3.12.11
PY=python

# Final check
ACTUAL=$($PY --version 2>&1 | awk '{print $2}')
if [[ "$ACTUAL" != "3.12.11" ]]; then
  echo "ERROR: Python 3.12.11 required (found $ACTUAL)" >&2
  exit 1
fi
echo "→ Using $PY ($ACTUAL)"

# 4) Virtualenv
echo "Step 4/4: Creating virtualenv at .venv"
if [[ ! -d .venv ]]; then
  $PY -m venv .venv
else
  echo "→ .venv already exists"
fi

# Activation & install
echo "→ Activating and installing fractum"
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

echo "✅ Linux bootstrap complete!"
echo "👉 Run 'source .venv/bin/activate' to enter the environment."
