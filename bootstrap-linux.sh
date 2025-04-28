#!/usr/bin/env bash
set -euo pipefail

echo "==> fractum Linux bootstrap"
echo "Installs Python 3.12.10, creates .venv and installs fractum"

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
echo "Step 2/4: Installing pyenv for exact Python 3.12.10 version"
if ! command -v pyenv &>/dev/null; then
  echo "→ Installing pyenv..."
  curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
  
  # Add pyenv to PATH for this session
  export PYENV_ROOT="$HOME/.pyenv"
  export PATH="$PYENV_ROOT/bin:$PATH"
  eval "$(pyenv init --path)"
  eval "$(pyenv init -)"
  
  # Add to .bashrc for future sessions
  if ! grep -q 'pyenv init' ~/.bashrc; then
    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
  fi
else
  echo "→ pyenv already installed"
  export PYENV_ROOT="$HOME/.pyenv"
  export PATH="$PYENV_ROOT/bin:$PATH"
  eval "$(pyenv init --path)"
  eval "$(pyenv init -)"
fi

# 3) Install Python 3.12.10 with pyenv
echo "Step 3/4: Installing Python 3.12.10 with pyenv"
if ! pyenv versions | grep -q "3.12.10"; then
  echo "→ Installing Python 3.12.10..."
  pyenv install 3.12.10
else
  echo "→ Python 3.12.10 already installed via pyenv"
fi

# Use Python 3.12.10 for this project
pyenv local 3.12.10
PY=python

# Final check
ACTUAL=$($PY --version 2>&1 | awk '{print $2}')
if [[ "$ACTUAL" != "3.12.10" ]]; then
  echo "ERROR: Python 3.12.10 required (found $ACTUAL)" >&2
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
