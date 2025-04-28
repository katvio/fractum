#!/usr/bin/env bash
set -euo pipefail

echo "==> fractum Linux bootstrap"
echo "Installs Python 3.12.10, creates .venv and installs fractum"

# 1) System repositories and tools
if ! command -v git    &>/dev/null \
   || ! command -v curl &>/dev/null \
   || ! command -v wget &>/dev/null; then
  echo "Step 1/4: Installing system tools"
  sudo apt-get update
  sudo apt-get install -y git curl wget lsb-release software-properties-common build-essential
else
  echo "Step 1/4: System tools already installed"
  # Ensure software-properties-common is installed (needed for add-apt-repository)
  if ! dpkg -l | grep -q software-properties-common; then
    echo "→ Installing software-properties-common (required for PPA management)"
    sudo apt-get update
    sudo apt-get install -y software-properties-common
  fi
fi

# 2) Python 3.12.10
echo "Step 2/4: Checking for Python 3.12.10"
if command -v python3.12 &>/dev/null; then
  VER=$(python3.12 -c 'import sys; print("{}.{}.{}".format(*sys.version_info[:3]))')
  if [[ "$VER" == "3.12.10" ]]; then
    echo "→ Python 3.12.10 already present"
    PY=python3.12
  fi
fi

if [[ -z "${PY:-}" ]]; then
  echo "→ Installing Python 3.12.10 from deadsnakes PPA"
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update
  sudo apt-get install -y python3.12=3.12.10-1+$(lsb_release -cs) python3.12-venv=3.12.10-1+$(lsb_release -cs)
  PY=python3.12
fi

# Final check
ACTUAL=$($PY --version 2>&1 | awk '{print $2}')
if [[ "$ACTUAL" != "3.12.10" ]]; then
  echo "ERROR: Python 3.12.10 required (found $ACTUAL)" >&2
  exit 1
fi
echo "→ Using $PY ($ACTUAL)"

# 3) Virtualenv
echo "Step 3/4: Creating virtualenv at .venv"
if [[ ! -d .venv ]]; then
  $PY -m venv .venv
else
  echo "→ .venv already exists"
fi

# 4) Activation & install
echo "Step 4/4: Activating and installing fractum"
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -e .

echo "✅ Linux bootstrap complete!"
echo "👉 Run 'source .venv/bin/activate' to enter the environment."
