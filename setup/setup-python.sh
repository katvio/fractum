#!/bin/bash

# Colors for messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display messages
print_message() {
    echo -e "${GREEN}==>${NC} $1"
}

print_error() {
    echo -e "${RED}==>${NC} $1"
}

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    # Install Homebrew
    print_message "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    print_message "Homebrew is already installed"
fi

# Check if pyenv is installed
if ! command -v pyenv &> /dev/null; then
    # Install pyenv
    print_message "Installing pyenv..."
    brew install pyenv
else
    print_message "pyenv is already installed"
fi

# Check if Python 3.12.10 is already installed
if pyenv versions | grep -q "3.12.10"; then
    print_message "Python 3.12.10 is already installed"
else
    # Install Python 3.12.10
    print_message "Installing Python 3.12.10..."
    pyenv install 3.12.10
fi

# Check if Python 3.12.10 is already set as default
if pyenv version | grep -q "3.12.10"; then
    print_message "Python 3.12.10 is already set as default version"
else
    # Set Python 3.12.10 as default version
    print_message "Setting Python 3.12.10 as default version..."
    pyenv global 3.12.10
fi

# Check if virtual environment already exists
if [ -d "env" ]; then
    print_message "Virtual environment 'env' already exists"
else
    # Create virtual environment
    print_message "Creating virtual environment..."
    python -m venv env
fi

# Activate virtual environment
print_message "Activating virtual environment..."
source env/bin/activate

# Check if package is already installed in development mode
if pip list | grep -q "fractum"; then
    print_message "Package fractum is already installed in development mode"
else
    # Install dependencies and run setup.py
    print_message "Installing dependencies and running setup.py..."
    pip install --upgrade pip
fi

print_message "Installation completed successfully! 🎉"
print_message "Python 3.12.10 is now installed and set as default version"
print_message "Virtual environment is created and activated"
print_message "To verify the installation, run:"
echo "python --version"
print_message "To activate the virtual environment in the future, run:"
echo "source env/bin/activate"
print_message "IMPORTANT: To use the fractum command, you need to activate the virtual environment first:"
echo -e "${YELLOW}source env/bin/activate${NC}"
print_message "After activation, you can run commands like:"
echo -e "${YELLOW}fractum encrypt file.txt -t 3 -n 5 -l mylabel -v${NC}" 