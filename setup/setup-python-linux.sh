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

# Check if Python 3.12.10 is already installed
if command -v python3.12 &> /dev/null; then
    PYTHON_VERSION=$(python3.12 --version 2>&1 | cut -d' ' -f2)
    if [ "$PYTHON_VERSION" = "3.12.10" ]; then
        print_message "Python 3.12.10 is already installed"
    else
        print_message "Python 3.12.10 is not installed. Installing..."
        # Install dependencies for building Python
        print_message "Installing build dependencies..."
        sudo apt-get update
        sudo apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev
        
        # Download and install Python 3.12.10
        cd /tmp
        wget https://www.python.org/ftp/python/3.12.10/Python-3.12.10.tgz
        tar -xf Python-3.12.10.tgz
        cd Python-3.12.10
        ./configure --enable-optimizations
        make -j $(nproc)
        sudo make altinstall
        cd ..
        rm -rf Python-3.12.10 Python-3.12.10.tgz
    fi
else
    print_message "Python 3.12.10 is not installed. Installing..."
    # Install dependencies for building Python
    print_message "Installing build dependencies..."
    sudo apt-get update
    sudo apt-get install -y build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev
    
    # Download and install Python 3.12.10
    cd /tmp
    wget https://www.python.org/ftp/python/3.12.10/Python-3.12.10.tgz
    tar -xf Python-3.12.10.tgz
    cd Python-3.12.10
    ./configure --enable-optimizations
    make -j $(nproc)
    sudo make altinstall
    cd ..
    rm -rf Python-3.12.10 Python-3.12.10.tgz
fi

# Return to the original directory if we moved
cd - > /dev/null

# Install pip if not already installed
if ! command -v pip3.12 &> /dev/null; then
    print_message "Installing pip for Python 3.12..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python3.12 get-pip.py
    rm get-pip.py
fi

# Install venv module if not available
if ! python3.12 -m venv --help &> /dev/null; then
    print_message "Installing venv module..."
    sudo apt-get install -y python3.12-venv
fi

# Check if virtual environment already exists
if [ -d "env" ]; then
    print_message "Virtual environment 'env' already exists"
else
    # Create virtual environment
    print_message "Creating virtual environment..."
    python3.12 -m venv env
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
    pip install -e .
fi

print_message "Installation completed successfully! 🎉"
print_message "Python 3.12.10 is now installed"
print_message "Virtual environment is created and activated"
print_message "To verify the installation, run:"
echo "python --version"
print_message "To activate the virtual environment in the future, run:"
echo "source env/bin/activate"
print_message "IMPORTANT: To use the fractum command, you need to activate the virtual environment first:"
echo -e "${YELLOW}source env/bin/activate${NC}"
print_message "After activation, you can run commands like:"
echo -e "${YELLOW}fractum encrypt file.txt -t 3 -n 5 -l mylabel -v${NC}" 