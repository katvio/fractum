@echo off
setlocal enabledelayedexpansion

:: Colors for messages (using Windows-specific coloring)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "NC=[0m"

:: Function to display messages
:print_message
echo %GREEN%==>%NC% %~1
exit /b

:print_error
echo %RED%==>%NC% %~1
exit /b

:: Check for Administrator privileges
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo This script needs to be run as Administrator.
    echo Please right-click on this file and select "Run as administrator".
    pause
    exit /b 1
)

:: Check if Python 3.12.10 is already installed
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    call :print_message "Python is not installed. Please install Python 3.12.10 from https://www.python.org/downloads/release/python-31210/"
    echo Download and install Python 3.12.10, making sure to check "Add Python to PATH".
    echo After installation, run this script again.
    pause
    exit /b 1
)

for /f "tokens=2" %%I in ('python --version 2^>^&1') do set PYTHON_VERSION=%%I
echo Current Python version: %PYTHON_VERSION%

:: Compare version by extracting major, minor, and patch
for /f "tokens=1,2,3 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
    set PATCH=%%c
)

if "%MAJOR%" NEQ "3" (
    call :print_message "Python 3.12.10 is required. Current version: %PYTHON_VERSION%"
    call :print_message "Please install Python 3.12.10 from https://www.python.org/downloads/release/python-31210/"
    pause
    exit /b 1
) else if "%MINOR%" NEQ "12" (
    call :print_message "Python 3.12.10 is required. Current version: %PYTHON_VERSION%"
    call :print_message "Please install Python 3.12.10 from https://www.python.org/downloads/release/python-31210/"
    pause
    exit /b 1
) else if "%PATCH%" NEQ "10" (
    call :print_message "Python 3.12.10 is required. Current version: %PYTHON_VERSION%"
    call :print_message "Please install Python 3.12.10 from https://www.python.org/downloads/release/python-31210/"
    pause
    exit /b 1
) else (
    call :print_message "Python 3.12.10 is already installed"
)

:: Check if pip is installed
python -m pip --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    call :print_message "Pip is not installed. Installing Pip..."
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
    python get-pip.py
    del get-pip.py
) else (
    call :print_message "Pip is already installed"
)

:: Check if virtual environment already exists
if exist "env" (
    call :print_message "Virtual environment 'env' already exists"
) else (
    :: Create virtual environment
    call :print_message "Creating virtual environment..."
    python -m venv env
    if %ERRORLEVEL% NEQ 0 (
        call :print_error "Failed to create virtual environment. Installing venv module..."
        pip install virtualenv
        python -m virtualenv env
    )
)

:: Activate virtual environment
call :print_message "Activating virtual environment..."
call env\Scripts\activate.bat

:: Check if package is already installed in development mode
pip list | findstr "fractum" >nul
if %ERRORLEVEL% EQU 0 (
    call :print_message "Package fractum is already installed in development mode"
) else (
    :: Install dependencies and run setup.py
    call :print_message "Installing dependencies and running setup.py..."
    pip install --upgrade pip
    pip install -e .
)

call :print_message "Installation completed successfully!"
call :print_message "Python 3.12.10 is installed and configured"
call :print_message "Virtual environment is created and activated"
call :print_message "To verify the installation, run:"
echo python --version
call :print_message "To activate the virtual environment in the future, run:"
echo env\Scripts\activate.bat
call :print_message "IMPORTANT: To use the fractum command, you need to activate the virtual environment first:"
echo env\Scripts\activate.bat
call :print_message "After activation, you can run commands like:"
echo fractum encrypt file.txt -t 3 -n 5 -l mylabel -v

pause
endlocal 