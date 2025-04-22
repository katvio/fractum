@echo off
setlocal enabledelayedexpansion

:: Colors for messages
set "GREEN=[32m"
set "RED=[31m"
set "YELLOW=[33m"
set "NC=[0m"

:: Function to display messages
:print_message
echo %GREEN%==>%NC% %~1
exit /b

:print_error
echo %RED%==>%NC% %~1
exit /b

:: Check if Python 3.12.10 is already installed
python --version 2>nul
if %ERRORLEVEL% NEQ 0 (
    call :print_message "Python is not installed. Please install Python 3.12.10 from https://www.python.org/downloads/release/python-31210/"
    exit /b 1
)

for /f "tokens=2" %%I in ('python --version 2^>^&1') do set PYTHON_VERSION=%%I
if not "%PYTHON_VERSION%"=="3.12.10" (
    call :print_message "Python 3.12.10 is required. Current version: %PYTHON_VERSION%"
    call :print_message "Please install Python 3.12.10 from https://www.python.org/downloads/release/python-31210/"
    exit /b 1
) else (
    call :print_message "Python 3.12.10 is already installed"
)

:: Check if virtual environment already exists
if exist "env" (
    call :print_message "Virtual environment 'env' already exists"
) else (
    :: Create virtual environment
    call :print_message "Creating virtual environment..."
    python -m venv env
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

call :print_message "Installation completed successfully! 🎉"
call :print_message "Python 3.12.10 is now installed"
call :print_message "Virtual environment is created and activated"
call :print_message "To verify the installation, run:"
echo python --version
call :print_message "To activate the virtual environment in the future, run:"
echo env\Scripts\activate.bat
call :print_message "IMPORTANT: To use the fractum command, you need to activate the virtual environment first:"
echo %YELLOW%env\Scripts\activate.bat%NC%
call :print_message "After activation, you can run commands like:"
echo %YELLOW%fractum encrypt file.txt -t 3 -n 5 -l mylabel -v%NC%

endlocal 