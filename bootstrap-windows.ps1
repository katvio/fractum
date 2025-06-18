<#
.SYNOPSIS
  Bootstrap fractum on Windows
.DESCRIPTION
  Installs Python 3.12.11, creates .venv and installs fractum
#>

# 0) Check Admin
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Error "Re-launch PowerShell as Administrator"
  Exit 1
}

function Step($i,$total,$msg) {
  Write-Host "Step $i of $total`: $msg"
}

Write-Host "==> fractum Windows bootstrap"

# 1) Python 3.12.11
Step 1 4 "Checking/Installing Python 3.12.11"
if (-not (Get-Command python3.12 -ErrorAction SilentlyContinue)) {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "→ Installing Python 3.12.11 via winget..."
    winget install --id Python.Python.3.12 --version 3.12.11 --exact --accept-package-agreements --accept-source-agreements
    # Fallback if exact version isn't available
    if (-not $?) {
      Write-Host "→ Exact version not available via winget, trying Chocolatey..."
      Set-ExecutionPolicy Bypass -Scope Process -Force
      [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
      Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
      choco install python --version=3.12.11 -y
    }
  } else {
    Write-Host "→ Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install python --version=3.12.11 -y
  }
} else {
  Write-Host "→ Python 3.12.11 already installed"
}

# 2) Check version
Step 2 4 "Verifying Python version"
$py = if (Get-Command python3.12 -ErrorAction SilentlyContinue) { 'python3.12' } else { 'python' }
$ver = (& $py --version).Split()[1]
if ($ver -ne '3.12.11') {
  Write-Error "Python 3.12.11 required (found $ver)"
  Exit 1
}
Write-Host "→ Using $py ($ver)"

# 3) Virtualenv
Step 3 4 "Creating .venv"
if (-not (Test-Path '.\.venv')) {
  & $py -m venv .venv
} else {
  Write-Host "→ .venv already exists"
}

# 4) Activation & install
Step 4 4 "Activating .venv & installing fractum"
& .\.venv\Scripts\Activate.ps1
python.exe -m pip install --upgrade pip
pip install -e .

Write-Host "✅ Windows bootstrap complete!"
Write-Host "👉 Run '.\.venv\Scripts\Activate.ps1' to enter the environment."
