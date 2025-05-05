# fractum

A fully offline, portable CLI for Shamir's Secret Sharing (SSS) combined with AES-256-GCM file encryption. Split secrets (passwords, SSH keys, etc.) into shares and reconstruct them later—securely, cross-platform, with minimal setup. Works with any file type without restrictions (documents, images, archives, databases, etc.).

## Requirements

- **Operating Systems**:
  - Linux (Ubuntu/Debian-based recommended)
  - macOS 10.15 or later
  - Windows 10/11 (64-bit)

## How it works

### Input and Output Files

When you use Fractum to encrypt a file, the process transforms your data as follows:

**Input:**

- Your sensitive file (e.g., `passwords.txt`, `important_documents.zip`)

**Output:**

- An encrypted file with `.enc` extension (e.g., `passwords.txt.enc`, `important_documents.zip.enc`)
- Multiple share archives (ZIP files), one for each share (e.g., `share_1.zip`, `share_2.zip`, etc.)

Each share archive is completely self-contained and includes:

- The share file (e.g., `share_1.txt`) containing cryptographic data
- The encrypted file (`passwords.txt.enc`)
- The complete Fractum application with all necessary dependencies
- Bootstrap scripts for easy setup on any platform

This design allows you to distribute the shares to different storage locations while ensuring each share contains everything needed to recover your data when the time comes.

## Repository Layout
```text
fractum/
├── packages/
├── src/
│   └── __init__.py
├──tests/
├── bootstrap-linux.sh
├── bootstrap-macos.sh
├── bootstrap-windows.ps1
├── Dockerfile
├── README.md
└── setup.py
```

## The Docker way (recommended usage)

For ultra-secure operations, Fractum can run in a completely network-isolated Docker container, creating a "secure enclave" environment.

### Prerequisites

- Docker installed ([Installation Instructions](https://docs.docker.com/get-docker/))

### Setup

1. **Clone the repository**
```
git clone https://github.com/katvio/fractum.git
```
```
cd fractum
```

2. **Create data folders**
```
mkdir -p data
```

3. **Build the Docker image**
```
docker build -t fractum-secure .
```
4. **Place the file to be encrypted in the data folder**

This step is essential as the Docker container can only access files within the mounted data directory

### Usage

#### Encrypting a file

```
# For Linux/macOS:
docker run --rm -it \
  --network=none \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/shares:/app/shares" \
  fractum-secure encrypt /data/YOUR_FILE \
  --threshold 3 \
  --shares 5 \
  --label "descriptive-name" \
  -v

# For Windows (PowerShell):
docker run --rm -it `
  --network=none `
  -v "${PWD}\data:/data" `
  -v "${PWD}\shares:/app/shares" `
  fractum-secure encrypt /data/YOUR_FILE `
  --threshold 3 `
  --shares 5 `
  --label "descriptive-name" `
  -v
```

#### Decrypting a file

```
# For Linux/macOS:
docker run --rm -it \
  --network=none \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/shares:/app/shares" \
  fractum-secure decrypt /data/YOUR_FILE.enc \
  --shares-dir /app/shares

# For Windows (PowerShell):
docker run --rm -it `
  --network=none `
  -v "${PWD}\data:/data" `
  -v "${PWD}\shares:/app/shares" `
  fractum-secure decrypt /data/YOUR_FILE.enc `
  --shares-dir /app/shares
```

### Benefits to using Docker

The Docker approach provides several security benefits:

1. **Complete network isolation**: The `--network=none` flag prevents any network access
2. **Non-root execution**: Container runs as a non-privileged user
3. **Minimal attack surface**: Only necessary files are included in the container
4. **Read-only code**: Application code cannot be modified during execution
5. **Ephemeral environment**: Container is destroyed after each use with `--rm`

## Manual installation using venv

### 1. Clone the repository
```
git clone https://github.com/katvio/fractum.git
```
```
cd fractum
```

### 2. Bootstrap your environment
Choose the script for your OS (no prior configuration needed):

- **Linux**
  ```
  chmod +x bootstrap-linux.sh && ./bootstrap-linux.sh
  ```
  This script will:
  - Install required system tools (git, curl, wget, etc.)
  - Add deadsnakes PPA repository
  - Install Python 3.12.10
  - Create a virtual environment
  - Install fractum in development mode

- **macOS**
  ```
  chmod +x bootstrap-macos.sh && ./bootstrap-macos.sh
  ```
  This script will:
  - Install Xcode Command Line Tools
  - Install Homebrew (if not present)
  - Install pyenv
  - Install Python 3.12.10
  - Create a virtual environment
  - Install fractum in development mode

- **Windows (PowerShell)**
  1. Open PowerShell **as Administrator**
  2. Set the execution policy for the current process:
     ```
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
     ```
     then say yes to everything (T)
  3. Run:
     ```
     .\bootstrap-windows.ps1
     ```
  This script will:
  - Install Python 3.12.10 (using winget or Chocolatey)
  - Create a virtual environment
  - Install fractum CLI on your machine

### 3. Activate the virtual environment
- **Linux & macOS (Bash)**
  ```
  source .venv/bin/activate
  ```
- **Windows (PowerShell)**
  ```
  .\.venv\Scripts\Activate.ps1
  ```

### 4. Verify your installation
```bash
python --version          # Should report Python 3.12.10
pip list                  # Should list fractum (editable mode)
fractum --help            # Show CLI usage
```

### 5. Try it out

```bash
# Example: split a file into shares
fractum encrypt passwords.txt --threshold 3 --shares 5 --label "my passwords" -v
```

This command:

- Encrypts the `passwords.txt` file (creates `passwords.txt.enc`)
- Creates a "shares" folder containing:
  - 5 individual ZIP archives (one per share)
  - Each ZIP contains:
      - The share file
      - The encrypted file (`passwords.txt.enc`)
      - The source code of fractum and bootstrap scripts (for portability)
      
```bash
# Example: reconstruct using shares
fractum decrypt passwords.txt.enc --shares-dir <folder containing ZIPs or shares>
```

This command:

- Loads shares from ZIPs or individual files
- Reconstructs the key if at least 3 shares are available (threshold)
- Decrypts the file to recreate passwords.txt 