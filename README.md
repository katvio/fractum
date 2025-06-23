# Fractum

Fractum is designed for organizations and individuals who need to **securely store critical information**. It provides enterprise-grade **cold storage** with mathematical guarantees, eliminating single points of failure through distributed secret sharing.

It is a fully offline, portable CLI for Shamir's Secret Sharing (SSS) combined with AES-256-GCM file encryption. Split secrets (passwords, SSH keys, etc.) into shares and reconstruct them later—securely, cross-platform, with minimal setup. Works with any file type without restrictions (documents, images, zip, databases, etc.).

![How Fractum splits your secrets into shares](diagram.png)

**💼 High-Value Use Cases:**

- **Cryptocurrency wallet protection**: Seed phrases, private keys, hardware wallet backups
- **Backup encryption master keys**: Protect your backup infrastructure encryption keys
- **Root CA private keys**: Certificate authority and PKI infrastructure protection
- **Emergency recovery credentials**: Admin passwords, break-glass access credentials
- **Password manager exports**: LastPass, Bitwarden, KeePass backup files
- **Legal & financial documents**: Wills, contracts, tax records, insurance papers

**⚡️ Distributed Architecture Benefits:**

- **Bus Factor Protection**: Write a Will and instructions for family members - they can pool shares to recover your assets
- **Theft/Loss Protection**: House fire, kidnapping/hostage situations, or lost hardware wallet - shares remain secure because you cannot be forced to access distant physical locations immediately
- **Geographic distribution**: Store shares across multiple locations (family, friends, safe deposit boxes)
- **No single point of failure**: Distributed trust across shares with threshold cryptography
- **Zero-knowledge property**: K-1 shares reveal absolutely nothing about your secrets

**🛡️ Enterprise Security Features:**

- **Works completely offline**: perfect for air-gapped environments
- **Memory protection**: Secure deletion and swap prevention
- **FIPS 140-2 compatible**: Uses industry-standard algorithms
- **Container-native**: Docker with security hardening and non-root execution

## Table of Contents
- [The Docker way (recommended usage)](#the-docker-way-recommended-usage)
- [How it works](#how-it-works)
- [Security Architecture](#security-architecture)
- [Complete Security Architecture Details](https://fractum.katvio.com/security-architecture/)
  - [Setup](#setup)
  - [Usage](#usage)
    - [Encrypting a file](#encrypting-a-file)
    - [Decrypting a file](#decrypting-a-file)
- [Manual installation using venv](https://fractum.katvio.com/manual-installation/)
- [Contributing](#contributing)
- [License](#license)
- [Complete Documentation](https://fractum.katvio.com/)
- [Security Best Practices](https://fractum.katvio.com/security-best-practices/)

## The Docker way (recommended usage)

Fractum can run in a completely network-isolated Docker container. The primary benefit of this approach is that the `--network=none` flag provides users with confidence that the Fractum code cannot exfiltrate their secrets through any network connection. Additionally, this Docker setup can work inside a [TEE](https://www.halborn.com/blog/post/what-is-a-trusted-execution-environment-tee) using tools like [Enclaver.io](https://github.com/enclaver-io/enclaver) for even more advanced security scenarios.

📚 **[Complete Docker Usage Guide](https://fractum.katvio.com/docker-usage/)**

### Setup

1. **Clone the repository**
```
git clone https://github.com/katvio/fractum.git
```
```
cd fractum && git checkout tags/v1.2.0
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
```
mv /path/to/your/passwords-export.csv data/
```

This step is essential as the Docker container can only access files within the mounted data directory

### Usage

#### Encrypting a file

```
docker run --rm -it \
  --network=none \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/shares:/app/shares" \
  fractum-secure encrypt /data/passwords-export.csv \
  --threshold 3 \
  --shares 5 \
  --label "bitwarden-backup" \
  -v
```
Expected output:

```
Using label: bitwarden-backup
Using existing shares directory
Generated share set ID: 708c547f308b39a9
Generated shares: 5
Encrypted file: /data/passwords-export.csv.enc
Created archive: /app/shares/share_1.zip
Created archive: /app/shares/share_2.zip
Created archive: /app/shares/share_3.zip
Created archive: /app/shares/share_4.zip
Created archive: /app/shares/share_5.zip
```

#### Decrypting a file

```
docker run --rm -it \
  --network=none \
  -v "$(pwd)/data:/data" \
  -v "$(pwd)/shares:/app/shares" \
  fractum-secure decrypt /data/passwords-export.csv.enc \
  --shares-dir /app/shares

> File successfully decrypted: /data/passwords-export.csv
```

For more detailed Docker usage instructions and security considerations, see our [Docker Usage Guide](https://fractum.katvio.com/docker-usage/).

## How it works

Fractum transforms your sensitive files into distributed, encrypted shares using mathematically proven cryptographic techniques. Here's the technical process:

📚 **[Complete Documentation](https://fractum.katvio.com/)** | 🔍 **[Security Architecture Details](https://fractum.katvio.com/security-architecture/)**

### Input and Output Files

**Input:**

- Your sensitive file (any type: documents, images, databases, etc.)
- Optional: Existing shares for key reuse

**Output:**

- Encrypted file with `.enc` extension
- Multiple self-contained share archives (ZIP files)
- Each share contains: share data, encrypted file, complete Fractum application, and bootstrap scripts

📚 **Learn more:** [Encrypting Files Guide](https://fractum.katvio.com/encrypting-files/) | [Decrypting Files Guide](https://fractum.katvio.com/decrypting-files/) | [Security Best Practices](https://fractum.katvio.com/security-best-practices/)

## Security Architecture

Fractum's security architecture combines **AES-256-GCM encryption** with **Shamir's Secret Sharing** to provide information-theoretic security for long-term cold storage.

🔍 **[Complete Security Architecture Details](https://fractum.katvio.com/security-architecture/)**

**Core Security Features:**

- **AES-256-GCM**: Authenticated encryption with 256-bit keys and unique nonces
- **Threshold cryptography**: Configurable K-of-N security model using finite field arithmetic
- **Memory protection**: Automatic clearing with secure deletion and swap prevention
- **Air-gapped design**: No network dependencies during cryptographic operations
- **Multi-layer integrity**: GCM authentication tags + SHA-256 hashing + metadata validation

**Standards Compliance:**

- ✅ FIPS 140-2 compatible algorithms
- ✅ NIST recommended key sizes
- ✅ Information-theoretic security guarantees

## Contributing
If you want to contribute submit a GitHub pull request or open an issue. Thank you!
Any contribution is better than no contribution :)

📚 **[Contributing Guide](https://fractum.katvio.com/contributing/)** | 🔒 **[Security Best Practices](https://fractum.katvio.com/security-best-practices/)**

## License

Fractum is licensed under a Custom Proprietary Software License that permits personal, non-commercial use. Commercial use is not permitted under this license. 

📄 **[View Full License](LICENSE)**

