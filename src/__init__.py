#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import click
import hashlib
import shutil
import zipfile
from typing import List, Tuple, Optional, Union
from pathlib import Path
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import base64
import time
import random
import string

# Strict Python version check
REQUIRED_PYTHON_VERSION = (3, 12, 10)
if sys.version_info[:3] != REQUIRED_PYTHON_VERSION:
    sys.exit(f"Error: This application requires exactly Python {'.'.join(map(str, REQUIRED_PYTHON_VERSION))}. "
             f"Current version: {'.'.join(map(str, sys.version_info[:3]))}")

VERSION = "1.0.0"

def get_enhanced_random_bytes(length: int = 32) -> bytes:
    """Combines multiple entropy sources for enhanced randomness.
    
    Args:
        length (int): Length of random bytes to generate
        
    Returns:
        bytes: Cryptographically secure random bytes from mixed sources
    """
    # Collect entropy from multiple sources
    sources = [
        get_random_bytes(length),    # PyCryptodome source
        os.urandom(length),          # OS entropy pool
        str(time.time_ns()).encode(),  # High-precision timing information
        str(os.getpid()).encode(),   # Process ID
        str(id(object())).encode()   # Memory address (adds some randomness)
    ]
    
    # Add some environmental entropy if available
    try:
        if hasattr(os, 'getloadavg'):
            sources.append(str(os.getloadavg()).encode())
        if hasattr(os, 'times'):
            sources.append(str(os.times()).encode())
    except (OSError, AttributeError):
        pass
    
    # Mix sources using a hash function
    combined = b"".join(sources)
    result = hashlib.sha256(combined).digest()
    
    # If we need more than 32 bytes, use SHAKE256 (extendable output function)
    if length > 32:
        result = hashlib.shake_256(combined).digest(length)
    else:
        result = result[:length]
        
    return result

class SecureMemory:
    @staticmethod
    def secure_clear(data: Union[bytes, bytearray, str, list, memoryview]) -> None:
        """Securely clears sensitive data from memory with multiple overwrite patterns.
        
        Args:
            data: Data to securely clear, can be bytes, bytearray, str, list, or memoryview
        """
        import gc
        import sys
        
        # Different overwrite patterns for multiple passes
        patterns = [
            0x00, 0xFF, 0xAA, 0x55,  # Binary patterns: zeros, ones, alternating
            0xF0, 0x0F, 0xCC, 0x33   # More patterns for additional security
        ]
        
        if isinstance(data, str):
            # Convert string to bytearray for secure clearing
            byte_data = bytearray(data.encode())
            SecureMemory.secure_clear(byte_data)
            # Attempt to clear the original string from memory by filling variable with junk
            # This is not guaranteed but helps in some cases
            # Assign a new object with different id to variable
            data_len = len(data)
            del data
            # Create garbage with same size
            for _ in range(10):  # Multiple garbage creation attempts
                garbage = "X" * data_len
                del garbage
            
        elif isinstance(data, (bytes, memoryview)):
            # Convert immutable bytes to bytearray for clearing
            byte_data = bytearray(data)
            SecureMemory.secure_clear(byte_data)
            
        elif isinstance(data, bytearray):
            # Multiple overwrite passes with different patterns
            for pattern in patterns:
                for i in range(len(data)):
                    data[i] = pattern
                # Force Python to actually perform the memory writes
                sys.stderr.write("")
                sys.stderr.flush()
            
            # Final pass with zeros
            for i in range(len(data)):
                data[i] = 0
                
            # Attempt to release memory
            data_len = len(data)
            del data
            
            # Create and destroy some garbage to encourage memory reuse
            for _ in range(5):
                garbage = bytearray(data_len)
                del garbage
                
            # Force garbage collection multiple times
            for _ in range(3):
                gc.collect()
                
        elif isinstance(data, list):
            # For lists containing sensitive data
            for i in range(len(data)):
                if isinstance(data[i], (bytes, bytearray, str, list, memoryview)):
                    # Recursively clear complex elements
                    SecureMemory.secure_clear(data[i])
                else:
                    # For simple numeric types, just zero them
                    try:
                        data[i] = 0
                    except TypeError:
                        # If element is immutable, replace with None
                        data[i] = None
            
            # Clear the list itself
            data.clear()
            del data
            gc.collect()

    @classmethod
    def secure_context(cls, size: int = 32) -> 'SecureContext':
        """Creates a secure context manager for temporary sensitive data.
        
        Args:
            size: Size of the secure memory buffer
            
        Returns:
            A context manager for secure memory usage
        """
        return SecureContext(size)
            
    @staticmethod
    def secure_string() -> str:
        """Creates a secure string."""
        # Use cryptographically secure random bytes instead of random.choices
        random_bytes = get_enhanced_random_bytes(32)
        # Convert to alphanumeric characters
        charset = string.ascii_letters + string.digits
        # Map bytes to characters (without bias)
        result = ""
        for byte in random_bytes:
            # Ensure no modulo bias by rejecting values above the largest multiple of len(charset)
            max_value = 256 - (256 % len(charset))
            if byte < max_value:
                result += charset[byte % len(charset)]
                if len(result) >= 32:  # We want a 32-character result
                    break
        
        # If we don't have enough characters (unlikely), append more
        while len(result) < 32:
            more_bytes = get_enhanced_random_bytes(8)
            for byte in more_bytes:
                if byte < max_value and len(result) < 32:
                    result += charset[byte % len(charset)]
        
        return result

    @staticmethod
    def secure_bytes(length: int = 32) -> bytearray:
        """Creates a secure bytearray."""
        return bytearray(get_enhanced_random_bytes(length))

class SecureContext:
    """Context manager for securely handling sensitive data."""
    
    def __init__(self, size: int = 32):
        """Initialize secure context with memory buffer.
        
        Args:
            size: Size of the secure memory buffer
        """
        self.buffer = bytearray(size)
        self.size = size
        
    def __enter__(self) -> bytearray:
        """Enter the context and return secure buffer."""
        # Initialize with random data
        random_bytes = get_enhanced_random_bytes(self.size)
        for i in range(min(len(random_bytes), self.size)):
            self.buffer[i] = random_bytes[i]
        return self.buffer
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context and securely clear the buffer."""
        SecureMemory.secure_clear(self.buffer)
        # The buffer object itself will be garbage collected, but we've cleared its contents

class ShareMetadata:
    """Centralized management of share metadata."""
    
    def __init__(self, version: str = VERSION, label: str = None, threshold: int = 3, total_shares: int = 5):
        self.version = version
        self.label = label
        self.threshold = threshold
        self.total_shares = total_shares
        
    @classmethod
    def from_share_info(cls, share_info: dict) -> 'ShareMetadata':
        """Creates a ShareMetadata instance from share information."""
        # Look for version in different places to maintain compatibility with old files
        # 1. In tool_integrity.shares_tool_version (new format)
        # 2. Directly in shares_tool_version (intermediate format)
        # 3. In version (old format)
        # 4. Default to current VERSION
        version = None
        if 'tool_integrity' in share_info and 'shares_tool_version' in share_info['tool_integrity']:
            version = share_info['tool_integrity']['shares_tool_version']
        elif 'shares_tool_version' in share_info:
            version = share_info['shares_tool_version']
        elif 'version' in share_info:
            version = share_info['version']
        else:
            version = VERSION
            
        return cls(
            version=version,
            label=share_info['label'],
            threshold=share_info.get('threshold', 3),
            total_shares=share_info.get('total_shares', 5)
        )
        
    def to_dict(self) -> dict:
        """Converts metadata to dictionary."""
        metadata = {
            'version': self.version,
            'label': self.label,
            'threshold': self.threshold,
            'total_shares': self.total_shares
        }
        return metadata
        
    def validate(self) -> None:
        """Validates metadata."""
        if not isinstance(self.threshold, int) or self.threshold < 2:
            raise ValueError("Threshold must be a positive integer greater than 1")
        if not isinstance(self.total_shares, int) or self.total_shares < self.threshold:
            raise ValueError("Total shares must be greater than or equal to threshold")
        if self.total_shares > 255:
            raise ValueError("Total shares cannot exceed 255")
        if not self.label:
            raise ValueError("Label is required")

class ShareManager:
    def __init__(self, threshold: int, total_shares: int):
        """Initializes the share manager.
        
        Args:
            threshold (int): Minimum number of shares needed to reconstruct the secret
            total_shares (int): Total number of shares to generate
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not isinstance(threshold, int) or threshold < 2:
            raise ValueError("Threshold must be a positive integer greater than 1")
        if not isinstance(total_shares, int) or total_shares < threshold:
            raise ValueError("Total shares must be greater than or equal to threshold")
        if total_shares > 255:  # PyCryptodome limit
            raise ValueError("Total shares cannot exceed 255")
            
        self.threshold = threshold
        self.total_shares = total_shares
        self.version = VERSION

    def _prepare_secret(self, secret: bytes) -> bytes:
        """Prepares the secret for sharing by ensuring it's exactly 32 bytes.
        
        Args:
            secret (bytes): The secret to prepare
            
        Returns:
            bytes: The prepared 32-byte secret
            
        Raises:
            ValueError: If the secret is too long
        """
        if len(secret) > 32:
            raise ValueError("Secret cannot exceed 32 bytes")
        if len(secret) == 0:
            raise ValueError("Secret cannot be empty")
            
        # Padding with zeros if necessary
        return secret.ljust(32, b'\0')

    def generate_shares(self, secret: bytes, label: str) -> List[Tuple[int, bytes]]:
        """Generates shares from a secret.
        
        Args:
            secret (bytes): The secret to share
            label (str): Label to identify the shares
            
        Returns:
            List[Tuple[int, bytes]]: List of shares (share_index, share)
            
        Raises:
            ValueError: If the secret is invalid
        """
        if not isinstance(secret, bytes):
            raise ValueError("Secret must be in bytes")
        if not isinstance(label, str) or not label:
            raise ValueError("Label must be a non-empty string")
            
        prepared_secret = self._prepare_secret(secret)
        # Split the secret into two 16-byte parts for Shamir
        secret_part1 = prepared_secret[:16]
        secret_part2 = prepared_secret[16:]
        
        # Generate shares for each part
        shares1 = Shamir.split(self.threshold, self.total_shares, secret_part1)
        shares2 = Shamir.split(self.threshold, self.total_shares, secret_part2)
        
        # Combine shares
        combined_shares = []
        for i in range(self.total_shares):
            idx1, share1 = shares1[i]
            idx2, share2 = shares2[i]
            if idx1 != idx2:
                raise ValueError("Share share_index inconsistency")
            combined_shares.append((idx1, share1 + share2))
            
        return combined_shares

    def combine_shares(self, shares: List[Tuple[int, bytes]]) -> bytes:
        """Reconstructs the secret from shares.
        
        Args:
            shares (List[Tuple[int, bytes]]): List of shares to combine
            
        Returns:
            bytes: The reconstructed secret
            
        Raises:
            ValueError: If there are insufficient shares or invalid shares
        """
        if not isinstance(shares, list):
            raise ValueError("Shares must be provided as a list")
        if len(shares) < self.threshold:
            raise ValueError(f"Insufficient number of shares: {len(shares)} < {self.threshold}")
            
        # share_index verification
        indices = set(idx for idx, _ in shares)
        if len(indices) != len(shares):
            raise ValueError("Duplicate indices detected")
            
        try:
            # Split shares into two parts
            shares1 = [(idx, share[:16]) for idx, share in shares]
            shares2 = [(idx, share[16:]) for idx, share in shares]
            
            # Reconstruct each part
            secret_part1 = Shamir.combine(shares1[:self.threshold])
            secret_part2 = Shamir.combine(shares2[:self.threshold])
            
            # Combine parts
            return secret_part1 + secret_part2
        except Exception as e:
            raise ValueError(f"Error reconstructing secret: {str(e)}")

    def verify_shares(self, shares: List[Tuple[int, bytes]]) -> bool:
        """Verifies share validity without revealing the secret.
        
        Args:
            shares (List[Tuple[int, bytes]]): List of shares to verify
            
        Returns:
            bool: True if shares are valid, False otherwise
        """
        if not isinstance(shares, list):
            return False
        if len(shares) < self.threshold:
            return False
            
        try:
            # share_index verification
            indices = set(idx for idx, _ in shares)
            if len(indices) != len(shares):
                return False
                
            # Test reconstruction with a subset
            test_shares = shares[:self.threshold]
            Shamir.combine(test_shares)
            return True
        except:
            return False

    @staticmethod
    def load_shares(share_files: List[str]) -> Tuple[List[Tuple[int, bytes]], ShareMetadata]:
        """Loads shares from files."""
        shares = []
        metadata = None
        
        for share_file in share_files:
            with open(share_file, 'r') as f:
                share_info = json.load(f)
                
                if metadata is None:
                    metadata = ShareMetadata.from_share_info(share_info)
                else:
                    current_metadata = ShareMetadata.from_share_info(share_info)
                    if metadata.version != current_metadata.version:
                        raise ValueError(f"Incompatible version in {share_file}")
                    if metadata.label != current_metadata.label:
                        raise ValueError(f"Incompatible label in {share_file}")
                    if metadata.threshold != current_metadata.threshold:
                        raise ValueError(f"Incompatible threshold in {share_file}")
                    if metadata.total_shares != current_metadata.total_shares:
                        raise ValueError(f"Incompatible total shares in {share_file}")
                
                # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                share_key = share_info.get('share_key', share_info.get('share'))
                if not share_key:
                    raise ValueError(f"No share key found in {share_file}")
                
                shares.append((
                    share_info['share_index'],
                    base64.b64decode(share_key)
                ))
        
        return shares, metadata

    def save_share(self, share: Tuple[int, bytes], label: str) -> str:
        """Saves a share to a file."""
        idx, share_data = share
        filename = f"share_{idx}.txt"
        
        metadata = ShareMetadata(
            version=self.version,
            label=label,
            threshold=self.threshold,
            total_shares=self.total_shares
        )
        metadata.validate()
        
        share_info = {
            **metadata.to_dict(),
            'share_index': idx,
            'share_key': base64.b64encode(share_data).decode(),
            'hash': hashlib.sha256(share_data).hexdigest()
        }
        
        with open(filename, 'w') as f:
            json.dump(share_info, f, indent=2)
            
        return filename

class FileEncryptor:
    def __init__(self, key: bytes):
        self.key = key
        self.version = VERSION

    def _write_metadata(self, f, data_hash: str, metadata: dict = None) -> None:
        """Writes metadata at the beginning of the file."""
        if metadata is None:
            metadata = {}
            
        # Ensure basic metadata is included
        metadata.update({
            'version': self.version,
            'timestamp': int(time.time()),
            'hash': data_hash
        })
            
        metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode('utf-8')
        f.write(len(metadata_bytes).to_bytes(4, 'big'))
        f.write(metadata_bytes)

    def _read_metadata(self, f) -> dict:
        """Reads metadata from the beginning of the file."""
        try:
            metadata_len = int.from_bytes(f.read(4), 'big')
            metadata_bytes = f.read(metadata_len)
            
            try:
                # First try with UTF-8 encoding
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except UnicodeDecodeError:
                # Fallback to latin-1 encoding with error replacement if UTF-8 fails
                try:
                    metadata = json.loads(metadata_bytes.decode('latin-1', errors='replace'))
                except json.JSONDecodeError:
                    # If JSON decoding fails, provide default metadata
                    metadata = {'version': self.version}
            except json.JSONDecodeError:
                # If JSON decoding fails, provide default metadata
                metadata = {'version': self.version}
            
            # Ensure version is included
            if 'version' not in metadata:
                metadata['version'] = self.version
            
            return metadata
        except Exception:
            # Last resort fallback for any other errors (like reading from corrupted file)
            return {'version': self.version}

    def encrypt_file(self, input_path: str, output_path: str, metadata: dict = None) -> None:
        """Encrypts a file with AES-256-GCM."""
        try:
            cipher = AES.new(self.key, AES.MODE_GCM)
            
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Calculate data hash
            data_hash = hashlib.sha256(data).hexdigest()
            
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            with open(output_path, 'wb') as f:
                # Write metadata
                if metadata is None:
                    metadata = {}
                    
                # Ensure basic metadata is included
                metadata.update({
                    'version': self.version,
                    'timestamp': int(time.time()),
                    'hash': data_hash
                })
                
                metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode('utf-8')
                f.write(len(metadata_bytes).to_bytes(4, 'big'))
                f.write(metadata_bytes)
                
                # Write encryption data
                f.write(cipher.nonce)  # Write the 16-byte nonce
                f.write(tag)           # Write the 16-byte tag
                f.write(ciphertext)    # Write the encrypted data
        except Exception as e:
            # Handle any exceptions that occur during encryption
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypts a file with AES-256-GCM."""
        try:
            with open(input_path, 'rb') as f:
                # Read metadata
                metadata = self._read_metadata(f)
                
                # Version check
                if metadata.get('version', self.version) != self.version:
                    raise ValueError(f"Incompatible version: expected {self.version}, found {metadata.get('version', self.version)}")
                
                # Read nonce and tag
                nonce = f.read(16)
                if not nonce or len(nonce) != 16:
                    raise ValueError("Invalid or missing nonce")
                    
                tag = f.read(16)
                if not tag or len(tag) != 16:
                    raise ValueError("Invalid or missing authentication tag")
                    
                ciphertext = f.read()
                if not ciphertext:
                    raise ValueError("No encrypted data found")
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            try:
                data = cipher.decrypt_and_verify(ciphertext, tag)
                
                # Hash verification - only if hash is present in metadata
                if 'hash' in metadata:
                    data_hash = hashlib.sha256(data).hexdigest()
                    if data_hash != metadata['hash']:
                        raise ValueError("Data hash mismatch")
                
                # Additional check: file should not be empty
                if len(data) == 0:
                    raise ValueError("Decrypted data is empty")
                
                with open(output_path, 'wb') as f:
                    f.write(data)
            except ValueError as e:
                if "authentication tag" in str(e):
                    raise ValueError("Incorrect key")
                raise
        except (ValueError, IOError) as e:
            # Provide more context with the specific error
            raise ValueError(f"Decryption failed: {str(e)}")
        except Exception as e:
            # Catch any other unexpected errors
            raise ValueError(f"Unexpected error during decryption: {str(e)}")

class ShareArchiver:
    """Archive manager for shares."""
    
    def __init__(self, base_dir: str = "shares"):
        """Initializes the archive manager.
        
        Args:
            base_dir (str): Base directory for archives
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        
    def create_share_archive(self, share_file: str, encrypted_file: str, share_share_index: int, label: str) -> str:
        """Creates a ZIP archive for a share.
        
        Args:
            share_file (str): Path to share file
            encrypted_file (str): Path to encrypted file
            share_share_index (int): Share share_index
            label (str): Share label
            
        Returns:
            str: Path to created ZIP archive
        """
        # Create temporary directory for archive
        temp_dir = self.base_dir / f"temp_share_{share_share_index}"
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Copy necessary files
            shutil.copy(share_file, temp_dir)
            shutil.copy(encrypted_file, temp_dir)
            
            # Copy project files if they exist
            files_to_copy = [
                ("README.md", "README.md"),
                ("requirements.txt", "requirements.txt"),
                ("setup.py", "setup.py"),
                ("LICENSE", "LICENSE"),
            ]
            
            for src, dst in files_to_copy:
                src_path = Path(src)
                if src_path.exists():
                    shutil.copy(src_path, temp_dir / dst)
            
            # Copy source code
            sss_dir = temp_dir / "src"
            sss_dir.mkdir(exist_ok=True)
            shutil.copy("src/__init__.py", sss_dir)
            
            # Create packages directory
            packages_dir = temp_dir / "packages"
            packages_dir.mkdir(exist_ok=True)
            
            # Copy packages
            packages_path = Path("packages")
            if packages_path.exists():
                for package_file in packages_path.glob("*.whl"):
                    shutil.copy(package_file, packages_dir)
            
            # Create ZIP archive with sequential naming
            base_name = f"share_{share_share_index}"
            archive_path = self.base_dir / f"{base_name}.zip"
            
            # Check if file already exists and generate unique name with simple numeric suffix
            counter = 2
            while archive_path.exists():
                archive_path = self.base_dir / f"{base_name}_{counter}.zip"
                counter += 1
            
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(temp_dir)
                        zipf.write(file_path, arcname)
            
            return str(archive_path)
            
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)

def calculate_tool_integrity():
    """Calculates integrity hashes of the tool and its dependencies."""
    integrity = {
        'tool_hash': '',
        'packages_hash': {},
        'shares_tool_version': VERSION
    }
    
    # Hash of __init__.py file
    init_path = Path(__file__)
    if init_path.exists():
        with open(init_path, 'rb') as f:
            integrity['tool_hash'] = hashlib.sha256(f.read()).hexdigest()
    
    # Hash of packages
    packages_dir = Path('packages')
    if packages_dir.exists():
        for whl in packages_dir.glob('*.whl'):
            with open(whl, 'rb') as f:
                integrity['packages_hash'][whl.name] = hashlib.sha256(f.read()).hexdigest()
    
    return integrity

@click.group(invoke_without_command=True)
@click.version_option(version=VERSION)
@click.option('--interactive', '-i', is_flag=True, help='Launch interactive mode')
@click.pass_context
def cli(ctx, interactive):
    """Shamir's Secret Sharing Tool.

    A secure tool for file encryption and secret sharing using Shamir's Secret Sharing scheme.
    All operations can be performed offline using local packages.

    Available commands:

    encrypt:

        Encrypts a file and generates shares using Shamir's Secret Sharing.
        Creates ZIP archives containing shares and necessary files for decryption.

        Options:

            --threshold, -t
            Minimum number of shares needed to reconstruct the secret (must be > 1)

            --shares, -n
            Total number of shares to generate (must be >= threshold)

            --label, -l
            Label to identify the shares (used in filenames)

            --existing-shares, -e
            Directory containing existing shares to use for encryption
            (allows reusing shares from previous operations)

            --verbose, -v
            Enable verbose output for detailed operation information

    decrypt:

        Decrypts a file using the provided shares.
        Can use either individual share files or ZIP archives.

        Options:

            --shares-dir, -s
            Directory containing shares or ZIP archives
            (can contain a mix of .txt files and .zip archives)

            --manual-shares, -m
            Manually enter share values instead of using files
            (allows direct input of share index and share_key value in Base64 or Hex format)

            --verbose, -v
            Enable verbose output for detailed operation information

    verify:

        Verifies the integrity of shares and their compatibility.
        Checks both individual share files and ZIP archives.

        Options:

            --shares-dir, -s
            Directory containing shares or ZIP archives to verify
            (can be a single file or a directory)

    Global Options:

        --interactive, -i
        Launch the interactive mode that guides you through the operations step by step
        (a menu-driven interface that simplifies using the tool without command line arguments)

    Examples:

        # Launch interactive mode (recommended for new users)
        fractum -i

        # Encrypt a file with 3-5 scheme
        fractum encrypt secret.txt -t 3 -n 5 -l mysecret

        # Decrypt using shares from a directory
        fractum decrypt secret.txt.enc -s ./shares

        # Decrypt by manually entering share values
        fractum decrypt secret.txt.enc -m

        # Verify shares in a directory
        fractum verify -s ./shares
    """
    if ctx.invoked_subcommand is None:
        if interactive:
            interactive_mode()
        else:
            click.echo(ctx.get_help())
            ctx.exit()

def interactive_mode():
    """Interactive mode guiding the user step by step."""
    click.echo("\n=== Fractum Interactive Mode ===")
    
    # Mapping choices to functions
    operations = {
        1: ("Encrypt a file", interactive_encrypt),
        2: ("Decrypt a file", interactive_decrypt),
        3: ("Verify shares", interactive_verify),
        4: ("Quit", None)
    }
    
    while True:
        click.echo("\nWhat would you like to do?")
        for choice, (description, _) in operations.items():
            click.echo(f"{choice}. {description}")
        
        try:
            choice = click.prompt("Your choice", type=int)
            if choice not in operations:
                click.echo("Invalid choice. Please enter a number between 1 and 4.")
                continue
                
            if choice == 4:  # Quit
                click.echo("\nGoodbye!")
                break
                
            description, operation = operations[choice]
            click.echo(f"\n=== {description} ===")
            
            try:
                if operation():
                    click.echo("\nOperation completed successfully!")
            except Exception as e:
                click.echo(f"\nError: {str(e)}", err=True)
                
            if not click.confirm("\nWould you like to perform another operation?", default=None):
                click.echo("\nGoodbye!")
                break
                
        except ValueError:
            click.echo("Please enter a valid number.")
            continue

def interactive_encrypt():
    """Interactive mode for encryption."""
    try:
        # Ask for file to encrypt
        input_file = click.prompt("Full path of the file to encrypt", type=click.Path(exists=True, dir_okay=False, file_okay=True))
        
        # Ask if using existing shares
        use_existing = click.confirm("Do you want to use existing shares?", default=None)
        existing_shares = None
        if use_existing:
            existing_shares = click.prompt("Full path of the directory containing existing shares", type=click.Path(exists=True, dir_okay=True, file_okay=False))
            
            # Check existing shares - examine all files, not just those with specific names
            share_files = []
            for file_path in Path(existing_shares).glob("*.*"):
                if file_path.is_file():
                    try:
                        with open(file_path, 'r') as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if all(key in share_info for key in ['share_index', 'share', 'label', 'threshold', 'total_shares']):
                                share_files.append(file_path)
                    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                        # Not a valid JSON file, skip it
                        continue
            
            if not share_files:
                raise ValueError("No valid share files found in specified directory")
                
            # Read label from first share
            with open(share_files[0], 'r') as f:
                share_info = json.load(f)
                existing_label = share_info['label']
                
            click.echo(f"\nExisting shares found with label: {existing_label}")
            click.echo("You must use the same label for compatibility")
            label = existing_label
            click.echo(f"Label used: {label}")
            
            # Read parameters from existing shares
            threshold = share_info.get('threshold', 3)
            total_shares = share_info.get('total_shares', 5)
            click.echo(f"Existing shares parameters:")
            click.echo(f"- Threshold: {threshold}")
            click.echo(f"- Total shares: {total_shares}")
            
        else:
            # Ask for threshold
            threshold = click.prompt("Minimum number of shares needed for decryption", type=int)
            while threshold < 2:
                click.echo("Threshold must be greater than 1")
                threshold = click.prompt("Minimum number of shares needed for decryption", type=int)
            
            # Ask for total shares
            total_shares = click.prompt("Total number of shares to generate", type=int)
            while total_shares < threshold:
                click.echo(f"Total shares must be greater than or equal to threshold ({threshold})")
                total_shares = click.prompt("Total number of shares to generate", type=int)
            
            # Ask for label
            label = click.prompt("Label to identify the shares")
            if not label:
                click.echo("Label cannot be empty")
                return False
        
        # Ask for verbose mode
        verbose = click.confirm("Do you want to enable verbose mode?", default=None)
        
        # Confirm parameters
        click.echo("\nEncryption parameters:")
        click.echo(f"File to encrypt: {input_file}")
        click.echo(f"Threshold: {threshold}")
        click.echo(f"Total shares: {total_shares}")
        click.echo(f"Label: {label}")
        click.echo(f"Existing shares: {'Yes' if use_existing else 'No'}")
        if use_existing:
            click.echo(f"Shares directory: {existing_shares}")
        click.echo(f"Verbose mode: {'Enabled' if verbose else 'Disabled'}")
        
        # Execute command via Click
        ctx = click.get_current_context()
        ctx.invoke(encrypt, 
                  input_file=input_file,
                  threshold=threshold,
                  shares=total_shares,
                  label=label,
                  existing_shares=existing_shares,
                  verbose=verbose)
        return True
        
    except Exception as e:
        click.echo(f"\nError during encryption: {str(e)}", err=True)
        return False

@cli.command()
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False, file_okay=True))
@click.option('--shares-dir', '-s', type=click.Path(exists=True, dir_okay=True, file_okay=False), help='Path to directory containing shares or ZIP archives')
@click.option('--manual-shares', '-m', is_flag=True, help='Manually enter share values instead of using files')
@click.option('--verbose', '-v', is_flag=True, help='Verbose mode')
def decrypt(input_file: str, shares_dir: str, manual_shares: bool, verbose: bool):
    """Decrypts a file using shares."""
    try:
        # If manual shares option is selected, collect shares interactively
        if manual_shares:
            if verbose:
                click.echo("Manual share entry mode activated")
            shares_data, metadata = collect_manual_shares()
            
            if not shares_data or len(shares_data) < 2:
                raise ValueError("Not enough valid shares provided. Minimum 2 shares required.")
            
            if verbose:
                click.echo(f"Collected {len(shares_data)} manual shares successfully")
                click.echo(f"Using shares with parameters: threshold={metadata['threshold']}, total_shares={metadata['total_shares']}")
                
            # Reconstruct key
            share_manager = ShareManager(metadata['threshold'], metadata['total_shares'])
            key = share_manager.combine_shares(shares_data)
            
            # Decrypt file
            output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + '.dec'
            encryptor = FileEncryptor(key)
            encryptor.decrypt_file(input_file, output_file)
            
            # Get absolute path of the decrypted file
            output_path = Path(output_file).absolute()
            click.echo(f"File successfully decrypted: {output_path}")
            
            # Secure cleanup
            SecureMemory.secure_clear(key)
            return
            
        # Original code for file-based shares
        if not shares_dir:
            raise ValueError("Either --shares-dir or --manual-shares must be provided")
            
        shares_path = Path(shares_dir)
        
        # Extract share_set_id from metadata
        extracted_share_set_id = None
        with open(input_file, 'rb') as f:
            # Read metadata
            encryptor = FileEncryptor(SecureMemory.secure_bytes(32))
            metadata = encryptor._read_metadata(f)
            extracted_share_set_id = metadata.get('share_set_id')
            
            if verbose:
                if extracted_share_set_id:
                    click.echo(f"Found share set ID in metadata: {extracted_share_set_id}")
                else:
                    click.echo("No share set ID found in metadata")
        
        # Dictionary to store shares by set_id and label
        shares_by_set_id = {}
        shares_by_label = {}
        
        # Look for share files in directory
        share_files = []
        
        # First try to find ZIP archives
        zip_files = list(shares_path.glob("*.zip"))
        if zip_files:
            share_files.extend(zip_files)
            if verbose:
                click.echo(f"Found {len(zip_files)} ZIP archives")
        
        # Then look for all potential share files by examining content
        content_share_files = []
        for file_path in shares_path.glob("*.*"):
            if file_path.is_file() and not file_path.suffix == '.zip':  # Skip ZIP files which we already handled
                try:
                    with open(file_path, 'r') as f:
                        share_info = json.load(f)
                        # Check if this is a valid share file by looking for essential fields
                        if all(key in share_info for key in ['share_index', 'share', 'label']):
                            content_share_files.append(file_path)
                except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                    # Not a valid JSON file, skip it
                    continue
        
        # Add the content-detected share files
        if content_share_files:
            share_files.extend(content_share_files)
            
        if not share_files:
            # Try to find any file that might be a share
            all_files = list(shares_path.glob("*"))
            share_files = [f for f in all_files if f.is_file()]
            if not share_files:
                raise ValueError(f"No files found in directory {shares_dir}")
            else:
                click.echo(f"Found {len(share_files)} files in directory, but none match the expected share format")
                click.echo("Please ensure you're pointing to a directory containing valid share files or archives")
                return
        
        if verbose:
            click.echo(f"Processing {len(share_files)} share files/archives")
        
        # Process each file and group by set_id and label
        for share_file in share_files:
            if str(share_file).endswith('.zip'):
                # Extract archive to temporary directory
                temp_dir = Path(f"temp_share_{share_file.stem}")
                temp_dir.mkdir(exist_ok=True)
                
                try:
                    with zipfile.ZipFile(share_file, 'r') as zipf:
                        zipf.extractall(temp_dir)
                    
                    # Look for share file
                    share_files_in_zip = list(temp_dir.glob("share_*.txt"))
                    if not share_files_in_zip:
                        if verbose:
                            click.echo(f"No share file found in archive {share_file}")
                        continue
                    
                    share_file = share_files_in_zip[0]
                except Exception as e:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    if verbose:
                        click.echo(f"Error extracting archive {share_file}: {str(e)}")
                    continue
            
            try:
                with open(share_file, 'r') as f:
                    share_info = json.load(f)
                    label = share_info['label']
                    share_set_id = share_info.get('share_set_id', None)
                    
                    # If share has a set_id, store by set_id
                    if share_set_id:
                        if share_set_id not in shares_by_set_id:
                            # Look for version in different places to maintain compatibility with old files
                            version = None
                            if 'tool_integrity' in share_info and 'shares_tool_version' in share_info['tool_integrity']:
                                version = share_info['tool_integrity']['shares_tool_version']
                            elif 'shares_tool_version' in share_info:
                                version = share_info['shares_tool_version']
                            elif 'version' in share_info:
                                version = share_info['version']
                            else:
                                version = VERSION
                                
                            shares_by_set_id[share_set_id] = {
                                'shares': [],
                                'metadata': {
                                    'version': version,
                                    'label': label,
                                    'threshold': share_info.get('threshold', 3),
                                    'total_shares': share_info.get('total_shares', 5)
                                }
                            }
                        
                        # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                        share_key = share_info.get('share_key', share_info.get('share'))
                        if not share_key:
                            raise ValueError(f"No share key found in {share_file}")
                        
                        shares_by_set_id[share_set_id]['shares'].append((
                            share_info['share_index'],
                            base64.b64decode(share_key)
                        ))
                    
                    # Also store by label for backward compatibility
                    if label not in shares_by_label:
                        # Look for version in different places to maintain compatibility with old files
                        version = None
                        if 'tool_integrity' in share_info and 'shares_tool_version' in share_info['tool_integrity']:
                            version = share_info['tool_integrity']['shares_tool_version']
                        elif 'shares_tool_version' in share_info:
                            version = share_info['shares_tool_version']
                        elif 'version' in share_info:
                            version = share_info['version']
                        else:
                            version = VERSION
                            
                        shares_by_label[label] = {
                            'shares': [],
                            'metadata': {
                                'version': version,
                                'label': label,
                                'threshold': share_info.get('threshold', 3),
                                'total_shares': share_info.get('total_shares', 5)
                            }
                        }
                    
                    # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                    share_key = share_info.get('share_key', share_info.get('share'))
                    if not share_key:
                        if verbose:
                            click.echo(f"No share key found in {share_file}")
                        continue
                    
                    shares_by_label[label]['shares'].append((
                        share_info['share_index'],
                        base64.b64decode(share_key)
                    ))
            except Exception as e:
                if verbose:
                    click.echo(f"Error processing {share_file}: {str(e)}")
                continue
            
            # Clean up temporary directory if it was an archive
            if str(share_file).endswith('.zip'):
                shutil.rmtree(temp_dir, ignore_errors=True)
        
        if verbose:
            if shares_by_set_id:
                click.echo(f"\nFound shares with set IDs: {', '.join(shares_by_set_id.keys())}")
            click.echo(f"Found shares for {len(shares_by_label)} different labels")
            for label in shares_by_label:
                click.echo(f"  - {label}: {len(shares_by_label[label]['shares'])} shares (threshold: {shares_by_label[label]['metadata']['threshold']})")
        
        # First attempt to find shares by share_set_id extracted from metadata
        if extracted_share_set_id and extracted_share_set_id in shares_by_set_id:
            if verbose:
                click.echo(f"Using shares with set ID: {extracted_share_set_id}")
            share_data = shares_by_set_id[extracted_share_set_id]['shares']
            metadata = shares_by_set_id[extracted_share_set_id]['metadata']
        else:
            # If not found by share_set_id, try to find matching shares by label
            if verbose:
                if shares_by_set_id:
                    click.echo(f"Found shares with set IDs: {', '.join(shares_by_set_id.keys())}")
                click.echo(f"Found shares for {len(shares_by_label)} different labels")
                for label in shares_by_label:
                    click.echo(f"  - {label}: {len(shares_by_label[label]['shares'])} shares (threshold: {shares_by_label[label]['metadata']['threshold']})")
            
            # Try to find matching shares for the input file by label
            input_label = None
            for label in shares_by_label:
                if label in input_file:
                    input_label = label
                    break
            
            if input_label is None:
                # If no exact match, try all available labels until one works
                if shares_by_label:
                    # Try each label until one works
                    for label in shares_by_label:
                        try:
                            if verbose:
                                click.echo(f"Trying shares with label: {label}")
                            
                            share_data = shares_by_label[label]['shares']
                            metadata = shares_by_label[label]['metadata']
                            
                            # Try to reconstruct key
                            share_manager = ShareManager(metadata['threshold'], metadata['total_shares'])
                            key = share_manager.combine_shares(share_data)
                            
                            # Try to decrypt with this key
                            output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + '.dec'
                            encryptor = FileEncryptor(key)
                            
                            # Try to decrypt a small portion of the file to verify the key
                            with open(input_file, 'rb') as f:
                                # Skip metadata
                                metadata_len = int.from_bytes(f.read(4), 'big')
                                f.read(metadata_len)
                                
                                # Read a small portion of the encrypted data
                                nonce = f.read(16)
                                tag = f.read(16)
                                ciphertext = f.read(32)  # Just read a small portion
                            
                            # Try to decrypt this small portion
                            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                            try:
                                cipher.decrypt_and_verify(ciphertext, tag)
                                # If we get here, the key is correct
                                if verbose:
                                    click.echo(f"Successfully verified key with label: {label}")
                                break
                            except ValueError:
                                # Key is incorrect, try next label
                                if verbose:
                                    click.echo(f"Key verification failed for label: {label}")
                                continue
                        except Exception as e:
                            if verbose:
                                click.echo(f"Error trying label {label}: {str(e)}")
                            continue
                    else:
                        # If we get here, none of the labels worked
                        raise ValueError("No compatible shares found. None of the available shares could decrypt the file.")
                else:
                    raise ValueError("No compatible shares found")
            else:
                share_data = shares_by_label[input_label]['shares']
                metadata = shares_by_label[input_label]['metadata']
        
        if verbose:
            if 'label' in metadata:
                click.echo(f"\nUsing shares for label: {metadata['label']}")
            click.echo(f"Found {len(share_data)} shares (need {metadata['threshold']})")
        
        # Get scheme parameters from metadata
        threshold = metadata['threshold']
        total_shares = metadata['total_shares']
        
        # Reconstruct key
        share_manager = ShareManager(threshold, total_shares)
        key = share_manager.combine_shares(share_data)
        if verbose:
            click.echo("Key reconstructed from shares")
        
        # File decryption
        output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + '.dec'
        encryptor = FileEncryptor(key)
        encryptor.decrypt_file(input_file, output_file)
        
        # Get absolute path of the decrypted file
        output_path = Path(output_file).absolute()
        click.echo(f"File successfully decrypted: {output_path}")
        
        # Secure cleanup
        SecureMemory.secure_clear(key)
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

def collect_manual_shares() -> Tuple[List[Tuple[int, bytes]], dict]:
    """Collects shares manually from user input."""
    click.echo("\n=== Manual Share Entry ===")
    click.echo("Enter share details when prompted. Enter 'done' when finished.")
    
    shares = []
    metadata = None
    
    while True:
        # Get share index
        share_index_input = click.prompt("Share index (or 'done' to finish)", type=str)
        if share_index_input.lower() == 'done':
            break
            
        try:
            share_index = int(share_index_input)
            if share_index < 1 or share_index > 255:
                click.echo("Invalid share index. Must be between 1 and 255.")
                continue
        except ValueError:
            click.echo("Invalid share index. Please enter a number.")
            continue
            
        # Get share key value
        share_value = click.prompt("Share key value (Base64 or Hex encoded)", type=str)
        
        # Try to detect the format and decode accordingly
        try:
            # Try Base64 first
            try:
                share_data = base64.b64decode(share_value)
                
                # Verify this is actually valid Base64 by checking the length
                # The decoded data should be 32 bytes for our shares
                if len(share_data) != 32:
                    # Maybe it's hex encoded
                    raise ValueError("Incorrect data length for Base64")
                    
            except (ValueError, base64.binascii.Error):
                # If Base64 fails, try hex
                # Remove any whitespace or colons that might be in the hex string
                hex_value = share_value.replace(":", "").replace(" ", "")
                
                # Check if it looks like a hex string (only hex chars)
                if all(c in '0123456789abcdefABCDEF' for c in hex_value):
                    # Convert from hex to bytes
                    share_data = bytes.fromhex(hex_value)
                    
                    # Check length - should be 32 bytes
                    if len(share_data) != 32:
                        raise ValueError(f"Incorrect length for Hex data: {len(share_data)} bytes (expected 32)")
                else:
                    raise ValueError("Share key value must be valid Base64 or Hex")
                
        except Exception as e:
            click.echo(f"Invalid share key value: {str(e)}. Please try again.")
            continue
            
        # First share determines metadata
        if not metadata:
            threshold = click.prompt("Threshold (minimum number of shares needed)", type=int)
            total_shares = click.prompt("Total shares", type=int)
            
            if threshold < 2 or threshold > total_shares or total_shares > 255:
                click.echo("Invalid parameters. Threshold must be >= 2, total_shares must be >= threshold and <= 255.")
                continue
                
            metadata = {
                'version': VERSION,
                'threshold': threshold,
                'total_shares': total_shares
            }
            
        # Add share to collection
        shares.append((share_index, share_data))
        click.echo(f"Share {share_index} added successfully. Total shares: {len(shares)}")
        
        # Check if we have enough shares
        if len(shares) >= metadata['threshold']:
            if click.confirm("You have enough shares for reconstruction. Proceed with decryption?", default=None):
                break
    
    # Final verification
    if len(shares) < 2:
        click.echo("Warning: Not enough shares provided. Minimum 2 shares required.")
        
    return shares, metadata

def interactive_decrypt():
    """Interactive mode for decryption."""
    try:
        # Ask for file to decrypt
        input_file = click.prompt("Full path of the file to decrypt", type=click.Path(exists=True, dir_okay=False, file_okay=True))
        
        # Ask if using files or manual entry
        use_manual = click.confirm("Do you want to enter the share keys manually? If not, you will be asked to provide the path to the folder containing the necessary share files?", default=None)
        
        if use_manual:
            shares_dir = None
        else:
            # Ask for shares directory
            shares_dir = click.prompt("Full path of the directory containing shares", type=click.Path(exists=True, dir_okay=True, file_okay=False))
        
        # Ask for verbose mode
        verbose = click.confirm("Do you want to enable verbose mode?", default=None)
        
        # Confirm parameters
        click.echo("\nDecryption parameters:")
        click.echo(f"File to decrypt: {input_file}")
        if use_manual:
            click.echo("Share entry: Manual")
        else:
            click.echo(f"Shares directory: {shares_dir}")
        click.echo(f"Verbose mode: {'Enabled' if verbose else 'Disabled'}")
        
        # Execute command via Click
        ctx = click.get_current_context()
        ctx.invoke(decrypt,
                  input_file=input_file,
                  shares_dir=shares_dir,
                  manual_shares=use_manual,
                  verbose=verbose)
        return True
        
    except Exception as e:
        click.echo(f"\nError during decryption: {str(e)}", err=True)
        return False

def interactive_verify():
    """Interactive mode for verification."""
    try:
        # Ask for shares directory
        shares_dir = click.prompt("Full path of the directory containing shares", type=click.Path(exists=True))
        
        # Confirm parameters
        click.echo("\nVerification parameters:")
        click.echo(f"Shares directory: {shares_dir}")
        
        # Execute command via Click - Fixed to avoid passing input_file
        ctx = click.get_current_context()
        ctx.invoke(verify, shares_dir=shares_dir)
        return True
        
    except Exception as e:
        click.echo(f"\nError during verification: {str(e)}", err=True)
        return False

@cli.command()
@click.argument('input_file', type=click.Path(exists=True, dir_okay=False, file_okay=True))
@click.option('--threshold', '-t', required=True, type=int, help='Minimum number of shares needed')
@click.option('--shares', '-n', required=True, type=int, help='Total number of shares to generate')
@click.option('--label', '-l', required=True, help='Label to identify shares')
@click.option('--existing-shares', '-e', type=click.Path(exists=True, dir_okay=True, file_okay=False), help='Directory containing existing shares')
@click.option('--verbose', '-v', is_flag=True, help='Verbose mode')
def encrypt(input_file: str, threshold: int, shares: int, label: str, existing_shares: str, verbose: bool):
    """Encrypts a file and generates shares."""
    try:
        # Replace spaces with underscores in label
        label = label.replace(' ', '_')
        if verbose:
            click.echo(f"Using label: {label} (spaces replaced with underscores)")
            
        # Check Python version
        if sys.version_info < (3, 8):
            raise ValueError("Python 3.8 or higher is required")
            
        # Create shares directory if it doesn't exist
        shares_dir = Path("shares")
        if not shares_dir.exists():
            shares_dir.mkdir()
            if verbose:
                click.echo("Created shares directory")
        elif verbose:
            click.echo("Using existing shares directory")
        
        # Calculate integrity hashes
        tool_integrity = calculate_tool_integrity()
        
        if existing_shares:
            # Use existing shares - examine all files, not just those with specific names
            share_files = []
            for file_path in Path(existing_shares).glob("*.*"):
                if file_path.is_file():
                    try:
                        with open(file_path, 'r') as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if all(key in share_info for key in ['share_index', 'share', 'label', 'threshold', 'total_shares']):
                                share_files.append(file_path)
                    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                        # Not a valid JSON file, skip it
                        continue
            
            if not share_files:
                raise ValueError("No valid share files found in specified directory")
            
            shares_data, metadata = ShareManager.load_shares(share_files)
            
            # Verify metadata compatibility
            if metadata.label != label:
                raise ValueError(f"Share label mismatch: expected {label}, found {metadata.label}")
            
            # Use original parameters from metadata
            threshold = metadata.threshold
            shares = metadata.total_shares
            
            if verbose:
                click.echo(f"Using existing shares with parameters: threshold={threshold}, total_shares={shares}")
            
            share_manager = ShareManager(threshold, shares)
            key = share_manager.combine_shares(shares_data)
            
            # Get existing share_set_id
            with open(share_files[0], 'r') as f:
                share_info = json.load(f)
                share_set_id = share_info.get('share_set_id', None)
            
            if verbose:
                click.echo(f"Using {len(shares_data)} existing shares with ID: {share_set_id}")
        else:
            # Generate new shares
            # Generate new key with enhanced entropy
            key = get_enhanced_random_bytes(32)
            
            # Generate a unique set identifier hash for this group of shares
            # Using enhanced entropy for share_set_id generation
            random_component = get_enhanced_random_bytes(16).hex()
            input_filename = Path(input_file).stem
            timestamp = str(time.time())
            share_set_id = hashlib.sha256((label + input_filename + timestamp + random_component).encode()).hexdigest()[:16]
            
            if verbose:
                click.echo(f"Generated share set ID: {share_set_id}")
            
            share_manager = ShareManager(threshold, shares)
            share_data = share_manager.generate_shares(key, label)
            
            # Create archive manager
            archiver = ShareArchiver()
            
            # Save shares and create archives
            share_files = []
            for idx, share in share_data:
                share_file = f"share_{idx}.txt"
                with open(share_file, 'w') as f:
                    json.dump({
                        'share_index': idx,
                        'share_key': base64.b64encode(share).decode(),
                        'label': label,
                        'share_integrity_hash': hashlib.sha256(share).hexdigest(),
                        'threshold': threshold,
                        'total_shares': shares,
                        'tool_integrity': tool_integrity,
                        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                        'share_set_id': share_set_id  # Add the share set ID to identify related shares
                    }, f, indent=2)
                share_files.append(share_file)
            
            if verbose:
                click.echo(f"Generated shares: {shares}")
        
        # File encryption
        output_file = f"{input_file}.enc"
        encryptor = FileEncryptor(key)
        
        # Add share_set_id to metadata before encryption
        metadata = {
            'version': VERSION,
            'timestamp': int(time.time()),
            'share_set_id': share_set_id if share_set_id else None
        }
        
        # Calculate data hash
        with open(input_file, 'rb') as f:
            data = f.read()
        data_hash = hashlib.sha256(data).hexdigest()
        
        # Encrypt the file with metadata
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            # Write metadata
            encryptor._write_metadata(f_out, data_hash, metadata)
            
            # Read the input file
            data = f_in.read()
            
            # Encrypt the data
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            # Write encryption data
            f_out.write(cipher.nonce)
            f_out.write(tag)
            f_out.write(ciphertext)
        
        if verbose:
            click.echo(f"Encrypted file: {output_file}")
        
        # Create archives for each share
        if not existing_shares:
            for idx, share_file in enumerate(share_files, 1):
                archive_path = archiver.create_share_archive(share_file, output_file, idx, label)
                if verbose:
                    click.echo(f"Created archive: {Path(archive_path).absolute()}")
                
                # Remove temporary share file
                os.remove(share_file)
        
        # Secure cleanup
        SecureMemory.secure_clear(key)
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.option('--shares-dir', '-s', required=True, type=click.Path(exists=True), help='Path to directory containing shares or ZIP archives')
def verify(shares_dir: str):
    """Verifies share integrity."""
    try:
        shares_path = Path(shares_dir)
        
        # Check if it's an archive directory
        if shares_path.is_dir():
            # First look for ZIP archives
            share_files = list(shares_path.glob("*.zip"))
            
            # Then look for all potential share files by examining content
            content_share_files = []
            for file_path in shares_path.glob("*.*"):
                if file_path.is_file() and not file_path.suffix == '.zip':  # Skip ZIP files which we already handled
                    try:
                        with open(file_path, 'r') as f:
                            share_info = json.load(f)
                            # Check if this is a valid share file by looking for essential fields
                            if all(key in share_info for key in ['share_index', 'share', 'label']):
                                content_share_files.append(file_path)
                    except (json.JSONDecodeError, UnicodeDecodeError, IOError):
                        # Not a valid JSON file, skip it
                        continue
                        
            # Add the content-detected share files
            if content_share_files:
                share_files.extend(content_share_files)
                
            if not share_files:
                # Try to find any file that might be a share
                all_files = list(shares_path.glob("*"))
                share_files = [f for f in all_files if f.is_file()]
                if not share_files:
                    raise ValueError(f"No files found in directory {shares_dir}")
                else:
                    click.echo(f"Found {len(share_files)} files in directory, but none match the expected share format")
                    click.echo("Please ensure you're pointing to a directory containing valid share files or archives")
                    return
        else:
            # It's a single file (archive or share)
            share_files = [shares_path]
        
        # Process each file
        for share_file in share_files:
            if str(share_file).endswith('.zip'):
                # Extract archive to temporary directory
                temp_dir = Path(f"temp_share_{share_file.stem}")
                temp_dir.mkdir(exist_ok=True)
                
                try:
                    with zipfile.ZipFile(share_file, 'r') as zipf:
                        zipf.extractall(temp_dir)
                    
                    # Look for share file
                    share_files_in_zip = list(temp_dir.glob("share_*.txt"))
                    if not share_files_in_zip:
                        click.echo(f"No share file found in archive {share_file}", err=True)
                        continue
                    
                    share_file = share_files_in_zip[0]
                except Exception as e:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    click.echo(f"Error extracting archive {share_file}: {str(e)}", err=True)
                    continue
            
            try:
                with open(share_file, 'r') as f:
                    share_info = json.load(f)
                    share_data = base64.b64decode(share_info.get('share_key', share_info.get('share')))
                    computed_hash = hashlib.sha256(share_data).hexdigest()
                    
                    if computed_hash != share_info['share_integrity_hash']:
                        click.echo(f"Verification error for {share_file}", err=True)
                    else:
                        click.echo(f"Share {share_file} successfully verified")
            except json.JSONDecodeError:
                click.echo(f"Invalid JSON format in {share_file}", err=True)
            except KeyError as e:
                click.echo(f"Missing required field in {share_file}: {str(e)}", err=True)
            except Exception as e:
                click.echo(f"Error processing {share_file}: {str(e)}", err=True)
            
            # Clean up temporary directory if it was an archive
            if str(share_file).endswith('.zip'):
                shutil.rmtree(temp_dir, ignore_errors=True)
                    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli() 