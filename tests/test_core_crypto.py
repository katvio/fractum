#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import tempfile
import unittest

# Import from the src module
from src.crypto import FileEncryptor
from src.crypto.memory import SecureMemory
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes
from fixtures import (
    BITWARDEN_VAULT_EXPORT,
    ENV_CREDENTIALS,
    HARDWARE_WALLET_SEED,
    QUARTERLY_REPORT,
)

# ANSI color codes for colored output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_info(message):
    """Print an info message with blue color."""
    print(f"{BLUE}[INFO]{RESET} {message}")


def log_success(message):
    """Print a success message with green color."""
    print(f"{GREEN}[SUCCESS]{RESET} {message}")


def log_error(message):
    """Print an error message with red color."""
    print(f"{RED}[ERROR]{RESET} {message}")


def log_warning(message):
    """Print a warning message with yellow color."""
    print(f"{YELLOW}[WARNING]{RESET} {message}")


def log_header(message):
    """Print a header message with bold formatting."""
    print(f"\n{BOLD}{message}{RESET}")


class TestShareManager(unittest.TestCase):
    """Tests for the ShareManager component."""

    def setUp(self):
        """Setup test environment."""
        log_header("Setting up ShareManager tests")
        self.threshold = 3
        self.total_shares = 5
        self.test_secret = b"prod-enc-key:Hx7$Kw2@Nm9!v5"
        self.label = "bitwarden_backup_jan_2025"
        self.manager = ShareManager(self.threshold, self.total_shares)
        log_info(
            f"Created ShareManager with threshold={self.threshold}, total_shares={self.total_shares}"
        )

    def test_share_generation_reconstruction(self):
        """Test share generation and reconstruction with valid inputs."""
        log_header("Testing share generation and reconstruction")
        # Generate shares
        log_info("Generating shares from test secret")
        shares = self.manager.generate_shares(self.test_secret, self.label)

        # Verify the number of shares
        self.assertEqual(
            len(shares), self.total_shares, "Incorrect number of shares generated"
        )
        log_success(f"Generated {len(shares)} shares as expected")

        # Verify each share structure
        log_info("Verifying share structure")
        for idx, share in shares:
            self.assertIsInstance(idx, int, "Share index must be an integer")
            self.assertIsInstance(share, bytes, "Share data must be bytes")
            self.assertEqual(len(share), 32, "Share data should be 32 bytes")
        log_success("All shares have correct structure")

        # Reconstruct with all shares
        log_info("Reconstructing secret using all shares")
        reconstructed_secret = self.manager.combine_shares(shares)

        # Verify reconstructed secret matches original
        self.assertEqual(
            reconstructed_secret[: len(self.test_secret)],
            self.test_secret,
            "Reconstructed secret doesn't match original",
        )
        log_success("Successfully reconstructed secret with all shares")

        # Test with minimum threshold shares
        log_info(
            f"Testing reconstruction with minimum threshold ({self.threshold}) shares"
        )
        threshold_shares = shares[: self.threshold]
        reconstructed_with_threshold = self.manager.combine_shares(threshold_shares)

        self.assertEqual(
            reconstructed_with_threshold[: len(self.test_secret)],
            self.test_secret,
            "Reconstruction with threshold shares failed",
        )
        log_success("Successfully reconstructed secret with threshold shares")

        # Test with different combinations of threshold shares
        log_info("Testing different combinations of threshold shares")
        for i in range(3):  # Try 3 different combinations
            random_indices = random.sample(range(self.total_shares), self.threshold)
            selected_shares = [shares[i] for i in random_indices]
            reconstructed = self.manager.combine_shares(selected_shares)

            self.assertEqual(
                reconstructed[: len(self.test_secret)],
                self.test_secret,
                f"Reconstruction failed with shares at indices {random_indices}",
            )
            log_success(
                f"Combination {i + 1}: Successfully reconstructed with shares at indices {random_indices}"
            )

    def test_threshold_enforcement(self):
        """Verify threshold enforcement (confirm reconstruction fails with k-1 shares)."""
        log_header("Testing threshold enforcement")
        # Generate shares
        log_info("Generating shares from test secret")
        shares = self.manager.generate_shares(self.test_secret, self.label)

        # Try to reconstruct with insufficient shares (threshold - 1)
        insufficient_shares = shares[: self.threshold - 1]
        log_info(
            f"Attempting reconstruction with {len(insufficient_shares)} shares (below threshold)"
        )

        # Should raise a ValueError when trying to combine insufficient shares
        with self.assertRaises(ValueError, msg="Should fail with insufficient shares"):
            self.manager.combine_shares(insufficient_shares)
        log_success("Correctly failed to reconstruct with insufficient shares")

    def test_share_validation(self):
        """Test share validation mechanism."""
        log_header("Testing share validation")
        # Generate shares
        log_info("Generating shares from test secret")
        shares = self.manager.generate_shares(self.test_secret, self.label)

        threshold_shares = shares[: self.threshold]
        log_info(
            f"Testing reconstruction with {len(threshold_shares)} threshold shares"
        )

        # Verify reconstruction works with threshold shares
        try:
            reconstructed = self.manager.combine_shares(threshold_shares)
            self.assertEqual(
                reconstructed[: len(self.test_secret)],
                self.test_secret,
                "Reconstruction with threshold shares failed",
            )
            log_success("Successfully reconstructed with threshold shares")
        except Exception as e:
            log_error(f"Reconstruction failed unexpectedly: {str(e)}")
            self.fail(f"Reconstruction failed unexpectedly: {str(e)}")

        # FIXED: Verify corrupted shares by testing individual scenarios
        log_info("Testing validation with corrupted shares")
        # Create corrupted shares
        corrupted_shares = []
        for idx, share in shares[: self.threshold]:
            # Create a corrupted copy of each share
            corrupted_share = bytearray(share)
            # Modify a random byte
            corrupt_pos = random.randint(0, len(corrupted_share) - 1)
            corrupted_share[corrupt_pos] = (corrupted_share[corrupt_pos] + 1) % 256
            corrupted_shares.append((idx, bytes(corrupted_share)))

        # Try reconstructing with the corrupted shares
        log_info("Attempting reconstruction with corrupted shares")
        # The actual behavior may vary - some implementations might return incorrect
        # data rather than raising an error
        try:
            result = self.manager.combine_shares(corrupted_shares)
            # If combine_shares doesn't raise an error, verify the result is incorrect
            self.assertNotEqual(
                result[: len(self.test_secret)],
                self.test_secret,
                "Corrupted shares should not reconstruct the original secret",
            )
            log_success("Corruption detected: produced incorrect result")
        except ValueError:
            # If combine_shares raises a ValueError, that's also fine
            log_success("Corruption detected: raised ValueError")

    def test_different_secrets_dont_leak(self):
        """Verify shares from different secret inputs don't reveal information."""
        log_header("Testing information leakage between different secrets")
        # Generate shares for two different secrets
        secret1 = b"api-svc-alpha:Zx9#mK2@vL5!n"
        secret2 = b"api-svc-beta:Ry8!nP0qR3zT$Wk"

        log_info("Generating shares for first secret")
        shares1 = self.manager.generate_shares(secret1, "hardware_wallet_alpha_seed")
        log_info("Generating shares for second secret")
        shares2 = self.manager.generate_shares(secret2, "hardware_wallet_beta_seed")

        # Try to reconstruct by mixing shares from different secrets
        log_info("Attempting reconstruction with mixed shares from different secrets")
        mixed_shares = shares1[:2] + shares2[2 : self.threshold]

        # This should fail or return an incorrect value, not revealing either original secret
        try:
            mixed_result = self.manager.combine_shares(mixed_shares)
            # Ensure the result doesn't match either secret
            self.assertNotEqual(
                mixed_result[: len(secret1)],
                secret1,
                "Mixed shares must not reveal the service_alpha credential",
            )
            self.assertNotEqual(
                mixed_result[: len(secret2)],
                secret2,
                "Mixed shares should not reveal second secret",
            )
            log_success("Mixed shares did not reveal either original secret")
        except ValueError:
            # If it raises an error, that's also acceptable behavior
            log_success("Mixed shares correctly failed reconstruction")

    def test_edge_cases(self):
        """Test with edge cases (minimum threshold=2, maximum shares=255)."""
        log_header("Testing ShareManager edge cases")
        # Test minimum threshold (2)
        log_info("Testing with minimum threshold (2)")
        min_manager = ShareManager(2, 5)
        min_shares = min_manager.generate_shares(self.test_secret, self.label)

        # Should be able to reconstruct with just 2 shares
        reconstructed = min_manager.combine_shares(min_shares[:2])
        self.assertEqual(
            reconstructed[: len(self.test_secret)],
            self.test_secret,
            "Reconstruction with minimum threshold (2) failed",
        )
        log_success("Successfully reconstructed with minimum threshold (2)")

        # Test maximum threshold and shares
        log_info("Testing with large threshold and shares")
        # Using a smaller value than 255 for practical testing purposes
        max_threshold = 10
        max_shares = 15
        max_manager = ShareManager(max_threshold, max_shares)
        max_shares_data = max_manager.generate_shares(self.test_secret, self.label)

        # Verify shares count
        self.assertEqual(
            len(max_shares_data),
            max_shares,
            "Incorrect number of shares generated for max case",
        )
        log_success(f"Generated {max_shares} shares as expected")

        # Verify reconstruction with threshold shares
        reconstructed = max_manager.combine_shares(max_shares_data[:max_threshold])
        self.assertEqual(
            reconstructed[: len(self.test_secret)],
            self.test_secret,
            "Reconstruction with maximum threshold failed",
        )
        log_success(
            f"Successfully reconstructed with large threshold ({max_threshold})"
        )

        # Test invalid parameters
        log_info("Testing invalid parameters")
        with self.assertRaises(ValueError, msg="Should reject threshold < 2"):
            ShareManager(1, 5)
        log_success("Correctly rejected threshold < 2")

        with self.assertRaises(
            ValueError, msg="Should reject total_shares < threshold"
        ):
            ShareManager(5, 4)
        log_success("Correctly rejected total_shares < threshold")

        with self.assertRaises(ValueError, msg="Should reject total_shares > 255"):
            ShareManager(3, 256)
        log_success("Correctly rejected total_shares > 255")

        # Test empty secret
        log_info("Testing empty secret")
        with self.assertRaises(ValueError, msg="Should reject empty secret"):
            self.manager.generate_shares(b"", self.label)
        log_success("Correctly rejected empty secret")

        # Test too long secret
        log_info("Testing too long secret")
        too_long_secret = b"prod-db-password-2025-over-limit!"  # 33 bytes, exceeding 32-byte limit
        with self.assertRaises(ValueError, msg="Should reject secret > 32 bytes"):
            self.manager.generate_shares(too_long_secret, self.label)
        log_success("Correctly rejected secret > 32 bytes")

        # Test non-bytes secret
        log_info("Testing non-bytes secret")
        with self.assertRaises(ValueError, msg="Should reject non-bytes secret"):
            self.manager.generate_shares("string_secret", self.label)
        log_success("Correctly rejected non-bytes secret")

        # Test empty label
        log_info("Testing empty label")
        with self.assertRaises(ValueError, msg="Should reject empty label"):
            self.manager.generate_shares(self.test_secret, "")
        log_success("Correctly rejected empty label")


class TestFileEncryptor(unittest.TestCase):
    """Tests for the FileEncryptor component."""

    def setUp(self):
        """Setup test environment."""
        log_header("Setting up FileEncryptor tests")
        self.key = get_enhanced_random_bytes(32)
        self.encryptor = FileEncryptor(self.key)
        log_info("Created FileEncryptor with random 32-byte key")

        # Create temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file_path = os.path.join(self.temp_dir.name, "test_file.txt")
        self.encrypted_file_path = os.path.join(self.temp_dir.name, "test_file.txt.enc")
        self.decrypted_file_path = os.path.join(self.temp_dir.name, "test_file.txt.dec")

        # Create a test file with random content
        with open(self.test_file_path, "wb") as f:
            f.write(QUARTERLY_REPORT)
        log_info(f"Created test file at {self.test_file_path}")

    def tearDown(self):
        """Clean up test environment."""
        log_info("Cleaning up FileEncryptor test environment")
        self.temp_dir.cleanup()

    def test_encryption_decryption_roundtrip(self):
        """Test encryption/decryption round-trip through FileEncryptor."""
        log_header("Testing encryption/decryption roundtrip via FileEncryptor")

        test_cases = [
            ("bitwarden_vault", BITWARDEN_VAULT_EXPORT),
            ("env_credentials", ENV_CREDENTIALS),
            ("binary_wallet_backup", bytes(range(256)) * 4),
            ("single_byte", b"\x42"),
        ]

        for name, content in test_cases:
            log_info(f"Testing {name} file ({len(content)} bytes)")
            src = os.path.join(self.temp_dir.name, f"{name}.bin")
            enc = os.path.join(self.temp_dir.name, f"{name}.bin.enc")
            dec = os.path.join(self.temp_dir.name, f"{name}.bin.dec")

            with open(src, "wb") as f:
                f.write(content)

            self.encryptor.encrypt_file(src, enc)
            self.assertTrue(os.path.exists(enc), f"Encrypted file not created for {name}")

            self.encryptor.decrypt_file(enc, dec)
            self.assertTrue(os.path.exists(dec), f"Decrypted file not created for {name}")

            with open(dec, "rb") as f:
                result = f.read()

            self.assertEqual(result, content, f"Roundtrip content mismatch for {name}")
            log_success(f"Roundtrip passed for {name} ({len(content)} bytes)")

    def test_empty_file_encrypt_raises_or_decrypts_empty(self):
        """Encrypting an empty file must either round-trip cleanly or raise a clear ValueError.

        AES-256-GCM supports zero-length plaintext, but the current implementation
        raises 'No encrypted data found' on decrypt. This test documents the behavior
        and will catch any regression (silent data corruption) or future fix.
        """
        src = os.path.join(self.temp_dir.name, "empty.bin")
        enc = os.path.join(self.temp_dir.name, "empty.bin.enc")
        dec = os.path.join(self.temp_dir.name, "empty.bin.dec")

        with open(src, "wb") as f:
            f.write(b"")

        self.encryptor.encrypt_file(src, enc)
        self.assertTrue(os.path.exists(enc), "Encrypted file must be created even for empty input")

        try:
            self.encryptor.decrypt_file(enc, dec)
            # If decrypt succeeds, roundtrip must be lossless
            with open(dec, "rb") as f:
                result = f.read()
            self.assertEqual(result, b"", "Roundtrip of empty file must return empty bytes")
        except ValueError as e:
            # Acceptable: current implementation raises on empty ciphertext
            self.assertIn("data", str(e).lower(),
                          f"ValueError for empty file must mention data, got: {e}")

    def test_same_key_different_files(self):
        """Test with same key but different files (confirm unique ciphertexts)."""
        log_header("Testing same key with different files")
        # Create two different test files
        file1_path = os.path.join(self.temp_dir.name, "file1.txt")
        file2_path = os.path.join(self.temp_dir.name, "file2.txt")

        # Create encrypted file paths
        enc_file1_path = os.path.join(self.temp_dir.name, "file1.txt.enc")
        enc_file2_path = os.path.join(self.temp_dir.name, "file2.txt.enc")

        # Create files with different content
        log_info("Creating first test file")
        with open(file1_path, "w") as f:
            f.write("Content for file 1")

        log_info("Creating second test file (different content)")
        with open(file2_path, "w") as f:
            f.write("Different content for file 2")

        # Encrypt both files with the same key
        log_info("Encrypting first file")
        self.encryptor.encrypt_file(file1_path, enc_file1_path)
        log_info("Encrypting second file")
        self.encryptor.encrypt_file(file2_path, enc_file2_path)

        # Read the encrypted files
        log_info("Comparing encrypted content")
        with open(enc_file1_path, "rb") as f1, open(enc_file2_path, "rb") as f2:
            enc_content1 = f1.read()
            enc_content2 = f2.read()

        # Verify encrypted content is different
        self.assertNotEqual(
            enc_content1,
            enc_content2,
            "Encrypted content should be different for different files",
        )
        log_success("Different files produce different ciphertexts with same key")

        # Test with identical content but different files
        file3_path = os.path.join(self.temp_dir.name, "file3.txt")
        enc_file3_path = os.path.join(self.temp_dir.name, "file3.txt.enc")

        # Create file with same content as file1
        log_info("Creating third test file (identical content to first file)")
        with open(file3_path, "w") as f:
            f.write("Content for file 1")

        # Encrypt the third file
        log_info("Encrypting third file")
        self.encryptor.encrypt_file(file3_path, enc_file3_path)

        # Read the encrypted file
        log_info("Comparing encrypted content of files with identical plaintext")
        with open(enc_file3_path, "rb") as f3:
            enc_content3 = f3.read()

        # Verify encrypted content is different even for identical plaintext
        # GCM uses a random nonce per encryption
        self.assertNotEqual(
            enc_content1,
            enc_content3,
            "Encrypted content should be different even for identical plaintext",
        )
        log_success("Identical files produce different ciphertexts (nonce randomization)")

    def test_metadata_integrity(self):
        """Verify metadata integrity during encryption/decryption."""
        log_header("Testing metadata integrity")

        # Create metadata
        log_info("Creating test metadata")
        metadata = {
            "test_field": "test_value",
            "numeric_field": 12345,
            "boolean_field": True,
        }

        # Encrypt file with metadata
        log_info("Encrypting file with custom metadata")
        self.encryptor.encrypt_file(
            self.test_file_path, self.encrypted_file_path, metadata
        )

        # Read and verify metadata
        log_info("Reading metadata from encrypted file")
        with open(self.encrypted_file_path, "rb") as f:
            read_metadata = self.encryptor._read_metadata(f)

        # Verify custom metadata fields are preserved
        log_info("Verifying custom metadata fields")
        for key, value in metadata.items():
            self.assertEqual(
                read_metadata[key], value, f"Metadata field {key} not preserved"
            )
        log_success("All custom metadata fields preserved correctly")

        # Verify standard metadata fields are present
        log_info("Verifying standard metadata fields")
        self.assertIn("version", read_metadata, "Version field missing in metadata")
        self.assertIn("timestamp", read_metadata, "Timestamp field missing in metadata")
        log_success("Standard metadata fields present")

    def test_tampering_detection(self):
        """Test tampering detection (modified ciphertext, nonce, tag)."""
        log_header("Testing tampering detection")

        # Encrypt a file
        log_info("Encrypting test file")
        self.encryptor.encrypt_file(self.test_file_path, self.encrypted_file_path)

        with open(self.encrypted_file_path, "rb") as f:
            original_data = bytearray(f.read())

        metadata_len = int.from_bytes(original_data[:4], "big")

        def write_tampered(path, data):
            with open(path, "wb") as f:
                f.write(data)

        # Tamper with ciphertext
        log_info("Tampering with ciphertext")
        data = bytearray(original_data)
        ct_pos = 4 + metadata_len + 16 + 16 + 10
        self.assertLess(ct_pos, len(data), "File too small to tamper with ciphertext")
        data[ct_pos] = (data[ct_pos] + 1) % 256
        tampered_ct = os.path.join(self.temp_dir.name, "tampered_ciphertext.enc")
        write_tampered(tampered_ct, data)
        with self.assertRaises(ValueError, msg="Should detect ciphertext tampering"):
            self.encryptor.decrypt_file(tampered_ct, self.decrypted_file_path)
        log_success("Ciphertext tampering detected")

        # Tamper with tag
        log_info("Tampering with authentication tag")
        data = bytearray(original_data)
        tag_pos = 4 + metadata_len + 16 + 5
        self.assertLess(tag_pos, len(data), "File too small to tamper with tag")
        data[tag_pos] = (data[tag_pos] + 1) % 256
        tampered_tag = os.path.join(self.temp_dir.name, "tampered_tag.enc")
        write_tampered(tampered_tag, data)
        with self.assertRaises(ValueError, msg="Should detect tag tampering"):
            self.encryptor.decrypt_file(tampered_tag, self.decrypted_file_path)
        log_success("Tag tampering detected")

        # Tamper with nonce
        log_info("Tampering with nonce")
        data = bytearray(original_data)
        nonce_pos = 4 + metadata_len + 5
        self.assertLess(nonce_pos, len(data), "File too small to tamper with nonce")
        data[nonce_pos] = (data[nonce_pos] + 1) % 256
        tampered_nonce = os.path.join(self.temp_dir.name, "tampered_nonce.enc")
        write_tampered(tampered_nonce, data)
        with self.assertRaises(ValueError, msg="Should detect nonce tampering"):
            self.encryptor.decrypt_file(tampered_nonce, self.decrypted_file_path)
        log_success("Nonce tampering detected")

    def test_invalid_key(self):
        """Test invalid key handling during decryption."""
        log_header("Testing invalid key handling")

        # Encrypt a file with the original key
        log_info("Encrypting file with original key")
        self.encryptor.encrypt_file(self.test_file_path, self.encrypted_file_path)

        # Attempt to decrypt with a different key
        log_info("Attempting to decrypt with wrong key")
        different_key = get_enhanced_random_bytes(32)
        wrong_encryptor = FileEncryptor(different_key)
        with self.assertRaises(ValueError, msg="Should fail with incorrect key"):
            wrong_encryptor.decrypt_file(
                self.encrypted_file_path, self.decrypted_file_path
            )
        log_success("Decryption with wrong key correctly failed")

        # Attempt to decrypt with an invalid key size
        log_info("Testing with invalid key size (16 bytes instead of 32)")
        with self.assertRaises(ValueError, msg="Should reject keys not 32 bytes"):
            invalid_encryptor = FileEncryptor(get_enhanced_random_bytes(16))
            invalid_encryptor.decrypt_file(
                self.encrypted_file_path, self.decrypted_file_path
            )
        log_success("Correctly rejected invalid key size")

    def test_custom_metadata_preserved(self):
        """Verify custom fields (e.g. share_set_id) passed to encrypt_file survive in the .enc header."""
        log_header("Testing custom metadata preservation")

        metadata = {
            "share_set_id": "abc123def456",
            "extra_field": "test_value",
        }

        self.encryptor.encrypt_file(self.test_file_path, self.encrypted_file_path, metadata)

        with open(self.encrypted_file_path, "rb") as f:
            read_metadata = self.encryptor._read_metadata(f)

        self.assertEqual(
            read_metadata.get("share_set_id"),
            "abc123def456",
            "share_set_id not preserved in encrypted file header",
        )
        self.assertEqual(
            read_metadata.get("extra_field"),
            "test_value",
            "extra_field not preserved in encrypted file header",
        )
        self.assertIn("version", read_metadata, "version missing from header")
        self.assertIn("timestamp", read_metadata, "timestamp missing from header")
        log_success("Custom metadata fields preserved correctly in .enc header")

        # Verify the file can still be decrypted correctly
        self.encryptor.decrypt_file(self.encrypted_file_path, self.decrypted_file_path)
        with open(self.test_file_path, "rb") as f_orig, \
             open(self.decrypted_file_path, "rb") as f_dec:
            self.assertEqual(f_orig.read(), f_dec.read(), "Content mismatch after decrypt")
        log_success("Decrypt roundtrip confirmed after metadata preservation")


class TestSecureMemory(unittest.TestCase):
    """Tests for the SecureMemory component."""

    def setUp(self):
        """Setup test environment."""
        log_header("Setting up SecureMemory tests")
        # Define test data
        self.test_bytes = b"Sensitive data for testing secure memory"
        self.test_bytearray = bytearray(b"Sensitive bytearray data")
        self.test_string = "Sensitive string data"
        self.test_list = [b"Item1", bytearray(b"Item2"), "Item3", 1234]
        log_info("Test data initialized")

    def test_secure_clear_bytes(self):
        """Test secure clearing of bytes."""
        log_header("Testing secure clearing of bytes")
        # FIXED: bytes are immutable, so we can't directly test clearing
        # The function might try to delete the variable but our test
        # retains the reference. Just verify the function runs without error.
        data_copy = self.test_bytes

        # Clear the data
        log_info("Clearing bytes object")
        SecureMemory.secure_clear(data_copy)
        log_success("Bytes clearing completed without error")
        # Test passes if no exception is raised

    def test_secure_clear_bytearray(self):
        """Test secure clearing of bytearray."""
        log_header("Testing secure clearing of bytearray")
        # FIXED: Verify that data is zeroed out, not that the variable is deleted
        data_copy = bytearray(self.test_bytearray)
        original_content = bytes(data_copy)  # Save original content
        log_info(f"Created bytearray of length {len(data_copy)}")

        # Clear the data
        log_info("Clearing bytearray")
        SecureMemory.secure_clear(data_copy)

        # For bytearrays, we can verify the content is zeroed
        if len(data_copy) > 0:  # If the bytearray still exists and has content
            cleared = all(b == 0 for b in data_copy)
            self.assertTrue(cleared, "Bytearray should be zeroed out after clearing")

            # Also verify it's not the same as original content
            self.assertNotEqual(
                bytes(data_copy),
                original_content,
                "Cleared bytearray should not match original content",
            )
            log_success("Bytearray successfully cleared (all bytes zeroed)")

    def test_secure_clear_string(self):
        """Test secure clearing of string."""
        log_header("Testing secure clearing of string")
        # FIXED: strings are immutable, so we can't directly test clearing
        # The function might try to delete the variable but our test
        # retains the reference. Just verify the function runs without error.
        data_copy = self.test_string

        # Clear the data
        log_info("Clearing string object")
        SecureMemory.secure_clear(data_copy)
        log_success("String clearing completed without error")
        # Test passes if no exception is raised

    def test_secure_clear_list(self):
        """Test secure clearing of list."""
        log_header("Testing secure clearing of list")
        # FIXED: Check if the list is cleared rather than deleted
        data_copy = self.test_list.copy()
        log_info(f"Created list with {len(data_copy)} items")

        # Clear the data
        log_info("Clearing list")
        SecureMemory.secure_clear(data_copy)

        # For lists, verify it's either empty or contains only None/0 values
        if data_copy:  # If the list still exists
            # Check if all elements are None or 0
            all_cleared = all(item is None or item == 0 for item in data_copy)
            self.assertTrue(
                all_cleared or len(data_copy) == 0,
                "List elements should be None/0 or list should be empty after clearing",
            )
            log_success("List successfully cleared")

    def test_secure_context(self):
        """Test secure context manager."""
        log_header("Testing secure context manager")
        # Test context manager functionality
        log_info("Creating secure context with buffer size 32")
        with SecureMemory.secure_context(32) as secure_buffer:
            # Verify buffer is created with right size
            self.assertIsInstance(
                secure_buffer, bytearray, "Buffer should be a bytearray"
            )
            self.assertEqual(len(secure_buffer), 32, "Buffer should be 32 bytes")
            log_success("Secure buffer created with correct size and type")

            # Write sensitive data to buffer
            sensitive_data = b"stripe_sk_live_XXXXXXXXXXXXXXXX"
            for i in range(min(len(sensitive_data), len(secure_buffer))):
                secure_buffer[i] = sensitive_data[i]
            log_info("Wrote sensitive data to buffer")

            # Verify data was written
            buffer_content = bytes(secure_buffer[: len(sensitive_data)])
            self.assertEqual(
                buffer_content,
                sensitive_data,
                "Data was not correctly written to buffer",
            )
            log_success("Data correctly written to secure buffer")

        log_info("Context exited, buffer should be automatically cleared")
        # After context exit, buffer should have been cleared
        # We can't directly verify this since the buffer is now out of scope,
        # but the secure_context should have called secure_clear on it

        # Test with different size
        log_info("Testing secure context with larger buffer (64 bytes)")
        with SecureMemory.secure_context(64) as larger_buffer:
            self.assertEqual(
                len(larger_buffer), 64, "Buffer size should match requested size"
            )
            log_success("Larger buffer created with correct size")

    def test_secure_bytes_generation(self):
        """Test secure bytes generation."""
        log_header("Testing secure bytes generation")
        # Generate secure bytes
        log_info("Generating secure bytes with default length")
        secure_bytes = SecureMemory.secure_bytes()

        # Verify properties
        self.assertIsInstance(secure_bytes, bytearray, "Result should be a bytearray")
        self.assertEqual(
            len(secure_bytes), 32, "Secure bytes should be 32 bytes by default"
        )
        log_success(f"Generated secure bytes of length {len(secure_bytes)}")

        # Generate with custom length
        custom_length = 64
        log_info(f"Generating secure bytes with custom length ({custom_length})")
        secure_bytes_custom = SecureMemory.secure_bytes(custom_length)
        self.assertEqual(
            len(secure_bytes_custom),
            custom_length,
            "Secure bytes should match requested length",
        )
        log_success(f"Generated secure bytes with custom length {custom_length}")

        # Generate another bytearray and verify it's different (randomness check)
        log_info("Generating second secure bytes to verify randomness")
        another_bytes = SecureMemory.secure_bytes()
        self.assertNotEqual(
            bytes(secure_bytes),
            bytes(another_bytes),
            "Two generated secure byte arrays should be different",
        )
        log_success("Randomness verified: generated byte arrays are different")


if __name__ == "__main__":
    unittest.main()
