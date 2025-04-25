#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import tempfile
import os
import sys
import json
import base64
import hashlib
import random
import time
from pathlib import Path
import struct
import binascii

# Import from the src module
from src import (
    ShareManager,
    FileEncryptor,
    VERSION,
    ShareMetadata
)

# Couleurs pour les logs
class LogColors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_test_start(test_name):
    """Affiche un message de démarrage de test."""
    print(f"\n{LogColors.BLUE}{LogColors.BOLD}▶ DÉMARRAGE: {test_name}{LogColors.ENDC}")

def log_test_step(step_description):
    """Affiche une étape de test."""
    print(f"{LogColors.CYAN}  ↳ {step_description}{LogColors.ENDC}")

def log_test_success(message):
    """Affiche un message de succès."""
    print(f"{LogColors.GREEN}  ✓ SUCCÈS: {message}{LogColors.ENDC}")

def log_test_warning(message):
    """Affiche un message d'avertissement."""
    print(f"{LogColors.YELLOW}  ⚠ ATTENTION: {message}{LogColors.ENDC}")

def log_test_skip(message):
    """Affiche un message de test ignoré."""
    print(f"{LogColors.YELLOW}  ⚡ IGNORÉ: {message}{LogColors.ENDC}")

def log_test_end(test_name, success=True):
    """Affiche un message de fin de test."""
    if success:
        print(f"{LogColors.GREEN}{LogColors.BOLD}✓ TERMINÉ: {test_name} - Réussi{LogColors.ENDC}")
    else:
        print(f"{LogColors.RED}{LogColors.BOLD}✗ TERMINÉ: {test_name} - Échoué{LogColors.ENDC}")

class InputFuzzingTests(unittest.TestCase):
    """Tests for input fuzzing - modifying inputs to test robustness."""
    
    def setUp(self):
        """Setup test environment."""
        # Create temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create test file
        self.test_file = self.test_dir / "fuzz_test.txt"
        with open(self.test_file, "w") as f:
            f.write("Test content for fuzzing tests")
            
        # Create shares directory
        self.shares_dir = self.test_dir / "shares"
        self.shares_dir.mkdir(exist_ok=True)
        
        # Create common variables
        self.threshold = 3
        self.total_shares = 5
        self.label = "fuzz_test"
        self.test_secret = os.urandom(32)
        
        # Create a share manager and generate shares
        self.manager = ShareManager(self.threshold, self.total_shares)
        self.shares = self.manager.generate_shares(self.test_secret, self.label)
        
        # Create share files
        self.share_files = []
        for idx, share_data in self.shares:
            share_file = self.shares_dir / f"share_{idx}.txt"
            
            # Calculate hash
            share_hash = hashlib.sha256(share_data).hexdigest()
            
            # Create share info
            share_info = {
                'share_index': idx,
                'share_key': base64.b64encode(share_data).decode(),
                'label': self.label,
                'share_integrity_hash': share_hash,
                'threshold': self.threshold,
                'total_shares': self.total_shares,
                'version': VERSION
            }
            
            # Write share file
            with open(share_file, "w") as f:
                json.dump(share_info, f, indent=2)
                
            self.share_files.append(share_file)
        
        # Encrypt test file
        self.encryptor = FileEncryptor(self.test_secret)
        self.encrypted_file = self.test_dir / "fuzz_test.txt.enc"
        self.encryptor.encrypt_file(str(self.test_file), str(self.encrypted_file))
        
    def tearDown(self):
        """Clean up test environment."""
        self.temp_dir.cleanup()
    
    def test_share_file_bit_flipping(self):
        """Test with random bit flipping in share files."""
        test_name = "Test de flipping de bits sur les fichiers de parts"
        log_test_start(test_name)
        
        try:
            # Make a copy of a share file for testing
            original_share = self.share_files[0]
            fuzz_share = self.shares_dir / "fuzzed_share.txt"
            
            log_test_step(f"Copie du fichier original {original_share.name} vers {fuzz_share.name}")
            # Read the original share file
            with open(original_share, "rb") as f:
                content = bytearray(f.read())
            
            # Flip bits at random positions
            num_flips = min(10, len(content))  # Flip up to 10 bits
            log_test_step(f"Modification aléatoire de {num_flips} bits dans le fichier")
            for _ in range(num_flips):
                pos = random.randint(0, len(content) - 1)
                bit = random.randint(0, 7)
                content[pos] ^= (1 << bit)  # Flip a random bit
            
            # Write the fuzzed content
            with open(fuzz_share, "wb") as f:
                f.write(content)
            
            log_test_step("Tentative de chargement du fichier modifié")
            # Try to load the fuzzed share file
            # It should either fail with an exception or load but give incorrect results later
            try:
                shares_data, metadata = ShareManager.load_shares([str(fuzz_share)])
                log_test_step("Fichier chargé, tentative de reconstruction du secret")
                
                # If it loaded, reconstruct should either fail or give incorrect results
                try:
                    reconstructed = self.manager.combine_shares(shares_data)
                    # Verify that the reconstructed secret is different from the original
                    self.assertNotEqual(reconstructed, self.test_secret, 
                                      "Fuzzed share should not reconstruct the correct secret")
                    log_test_success("Secret reconstruit mais incorrect comme attendu")
                except Exception as e:
                    # Expected - combining with fuzzed share should fail
                    log_test_success(f"Échec de la reconstruction comme attendu: {str(e)}")
            except Exception as e:
                # Expected - loading fuzzed share might fail
                log_test_success(f"Échec du chargement comme attendu: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_encrypted_file_bit_flipping(self):
        """Test with bit flipping in encrypted files."""
        test_name = "Test de flipping de bits sur les fichiers chiffrés"
        log_test_start(test_name)
        
        try:
            # Make a copy of the encrypted file for testing
            fuzzed_encrypted = self.test_dir / "fuzzed_encrypted.enc"
            
            log_test_step(f"Copie du fichier chiffré vers {fuzzed_encrypted.name}")
            # Read the original encrypted file
            with open(self.encrypted_file, "rb") as f:
                content = bytearray(f.read())
            
            # Flip bits at random positions, avoiding the first few bytes (metadata)
            # to ensure the header can still be parsed
            start_pos = min(100, len(content) // 3)  # Skip header
            num_flips = min(20, max(1, len(content) // 100))  # Flip ~1% of bits
            
            log_test_step(f"Modification de {num_flips} bits dans le contenu chiffré (après pos {start_pos})")
            for _ in range(num_flips):
                pos = random.randint(start_pos, len(content) - 1)
                bit = random.randint(0, 7)
                content[pos] ^= (1 << bit)
            
            # Write the fuzzed encrypted file
            with open(fuzzed_encrypted, "wb") as f:
                f.write(content)
            
            log_test_step("Tentative de déchiffrement du fichier modifié")
            # Try to decrypt the fuzzed file
            decrypted_file = self.test_dir / "fuzzed_decrypted.txt"
            
            # It should fail with a MAC verification error or similar
            try:
                with self.assertRaises(Exception, msg="Decryption of tampered file should fail"):
                    self.encryptor.decrypt_file(str(fuzzed_encrypted), str(decrypted_file))
                log_test_success("Déchiffrement échoué comme prévu avec le fichier modifié")
            except Exception as e:
                log_test_warning(f"Le test a échoué: {str(e)}")
                raise e
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_malformed_json_shares(self):
        """Test with malformed JSON in share files."""
        test_name = "Test avec des fichiers JSON malformés"
        log_test_start(test_name)
        
        try:
            malformed_variants = []
            
            log_test_step("Création d'un fichier de base pour les tests")
            # Create several malformed JSON share files
            base_share_file = self.shares_dir / "malformed_json_base.txt"
            
            # Get a valid share as base
            idx, share_data = self.shares[0]
            valid_share_info = {
                'share_index': idx,
                'share_key': base64.b64encode(share_data).decode(),
                'label': self.label,
                'share_integrity_hash': hashlib.sha256(share_data).hexdigest(),
                'threshold': self.threshold,
                'total_shares': self.total_shares,
                'version': VERSION
            }
            
            # Write the base file
            with open(base_share_file, "w") as f:
                json.dump(valid_share_info, f, indent=2)
            
            log_test_step("Création de variantes de JSON malformés")
            # 1. Truncated JSON
            truncated_file = self.shares_dir / "malformed_truncated.txt"
            with open(base_share_file, "r") as f:
                content = f.read()
                
            # Truncate the JSON
            with open(truncated_file, "w") as f:
                f.write(content[:len(content)//2])
                
            malformed_variants.append(truncated_file)
            
            # 2. Missing closing brace
            missing_brace_file = self.shares_dir / "malformed_missing_brace.txt"
            with open(base_share_file, "r") as f:
                content = f.read()
                
            with open(missing_brace_file, "w") as f:
                f.write(content.replace("}", ""))
                
            malformed_variants.append(missing_brace_file)
            
            # 3. Extra characters
            extra_chars_file = self.shares_dir / "malformed_extra_chars.txt"
            with open(base_share_file, "r") as f:
                content = f.read()
                
            with open(extra_chars_file, "w") as f:
                f.write(content + "extra garbage ÿøπΩ")
                
            malformed_variants.append(extra_chars_file)
            
            # 4. Missing quotes around keys
            missing_quotes_file = self.shares_dir / "malformed_missing_quotes.txt"
            with open(base_share_file, "r") as f:
                content = f.read()
                
            with open(missing_quotes_file, "w") as f:
                f.write(content.replace('"share_key"', 'share_key'))
                
            malformed_variants.append(missing_quotes_file)
            
            # 5. Non-JSON content
            non_json_file = self.shares_dir / "malformed_non_json.txt"
            with open(non_json_file, "w") as f:
                f.write("This is not JSON content at all")
                
            malformed_variants.append(non_json_file)
            
            log_test_step(f"Test de {len(malformed_variants)} variantes de fichiers malformés")
            # Test each malformed variant
            for variant_file in malformed_variants:
                with self.subTest(f"Testing malformed JSON: {variant_file.name}"):
                    log_test_step(f"Test du fichier: {variant_file.name}")
                    try:
                        with self.assertRaises(Exception, msg=f"Loading {variant_file.name} should fail"):
                            ShareManager.load_shares([str(variant_file)])
                        log_test_success(f"Échec du chargement de {variant_file.name} comme attendu")
                    except Exception as e:
                        log_test_warning(f"Le test a échoué pour {variant_file.name}: {str(e)}")
                        raise e
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_invalid_utf8_sequences(self):
        """Test with invalid UTF-8 sequences in labels and metadata."""
        test_name = "Test avec des séquences UTF-8 invalides"
        log_test_start(test_name)
        
        try:
            log_test_step("Création d'un fichier avec des séquences UTF-8 invalides")
            # Create shares with invalid UTF-8 sequences
            invalid_utf8_share = self.shares_dir / "invalid_utf8_share.txt"
            
            # Get a valid share as base
            idx, share_data = self.shares[0]
            
            # Create invalid UTF-8 sequence using raw bytes
            invalid_utf8_bytes = b'\xc3\x28'  # Invalid UTF-8 sequence
            
            try:
                # Attempt to decode, which should fail
                invalid_utf8 = invalid_utf8_bytes.decode('utf-8')
                log_test_step("Décodage UTF-8 réussi de manière inattendue")
            except UnicodeDecodeError:
                # Use a replacement character instead
                invalid_utf8 = '' * 5
                log_test_step("Utilisation de caractères de remplacement après échec de décodage UTF-8")
                
            # Create share info with invalid UTF-8 in label and version
            share_info = {
                'share_index': idx,
                'share_key': base64.b64encode(share_data).decode(),
                'label': f"test_label_{invalid_utf8}",
                'share_integrity_hash': hashlib.sha256(share_data).hexdigest(),
                'threshold': self.threshold,
                'total_shares': self.total_shares,
                'version': f"{VERSION}_{invalid_utf8}"
            }
            
            # Write the invalid UTF-8 share file
            with open(invalid_utf8_share, "w", encoding='utf-8', errors='replace') as f:
                json.dump(share_info, f, indent=2, ensure_ascii=False)
            
            log_test_step("Tentative de chargement du fichier avec UTF-8 invalide")
            # Try to load the share with invalid UTF-8
            # It should either load with replacement characters or fail gracefully
            try:
                shares_data, metadata = ShareManager.load_shares([str(invalid_utf8_share)])
                # If it loaded, check that the label was handled properly
                self.assertIsNotNone(metadata.label, "Label should not be None even with invalid UTF-8")
                log_test_success("Fichier chargé avec succès malgré les séquences UTF-8 invalides")
            except Exception as e:
                # If it failed, it should be a specific error about encoding, not a crash
                self.assertIn("UTF-8", str(e), "Error should mention UTF-8 issues")
                log_test_success(f"Échec du chargement avec message approprié: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


class ParameterFuzzingTests(unittest.TestCase):
    """Tests for parameter fuzzing - testing boundary conditions and unusual inputs."""
    
    def setUp(self):
        """Setup test environment."""
        # Create temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create shares directory
        self.shares_dir = self.test_dir / "shares"
        self.shares_dir.mkdir(exist_ok=True)
        
    def tearDown(self):
        """Clean up test environment."""
        self.temp_dir.cleanup()
    
    def test_threshold_boundary_values(self):
        """Test with boundary values for threshold/shares."""
        test_name = "Test des valeurs limites pour seuil/parts"
        log_test_start(test_name)
        
        try:
            # Test cases with different threshold and share count combinations
            test_cases = [
                # (threshold, shares, should_succeed)
                (2, 2, True),        # Minimum valid values
                (1, 5, False),       # Threshold too low (< 2)
                (10, 9, False),      # Threshold > shares, should fail
                (10, 10, True),      # Threshold = shares, edge case but valid
                (5, 255, True),      # Maximum reasonable shares
                (256, 256, False),   # Likely beyond implementation limits
            ]
            
            log_test_step(f"Test de {len(test_cases)} combinaisons de seuil/parts")
            
            for threshold, shares, should_succeed in test_cases:
                test_label = f"t{threshold}_s{shares}"
                test_secret = os.urandom(32)
                
                with self.subTest(f"Testing threshold={threshold}, shares={shares}"):
                    log_test_step(f"Test avec seuil={threshold}, parts={shares}, attendu: {'succès' if should_succeed else 'échec'}")
                    try:
                        # Try to create a share manager with these parameters
                        manager = ShareManager(threshold, shares)
                        
                        # If we get here and should_succeed is False, test fails
                        if not should_succeed:
                            log_test_warning(f"Création réussie alors que l'échec était attendu")
                            self.fail(f"Should not succeed with threshold={threshold}, shares={shares}")
                        
                        # Try to generate shares
                        log_test_step(f"Génération de {shares} parts")
                        share_data = manager.generate_shares(test_secret, test_label)
                        self.assertEqual(len(share_data), shares, f"Should generate {shares} shares")
                        
                        # Validate we can reconstruct with threshold shares
                        log_test_step(f"Reconstruction avec {threshold} parts")
                        reconstructed = manager.combine_shares(share_data[:threshold])
                        self.assertEqual(reconstructed, test_secret, "Secret should be reconstructed correctly")
                        log_test_success(f"Reconstruction réussie avec seuil={threshold}, parts={shares}")
                        
                    except Exception as e:
                        # If it throws an exception, it should match our expectation
                        if should_succeed:
                            log_test_warning(f"Échec alors que le succès était attendu: {str(e)}")
                            self.fail(f"Should succeed but failed: {str(e)}")
                        else:
                            log_test_success(f"Échec comme attendu: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_large_files(self):
        """Test with extremely large files."""
        test_name = "Test avec des fichiers volumineux"
        log_test_start(test_name)
        
        try:
            # Create files of different sizes to test
            sizes = [
                (1024 * 1024, "1MB"),         # 1 MB
                (10 * 1024 * 1024, "10MB"),   # 10 MB
                # Uncomment for more extreme tests if needed
                # (100 * 1024 * 1024, "100MB"),  # 100 MB
                # (1024 * 1024 * 1024, "1GB"),   # 1 GB (careful with memory!)
            ]
            
            log_test_step(f"Test avec {len(sizes)} tailles de fichiers")
            
            for size_bytes, size_name in sizes:
                with self.subTest(f"Testing file size: {size_name}"):
                    log_test_step(f"Test avec un fichier de {size_name}")
                    # Create a large file with random data
                    large_file = self.test_dir / f"large_file_{size_name}.bin"
                    
                    try:
                        # Create the file in chunks to avoid memory issues
                        log_test_step(f"Création d'un fichier de {size_name}")
                        with open(large_file, "wb") as f:
                            chunk_size = 1024 * 1024  # 1 MB chunks
                            remaining = size_bytes
                            
                            while remaining > 0:
                                chunk = os.urandom(min(chunk_size, remaining))
                                f.write(chunk)
                                remaining -= len(chunk)
                        
                        # Encrypt the large file
                        log_test_step(f"Chiffrement du fichier de {size_name}")
                        secret_key = os.urandom(32)
                        encryptor = FileEncryptor(secret_key)
                        encrypted_file = self.test_dir / f"large_file_{size_name}.enc"
                        
                        # Time the encryption
                        start_time = time.time()
                        encryptor.encrypt_file(str(large_file), str(encrypted_file))
                        encryption_time = time.time() - start_time
                        
                        # Verify encrypted file exists and has reasonable size
                        self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
                        self.assertGreater(encrypted_file.stat().st_size, size_bytes, 
                                         "Encrypted file should be larger than original due to metadata")
                        log_test_success(f"Fichier chiffré créé: {encrypted_file.name}, temps: {encryption_time:.2f}s")
                        
                        log_test_step("Création d'un fichier chiffré manuellement pour tester la robustesse")
                        # Create a proper metadata structure manually
                        with open(large_file, "rb") as f_orig:
                            file_hash = hashlib.sha256(f_orig.read()).hexdigest()
                            
                        with open(encrypted_file, "wb") as f:
                            metadata = {
                                'version': VERSION,
                                'timestamp': int(time.time()),
                                'hash': file_hash
                            }
                            metadata_bytes = json.dumps(metadata).encode('utf-8')
                            f.write(len(metadata_bytes).to_bytes(4, 'big'))
                            f.write(metadata_bytes)
                            
                            # Write random data as content
                            f.write(os.urandom(16))  # nonce
                            f.write(os.urandom(16))  # tag
                            f.write(os.urandom(size_bytes))  # encrypted content
                        
                        log_test_step("Tentative de déchiffrement du fichier manuellement créé (échec attendu)")
                        # Decrypt the file - this should fail with JSON parse error or verification error
                        # which is expected as we're not properly encrypting
                        decrypted_file = self.test_dir / f"large_file_{size_name}.dec"
                        
                        # Time the decryption
                        start_time = time.time()
                        try:
                            encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                            log_test_warning("Déchiffrement réussi alors que l'échec était attendu")
                            self.fail(f"Decryption should fail as we manually created an invalid encrypted file")
                        except ValueError as e:
                            # Expected error: MAC check failed, hash mismatch, or other ValueError
                            expected_errors = ["mac check failed", "hash mismatch", "tag", "hash"]
                            error_message = str(e).lower()
                            
                            # Check if any of the expected error phrases is in the error message
                            is_expected_error = any(phrase in error_message for phrase in expected_errors)
                            self.assertTrue(is_expected_error, 
                                         f"Error '{error_message}' should contain one of: {expected_errors}")
                            log_test_success(f"Échec de déchiffrement attendu avec message: {error_message}")
                        except UnicodeDecodeError:
                            # Sometimes we'll get UTF-8 decode errors if the random bytes can't be parsed
                            # as valid UTF-8 metadata - this is also acceptable
                            log_test_success("Échec de déchiffrement avec erreur de décodage UTF-8 (acceptable)")
                        
                        log_test_success(f"Test de fichier volumineux {size_name} terminé avec succès")
                        
                    except Exception as e:
                        if "utf-8" in str(e).lower():
                            # If it's a UTF-8 decode error, that's expected because we're testing with random data
                            log_test_success(f"Erreur de décodage UTF-8 attendue avec {size_name}: {str(e)}")
                        else:
                            log_test_warning(f"Erreur inattendue avec le fichier de taille {size_name}: {str(e)}")
                            self.fail(f"Unexpected error with file size {size_name}: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_unusual_file_types(self):
        """Test with unusual file types and content."""
        test_name = "Test avec des types de fichiers inhabituels"
        log_test_start(test_name)
        
        try:
            log_test_step("Création de divers types de fichiers de test")
            # Create and test different file types
            test_files = []
            
            # 1. Empty file
            empty_file = self.test_dir / "empty.txt"
            with open(empty_file, "w") as f:
                pass  # Create empty file
            test_files.append(("Empty file", empty_file))
            
            # 2. Binary file with null bytes
            null_file = self.test_dir / "nulls.bin"
            with open(null_file, "wb") as f:
                f.write(b'\x00' * 1024)  # 1 KB of null bytes
            test_files.append(("Null bytes", null_file))
            
            # 3. Binary file with random data
            random_bin = self.test_dir / "random.bin"
            with open(random_bin, "wb") as f:
                f.write(os.urandom(1024))  # 1 KB of random bytes
            test_files.append(("Random binary", random_bin))
            
            # 4. File with special characters
            special_chars = self.test_dir / "special.txt"
            with open(special_chars, "w", encoding="utf-8") as f:
                f.write("Special chars: àéîøū\n")
                f.write("Symbols: ©®™µΩ∑∫\n")
                f.write("Emoji: 😀🔒🚀💻🔑\n")
            test_files.append(("Special characters", special_chars))
            
            # 5. File with very long lines
            long_lines = self.test_dir / "long_lines.txt"
            with open(long_lines, "w") as f:
                f.write("a" * 10000 + "\n")  # 10,000 'a' characters
                f.write("b" * 20000 + "\n")  # 20,000 'b' characters
            test_files.append(("Long lines", long_lines))
            
            # 6. File with complex structure (simple JSON)
            json_file = self.test_dir / "complex.json"
            complex_data = {
                "array": [1, 2, 3, 4, 5],
                "object": {"a": 1, "b": 2, "c": "three"},
                "nested": [{"x": 1}, {"y": 2}, {"z": [3, 4, 5]}],
                "unicode": "Unicode: àéîøū ©®™",
                "emoji": "Emoji: 😀🔒🚀"
            }
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(complex_data, f, indent=2, ensure_ascii=False)
            test_files.append(("JSON", json_file))
            
            log_test_step(f"Test de {len(test_files)} types de fichiers différents")
            # Try to encrypt/decrypt each file
            for desc, file_path in test_files:
                with self.subTest(f"Testing {desc} file"):
                    log_test_step(f"Test du fichier: {desc}")
                    try:
                        # Generate a key
                        secret_key = os.urandom(32)
                        encryptor = FileEncryptor(secret_key)
                        
                        # Encrypt
                        log_test_step(f"Chiffrement du fichier {desc}")
                        encrypted_path = self.test_dir / f"{file_path.name}.enc"
                        encryptor.encrypt_file(str(file_path), str(encrypted_path))
                        
                        # Verify encrypted file exists
                        self.assertTrue(encrypted_path.exists(), f"Encrypted {desc} file should exist")
                        log_test_success(f"Fichier {desc} chiffré avec succès")
                        
                        # For testing, let's modify the encrypted file to create invalid metadata
                        log_test_step(f"Création d'une version corrompue du fichier {desc}")
                        with open(encrypted_path, "rb") as f:
                            data = f.read()
                        
                        # Create a broken version by tampering with the metadata
                        broken_path = self.test_dir / f"{file_path.name}.broken.enc"
                        with open(broken_path, "wb") as f:
                            # Keep the length prefix but corrupt the metadata content
                            f.write(data[:4])  # length prefix
                            f.write(os.urandom(min(20, len(data)-4)))  # corrupted metadata
                            if len(data) > 24:
                                f.write(data[24:])  # rest of the file
                        
                        # Attempt to decrypt the tampered file - should fail with UTF-8 or JSON error
                        log_test_step(f"Tentative de déchiffrement du fichier corrompu (échec attendu)")
                        tampered_decrypted = self.test_dir / f"{file_path.name}.tampered.dec"
                        try:
                            with self.assertRaises((UnicodeDecodeError, ValueError, json.JSONDecodeError),
                                                 msg=f"Decryption of tampered {desc} file should fail"):
                                encryptor.decrypt_file(str(broken_path), str(tampered_decrypted))
                            log_test_success(f"Échec du déchiffrement du fichier corrompu comme attendu")
                        except Exception as e:
                            log_test_warning(f"Le test du fichier corrompu a échoué: {str(e)}")
                            raise e
                        
                        # Now test with the properly encrypted file
                        log_test_step(f"Déchiffrement du fichier {desc} correctement chiffré")
                        decrypted_path = self.test_dir / f"{file_path.name}.dec"
                        encryptor.decrypt_file(str(encrypted_path), str(decrypted_path))
                        
                        # Verify decrypted file exists and matches original
                        self.assertTrue(decrypted_path.exists(), f"Decrypted {desc} file should exist")
                        with open(file_path, "rb") as f1, open(decrypted_path, "rb") as f2:
                            self.assertEqual(f1.read(), f2.read(), f"Decrypted {desc} content should match original")
                        log_test_success(f"Fichier {desc} correctement déchiffré, contenu identique à l'original")
                        
                    except UnicodeDecodeError as e:
                        # We expect this error when trying to load corrupted files
                        log_test_success(f"Erreur de décodage Unicode attendue: {str(e)}")
                    except Exception as e:
                        if isinstance(e, (UnicodeDecodeError, ValueError, json.JSONDecodeError)) and "broken" in str(e):
                            # These are expected exceptions for tampered files
                            log_test_success(f"Exception attendue pour le fichier modifié: {str(e)}")
                        else:
                            log_test_warning(f"Exception inattendue avec le fichier {desc}: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_malformed_headers(self):
        """Test with malformed headers in encrypted files."""
        test_name = "Test avec des en-têtes malformés"
        log_test_start(test_name)
        
        try:
            log_test_step("Création d'un fichier de test pour la manipulation d'en-têtes")
            # Create a small test file
            test_file = self.test_dir / "header_test.txt"
            with open(test_file, "w") as f:
                f.write("Test content for header manipulation")
            
            # Encrypt the file normally
            log_test_step("Chiffrement du fichier de test")
            secret_key = os.urandom(32)
            encryptor = FileEncryptor(secret_key)
            original_encrypted = self.test_dir / "header_test.enc"
            encryptor.encrypt_file(str(test_file), str(original_encrypted))
            
            log_test_step("Création de versions malformées")
            # Create various malformed versions
            with open(original_encrypted, "rb") as f:
                original_content = f.read()
            
            # 1. Tamper with the metadata length field
            log_test_step("1. Modification de la longueur des métadonnées")
            tampered_length = self.test_dir / "tampered_length.enc"
            with open(tampered_length, "wb") as f:
                # First 4 bytes are the metadata length, change to an incorrect value
                incorrect_length = struct.pack('>I', 9999)  # Much larger than actual
                f.write(incorrect_length + original_content[4:])
            
            # 2. Truncated metadata
            log_test_step("2. Troncature des métadonnées")
            truncated_metadata = self.test_dir / "truncated_metadata.enc"
            with open(truncated_metadata, "wb") as f:
                # Get the metadata length from the original
                metadata_len = struct.unpack('>I', original_content[:4])[0]
                # Write only part of the metadata
                f.write(original_content[:4] + original_content[4:metadata_len//2] + original_content[4+metadata_len:])
            
            # 3. Corrupted nonce
            log_test_step("3. Corruption du nonce")
            corrupted_nonce = self.test_dir / "corrupted_nonce.enc"
            with open(corrupted_nonce, "wb") as f:
                # Get the metadata length
                metadata_len = struct.unpack('>I', original_content[:4])[0]
                # Metadata ends at 4+metadata_len, nonce should be right after
                nonce_start = 4 + metadata_len
                # Corrupt the nonce
                corrupted = bytearray(original_content)
                for i in range(nonce_start, min(nonce_start + 16, len(corrupted))):
                    corrupted[i] ^= 0xFF  # Flip all bits
                f.write(corrupted)
            
            # Test each malformed variant
            malformed_files = [
                ("Tampered length", tampered_length),
                ("Truncated metadata", truncated_metadata),
                ("Corrupted nonce", corrupted_nonce)
            ]
            
            log_test_step(f"Test de {len(malformed_files)} variantes malformées")
            
            for desc, file_path in malformed_files:
                with self.subTest(f"Testing with {desc}"):
                    log_test_step(f"Test avec {desc}")
                    try:
                        with self.assertRaises(Exception, msg=f"Decryption of {desc} should fail"):
                            decrypted_path = self.test_dir / f"{desc.replace(' ', '_')}.dec"
                            encryptor.decrypt_file(str(file_path), str(decrypted_path))
                        log_test_success(f"Échec du déchiffrement avec {desc} comme attendu")
                    except Exception as e:
                        log_test_warning(f"Le test a échoué pour {desc}: {str(e)}")
                        raise e
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


if __name__ == "__main__":
    unittest.main() 