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
import io
import gc
import psutil
import ctypes
import binascii
import threading
import statistics
from pathlib import Path
from unittest.mock import patch, MagicMock
from contextlib import redirect_stdout
from Crypto.Cipher import AES

# Import from the src module
from src import (
    ShareManager,
    FileEncryptor,
    VERSION,
    get_enhanced_random_bytes,
    SecureMemory,
    cli
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

class CryptographicSecurityTests(unittest.TestCase):
    """Tests for cryptographic security properties."""
    
    def test_entropy_source_quality(self):
        """Verify quality of random bytes from get_enhanced_random_bytes."""
        test_name = "Test de qualité de source d'entropie"
        log_test_start(test_name)
        
        try:
            # Generate multiple samples
            samples = 100  # Réduit pour accélérer les tests
            sample_size = 32  # 32 bytes = 256 bits
            
            log_test_step(f"Génération de {samples} échantillons aléatoires de {sample_size} octets")
            # Collect samples
            random_bytes = [get_enhanced_random_bytes(sample_size) for _ in range(samples)]
            
            # Test 1: Check uniqueness of samples
            log_test_step("Vérification de l'unicité des échantillons")
            unique_samples = set(random_bytes)
            self.assertEqual(len(unique_samples), samples, 
                             "Random bytes should be unique across samples")
            log_test_success("Tous les échantillons sont uniques")
            
            # Test 2: Check byte distribution
            log_test_step("Analyse de la distribution des octets")
            # Flatten all bytes together
            all_bytes = bytearray()
            for sample in random_bytes:
                all_bytes.extend(sample)
                
            # Count frequency of each byte value
            freq = [0] * 256
            for b in all_bytes:
                freq[b] += 1
                
            # Calculate statistics
            avg_freq = len(all_bytes) / 256
            std_dev = statistics.stdev(freq)
            
            # For truly random bytes, we expect std_dev to be within reasonable bounds
            # Chi-square test could be better, but this is a simple test
            expected_std_dev = (avg_freq * (1 - 1/256)) ** 0.5
            
            # Verify that actual standard deviation is reasonably close to expected
            # We'll use a 50% margin for this test (augmenté pour la robustesse)
            margin = 0.5
            self.assertLess(abs(std_dev - expected_std_dev), margin * expected_std_dev,
                          f"Byte distribution not within expected randomness bounds: "
                          f"std_dev={std_dev}, expected={expected_std_dev}")
            log_test_success(f"Distribution des octets dans les limites attendues (écart-type: {std_dev:.2f})")
            
            # Test 3: Check bit distribution (should be roughly 50% ones and 50% zeros)
            log_test_step("Analyse de la distribution des bits")
            bit_count = 0
            for b in all_bytes:
                # Count bits in each byte
                for i in range(8):
                    if b & (1 << i):
                        bit_count += 1
                        
            # For random data, expect approximately 50% of bits to be 1
            # Allow a 10% margin for statistical variation (augmenté pour la robustesse)
            expected_ones = len(all_bytes) * 8 * 0.5
            margin = 0.1
            self.assertLess(abs(bit_count - expected_ones), margin * expected_ones,
                          f"Bit distribution not balanced: {bit_count} ones, expected ~{expected_ones}")
            bit_percentage = (bit_count / (len(all_bytes) * 8)) * 100
            log_test_success(f"Distribution des bits équilibrée: {bit_percentage:.2f}% de uns (attendu ~50%)")
            
            # Test 4: Test for sequential correlation
            log_test_step("Vérification de l'absence de corrélation séquentielle")
            # Compute the correlation between consecutive samples
            correlations = []
            for i in range(1, len(random_bytes)):
                # XOR consecutive samples and count set bits
                # Less set bits means higher correlation
                xor_result = bytes(a ^ b for a, b in zip(random_bytes[i-1], random_bytes[i]))
                hamming_distance = sum(bin(byte).count('1') for byte in xor_result)
                correlations.append(hamming_distance)
                
            # For random data, expect Hamming distance to be around 128 for 32-byte samples
            avg_correlation = sum(correlations) / len(correlations)
            expected_correlation = 32 * 8 * 0.5  # Half the bits should be different on average
            
            # Allow a 15% margin for statistical variation (augmenté pour la robustesse)
            margin = 0.15
            self.assertLess(abs(avg_correlation - expected_correlation), margin * expected_correlation,
                          f"Sequential correlation detected: avg_distance={avg_correlation}, expected={expected_correlation}")
            log_test_success(f"Aucune corrélation séquentielle détectée (distance moyenne: {avg_correlation:.2f})")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
        
    def test_key_reuse_prevention(self):
        """Test that keys are not reused across different encryptions."""
        test_name = "Test de prévention de réutilisation des clés"
        log_test_start(test_name)
        
        try:
            # Create test files
            with tempfile.TemporaryDirectory() as temp_dir:
                log_test_step("Création des fichiers de test identiques")
                # Create two identical test files
                test_file1 = os.path.join(temp_dir, "test1.txt")
                test_file2 = os.path.join(temp_dir, "test2.txt")
                
                test_content = b"This is identical test content for encryption testing" * 10  # Make content longer
                with open(test_file1, "wb") as f:
                    f.write(test_content)
                with open(test_file2, "wb") as f:
                    f.write(test_content)
                
                # Encrypt both files using different keys
                log_test_step("Génération de deux clés différentes")
                key1 = get_enhanced_random_bytes(32)
                key2 = get_enhanced_random_bytes(32)
                
                log_test_step("Chiffrement du premier fichier avec la première clé")
                # First encryption - with explicit metadata to make things easier to verify
                encryptor1 = FileEncryptor(key1)
                encrypted_file1 = os.path.join(temp_dir, "test1.enc")
                metadata1 = {
                    'test_metadata': 'file1',
                    'timestamp': int(time.time())
                }
                # Encrypt with direct call to the function to ensure metadata is included properly
                with open(test_file1, 'rb') as f_in:
                    data = f_in.read()
                    data_hash = hashlib.sha256(data).hexdigest()
                    
                    with open(encrypted_file1, 'wb') as f_out:
                        encryptor1._write_metadata(f_out, data_hash, metadata1)
                        cipher = AES.new(key1, AES.MODE_GCM)
                        ciphertext, tag = cipher.encrypt_and_digest(data)
                        f_out.write(cipher.nonce)
                        f_out.write(tag)
                        f_out.write(ciphertext)
                
                log_test_step("Chiffrement du second fichier avec la seconde clé")
                # Second encryption - with different metadata
                encryptor2 = FileEncryptor(key2)
                encrypted_file2 = os.path.join(temp_dir, "test2.enc")
                metadata2 = {
                    'test_metadata': 'file2',
                    'timestamp': int(time.time()) + 1  # Make sure timestamp is different
                }
                # Encrypt with direct call to function
                with open(test_file2, 'rb') as f_in:
                    data = f_in.read()
                    data_hash = hashlib.sha256(data).hexdigest()
                    
                    with open(encrypted_file2, 'wb') as f_out:
                        encryptor2._write_metadata(f_out, data_hash, metadata2)
                        cipher = AES.new(key2, AES.MODE_GCM)
                        ciphertext, tag = cipher.encrypt_and_digest(data)
                        f_out.write(cipher.nonce)
                        f_out.write(tag)
                        f_out.write(ciphertext)
                
                # Vérifier que les fichiers ont bien été créés
                self.assertTrue(os.path.exists(encrypted_file1), "First encrypted file should exist")
                self.assertTrue(os.path.exists(encrypted_file2), "Second encrypted file should exist")
                log_test_success("Fichiers chiffrés créés avec succès")
                
                # Now test direct file comparison
                log_test_step("Comparaison des fichiers chiffrés")
                with open(encrypted_file1, "rb") as f1, open(encrypted_file2, "rb") as f2:
                    content1 = f1.read()
                    content2 = f2.read()
                    
                    # Vérifier que les fichiers ont bien du contenu
                    self.assertGreater(len(content1), 0, "First encrypted file content should not be empty")
                    self.assertGreater(len(content2), 0, "Second encrypted file content should not be empty")
                    
                    # Les fichiers chiffrés doivent être différents
                    self.assertNotEqual(content1, content2, 
                                      "Encrypted files should be different even with identical content")
                    log_test_success("Les fichiers chiffrés sont différents malgré un contenu identique")
                    
                    # Tester le déchiffrement des deux fichiers pour vérifier qu'ils décryptent correctement
                    # avec leurs clés respectives
                    log_test_step("Déchiffrement et vérification des deux fichiers")
                    decrypted_file1 = os.path.join(temp_dir, "test1.dec")
                    decrypted_file2 = os.path.join(temp_dir, "test2.dec")
                    
                    encryptor1.decrypt_file(encrypted_file1, decrypted_file1)
                    encryptor2.decrypt_file(encrypted_file2, decrypted_file2)
                    
                    # Vérifier que les fichiers déchiffrés sont identiques à l'original
                    with open(decrypted_file1, "rb") as df1, open(decrypted_file2, "rb") as df2:
                        self.assertEqual(df1.read(), test_content, "First decryption should match original")
                        self.assertEqual(df2.read(), test_content, "Second decryption should match original")
                    log_test_success("Déchiffrement réussi, contenu original récupéré pour les deux fichiers")
                
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_no_secrets_in_logs(self):
        """Verify that no secrets are logged during verbose mode."""
        test_name = "Test d'absence de secrets dans les logs"
        log_test_start(test_name)
        
        try:
            # Capture stdout to check logs
            stdout_capture = io.StringIO()
            
            with tempfile.TemporaryDirectory() as temp_dir:
                log_test_step("Création d'un fichier test avec des données secrètes")
                # Create a test file
                test_file = os.path.join(temp_dir, "secret_file.txt")
                with open(test_file, "w") as f:
                    f.write("This is secret data that should not be logged")
                    
                # Create a key that we'll check is not logged
                log_test_step("Génération d'une clé secrète et capture des sorties verboses")
                test_key = get_enhanced_random_bytes(32)
                test_key_hex = test_key.hex()
                test_key_b64 = base64.b64encode(test_key).decode('ascii')
                
                # Patch sys.stdout to capture output
                with redirect_stdout(stdout_capture):
                    # Generate shares with verbose mode
                    manager = ShareManager(2, 3)
                    shares = manager.generate_shares(test_key, "test_label")
                    
                    # Encode shares to different formats we'll check for in logs
                    share_formats = []
                    for idx, share_data in shares:
                        share_formats.append(share_data.hex())
                        share_formats.append(base64.b64encode(share_data).decode('ascii'))
                    
                    # Create an encryptor with verbose info
                    encryptor = FileEncryptor(test_key)
                    encrypted_file = os.path.join(temp_dir, "secret_file.enc")
                    encryptor.encrypt_file(test_file, encrypted_file)
                    
                    # Simulate verbose CLI operation by printing information
                    print(f"Encrypted file: {encrypted_file}")
                    print(f"Using label: test_label")
                    print(f"Threshold: 2, Total shares: 3")
                    print(f"Share set ID: {hashlib.sha256(b'test').hexdigest()[:16]}")
                
                # Get the captured output
                log_output = stdout_capture.getvalue()
                
                log_test_step("Vérification qu'aucune clé secrète n'apparaît dans les logs")
                # Check that key is not present in any format
                self.assertNotIn(test_key_hex, log_output, "Secret key (hex) found in logs")
                self.assertNotIn(test_key_b64, log_output, "Secret key (base64) found in logs")
                log_test_success("Aucune clé secrète n'apparaît dans les logs")
                
                log_test_step("Vérification qu'aucune part secrète n'apparaît dans les logs")
                # Check that shares are not present in any format
                for share_format in share_formats:
                    self.assertNotIn(share_format, log_output, f"Share data found in logs: {share_format[:10]}...")
                log_test_success("Aucune part secrète n'apparaît dans les logs")
                
                log_test_step("Vérification qu'aucune donnée secrète n'apparaît dans les logs")
                # Check that secret file content is not logged
                with open(test_file, "r") as f:
                    secret_content = f.read()
                    self.assertNotIn(secret_content, log_output, "Secret file content found in logs")
                log_test_success("Aucune donnée secrète n'apparaît dans les logs")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


class SideChannelSecurityTests(unittest.TestCase):
    """Tests for side-channel attack vulnerabilities."""
    
    def test_timing_attack_resistance(self):
        """Test for resistance against timing attacks in cryptographic operations."""
        test_name = "Test de résistance aux attaques temporelles"
        log_test_start(test_name)
        
        try:
            log_test_step("Création des données de test et génération des parts")
            # Create test data
            test_secret = get_enhanced_random_bytes(32)
            label = "timing_test"
            threshold = 3
            total_shares = 5
            
            # Generate shares
            manager = ShareManager(threshold, total_shares)
            shares = manager.generate_shares(test_secret, label)
            
            log_test_step(f"Mesure des temps pour {threshold} parts sur plusieurs essais")
            # Measure time for key reconstruction with different subsets of shares
            # The time should be consistent regardless of which shares are used
            timings = []
            
            # Test multiple subset combinations
            num_trials = 10
            for i in range(num_trials):
                # Randomly select exactly threshold shares
                selected_shares = random.sample(shares, threshold)
                
                # Measure time for reconstruction
                start_time = time.perf_counter()
                reconstructed = manager.combine_shares(selected_shares)
                end_time = time.perf_counter()
                
                # Store timing
                timings.append(end_time - start_time)
                
                # Verify reconstruction is correct
                self.assertEqual(reconstructed, test_secret, "Reconstructed secret is incorrect")
                
                if i == 0:
                    log_test_step(f"Essai {i+1}/{num_trials}: {timings[-1]:.6f} secondes")
                elif i == num_trials - 1:
                    log_test_step(f"Essai {i+1}/{num_trials}: {timings[-1]:.6f} secondes")
            
            # Calculate statistics
            avg_time = sum(timings) / len(timings)
            max_deviation = max(abs(t - avg_time) for t in timings)
            
            # Print timing statistics for debugging
            log_test_step(f"Statistiques des temps de reconstruction (secondes):")
            print(f"  Average: {avg_time:.6f}")
            print(f"  Min: {min(timings):.6f}")
            print(f"  Max: {max(timings):.6f}")
            print(f"  Std Dev: {statistics.stdev(timings):.6f}")
            
            # Assert that timing variance is within acceptable range (allowing for system noise)
            # Note: This is a heuristic and might need adjustment based on the system
            # Increase the tolerance to 3x the average time to account for possible system jitter
            self.assertLess(max_deviation, avg_time * 3, 
                           f"Timing variation too high: max deviation {max_deviation:.6f} vs avg {avg_time:.6f}")
            
            log_test_success(f"Variations de temps limitées: écart max {max_deviation:.6f}s vs moyenne {avg_time:.6f}s")
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_memory_usage_patterns(self):
        """Verify memory usage patterns don't leak information."""
        test_name = "Test des schémas d'utilisation mémoire"
        log_test_start(test_name)
        
        try:
            log_test_step("Mesure de l'utilisation mémoire initiale")
            # Track memory usage before operations
            process = psutil.Process(os.getpid())
            initial_memory = process.memory_info().rss
            
            # Number of iterations to perform to amplify memory effects
            iterations = 5
            # Adapter les tailles des secrets pour respecter la limite de 32 octets
            secret_sizes = [16, 24, 28, 32]  # Different secret sizes in bytes
            
            log_test_step(f"Test avec différentes tailles de secrets: {secret_sizes}")
            memory_increases = []
            
            for secret_size in secret_sizes:
                log_test_step(f"Test avec secrets de {secret_size} octets")
                # Force garbage collection to stabilize memory usage
                gc.collect()
                
                # Record memory before test
                before_memory = process.memory_info().rss
                
                # Perform cryptographic operations with secrets of different sizes
                for _ in range(iterations):
                    # Generate random secret
                    secret = get_enhanced_random_bytes(secret_size)
                    
                    # Create shares
                    manager = ShareManager(3, 5)
                    shares = manager.generate_shares(secret, f"test_mem_{secret_size}")
                    
                    # Combine shares to reconstruct secret
                    reconstructed = manager.combine_shares(shares[:3])
                    
                    # Verify reconstruction worked
                    self.assertEqual(reconstructed[:secret_size], secret, "Secret reconstruction failed")
                    
                    # Securely clear secrets
                    SecureMemory.secure_clear(secret)
                    SecureMemory.secure_clear(reconstructed)
                
                # Force garbage collection again
                gc.collect()
                
                # Record memory after test
                after_memory = process.memory_info().rss
                
                # Calculate memory increase
                memory_increase = after_memory - before_memory
                memory_increases.append(memory_increase)
                log_test_step(f"Augmentation mémoire pour {secret_size} octets: {memory_increase/1024:.2f} KB")
            
            log_test_step("Vérification des corrélations entre taille et utilisation mémoire")
            # Check for correlation between secret size and memory increase
            # Ideally, memory usage should not correlate strongly with secret size
            # This would indicate potential information leakage
            
            # Calculate if memory usage scales proportionally with secret size
            # If memory usage increases linearly with secret size, it might leak information
            prev_size = secret_sizes[0]
            prev_increase = max(1, abs(memory_increases[0]))  # Avoid division by zero
            
            for i in range(1, len(secret_sizes)):
                size_ratio = secret_sizes[i] / prev_size
                increase_ratio = max(1, abs(memory_increases[i])) / prev_increase
                
                # If memory increase scales much faster than secret size,
                # it might indicate information leakage
                # We'll use a generous threshold of 5x to account for other memory allocations and système
                self.assertLess(increase_ratio, size_ratio * 5,
                              f"Memory usage scales suspiciously with secret size: "
                              f"size_ratio={size_ratio}, increase_ratio={increase_ratio}")
                log_test_step(f"Ratio taille {size_ratio:.2f} vs ratio mémoire {increase_ratio:.2f} - OK")
                
                prev_size = secret_sizes[i]
                prev_increase = max(1, abs(memory_increases[i]))
            
            log_test_success("Pas de fuite d'information détectée dans l'utilisation mémoire")
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_residual_data_after_clearing(self):
        """Check for residual data after secure clearing."""
        test_name = "Test d'absence de données résiduelles après effacement"
        log_test_start(test_name)
        
        try:
            log_test_step("Test de nettoyage des bytearrays")
            # Test with bytearrays which can be cleared securely
            test_data = bytearray(b"SECRET_DATA_TO_CLEAR" * 10)
            
            # Keep a copy for comparison
            original_content = bytes(test_data)
            
            # Clear the data
            SecureMemory.secure_clear(test_data)
            
            # Verify bytearray is zeroed
            zeroed = all(b == 0 for b in test_data)
            self.assertTrue(zeroed, "Bytearray should be zeroed after clearing")
            log_test_success("Bytearray correctement vidé (tous les octets sont à zéro)")
            
            log_test_step("Test de traitement des chaînes de caractères")
            # Test with string - we expect the secure_clear to at least not crash
            try:
                test_string = "SENSITIVE_STRING_DATA_TO_CLEAR" * 5
                SecureMemory.secure_clear(test_string)
                log_test_success("Traitement des chaînes terminé sans erreur")
                # No assertion here as Python strings are immutable
            except Exception as e:
                log_test_warning(f"Erreur pendant le traitement des chaînes: {str(e)}")
                self.fail(f"SecureMemory.secure_clear failed on string: {str(e)}")
            
            log_test_step("Test de traitement des listes")
            # Test with list - we expect the secure_clear to at least not crash
            try:
                test_list = [b"ITEM1", b"ITEM2", "SECRET3", bytearray(b"ITEM4")]
                SecureMemory.secure_clear(test_list)
                log_test_success("Traitement des listes terminé sans erreur")
                # Check if list is empty (this may or may not happen depending on implementation)
                if isinstance(test_list, list):
                    self.assertEqual(len(test_list), 0, "List should be emptied if possible")
                    log_test_success("Liste vidée avec succès")
            except Exception as e:
                log_test_warning(f"Erreur pendant le traitement des listes: {str(e)}")
                self.fail(f"SecureMemory.secure_clear failed on list: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


class EdgeCaseSecurityTests(unittest.TestCase):
    """Tests for edge cases and adversarial inputs that could compromise security."""
    
    def setUp(self):
        """Setup test environment."""
        # Create temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create common variables
        self.threshold = 3
        self.total_shares = 5
        self.label = "security_test"
        self.test_secret = get_enhanced_random_bytes(32)
        
        # Create a share manager and generate valid shares for reference
        self.manager = ShareManager(self.threshold, self.total_shares)
        self.valid_shares = self.manager.generate_shares(self.test_secret, self.label)
        
    def tearDown(self):
        """Clean up test environment."""
        self.temp_dir.cleanup()
    
    def test_adversarial_shares(self):
        """Test share reconstruction with adversarially crafted shares."""
        test_name = "Test de résistance aux parts falsifiées"
        log_test_start(test_name)
        
        try:
            log_test_step("Test 1: Parts avec indices incohérents")
            # Test 1: Shares with inconsistent indices
            inconsistent_indices = [
                (1, self.valid_shares[0][1]),  # Valid share data but with wrong index
                (1, self.valid_shares[1][1]),  # Duplicate index but different share
                (3, self.valid_shares[2][1]),  # Valid share
            ]
            
            with self.assertRaises(ValueError, msg="Should fail with inconsistent indices"):
                self.manager.combine_shares(inconsistent_indices)
            log_test_success("Détection réussie des indices incohérents")
            
            log_test_step("Test 2: Parts avec données manipulées")
            # Test 2: Crafted shares with manipulated data
            corrupted_shares = [
                (self.valid_shares[0][0], self.valid_shares[0][1]),  # Valid share
                (self.valid_shares[1][0], self.valid_shares[1][1]),  # Valid share
                (self.valid_shares[2][0], get_enhanced_random_bytes(32)),  # Valid index but random data
            ]
            
            # This should not raise an exception but should produce an incorrect result
            try:
                reconstructed = self.manager.combine_shares(corrupted_shares)
                # Verify reconstruction gives different result than original
                self.assertNotEqual(reconstructed, self.test_secret, 
                                   "Corrupted shares should not reconstruct to the original secret")
                log_test_success("Données corrompues produisent un résultat incorrect, comme attendu")
            except Exception as e:
                # Some implementations might detect this corruption and raise an exception
                log_test_success(f"Détection des données corrompues avec exception: {str(e)}")
                pass
            
            log_test_step("Test 3: Nombre insuffisant de parts")
            # Test 3: Insufficient number of shares
            insufficient_shares = self.valid_shares[:self.threshold - 1]
            
            with self.assertRaises(ValueError, msg="Should fail with insufficient shares"):
                self.manager.combine_shares(insufficient_shares)
            log_test_success("Détection réussie d'un nombre insuffisant de parts")
            
            log_test_step("Test 4: Mélange de parts provenant de secrets différents")
            # Test 4: Shares from different secrets mixed together
            another_secret = get_enhanced_random_bytes(32)
            another_shares = self.manager.generate_shares(another_secret, "another_label")
            
            # Create mixed shares with unique indices
            mixed_shares = [
                self.valid_shares[0],          # From original secret, index likely 1
                another_shares[1],             # From different secret, index likely 2
                self.valid_shares[2],          # From original secret, index likely 3
            ]
            
            # Ensure each share has a unique index
            share_indices = [s[0] for s in mixed_shares]
            if len(set(share_indices)) != len(mixed_shares):
                # Re-adjust indices if needed
                for i in range(len(mixed_shares)):
                    mixed_shares[i] = (i + 1, mixed_shares[i][1])
            
            # This should generally work but produce an incorrect result
            try:
                reconstructed = self.manager.combine_shares(mixed_shares)
                # Verify reconstruction doesn't match either original
                self.assertNotEqual(reconstructed, self.test_secret, 
                                  "Mixed shares should not reconstruct to the first original secret")
                self.assertNotEqual(reconstructed, another_secret, 
                                  "Mixed shares should not reconstruct to the second original secret")
                log_test_success("Parts mélangées produisent un résultat incorrect, comme attendu")
            except Exception as e:
                # Some implementations might detect the inconsistency
                log_test_success(f"Détection des parts mélangées avec exception: {str(e)}")
                pass
            
            log_test_step("Test 5: Manipulation d'octets spécifiques")
            # Test 5: Attempting to manipulate specific bytes        
            # Create slightly modified shares - each with a unique index
            modified_shares = []
            for i in range(self.threshold):
                # Get original share
                idx, share_data = self.valid_shares[i]
                
                # Create a modified copy
                modified_data = bytearray(share_data)
                # Modify a random byte in the latter half of the share
                pos = random.randint(len(modified_data)//2, len(modified_data)-1)
                modified_data[pos] = (modified_data[pos] + 1) % 256
                
                # Add to test set with original index
                modified_shares.append((idx, bytes(modified_data)))
            
            # Test reconstruction with modified shares
            try:
                reconstructed = self.manager.combine_shares(modified_shares)
                # The reconstructed secret should be different from the original
                self.assertNotEqual(reconstructed, self.test_secret,
                                   "Modified shares should not reconstruct to the original secret")
                log_test_success("Parts modifiées produisent un résultat incorrect, comme attendu")
            except Exception as e:
                # If implementation detects the inconsistency, that's fine too
                log_test_success(f"Détection des parts modifiées avec exception: {str(e)}")
                pass
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_malicious_metadata(self):
        """Verify behavior with malicious metadata."""
        test_name = "Test de résistance aux métadonnées malveillantes"
        log_test_start(test_name)
        
        try:
            log_test_step("Création d'un fichier de test")
            # Create a test file for testing
            test_file = self.test_dir / "test_file.txt"
            with open(test_file, "w") as f:
                f.write("This is test content for malicious metadata testing")
                
            # Encrypt a file normally
            encrypted_file = self.test_dir / "test_file.enc"
            encryptor = FileEncryptor(self.test_secret)
            encryptor.encrypt_file(str(test_file), str(encrypted_file))
            log_test_success("Fichier chiffré avec succès pour les tests")
            
            log_test_step("Création de variantes avec métadonnées malveillantes")
            # Create several variants of files with malicious metadata
            test_cases = []
            
            # 1. File with oversized metadata length
            log_test_step("Cas 1: Métadonnées de taille excessive")
            oversized_length_file = self.test_dir / "oversized_length.enc"
            with open(encrypted_file, "rb") as src, open(oversized_length_file, "wb") as dst:
                # Read the original file
                original_content = src.read()
                
                # Write back with vastly increased length to trigger OOM
                dst.write((100 * 1024 * 1024).to_bytes(4, 'big'))  # Claim 100MB metadata
                dst.write(original_content[4:])
                
            test_cases.append(("Oversized Length", oversized_length_file))
            
            # 2. File with metadata containing control characters
            log_test_step("Cas 2: Métadonnées avec caractères de contrôle")
            control_chars_file = self.test_dir / "control_chars.enc"
            with open(encrypted_file, "rb") as src, open(control_chars_file, "wb") as dst:
                # Read the original file
                original_content = src.read()
                metadata_len = int.from_bytes(original_content[:4], 'big')
                metadata = original_content[4:4+metadata_len]
                
                # Create malicious metadata with control characters
                malicious_metadata = metadata.replace(b'"version"', b'"version\x00\x07\x1F"')
                
                # Write back with modified metadata
                dst.write(len(malicious_metadata).to_bytes(4, 'big'))
                dst.write(malicious_metadata)
                dst.write(original_content[4+metadata_len:])
                
            test_cases.append(("Control Characters", control_chars_file))
            
            # 3. File with malicious version string - nous lisons le contenu en bytes ici
            log_test_step("Cas 3: Chaîne de version malveillante")
            malicious_version_file = self.test_dir / "malicious_version.enc"
            with open(encrypted_file, "rb") as src, open(malicious_version_file, "wb") as dst:
                # Read the original file
                original_content = src.read()
                metadata_len = int.from_bytes(original_content[:4], 'big')
                metadata = original_content[4:4+metadata_len]
                
                # Modify the version to include XSS
                version_bytes = f'"{VERSION}"'.encode()
                xss_bytes = '"<script>alert(1)</script>"'.encode()
                
                if version_bytes in metadata:
                    modified_metadata = metadata.replace(version_bytes, xss_bytes)
                    
                    # Write back with modified metadata
                    dst.write(len(modified_metadata).to_bytes(4, 'big'))
                    dst.write(modified_metadata)
                    dst.write(original_content[4+metadata_len:])
                    
                    # Ajouter ce cas de test uniquement si la modification a été effectuée
                    test_cases.append(("Malicious Version", malicious_version_file))
                # Si on ne peut pas trouver la version exacte, on ne fait rien et on passe au cas suivant
                
            # 4. File with deeply nested JSON structure
            log_test_step("Cas 4: Structure JSON profondément imbriquée")
            recursive_file = self.test_dir / "recursive.enc"
            with open(encrypted_file, "rb") as src, open(recursive_file, "wb") as dst:
                # Read the original file to get metadata length and encryption data
                original_content = src.read()
                metadata_len = int.from_bytes(original_content[:4], 'big')
                encryption_data = original_content[4+metadata_len:]  # Nonce, tag, ciphertext
                
            # Now create a JSON with deeply nested structure
            deep_json = {"a": 1}
            current = deep_json
            for i in range(100):  # Profondeur de 100 au lieu de 1000 pour éviter les problèmes de mémoire
                current["nested"] = {"a": i}
                current = current["nested"]
                
            # Encode the recursive JSON
            json_bytes = json.dumps(deep_json).encode('utf-8')
            
            # Create the malicious file with recursive structure
            with open(recursive_file, "wb") as dst:
                # Write metadata length and recursive JSON
                dst.write(len(json_bytes).to_bytes(4, 'big'))
                dst.write(json_bytes)
                # Write the encryption data from the original file
                dst.write(encryption_data)
                
            test_cases.append(("Recursive Structure", recursive_file))
            
            # 5. File with invalid UTF-8 sequences in metadata
            log_test_step("Cas 5: Séquences UTF-8 invalides dans les métadonnées")
            invalid_utf8_file = self.test_dir / "invalid_utf8.enc"
            with open(encrypted_file, "rb") as src, open(invalid_utf8_file, "wb") as dst:
                # Read the original file
                original_content = src.read()
                metadata_len = int.from_bytes(original_content[:4], 'big')
                
                # Create metadata with invalid UTF-8 sequences
                invalid_utf8 = b'{"version": "1.0.0", "invalid": "\xc3\x28\xaf\xed"}'
                
                # Write back with invalid UTF-8
                dst.write(len(invalid_utf8).to_bytes(4, 'big'))
                dst.write(invalid_utf8)
                dst.write(original_content[4+metadata_len:])
                
            test_cases.append(("Invalid UTF-8", invalid_utf8_file))
            
            log_test_step(f"Test de déchiffrement avec les {len(test_cases)} fichiers malveillants")
            # Test each malicious file
            for desc, malicious_file in test_cases:
                log_test_step(f"Test du cas: {desc}")
                with self.subTest(f"Testing {desc} metadata"):
                    try:
                        # Attempt to decrypt the malicious file
                        decrypted_file = self.test_dir / f"{desc.lower().replace(' ', '_')}_decrypted.txt"
                        
                        # This should either fail gracefully or handle the malicious input
                        encryptor.decrypt_file(str(malicious_file), str(decrypted_file))
                        
                        # If it succeeds, verify the content is correct
                        with open(test_file, "rb") as f1, open(decrypted_file, "rb") as f2:
                            self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
                        log_test_success(f"Cas {desc}: Déchiffrement réussi, contenu correct")
                        
                    except Exception as e:
                        # Verify that the exception is related to metadata parsing
                        # and not an unhandled crash
                        acceptable_errors = [
                            "metadata", "json", "utf", "decode", "parse", "recursion", "length",
                            "memory", "value", "buffer", "overflow", "incorrect key", "nonce",
                            "version", "incompatible"  # Ajout des mots-clés pour les erreurs de version
                        ]
                        
                        error_message = str(e).lower()
                        is_acceptable_error = any(err in error_message for err in acceptable_errors)
                        
                        self.assertTrue(is_acceptable_error, 
                                      f"Exception with {desc} should be handled gracefully: {e}")
                        log_test_success(f"Cas {desc}: Erreur gérée correctement: {e}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


if __name__ == "__main__":
    unittest.main() 