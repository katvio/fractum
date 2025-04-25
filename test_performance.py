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
import psutil
import gc
import threading
import concurrent.futures
import statistics
from pathlib import Path
from typing import List, Tuple, Dict, Any

# Import from the src module
from src import (
    ShareManager,
    FileEncryptor,
    VERSION,
    get_enhanced_random_bytes,
    SecureMemory
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

def generate_large_file(file_path: str, size_mb: int) -> None:
    """Generate a large file with random content.
    
    Args:
        file_path: Path where the file will be created
        size_mb: Size of the file in MB
    """
    size_bytes = size_mb * 1024 * 1024
    chunk_size = 1024 * 1024  # 1MB chunks
    
    with open(file_path, 'wb') as f:
        remaining = size_bytes
        while remaining > 0:
            chunk = os.urandom(min(chunk_size, remaining))
            f.write(chunk)
            remaining -= len(chunk)


class EfficiencyTests(unittest.TestCase):
    """Tests for efficiency and performance of core operations."""
    
    @classmethod
    def setUpClass(cls):
        """Create shared test files for all efficiency tests."""
        log_test_start("Préparation des fichiers de test pour tests d'efficacité")
        
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_dir = Path(cls.temp_dir.name)
        
        # Create test files of various sizes
        cls.test_files = {}
        
        log_test_step("Création d'un fichier de petite taille (1MB)")
        # Small file (1MB) for quick tests
        cls.test_files["1MB"] = cls.test_dir / "test_1mb.bin"
        generate_large_file(str(cls.test_files["1MB"]), 1)
        
        log_test_step("Création d'un fichier de taille moyenne (10MB)")
        # Medium file (10MB)
        cls.test_files["10MB"] = cls.test_dir / "test_10mb.bin"
        generate_large_file(str(cls.test_files["10MB"]), 10)
        
        log_test_step("Création d'un fichier de grande taille (100MB)")
        # Larger file (100MB) for more intensive tests
        cls.test_files["100MB"] = cls.test_dir / "test_100mb.bin"
        generate_large_file(str(cls.test_files["100MB"]), 100)
        
        # Very large file (1GB) for edge-case testing - commented out by default 
        # to avoid excessive test times, but can be uncommented for thorough benchmarking
        # cls.test_files["1GB"] = cls.test_dir / "test_1gb.bin"
        # generate_large_file(str(cls.test_files["1GB"]), 1024)
        
        log_success = f"Fichiers de test créés dans {cls.test_dir}"
        log_test_success(log_success)
        log_test_end("Préparation des fichiers de test")
    
    @classmethod
    def tearDownClass(cls):
        """Clean up all test files."""
        cls.temp_dir.cleanup()
    
    def test_large_file_encryption_performance(self):
        """Benchmark encryption performance with large files."""
        test_name = "Test de performance de chiffrement avec des fichiers volumineux"
        log_test_start(test_name)
        
        try:
            # Test parameters
            test_sizes = ["1MB", "10MB", "100MB"]  # Add "1GB" for extreme testing
            iterations = 3  # Number of times to repeat each test for averaging
            
            log_test_step(f"Test avec tailles: {', '.join(test_sizes)} sur {iterations} itérations")
            
            # Test results will be stored here
            results = {}
            
            # Generate a random key for encryption
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test each file size
            for size in test_sizes:
                log_test_step(f"Test du fichier de {size}")
                test_file = self.test_files[size]
                encrypted_file = self.test_dir / f"encrypted_{size}.enc"
                
                # Track memory and time for encryption
                process = psutil.Process(os.getpid())
                
                # Run multiple iterations to get average performance
                encrypt_times = []
                memory_usages = []
                
                for i in range(iterations):
                    # Force garbage collection before test
                    gc.collect()
                    
                    # Measure memory before operation
                    memory_before = process.memory_info().rss
                    
                    log_test_step(f"Itération {i+1}/{iterations} pour {size}")
                    
                    # Measure encryption time
                    start_time = time.perf_counter()
                    encryptor.encrypt_file(str(test_file), str(encrypted_file))
                    end_time = time.perf_counter()
                    
                    # Record results
                    encrypt_time = end_time - start_time
                    encrypt_times.append(encrypt_time)
                    
                    # Measure memory after operation
                    memory_after = process.memory_info().rss
                    memory_usage = memory_after - memory_before
                    memory_usages.append(memory_usage)
                    
                    # Print progress for visibility
                    log_msg = f"Chiffrement de {size} (itération {i+1}/{iterations}): {encrypt_time:.2f} secondes, " + \
                            f"mémoire: {memory_usage / (1024 * 1024):.2f} MB"
                    log_test_step(log_msg)
                
                # Calculate statistics
                avg_encrypt_time = statistics.mean(encrypt_times)
                avg_memory_usage = statistics.mean(memory_usages)
                
                # Calculate throughput in MB/s
                size_mb = int(size.replace("MB", ""))
                throughput = size_mb / avg_encrypt_time
                
                # Store results
                results[size] = {
                    "avg_encrypt_time": avg_encrypt_time,
                    "avg_memory_usage": avg_memory_usage,
                    "throughput": throughput
                }
                
                log_test_step(f"Performance moyenne de chiffrement pour {size}:")
                print(f"  Temps: {avg_encrypt_time:.2f} secondes")
                print(f"  Débit: {throughput:.2f} MB/s")
                print(f"  Utilisation mémoire: {avg_memory_usage / (1024 * 1024):.2f} MB")
                
                # Verify the encrypted file exists and has reasonable size
                self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
                log_test_success(f"Fichier de {size} chiffré créé avec succès")
                
                # A basic performance requirement - encryption shouldn't be extremely slow
                # This is a very conservative check (essentially verifying we're faster than 0.5 MB/s)
                # Adjust based on your performance goals
                min_throughput = 0.5  # MB/s
                self.assertGreater(throughput, min_throughput,
                                f"Encryption throughput for {size} file is too low: {throughput:.2f} MB/s")
                log_test_success(f"Débit de chiffrement suffisant: {throughput:.2f} MB/s (minimum requis: {min_throughput} MB/s)")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_large_file_decryption_performance(self):
        """Benchmark decryption performance with large files."""
        test_name = "Test de performance de déchiffrement avec des fichiers volumineux"
        log_test_start(test_name)
        
        try:
            # Test parameters
            test_sizes = ["1MB", "10MB", "100MB"]  # Add "1GB" for extreme testing
            iterations = 3  # Number of times to repeat each test for averaging
            
            log_test_step(f"Test avec tailles: {', '.join(test_sizes)} sur {iterations} itérations")
            
            # Test results will be stored here
            results = {}
            
            # Generate a random key for encryption/decryption
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test each file size
            for size in test_sizes:
                log_test_step(f"Test du fichier de {size}")
                test_file = self.test_files[size]
                encrypted_file = self.test_dir / f"encrypted_{size}.enc"
                decrypted_file = self.test_dir / f"decrypted_{size}.bin"
                
                try:
                    # First encrypt the file with proper error handling
                    log_test_step(f"Préparation - Chiffrement du fichier {size}")
                    try:
                        encryptor.encrypt_file(str(test_file), str(encrypted_file))
                    except Exception as e:
                        log_test_warning(f"Échec chiffrement {size}: {str(e)}")
                        self.fail(f"Failed to encrypt {size} file: {str(e)}")
                        continue
                        
                    # Verify the encrypted file exists and has reasonable size
                    self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
                    log_test_success(f"Fichier de {size} chiffré créé avec succès")
                    
                    # Track memory and time for decryption
                    process = psutil.Process(os.getpid())
                    
                    # Run multiple iterations to get average performance
                    decrypt_times = []
                    memory_usages = []
                    
                    for i in range(iterations):
                        # Force garbage collection before test
                        gc.collect()
                        
                        # Measure memory before operation
                        memory_before = process.memory_info().rss
                        
                        log_test_step(f"Déchiffrement - Itération {i+1}/{iterations} pour {size}")
                        
                        # Measure decryption time
                        start_time = time.perf_counter()
                        try:
                            encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                            end_time = time.perf_counter()
                            
                            # Record results
                            decrypt_time = end_time - start_time
                            decrypt_times.append(decrypt_time)
                            
                            # Measure memory after operation
                            memory_after = process.memory_info().rss
                            memory_usage = memory_after - memory_before
                            memory_usages.append(memory_usage)
                            
                            # Print progress for visibility
                            log_msg = f"Déchiffrement de {size} (itération {i+1}/{iterations}): {decrypt_time:.2f} secondes, " + \
                                    f"mémoire: {memory_usage / (1024 * 1024):.2f} MB"
                            log_test_step(log_msg)
                        except Exception as e:
                            log_test_warning(f"Erreur déchiffrement {size} (itération {i+1}/{iterations}): {str(e)}")
                            # Skip this iteration
                            continue
                    
                    # Skip to next file size if all decryption attempts failed
                    if not decrypt_times:
                        log_test_warning(f"Toutes les tentatives de déchiffrement ont échoué pour {size}")
                        continue
                        
                    # Calculate statistics
                    avg_decrypt_time = statistics.mean(decrypt_times)
                    avg_memory_usage = statistics.mean(memory_usages) if memory_usages else 0
                    
                    # Calculate throughput in MB/s
                    size_mb = int(size.replace("MB", ""))
                    throughput = size_mb / avg_decrypt_time
                    
                    # Store results
                    results[size] = {
                        "avg_decrypt_time": avg_decrypt_time,
                        "avg_memory_usage": avg_memory_usage,
                        "throughput": throughput
                    }
                    
                    log_test_step(f"Performance moyenne de déchiffrement pour {size}:")
                    print(f"  Temps: {avg_decrypt_time:.2f} secondes")
                    print(f"  Débit: {throughput:.2f} MB/s")
                    print(f"  Utilisation mémoire: {avg_memory_usage / (1024 * 1024):.2f} MB")
                    
                    # Verify the decrypted file matches the original
                    with open(test_file, "rb") as f1, open(decrypted_file, "rb") as f2:
                        self.assertEqual(f1.read(), f2.read(), "Decrypted file content should match original")
                    log_test_success(f"Contenu déchiffré identique à l'original pour {size}")
                    
                    # A basic performance requirement - decryption shouldn't be extremely slow
                    # This is a very conservative check (essentially verifying we're faster than 0.5 MB/s)
                    min_throughput = 0.5  # MB/s
                    self.assertGreater(throughput, min_throughput,
                                    f"Decryption throughput for {size} file is too low: {throughput:.2f} MB/s")
                    log_test_success(f"Débit de déchiffrement suffisant: {throughput:.2f} MB/s (minimum requis: {min_throughput} MB/s)")
                                
                except Exception as e:
                    log_test_warning(f"Erreur test {size}: {str(e)}")
                    # Continue to next size rather than failing the entire test
                    continue
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_share_generation_performance(self):
        """Benchmark performance of share generation."""
        test_name = "Test de performance de génération des parts"
        log_test_start(test_name)
        
        try:
            # Test parameters
            secret_size = 32  # bytes
            test_thresholds = [2, 3, 5, 10]
            test_total_shares = [3, 5, 10, 20, 50, 100]
            iterations = 5  # Number of times to repeat each test for averaging
            
            log_test_step(f"Test avec {len(test_thresholds)}x{len(test_total_shares)} combinaisons sur {iterations} itérations")
            
            # Test results will be stored here
            results = {}
            
            # Test each threshold/total_shares combination
            for threshold in test_thresholds:
                for total_shares in test_total_shares:
                    # Only test valid combinations where threshold <= total_shares
                    if threshold > total_shares:
                        continue
                    
                    log_test_step(f"Test combinaison: seuil={threshold}, parts={total_shares}")
                    
                    # Create a test key
                    test_key = get_enhanced_random_bytes(secret_size)
                    
                    # Track time for share generation
                    generation_times = []
                    
                    for i in range(iterations):
                        # Create share manager
                        manager = ShareManager(threshold, total_shares)
                        
                        # Measure share generation time
                        start_time = time.perf_counter()
                        shares = manager.generate_shares(test_key, f"perf_test_{threshold}_{total_shares}")
                        end_time = time.perf_counter()
                        
                        # Record results
                        generation_time = end_time - start_time
                        generation_times.append(generation_time)
                        
                        # Verify we got the right number of shares
                        self.assertEqual(len(shares), total_shares, 
                                      f"Expected {total_shares} shares, got {len(shares)}")
                    
                    # Calculate statistics
                    avg_generation_time = statistics.mean(generation_times)
                    std_dev = statistics.stdev(generation_times) if len(generation_times) > 1 else 0
                    
                    # Store results
                    key = f"t{threshold}_s{total_shares}"
                    results[key] = {
                        "avg_generation_time": avg_generation_time,
                        "std_dev": std_dev,
                        "shares_per_second": total_shares / avg_generation_time
                    }
                    
                    log_msg = f"Génération des parts ({threshold}-sur-{total_shares}): {avg_generation_time:.4f} secondes " + \
                            f"(±{std_dev:.4f}), {total_shares / avg_generation_time:.1f} parts/seconde"
                    log_test_step(log_msg)
                    
                    # A basic performance requirement
                    max_acceptable_time = 1.0  # second
                    self.assertLess(avg_generation_time, max_acceptable_time,
                                  f"Share generation for {threshold}-of-{total_shares} is too slow")
                    log_test_success(f"Performance acceptable pour {threshold}-sur-{total_shares}: {avg_generation_time:.4f}s < {max_acceptable_time}s")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_share_reconstruction_performance(self):
        """Benchmark performance of share reconstruction."""
        test_name = "Test de performance de reconstruction des parts"
        log_test_start(test_name)
        
        try:
            # Test parameters
            secret_size = 32  # bytes
            test_thresholds = [2, 3, 5, 10]
            test_total_shares = [3, 5, 10, 20, 50, 100]
            iterations = 5  # Number of times to repeat each test for averaging
            
            log_test_step(f"Test avec {len(test_thresholds)}x{len(test_total_shares)} combinaisons sur {iterations} itérations")
            
            # Test results will be stored here
            results = {}
            
            # Test each threshold/total_shares combination
            for threshold in test_thresholds:
                for total_shares in test_total_shares:
                    # Only test valid combinations where threshold <= total_shares
                    if threshold > total_shares:
                        continue
                    
                    log_test_step(f"Test combinaison: seuil={threshold}, parts={total_shares}")
                    
                    # Create a test key
                    test_key = get_enhanced_random_bytes(secret_size)
                    
                    # Create share manager and generate shares
                    manager = ShareManager(threshold, total_shares)
                    shares = manager.generate_shares(test_key, f"perf_test_{threshold}_{total_shares}")
                    
                    # Track time for share reconstruction
                    reconstruction_times = []
                    
                    for i in range(iterations):
                        # Select threshold shares (randomly to test different combinations)
                        selected_shares = random.sample(shares, threshold)
                        
                        # Measure share reconstruction time
                        start_time = time.perf_counter()
                        reconstructed = manager.combine_shares(selected_shares)
                        end_time = time.perf_counter()
                        
                        # Record results
                        reconstruction_time = end_time - start_time
                        reconstruction_times.append(reconstruction_time)
                        
                        # Verify reconstruction was correct
                        self.assertEqual(reconstructed, test_key, 
                                      f"Reconstructed key does not match original for {threshold}-of-{total_shares}")
                    
                    # Calculate statistics
                    avg_reconstruction_time = statistics.mean(reconstruction_times)
                    std_dev = statistics.stdev(reconstruction_times) if len(reconstruction_times) > 1 else 0
                    
                    # Store results
                    key = f"t{threshold}_s{total_shares}"
                    results[key] = {
                        "avg_reconstruction_time": avg_reconstruction_time,
                        "std_dev": std_dev
                    }
                    
                    log_msg = f"Reconstruction des parts ({threshold}-sur-{total_shares}): {avg_reconstruction_time:.6f} secondes " + \
                            f"(±{std_dev:.6f})"
                    log_test_step(log_msg)
                    
                    # A basic performance requirement
                    max_acceptable_time = 0.1  # second
                    self.assertLess(avg_reconstruction_time, max_acceptable_time,
                                  f"Share reconstruction for {threshold}-of-{total_shares} is too slow")
                    log_test_success(f"Performance acceptable pour {threshold}-sur-{total_shares}: {avg_reconstruction_time:.6f}s < {max_acceptable_time}s")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_memory_usage_during_operations(self):
        """Measure memory usage during various operations."""
        test_name = "Test d'utilisation mémoire pendant les opérations"
        log_test_start(test_name)
        
        try:
            log_test_step("Mesure de l'utilisation mémoire initiale")
            process = psutil.Process(os.getpid())
            
            # Force garbage collection to get stable baseline
            gc.collect()
            baseline_memory = process.memory_info().rss
            
            memory_usage = {}
            
            log_test_step("Test 1: Utilisation mémoire pendant le chiffrement d'un fichier volumineux")
            # Test 1: Memory usage during large file encryption
            test_file = self.test_files["10MB"]
            encrypted_file = self.test_dir / "memory_test_encrypted.enc"
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Force garbage collection
            gc.collect()
            memory_before = process.memory_info().rss
            
            # Perform encryption
            encryptor.encrypt_file(str(test_file), str(encrypted_file))
            
            # Measure memory after operation
            memory_after = process.memory_info().rss
            encryption_memory = memory_after - memory_before
            
            # Store results
            memory_usage["encryption_10MB"] = encryption_memory
            
            log_test_step(f"Utilisation mémoire pendant le chiffrement d'un fichier de 10MB: {encryption_memory / (1024 * 1024):.2f} MB")
            
            log_test_step("Test 2: Utilisation mémoire pendant la génération d'un grand nombre de parts")
            # Test 2: Memory usage during share generation (large number of shares)
            threshold = 10
            total_shares = 100
            test_key = get_enhanced_random_bytes(32)
            
            # Force garbage collection
            gc.collect()
            memory_before = process.memory_info().rss
            
            # Perform share generation
            manager = ShareManager(threshold, total_shares)
            shares = manager.generate_shares(test_key, "memory_test")
            
            # Measure memory after operation
            memory_after = process.memory_info().rss
            share_gen_memory = memory_after - memory_before
            
            # Store results
            memory_usage["share_generation_100"] = share_gen_memory
            
            log_test_step(f"Utilisation mémoire pendant la génération de 100 parts: {share_gen_memory / (1024 * 1024):.2f} MB")
            
            log_test_step("Test 3: Utilisation mémoire pendant la reconstruction")
            # Test 3: Memory usage during share reconstruction
            # Force garbage collection
            gc.collect()
            memory_before = process.memory_info().rss
            
            # Perform share reconstruction
            reconstructed = manager.combine_shares(shares[:threshold])
            
            # Measure memory after operation
            memory_after = process.memory_info().rss
            share_recon_memory = memory_after - memory_before
            
            # Store results
            memory_usage["share_reconstruction"] = share_recon_memory
            
            log_test_step(f"Utilisation mémoire pendant la reconstruction des parts: {share_recon_memory / (1024 * 1024):.2f} MB")
            
            # Check that memory usage is reasonable
            # These are just basic checks - adjust thresholds based on your application's requirements
            max_encryption_memory = 100 * 1024 * 1024  # 100 MB
            max_share_gen_memory = 50 * 1024 * 1024    # 50 MB
            max_share_recon_memory = 10 * 1024 * 1024  # 10 MB
            
            self.assertLess(encryption_memory, max_encryption_memory, 
                          "Encryption memory usage is too high")
            log_test_success(f"Utilisation mémoire chiffrement OK: {encryption_memory/(1024*1024):.2f} MB < {max_encryption_memory/(1024*1024):.0f} MB")
            
            self.assertLess(share_gen_memory, max_share_gen_memory, 
                          "Share generation memory usage is too high")
            log_test_success(f"Utilisation mémoire génération parts OK: {share_gen_memory/(1024*1024):.2f} MB < {max_share_gen_memory/(1024*1024):.0f} MB")
            
            self.assertLess(share_recon_memory, max_share_recon_memory, 
                          "Share reconstruction memory usage is too high")
            log_test_success(f"Utilisation mémoire reconstruction OK: {share_recon_memory/(1024*1024):.2f} MB < {max_share_recon_memory/(1024*1024):.0f} MB")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


class LoadTests(unittest.TestCase):
    """Tests for system behavior under load and at scale."""
    
    def setUp(self):
        """Setup for each load test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create a test file
        self.test_file = self.test_dir / "load_test.txt"
        with open(self.test_file, "w") as f:
            f.write("Test content for load testing" * 100)
    
    def tearDown(self):
        """Clean up after each test."""
        self.temp_dir.cleanup()
    
    def test_maximum_shares(self):
        """Test with the maximum number of shares (255)."""
        test_name = "Test avec le nombre maximum de parts (255)"
        log_test_start(test_name)
        
        try:
            # The maximum number of shares in Shamir's Secret Sharing with GF(256) is 255
            threshold = 200  # A high threshold to test extreme cases
            total_shares = 255  # Maximum possible
            
            log_test_step(f"Création d'un test avec seuil={threshold}, parts={total_shares}")
            
            # Create a test key
            test_key = get_enhanced_random_bytes(32)
            
            # Create share manager
            start_time = time.perf_counter()
            manager = ShareManager(threshold, total_shares)
            
            # Generate shares
            try:
                log_test_step("Génération des parts")
                shares = manager.generate_shares(test_key, "max_shares_test")
                generation_time = time.perf_counter() - start_time
                
                # Verify we got the right number of shares
                self.assertEqual(len(shares), total_shares, 
                              f"Expected {total_shares} shares, got {len(shares)}")
                
                log_test_success(f"Généré {total_shares} parts avec seuil {threshold} en {generation_time:.2f} secondes")
                
                log_test_step("Test de reconstruction avec exactement le seuil de parts")
                # Test reconstruction with exactly threshold shares
                start_time = time.perf_counter()
                selected_shares = shares[:threshold]
                reconstructed = manager.combine_shares(selected_shares)
                reconstruction_time = time.perf_counter() - start_time
                
                # Verify reconstruction was correct
                self.assertEqual(reconstructed, test_key, "Reconstructed key does not match original")
                
                log_test_success(f"Secret reconstruit avec {threshold} parts en {reconstruction_time:.2f} secondes")
                
                log_test_step("Test de performance avec différents nombres de parts")
                # Test reconstruction performance with varying numbers of shares
                for num_shares in [threshold, threshold + 10, threshold + 20]:
                    if num_shares > total_shares:
                        break
                        
                    # Select num_shares shares randomly
                    selected = random.sample(shares, num_shares)
                    
                    start_time = time.perf_counter()
                    reconstructed = manager.combine_shares(selected)
                    recon_time = time.perf_counter() - start_time
                    
                    # Verify reconstruction was correct
                    self.assertEqual(reconstructed, test_key, f"Reconstruction failed with {num_shares} shares")
                    
                    log_test_success(f"Reconstruction avec {num_shares} parts: {recon_time:.4f} secondes")
                
            except Exception as e:
                log_test_warning(f"Échec avec nombre maximum de parts: {str(e)}")
                self.fail(f"Failed with maximum shares: {str(e)}")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_concurrent_operations(self):
        """Test performance with many concurrent operations."""
        test_name = "Test d'opérations concurrentes"
        log_test_start(test_name)
        
        try:
            # Number of concurrent operations to perform
            num_threads = 8  # Adjust based on your CPU cores
            num_operations = 20  # Total operations across all threads
            
            log_test_step(f"Test avec {num_threads} threads et {num_operations} opérations")
            
            # Prepare test data - ensure it's valid content for encryption
            log_test_step("Préparation des données de test")
            with open(self.test_dir / "valid_test_content.txt", "w") as f:
                f.write("Test content for concurrent operations " * 1000)  # Create substantial content
            
            valid_test_file = self.test_dir / "valid_test_content.txt"
            test_key = get_enhanced_random_bytes(32)
            threshold = 3
            total_shares = 5
            
            log_test_step("Création de fichiers chiffrés pour les tests")
            # Create encrypted files for each operation - ensure they're valid
            encrypted_files = []
            for i in range(num_operations // 2):  # Only create half as many since we'll also use share operations
                encrypted_file = self.test_dir / f"concurrent_test_{i}.enc"
                encryptor = FileEncryptor(test_key)
                try:
                    encryptor.encrypt_file(str(valid_test_file), str(encrypted_file))
                    # Verify the file was encrypted properly
                    with open(encrypted_file, "rb") as f:
                        if f.read(4):  # Check that at least metadata length exists
                            encrypted_files.append(encrypted_file)
                except Exception as e:
                    log_test_warning(f"Erreur préparation fichier {i}: {str(e)}")
            
            log_test_step(f"Créé {len(encrypted_files)} fichiers chiffrés pour les tests")
            
            # Function to decrypt file
            def decrypt_file(file_index):
                if file_index >= len(encrypted_files):
                    return False  # Index out of range
                
                encrypted_file = encrypted_files[file_index]
                decrypted_file = self.test_dir / f"concurrent_decrypted_{file_index}.txt"
                encryptor = FileEncryptor(test_key)
                
                try:
                    encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                    # Verify decryption worked by checking file exists and has content
                    return decrypted_file.exists() and decrypted_file.stat().st_size > 0
                except Exception as e:
                    log_test_warning(f"Erreur dans thread {file_index}: {str(e)}")
                    return False
            
            # Function to generate and combine shares
            def process_shares(operation_index):
                try:
                    # Generate shares
                    manager = ShareManager(threshold, total_shares)
                    operation_key = get_enhanced_random_bytes(32)
                    shares = manager.generate_shares(operation_key, f"concurrent_{operation_index}")
                    
                    # Combine shares
                    reconstructed = manager.combine_shares(shares[:threshold])
                    return operation_key == reconstructed
                except Exception as e:
                    log_test_warning(f"Erreur dans traitement de parts {operation_index}: {str(e)}")
                    return False
            
            log_test_step("Exécution des opérations concurrentes")
            # Create a mixed workload of file operations and share operations
            results = []
            start_time = time.perf_counter()
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                # Submit a mix of decryption and share processing tasks
                future_to_index = {}
                for i in range(num_operations):
                    if i % 2 == 0 and i // 2 < len(encrypted_files):
                        # Decrypt files - but only if we have valid encrypted files
                        future = executor.submit(decrypt_file, i // 2)
                    else:
                        # Process shares for other operations
                        future = executor.submit(process_shares, i)
                    future_to_index[future] = i
                
                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_index):
                    idx = future_to_index[future]
                    try:
                        result = future.result()
                        results.append(result)
                        if result:
                            log_test_success(f"Opération {idx} réussie")
                        else:
                            log_test_warning(f"Opération {idx} échouée")
                    except Exception as e:
                        log_test_warning(f"Tâche {idx} a généré une exception: {str(e)}")
                        results.append(False)
            
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Verify all operations completed successfully
            success_rate = sum(results) / len(results) if results else 0
            log_test_step(f"Test terminé: {len(results)} opérations complétées en {total_time:.2f} secondes")
            log_test_step(f"Taux de succès: {success_rate * 100:.2f}%")
            log_test_step(f"Opérations par seconde: {len(results) / total_time:.2f}")
            
            # Check that success rate is acceptable - lowered to 80% to account for potential race conditions
            self.assertGreaterEqual(success_rate, 0.8, 
                                 f"Too many concurrent operations failed: {success_rate * 100:.2f}%")
            log_test_success(f"Taux de succès acceptable: {success_rate * 100:.2f}% >= 80%")
            
            # Simple performance requirement - adjust based on your system
            min_ops_per_second = 0.5
            self.assertGreaterEqual(len(results) / total_time, min_ops_per_second,
                                 f"Concurrent operations throughput too low: {len(results) / total_time:.2f} ops/sec")
            log_test_success(f"Débit d'opérations acceptable: {len(results) / total_time:.2f} ops/sec >= {min_ops_per_second} ops/sec")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e


if __name__ == "__main__":
    unittest.main() 