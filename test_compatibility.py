#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
import os
import platform
import tempfile
import shutil
import subprocess
import importlib.util
import socket
from unittest import mock
from pathlib import Path

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

class OSCompatibilityTests(unittest.TestCase):
    """Tests for OS compatibility."""
    
    def setUp(self):
        """Set up before each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        self.current_os = platform.system().lower()
        
        # Create a test file
        self.test_file = self.test_dir / "os_test.txt"
        with open(self.test_file, "w") as f:
            f.write("Test content for OS compatibility")
    
    def tearDown(self):
        """Clean up after each test."""
        self.temp_dir.cleanup()
    
    def test_current_os_compatibility(self):
        """Test compatibility with the current OS."""
        test_name = f"Test de compatibilité avec {platform.system()}"
        log_test_start(test_name)
        
        try:
            log_test_step("Préparation des tests de compatibilité OS")
            # This test runs on the current OS and checks that basic operations work
            self.encrypted_file = self.test_dir / "os_test.enc"
            
            log_test_step("Génération d'une clé et chiffrement d'un fichier")
            # Generate a key and encrypt a file
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test encryption
            encryptor.encrypt_file(str(self.test_file), str(self.encrypted_file))
            self.assertTrue(self.encrypted_file.exists(), "Encrypted file should exist")
            log_test_success("Fichier chiffré créé avec succès")
            
            log_test_step("Déchiffrement du fichier et vérification de l'intégrité")
            # Test decryption
            decrypted_file = self.test_dir / "os_test_dec.txt"
            encryptor.decrypt_file(str(self.encrypted_file), str(decrypted_file))
            self.assertTrue(decrypted_file.exists(), "Decrypted file should exist")
            
            # Verify content matches
            with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
            log_test_success("Contenu déchiffré identique à l'original")
            
            log_test_step("Test de génération et reconstruction des parts")
            # Test share generation and reconstruction
            manager = ShareManager(3, 5)
            shares = manager.generate_shares(key, "os_test")
            reconstructed_key = manager.combine_shares(shares[:3])
            self.assertEqual(key, reconstructed_key, "Key reconstruction should work on the current OS")
            log_test_success("Reconstruction des parts fonctionnelle sur cet OS")
            
            # Report which OS this test passed on
            os_info = f"{platform.system()} {platform.release()}"
            log_test_success(f"Tests passés sur: {os_info}")
            
            if self.current_os == "darwin":
                log_test_success("Compatibilité macOS confirmée")
            elif self.current_os == "linux":
                log_test_success("Compatibilité Linux confirmée")
            elif self.current_os == "windows":
                log_test_success("Compatibilité Windows confirmée")
                
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_os_specific_path_handling(self):
        """Test OS-specific path handling."""
        test_name = "Test de gestion des chemins spécifiques à l'OS"
        log_test_start(test_name)
        
        try:
            log_test_step("Création d'une structure de répertoires imbriqués")
            # Create subdirectories to test path handling
            subdir = self.test_dir / "sub" / "dir" / "test"
            subdir.mkdir(parents=True, exist_ok=True)
            
            # Create a test file in the subdirectory
            test_file_in_subdir = subdir / "nested_test.txt"
            with open(test_file_in_subdir, "w") as f:
                f.write("Test content in nested directory")
            log_test_success("Structure de répertoires et fichier test créés")
            
            log_test_step("Chiffrement avec un chemin imbriqué")
            # Generate a key and encrypt a file using the nested path
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test encryption with nested path
            encrypted_file = subdir / "nested_test.enc"
            encryptor.encrypt_file(str(test_file_in_subdir), str(encrypted_file))
            self.assertTrue(encrypted_file.exists(), "Encrypted file should exist in nested directory")
            log_test_success("Fichier chiffré créé dans le répertoire imbriqué")
            
            log_test_step("Déchiffrement avec un chemin imbriqué")
            # Test decryption with nested path
            decrypted_file = subdir / "nested_test_dec.txt"
            encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
            self.assertTrue(decrypted_file.exists(), "Decrypted file should exist in nested directory")
            log_test_success("Fichier déchiffré créé dans le répertoire imbriqué")
            
            # Verify content matches
            with open(test_file_in_subdir, "r") as f1, open(decrypted_file, "r") as f2:
                self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original in nested directory")
            log_test_success("Contenu déchiffré identique à l'original dans le répertoire imbriqué")
            
            log_test_step(f"Utilisation du séparateur de chemin de {platform.system()}: {os.path.sep}")
            log_test_success(f"Gestion des chemins spécifiques à {platform.system()} testée avec succès")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e

class PythonVersionTests(unittest.TestCase):
    """Tests for Python version compatibility."""
    
    def test_current_python_version(self):
        """Test compatibility with the current Python version."""
        # Get the current Python version
        current_version = sys.version_info
        python_version = f"{current_version.major}.{current_version.minor}.{current_version.micro}"
        
        test_name = f"Test de compatibilité avec Python {python_version}"
        log_test_start(test_name)
        
        try:
            # Check if the current version is 3.12.10 as specified
            is_target_version = (current_version.major == 3 and 
                                current_version.minor == 12 and 
                                current_version.micro == 10)
            
            if is_target_version:
                log_test_success(f"Exécution sur la version cible: Python {python_version}")
            else:
                log_test_warning(f"Exécution sur Python {python_version}, pas sur la version cible 3.12.10")
                # Skip this test if not running on the target version
                if not is_target_version:
                    log_test_skip("Test ignoré car pas sur Python 3.12.10")
                    self.skipTest("Not running on Python 3.12.10")
            
            log_test_step("Test des fonctionnalités de base")
            # Test basic functionality
            self.temp_dir = tempfile.TemporaryDirectory()
            self.test_dir = Path(self.temp_dir.name)
            
            # Create a test file
            self.test_file = self.test_dir / "version_test.txt"
            with open(self.test_file, "w") as f:
                f.write("Test content for Python version compatibility")
            
            try:
                log_test_step("Génération de clé")
                # Test key generation
                key = get_enhanced_random_bytes(32)
                self.assertEqual(len(key), 32, "Key should be 32 bytes")
                log_test_success("Génération de clé réussie")
                
                log_test_step("Chiffrement et déchiffrement")
                # Test encryption and decryption
                encrypted_file = self.test_dir / "version_test.enc"
                encryptor = FileEncryptor(key)
                encryptor.encrypt_file(str(self.test_file), str(encrypted_file))
                log_test_success("Chiffrement réussi")
                
                decrypted_file = self.test_dir / "version_test_dec.txt"
                encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                log_test_success("Déchiffrement réussi")
                
                # Verify content matches
                with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                    self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
                log_test_success(f"Chiffrement et déchiffrement fonctionnent sur Python {python_version}")
                
                log_test_step("Test du partage de secret de Shamir")
                # Test Shamir's Secret Sharing
                manager = ShareManager(3, 5)
                shares = manager.generate_shares(key, "version_test")
                reconstructed_key = manager.combine_shares(shares[:3])
                self.assertEqual(key, reconstructed_key, "Key reconstruction should work on Python 3.12.10")
                log_test_success(f"Partage de secret de Shamir fonctionne sur Python {python_version}")
            
            finally:
                # Clean up
                self.temp_dir.cleanup()
                
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e

class OfflineOperationTests(unittest.TestCase):
    """Tests for offline operation."""
    
    def setUp(self):
        """Set up before each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create a test file
        self.test_file = self.test_dir / "offline_test.txt"
        with open(self.test_file, "w") as f:
            f.write("Test content for offline operation")
    
    def tearDown(self):
        """Clean up after each test."""
        self.temp_dir.cleanup()
    
    def test_offline_operation(self):
        """Test that the application works offline."""
        test_name = "Test de fonctionnement hors ligne"
        log_test_start(test_name)
        
        try:
            log_test_step("Préparation du test en mode hors ligne")
            # Mock socket.socket to prevent any network connections
            # This simulates an offline environment
            original_socket = socket.socket
            
            def mock_socket(*args, **kwargs):
                # This raises an error for any socket connection attempt
                raise socket.error("Network connection disabled for offline test")
            
            log_test_step("Blocage des connexions réseau")
            # Patch socket.socket to use our mock
            socket.socket = mock_socket
            
            try:
                log_test_step("Génération d'une clé et chiffrement en mode hors ligne")
                # Generate a key and encrypt a file
                key = get_enhanced_random_bytes(32)
                encryptor = FileEncryptor(key)
                
                # Test encryption
                encrypted_file = self.test_dir / "offline_test.enc"
                encryptor.encrypt_file(str(self.test_file), str(encrypted_file))
                self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
                log_test_success("Chiffrement hors ligne réussi")
                
                log_test_step("Déchiffrement en mode hors ligne")
                # Test decryption
                decrypted_file = self.test_dir / "offline_test_dec.txt"
                encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                self.assertTrue(decrypted_file.exists(), "Decrypted file should exist")
                log_test_success("Déchiffrement hors ligne réussi")
                
                # Verify content matches
                with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                    self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
                log_test_success("Contenu déchiffré identique à l'original")
                
                log_test_step("Test du partage de secret en mode hors ligne")
                # Test share generation and reconstruction
                manager = ShareManager(3, 5)
                shares = manager.generate_shares(key, "offline_test")
                reconstructed_key = manager.combine_shares(shares[:3])
                self.assertEqual(key, reconstructed_key, "Key reconstruction should work offline")
                log_test_success("Partage de secret fonctionnel en mode hors ligne")
                
                log_test_success("Toutes les opérations complétées avec succès en mode hors ligne")
            
            finally:
                # Restore original socket function
                socket.socket = original_socket
                log_test_step("Restauration des connexions réseau")
                
            log_test_end(test_name)
        except Exception as e:
            # Make sure to restore socket before raising exception
            if 'original_socket' in locals():
                socket.socket = original_socket
            log_test_end(test_name, success=False)
            raise e

class MinimalDependencyTests(unittest.TestCase):
    """Tests for minimal dependency requirements."""
    
    def setUp(self):
        """Set up before each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create a test file
        self.test_file = self.test_dir / "dependency_test.txt"
        with open(self.test_file, "w") as f:
            f.write("Test content for dependency tests")
        
        # List of required dependencies
        self.required_deps = [
            "Crypto.Protocol.SecretSharing",
            "Crypto.Cipher.AES",
            "Crypto.Random",
            "click"
        ]
    
    def tearDown(self):
        """Clean up after each test."""
        self.temp_dir.cleanup()
    
    def test_dependency_availability(self):
        """Test that all required dependencies are available."""
        test_name = "Test de disponibilité des dépendances"
        log_test_start(test_name)
        
        try:
            log_test_step("Vérification des dépendances requises")
            missing_deps = []
            
            for dep in self.required_deps:
                log_test_step(f"Vérification de {dep}")
                parts = dep.split('.')
                root_module = parts[0]
                
                if not importlib.util.find_spec(root_module):
                    missing_deps.append(dep)
                    log_test_warning(f"Module racine {root_module} non trouvé")
                    continue
                
                try:
                    # Try to import the full module path
                    exec(f"import {dep}")
                    log_test_success(f"Module {dep} importé avec succès")
                except ImportError:
                    missing_deps.append(dep)
                    log_test_warning(f"Impossible d'importer {dep}")
            
            if missing_deps:
                self.fail(f"Missing required dependencies: {', '.join(missing_deps)}")
            
            log_test_success("Toutes les dépendances requises sont disponibles")
            for dep in self.required_deps:
                log_test_success(f"Disponible: {dep}")
                
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_minimal_functionality(self):
        """Test that basic functionality works with minimal dependencies."""
        test_name = "Test de fonctionnalité minimale"
        log_test_start(test_name)
        
        try:
            log_test_step("Génération d'une clé et chiffrement")
            # Generate a key and encrypt a file
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test encryption
            encrypted_file = self.test_dir / "dependency_test.enc"
            encryptor.encrypt_file(str(self.test_file), str(encrypted_file))
            self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
            log_test_success("Fichier chiffré créé avec succès")
            
            log_test_step("Déchiffrement et vérification")
            # Test decryption
            decrypted_file = self.test_dir / "dependency_test_dec.txt"
            encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
            self.assertTrue(decrypted_file.exists(), "Decrypted file should exist")
            log_test_success("Fichier déchiffré créé avec succès")
            
            # Verify content matches
            with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
            log_test_success("Contenu déchiffré identique à l'original")
            
            log_test_step("Test du partage de secret avec dépendances minimales")
            # Test share generation and reconstruction
            manager = ShareManager(3, 5)
            shares = manager.generate_shares(key, "dependency_test")
            reconstructed_key = manager.combine_shares(shares[:3])
            self.assertEqual(key, reconstructed_key, "Key reconstruction should work with minimal dependencies")
            log_test_success("Reconstruction de la clé réussie avec les dépendances minimales")
            
            log_test_success("Fonctionnalité de base opérationnelle avec les dépendances minimales")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e

if __name__ == "__main__":
    unittest.main() 