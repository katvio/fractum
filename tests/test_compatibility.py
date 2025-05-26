#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
import sys
import os
import platform
import tempfile
import importlib.util
import socket
from pathlib import Path

# Import from the src module
from src import (
    ShareManager,
    FileEncryptor,
    get_enhanced_random_bytes
)

# Colors for logs
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
    """Display a test start message."""
    print(f"\n{LogColors.BLUE}{LogColors.BOLD}▶ STARTING: {test_name}{LogColors.ENDC}")

def log_test_step(step_description):
    """Display a test step."""
    print(f"{LogColors.CYAN}  ↳ {step_description}{LogColors.ENDC}")

def log_test_success(message):
    """Display a success message."""
    print(f"{LogColors.GREEN}  ✓ SUCCESS: {message}{LogColors.ENDC}")

def log_test_warning(message):
    """Display a warning message."""
    print(f"{LogColors.YELLOW}  ⚠ WARNING: {message}{LogColors.ENDC}")

def log_test_skip(message):
    """Display a skipped test message."""
    print(f"{LogColors.YELLOW}  ⚡ SKIPPED: {message}{LogColors.ENDC}")

def log_test_end(test_name, success=True):
    """Display a test end message."""
    if success:
        print(f"{LogColors.GREEN}{LogColors.BOLD}✓ FINISHED: {test_name} - Passed{LogColors.ENDC}")
    else:
        print(f"{LogColors.RED}{LogColors.BOLD}✗ FINISHED: {test_name} - Failed{LogColors.ENDC}")

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
        test_name = f"Compatibility test with {platform.system()}"
        log_test_start(test_name)
        
        try:
            log_test_step("Preparing OS compatibility tests")
            # This test runs on the current OS and checks that basic operations work
            self.encrypted_file = self.test_dir / "os_test.enc"
            
            log_test_step("Generating a key and encrypting a file")
            # Generate a key and encrypt a file
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test encryption
            encryptor.encrypt_file(str(self.test_file), str(self.encrypted_file))
            self.assertTrue(self.encrypted_file.exists(), "Encrypted file should exist")
            log_test_success("Encrypted file created successfully")
            
            log_test_step("Decrypting the file and verifying integrity")
            # Test decryption
            decrypted_file = self.test_dir / "os_test_dec.txt"
            encryptor.decrypt_file(str(self.encrypted_file), str(decrypted_file))
            self.assertTrue(decrypted_file.exists(), "Decrypted file should exist")
            
            # Verify content matches
            with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
            log_test_success("Decrypted content identical to original")
            
            log_test_step("Testing share generation and reconstruction")
            # Test share generation and reconstruction
            manager = ShareManager(3, 5)
            shares = manager.generate_shares(key, "os_test")
            reconstructed_key = manager.combine_shares(shares[:3])
            self.assertEqual(key, reconstructed_key, "Key reconstruction should work on the current OS")
            log_test_success("Share reconstruction functional on this OS")
            
            # Report which OS this test passed on
            os_info = f"{platform.system()} {platform.release()}"
            log_test_success(f"Tests passed on: {os_info}")
            
            if self.current_os == "darwin":
                log_test_success("macOS compatibility confirmed")
            elif self.current_os == "linux":
                log_test_success("Linux compatibility confirmed")
            elif self.current_os == "windows":
                log_test_success("Windows compatibility confirmed")
                
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_os_specific_path_handling(self):
        """Test OS-specific path handling."""
        test_name = "OS-specific path handling test"
        log_test_start(test_name)
        
        try:
            log_test_step("Creating a nested directory structure")
            # Create subdirectories to test path handling
            subdir = self.test_dir / "sub" / "dir" / "test"
            subdir.mkdir(parents=True, exist_ok=True)
            
            # Create a test file in the subdirectory
            test_file_in_subdir = subdir / "nested_test.txt"
            with open(test_file_in_subdir, "w") as f:
                f.write("Test content in nested directory")
            log_test_success("Directory structure and test file created")
            
            log_test_step("Encrypting with a nested path")
            # Generate a key and encrypt a file using the nested path
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test encryption with nested path
            encrypted_file = subdir / "nested_test.enc"
            encryptor.encrypt_file(str(test_file_in_subdir), str(encrypted_file))
            self.assertTrue(encrypted_file.exists(), "Encrypted file should exist in nested directory")
            log_test_success("Encrypted file created in nested directory")
            
            log_test_step("Decrypting with a nested path")
            # Test decryption with nested path
            decrypted_file = subdir / "nested_test_dec.txt"
            encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
            self.assertTrue(decrypted_file.exists(), "Decrypted file should exist in nested directory")
            log_test_success("Decrypted file created in nested directory")
            
            # Verify content matches
            with open(test_file_in_subdir, "r") as f1, open(decrypted_file, "r") as f2:
                self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original in nested directory")
            log_test_success("Decrypted content identical to original in nested directory")
            
            log_test_step(f"Using {platform.system()} path separator: {os.path.sep}")
            log_test_success(f"{platform.system()}-specific path handling tested successfully")
            
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
        
        test_name = f"Compatibility test with Python {python_version}"
        log_test_start(test_name)
        
        try:
            # Check if the current version is 3.12.10 as specified
            is_target_version = (current_version.major == 3 and 
                                current_version.minor == 12 and 
                                current_version.micro == 10)
            
            if is_target_version:
                log_test_success(f"Running on target version: Python {python_version}")
            else:
                log_test_warning(f"Running on Python {python_version}, not on target version 3.12.10")
                # Skip this test if not running on the target version
                if not is_target_version:
                    log_test_skip("Test skipped because not on Python 3.12.10")
                    self.skipTest("Not running on Python 3.12.10")
            
            log_test_step("Testing basic functionality")
            # Test basic functionality
            self.temp_dir = tempfile.TemporaryDirectory()
            self.test_dir = Path(self.temp_dir.name)
            
            # Create a test file
            self.test_file = self.test_dir / "version_test.txt"
            with open(self.test_file, "w") as f:
                f.write("Test content for Python version compatibility")
            
            try:
                log_test_step("Key generation")
                # Test key generation
                key = get_enhanced_random_bytes(32)
                self.assertEqual(len(key), 32, "Key should be 32 bytes")
                log_test_success("Key generation successful")
                
                log_test_step("Encryption and decryption")
                # Test encryption and decryption
                encrypted_file = self.test_dir / "version_test.enc"
                encryptor = FileEncryptor(key)
                encryptor.encrypt_file(str(self.test_file), str(encrypted_file))
                log_test_success("Encryption successful")
                
                decrypted_file = self.test_dir / "version_test_dec.txt"
                encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                log_test_success("Decryption successful")
                
                # Verify content matches
                with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                    self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
                log_test_success(f"Encryption and decryption work on Python {python_version}")
                
                log_test_step("Testing Shamir's Secret Sharing")
                # Test Shamir's Secret Sharing
                manager = ShareManager(3, 5)
                shares = manager.generate_shares(key, "version_test")
                reconstructed_key = manager.combine_shares(shares[:3])
                self.assertEqual(key, reconstructed_key, "Key reconstruction should work on Python 3.12.10")
                log_test_success(f"Shamir's Secret Sharing works on Python {python_version}")
            
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
        test_name = "Offline operation test"
        log_test_start(test_name)
        
        try:
            log_test_step("Preparing the offline mode test")
            # Mock socket.socket to prevent any network connections
            # This simulates an offline environment
            original_socket = socket.socket
            
            def mock_socket(*args, **kwargs):
                # This raises an error for any socket connection attempt
                raise socket.error("Network connection disabled for offline test")
            
            log_test_step("Blocking network connections")
            # Patch socket.socket to use our mock
            socket.socket = mock_socket
            
            try:
                log_test_step("Generating a key and encrypting in offline mode")
                # Generate a key and encrypt a file
                key = get_enhanced_random_bytes(32)
                encryptor = FileEncryptor(key)
                
                # Test encryption
                encrypted_file = self.test_dir / "offline_test.enc"
                encryptor.encrypt_file(str(self.test_file), str(encrypted_file))
                self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
                log_test_success("Offline encryption successful")
                
                log_test_step("Decrypting in offline mode")
                # Test decryption
                decrypted_file = self.test_dir / "offline_test_dec.txt"
                encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
                self.assertTrue(decrypted_file.exists(), "Decrypted file should exist")
                log_test_success("Offline decryption successful")
                
                # Verify content matches
                with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                    self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
                log_test_success("Decrypted content identical to original")
                
                log_test_step("Testing secret sharing in offline mode")
                # Test share generation and reconstruction
                manager = ShareManager(3, 5)
                shares = manager.generate_shares(key, "offline_test")
                reconstructed_key = manager.combine_shares(shares[:3])
                self.assertEqual(key, reconstructed_key, "Key reconstruction should work offline")
                log_test_success("Secret sharing functional in offline mode")
                
                log_test_success("All operations completed successfully in offline mode")
            
            finally:
                # Restore original socket function
                socket.socket = original_socket
                log_test_step("Restoring network connections")
                
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
        test_name = "Dependency availability test"
        log_test_start(test_name)
        
        try:
            log_test_step("Checking required dependencies")
            missing_deps = []
            
            for dep in self.required_deps:
                log_test_step(f"Checking {dep}")
                parts = dep.split('.')
                root_module = parts[0]
                
                if not importlib.util.find_spec(root_module):
                    missing_deps.append(dep)
                    log_test_warning(f"Root module {root_module} not found")
                    continue
                
                try:
                    # Try to import the full module path
                    exec(f"import {dep}")
                    log_test_success(f"Module {dep} imported successfully")
                except ImportError:
                    missing_deps.append(dep)
                    log_test_warning(f"Unable to import {dep}")
            
            if missing_deps:
                self.fail(f"Missing required dependencies: {', '.join(missing_deps)}")
            
            log_test_success("All required dependencies are available")
            for dep in self.required_deps:
                log_test_success(f"Available: {dep}")
                
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e
    
    def test_minimal_functionality(self):
        """Test that basic functionality works with minimal dependencies."""
        test_name = "Minimal functionality test"
        log_test_start(test_name)
        
        try:
            log_test_step("Generating a key and encrypting")
            # Generate a key and encrypt a file
            key = get_enhanced_random_bytes(32)
            encryptor = FileEncryptor(key)
            
            # Test encryption
            encrypted_file = self.test_dir / "dependency_test.enc"
            encryptor.encrypt_file(str(self.test_file), str(encrypted_file))
            self.assertTrue(encrypted_file.exists(), "Encrypted file should exist")
            log_test_success("Encrypted file created successfully")
            
            log_test_step("Decrypting and verifying")
            # Test decryption
            decrypted_file = self.test_dir / "dependency_test_dec.txt"
            encryptor.decrypt_file(str(encrypted_file), str(decrypted_file))
            self.assertTrue(decrypted_file.exists(), "Decrypted file should exist")
            log_test_success("Decrypted file created successfully")
            
            # Verify content matches
            with open(self.test_file, "r") as f1, open(decrypted_file, "r") as f2:
                self.assertEqual(f1.read(), f2.read(), "Decrypted content should match original")
            log_test_success("Decrypted content identical to original")
            
            log_test_step("Testing secret sharing with minimal dependencies")
            # Test share generation and reconstruction
            manager = ShareManager(3, 5)
            shares = manager.generate_shares(key, "dependency_test")
            reconstructed_key = manager.combine_shares(shares[:3])
            self.assertEqual(key, reconstructed_key, "Key reconstruction should work with minimal dependencies")
            log_test_success("Key reconstruction successful with minimal dependencies")
            
            log_test_success("Basic functionality operational with minimal dependencies")
            
            log_test_end(test_name)
        except Exception as e:
            log_test_end(test_name, success=False)
            raise e

if __name__ == "__main__":
    unittest.main() 