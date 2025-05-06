# Fractum Tests - Documentation

This document describes the different test suites of the Fractum project and their purpose.

## Test Environment Setup

Before running tests, you need to set up the test environment:

### Bootstrap your environment:

Linux:
`chmod +x bootstrap-linux.sh && ./bootstrap-linux.sh && source .venv/bin/activate`

MacOS:
`chmod +x bootstrap-macos.sh && ./bootstrap-macos.sh && source .venv/bin/activate`

Windows:

* `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
* `.\bootstrap-windows.ps1`
* `.\.venv\Scripts\Activate.ps1`

### Activate venv and install psutil:
```
cd tests
```
```
pip install psutil
```

### Running Tests

To run all tests:

```
python run_tests.py
```

To run a specific test:

```
python test_fuzzing.py
```
## Running tests with Docker

To run tests in Docker:

### Build the Docker image for testing
```
cd fractum
```
```
docker build -t fractum-test -f tests/Dockerfile.test .
```
### Run all tests with docker
```
docker run --rm fractum-test
```

## Overview of the test suites

### 0. 'run_tests.py' (to run all tests)
The main test runner script that executes all test files in a single command:

- Automatically discovers all test files matching the pattern `test_*.py`
- Executes each test file in a deterministic order
- Collects and aggregates test results
- Provides a consolidated report showing:
  - Number of test files executed
  - Total tests run
  - Success/failure statistics
  - Execution time
  - Detailed failure information if any tests fail
- Returns appropriate exit code (0 for success, 1 for failure) for integration with CI/CD systems
Usage: Simply run `python run_tests.py` from the tests directory to execute all tests.


### 1. test_functional.py
Tests that verify the main functionalities of the application:

**CLIEndToEndTests**:

- `test_archive_creation_extraction`: Verifies that share archives are correctly created and can be extracted.
- `test_different_threshold_share_combinations`: Tests various threshold and share count combinations (2/3, 3/5, 5/10).
- `test_encrypt_decrypt_small_file`: Verifies encryption and decryption of small text files.
- `test_interactive_mode`: Tests interactive mode by simulating user inputs.

**CompatibilityTests**:

- `test_cross_platform_compatibility`: Verifies that shares generated on different platforms (Windows/Linux/macOS) work together.
- `test_file_format_compatibility`: Tests compatibility between different share file formats.
- `test_version_compatibility`: Ensures that share versions remain compatible with future versions.

**ErrorHandlingTests**:

- `test_corrupted_shares`: Verifies handling of corrupted shares.
- `test_file_access_issues`: Tests reactions to file access problems (permissions).
- `test_incorrect_keys`: Verifies behavior during decryption attempts with incorrect keys.
- `test_insufficient_shares`: Tests behavior when an insufficient number of shares is provided.

### 2. test_fuzzing.py
Tests the application's robustness against malformed inputs:

**InputFuzzingTests**:

- `test_encrypted_file_bit_flipping`: Modifies bits in encrypted files to verify corruption resistance.
- `test_invalid_utf8_sequences`: Introduces invalid UTF-8 sequences in labels and metadata.
- `test_malformed_json_shares`: Tests handling of malformed JSON files in shares.

**BoundaryTests**:

- `test_extreme_values`: Tests behavior with extreme threshold and share values.
- `test_large_files`: Verifies handling of unusually large files.
- `test_tiny_files`: Tests behavior with empty or very small files.

### 3. test_compatibility.py
In-depth compatibility tests:

**VersionCompatibilityTests**:

- `test_version_forward_compatibility`: Verifies that older share formats remain usable with newer versions.
- `test_version_metadata_handling`: Tests handling of different version formats in metadata.
- `test_version_mismatch_detection`: Ensures version mismatches are properly detected and reported.

**PlatformCompatibilityTests**:

- `test_os_specific_paths`: Tests compatibility with different operating system path formats.
- `test_platform_specific_features`: Ensures consistent behavior across different platforms.
- `test_cross_platform_file_handling`: Verifies correct file handling across platforms.

### 4. test_metadata_integrity.py
Verifies metadata integrity in files and shares:

**MetadataPersistenceTests**:

- `test_metadata_persistence`: Checks correct persistence of version, threshold, and share count data.
- `test_metadata_extraction`: Tests extraction of metadata from share files.
- `test_metadata_validation`: Verifies validation of metadata fields.

**IntegrityTests**:

- `test_integrity_hashes`: Verifies the correct implementation of integrity hashes.
- `test_hash_verification`: Tests verification of file and share hashes.
- `test_partial_corruption_recovery`: Tests recovery from partially corrupted metadata.

### 5. test_performance.py
Measures application performance:

**ScalingTests**:

- `test_file_size_scaling`: Tests speed with different file sizes.
- `test_share_count_scaling`: Measures performance with varying numbers of shares.
- `test_threshold_impact`: Evaluates the impact of threshold values on performance.

**ResourceTests**:

- `test_memory_usage`: Monitors memory usage during encryption/decryption.
- `test_cpu_utilization`: Measures CPU usage during cryptographic operations.
- `test_concurrent_operations`: Tests performance with multiple simultaneous operations.

### 6. test_security.py
Verifies critical security aspects:

**MemorySecurityTests**:

- `test_memory_isolation`: Tests memory isolation for sensitive data.
- `test_secure_key_erasure`: Verifies secure erasure of keys from memory.
- `test_memory_patterns`: Checks for sensitive patterns in memory dumps.

**DataLeakageTests**:

- `test_sensitive_data_leakage`: Detects leaks of sensitive data.
- `test_encrypted_content_analysis`: Analyzes encrypted content for information leakage.
- `test_crypto_randomness`: Verifies cryptographic randomness quality.

### 7. 'test_core_crypto.py'
Tests core cryptographic primitives:

**ShamirImplementationTests**:

- `test_shamir_algorithm`: Verifies correct implementation of Shamir's Secret Sharing algorithm.
- `test_threshold_behavior`: Tests behavior at the exact threshold value.
- `test_share_reconstruction`: Tests correct reconstruction of secrets from shares.

**EncryptionTests**:

- `test_aes_gcm_encryption`: Tests AES-GCM encryption/decryption.
- `test_nonce_uniqueness`: Verifies uniqueness of encryption nonces.
- `test_random_generation`: Verifies quality of random number generation.

## Docker Test Notes

Some tests may behave differently in Docker environments:

- The `test_file_access_issues` test may fail due to differences in permission handling.
- Memory tests might report different values due to containerization.
- Performance tests should be interpreted relative to the Docker environment rather than absolute values.

## Test Best Practices

1. **Isolation**: All tests create temporary directories to avoid affecting user files.

2. **Cleanup**: Temporary data is deleted after each test, even in case of failure.

3. **Verbosity**: Verbose mode helps diagnose problems by displaying execution details.

4. **Independence**: Each test is designed to run independently of others.

5. **Reproducibility**: Tests use predefined seeds for random generation when necessary. 