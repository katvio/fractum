#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script to run all Fractum tests in a single command.
This script executes all unit test files and displays a results report.
"""

import importlib
import sys
import time
import unittest
from collections import defaultdict
from pathlib import Path

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_header(message):
    """Print a formatted header."""
    print(f"\n{BOLD}{BLUE}{'=' * 80}{RESET}")
    print(f"{BOLD}{BLUE}= {message}{RESET}")
    print(f"{BOLD}{BLUE}{'=' * 80}{RESET}\n")


def print_result(success, message):
    """Print a formatted result message."""
    if success:
        print(f"{GREEN}✓ {message}{RESET}")
    else:
        print(f"{RED}✗ {message}{RESET}")


def find_test_files():
    """Find all test files in the current directory."""
    test_files = []
    # Use the directory where this script is located
    script_dir = Path(__file__).parent
    for file in script_dir.glob("test_*.py"):
        if file.is_file() and file.stem != "test_all" and file.stem != "run_tests":
            test_files.append(file.stem)

    # Make sure tests are executed in a deterministic order
    test_files.sort()
    return test_files


def run_tests():
    """Run all test files and return the results."""
    start_time = time.time()
    test_files = find_test_files()

    if not test_files:
        print(f"{RED}No test files found!{RESET}")
        return False

    print_header(f"RUNNING ALL FRACTUM TESTS ({len(test_files)} files)")

    # Store results for summary
    results = defaultdict(int)
    detailed_results = []

    # Run each test file
    for i, test_file in enumerate(test_files):
        try:
            print_header(f"[{i + 1}/{len(test_files)}] RUNNING {test_file}")

            # Import the test module
            test_module = importlib.import_module(test_file)

            # Create a test suite and run it
            test_suite = unittest.defaultTestLoader.loadTestsFromModule(test_module)
            test_runner = unittest.TextTestRunner(verbosity=2)
            test_result = test_runner.run(test_suite)

            # Store results
            file_success = test_result.wasSuccessful()
            results["files"] += 1
            results["success"] += file_success
            results["fail"] += not file_success
            results["errors"] += len(test_result.errors)
            results["failures"] += len(test_result.failures)
            results["tests"] += test_result.testsRun

            detailed_results.append(
                {
                    "file": test_file,
                    "success": file_success,
                    "tests": test_result.testsRun,
                    "failures": len(test_result.failures),
                    "errors": len(test_result.errors),
                }
            )

            # Print result for this file
            if file_success:
                print_result(True, f"{test_file}: ALL TESTS PASSED")
            else:
                print_result(
                    False,
                    f"{test_file}: FAILED ({len(test_result.failures)} failures, {len(test_result.errors)} errors)",
                )

        except Exception as e:
            print(f"{RED}Error running {test_file}: {str(e)}{RESET}")
            results["files"] += 1
            results["fail"] += 1
            detailed_results.append(
                {
                    "file": test_file,
                    "success": False,
                    "tests": 0,
                    "failures": 0,
                    "errors": 1,
                    "exception": str(e),
                }
            )

    # Calculate elapsed time
    elapsed_time = time.time() - start_time

    # Print summary
    print_header("TEST SUMMARY")

    print(f"{BOLD}Total time:{RESET} {elapsed_time:.2f} seconds")
    print(f"{BOLD}Test files:{RESET} {results['files']}")
    print(f"{BOLD}Tests run:{RESET} {results['tests']}")
    print(f"{BOLD}Files passed:{RESET} {results['success']}/{results['files']}")

    if results["fail"] > 0:
        print(f"{RED}{BOLD}Files failed:{RESET} {results['fail']}/{results['files']}")
        print(f"{RED}{BOLD}Failures:{RESET} {results['failures']}")
        print(f"{RED}{BOLD}Errors:{RESET} {results['errors']}")

        # Print details of failed tests
        print(f"\n{BOLD}Failure details:{RESET}")
        for result in detailed_results:
            if not result["success"]:
                file_name = result["file"]
                if "exception" in result:
                    print(
                        f"{RED}- {file_name}: Exception - {result['exception']}{RESET}"
                    )
                else:
                    print(
                        f"{RED}- {file_name}: {result['failures']} failures, {result['errors']} errors{RESET}"
                    )

    overall_success = results["fail"] == 0
    print_result(overall_success, "TESTS COMPLETED")

    return overall_success


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
