#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import platform
import subprocess
import sys

def main():
    """Detect the operating system and run the appropriate setup script."""
    system = platform.system().lower()
    
    print("Detecting operating system...")
    
    if system == "darwin":  # macOS
        print("macOS detected. Running setup-python.sh...")
        script_path = "setup-python.sh"
        if not os.path.exists(script_path):
            print(f"Error: {script_path} not found.")
            return 1
        
        # Make the script executable
        os.chmod(script_path, 0o755)
        
        # Run the script
        try:
            subprocess.run([f"./{script_path}"], shell=True, check=True)
            return 0
        except subprocess.CalledProcessError:
            print("Error running setup script.")
            return 1
    
    elif system == "linux":
        print("Linux detected. Running setup-python-linux.sh...")
        script_path = "setup-python-linux.sh"
        if not os.path.exists(script_path):
            print(f"Error: {script_path} not found.")
            return 1
        
        # Make the script executable
        os.chmod(script_path, 0o755)
        
        # Run the script
        try:
            subprocess.run([f"./{script_path}"], shell=True, check=True)
            return 0
        except subprocess.CalledProcessError:
            print("Error running setup script.")
            return 1
    
    elif system == "windows":
        print("Windows detected. Running setup-python-windows.bat...")
        script_path = "setup-python-windows.bat"
        if not os.path.exists(script_path):
            print(f"Error: {script_path} not found.")
            return 1
        
        # Run the script
        try:
            subprocess.run([script_path], shell=True, check=True)
            return 0
        except subprocess.CalledProcessError:
            print("Error running setup script.")
            return 1
    
    else:
        print(f"Unsupported operating system: {system}")
        print("Please run the appropriate setup script manually:")
        print("  - For macOS: ./setup-python.sh")
        print("  - For Linux: ./setup-python-linux.sh")
        print("  - For Windows: setup-python-windows.bat")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 