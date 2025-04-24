#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import platform
import subprocess
import sys
from pathlib import Path

def main():
    """Detect the operating system and run the appropriate setup script."""
    system = platform.system().lower()
    
    print("Detecting operating system...")
    
    # Get the directory where this script is located
    script_dir = Path(__file__).parent.absolute()
    
    if system == "darwin":  # macOS
        print("macOS detected. Running setup-python.sh...")
        script_path = os.path.join(script_dir, "setup-python.sh")
        
        if not os.path.exists(script_path):
            print(f"Error: {script_path} not found.")
            return 1
        
        # Make the script executable
        try:
            os.chmod(script_path, 0o755)
        except Exception as e:
            print(f"Error making script executable: {e}")
            return 1
        
        # Run the script
        try:
            # Using bash directly to ensure proper execution
            result = subprocess.run(["/bin/bash", script_path], check=True)
            return result.returncode
        except subprocess.CalledProcessError as e:
            print(f"Error running setup script: {e}")
            return e.returncode
        except Exception as e:
            print(f"Unexpected error: {e}")
            return 1
    
    elif system == "linux":
        print("Linux detected. Running setup-python-linux.sh...")
        script_path = os.path.join(script_dir, "setup-python-linux.sh")
        
        if not os.path.exists(script_path):
            print(f"Error: {script_path} not found.")
            return 1
        
        # Make the script executable
        try:
            os.chmod(script_path, 0o755)
        except Exception as e:
            print(f"Error making script executable: {e}")
            return 1
        
        # Run the script
        try:
            # Using bash directly to ensure proper execution
            result = subprocess.run(["/bin/bash", script_path], check=True)
            return result.returncode
        except subprocess.CalledProcessError as e:
            print(f"Error running setup script: {e}")
            return e.returncode
        except Exception as e:
            print(f"Unexpected error: {e}")
            return 1
    
    elif system == "windows":
        print("Windows detected. Running setup-python-windows.bat...")
        script_path = os.path.join(script_dir, "setup-python-windows.bat")
        
        if not os.path.exists(script_path):
            print(f"Error: {script_path} not found.")
            return 1
        
        # Run the script
        try:
            # Using cmd directly for Windows
            result = subprocess.run(["cmd", "/c", script_path], check=True)
            return result.returncode
        except subprocess.CalledProcessError as e:
            print(f"Error running setup script: {e}")
            return e.returncode
        except Exception as e:
            print(f"Unexpected error: {e}")
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