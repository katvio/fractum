import os
import shutil
import zipfile
from pathlib import Path

class ShareArchiver:
    """Archive manager for shares."""
    
    def __init__(self, base_dir: str = "shares"):
        """Initializes the archive manager.
        
        Args:
            base_dir (str): Base directory for archives
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        
    def create_share_archive(self, share_file: str, encrypted_file: str, share_share_index: int, label: str) -> str:
        """Creates a ZIP archive for a share.
        
        Args:
            share_file (str): Path to share file
            encrypted_file (str): Path to encrypted file
            share_share_index (int): Share share_index
            label (str): Share label
            
        Returns:
            str: Path to created ZIP archive
        """
        # Create temporary directory for archive
        temp_dir = self.base_dir / f"temp_share_{share_share_index}"
        temp_dir.mkdir(exist_ok=True)
        
        try:
            # Copy necessary files
            shutil.copy(share_file, temp_dir)
            shutil.copy(encrypted_file, temp_dir)
            
            # Copy project files if they exist
            files_to_copy = [
                ("README.md", "README.md"),
                ("requirements.txt", "requirements.txt"),
                ("LICENSE", "LICENSE"),
                ("setup.py", "setup.py"),
                (".dockerignore", ".dockerignore"),
                ("Dockerfile", "Dockerfile"),
                ("bootstrap-linux.sh", "bootstrap-linux.sh"),
                ("bootstrap-macos.sh", "bootstrap-macos.sh"),
                ("bootstrap-windows.ps1", "bootstrap-windows.ps1")
            ]
            
            for src, dst in files_to_copy:
                src_path = Path(src)
                if src_path.exists():
                    shutil.copy(src_path, temp_dir / dst)
            
            # Copy source code - Use absolute path based on __file__
            sss_dir = temp_dir / "src"
            sss_dir.mkdir(exist_ok=True)
            
            # Get the absolute path of the current module structure
            src_dir = Path(__file__).parent.parent
            
            # Recursively copy the src directory
            for src_file in src_dir.glob("**/*.py"):
                # Calculate relative path
                rel_path = src_file.relative_to(src_dir.parent)
                # Create target path
                dst_path = temp_dir / rel_path
                # Ensure parent directories exist
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                # Copy the file
                shutil.copy(src_file, dst_path)
            
            # Copy setup folder with all setup files
            setup_src_dir = Path("setup")
            if setup_src_dir.exists():
                setup_dst_dir = temp_dir / "setup"
                setup_dst_dir.mkdir(exist_ok=True)
                for setup_file in setup_src_dir.glob("*"):
                    if setup_file.is_file():
                        shutil.copy(setup_file, setup_dst_dir)
            
            # Create packages directory
            packages_dir = temp_dir / "packages"
            packages_dir.mkdir(exist_ok=True)
            
            # Copy packages
            packages_path = Path("packages")
            if packages_path.exists():
                for package_file in packages_path.glob("*.whl"):
                    shutil.copy(package_file, packages_dir)
            
            # Create ZIP archive with sequential naming
            base_name = f"share_{share_share_index}"
            archive_path = self.base_dir / f"{base_name}.zip"
            
            # Check if file already exists and generate unique name with simple numeric suffix
            counter = 2
            while archive_path.exists():
                archive_path = self.base_dir / f"{base_name}_{counter}.zip"
                counter += 1
            
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = Path(root) / file
                        arcname = file_path.relative_to(temp_dir)
                        zipf.write(file_path, arcname)
            
            return str(archive_path)
            
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir, ignore_errors=True)
