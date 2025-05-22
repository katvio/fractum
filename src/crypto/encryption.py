import json
import time
import hashlib
from Crypto.Cipher import AES

from src import VERSION

class FileEncryptor:
    def __init__(self, key: bytes):
        self.key = key
        self.version = VERSION

    def _write_metadata(self, f, data_hash: str, metadata: dict = None) -> None:
        """Writes metadata at the beginning of the file."""
        if metadata is None:
            metadata = {}
            
        # Ensure basic metadata is included
        metadata.update({
            'version': self.version,
            'timestamp': int(time.time()),
            'hash': data_hash
        })
            
        metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode('utf-8')
        f.write(len(metadata_bytes).to_bytes(4, 'big'))
        f.write(metadata_bytes)

    def _read_metadata(self, f) -> dict:
        """Reads metadata from the beginning of the file."""
        try:
            metadata_len = int.from_bytes(f.read(4), 'big')
            metadata_bytes = f.read(metadata_len)
            
            try:
                # First try with UTF-8 encoding
                metadata = json.loads(metadata_bytes.decode('utf-8'))
            except UnicodeDecodeError:
                # Fallback to latin-1 encoding with error replacement if UTF-8 fails
                try:
                    metadata = json.loads(metadata_bytes.decode('latin-1', errors='replace'))
                except json.JSONDecodeError:
                    # If JSON decoding fails, provide default metadata
                    metadata = {'version': self.version}
            except json.JSONDecodeError:
                # If JSON decoding fails, provide default metadata
                metadata = {'version': self.version}
            
            # Ensure version is included
            if 'version' not in metadata:
                metadata['version'] = self.version
            
            return metadata
        except Exception:
            # Last resort fallback for any other errors (like reading from corrupted file)
            return {'version': self.version}

    def encrypt_file(self, input_path: str, output_path: str, metadata: dict = None) -> None:
        """Encrypts a file with AES-256-GCM."""
        try:
            cipher = AES.new(self.key, AES.MODE_GCM)
            
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Calculate data hash
            data_hash = hashlib.sha256(data).hexdigest()
            
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            with open(output_path, 'wb') as f:
                # Write metadata
                if metadata is None:
                    metadata = {}
                    
                # Ensure basic metadata is included
                metadata.update({
                    'version': self.version,
                    'timestamp': int(time.time()),
                    'hash': data_hash
                })
                
                metadata_bytes = json.dumps(metadata, ensure_ascii=False).encode('utf-8')
                f.write(len(metadata_bytes).to_bytes(4, 'big'))
                f.write(metadata_bytes)
                
                # Write encryption data
                f.write(cipher.nonce)  # Write the 16-byte nonce
                f.write(tag)           # Write the 16-byte tag
                f.write(ciphertext)    # Write the encrypted data
        except Exception as e:
            # Handle any exceptions that occur during encryption
            raise ValueError(f"Encryption failed: {str(e)}")

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        """Decrypts a file with AES-256-GCM."""
        try:
            with open(input_path, 'rb') as f:
                # Read metadata
                metadata = self._read_metadata(f)
                
                # Version check
                if metadata.get('version', self.version) != self.version:
                    raise ValueError(f"Incompatible version: expected {self.version}, found {metadata.get('version', self.version)}")
                
                # Read nonce and tag
                nonce = f.read(16)
                if not nonce or len(nonce) != 16:
                    raise ValueError("Invalid or missing nonce")
                    
                tag = f.read(16)
                if not tag or len(tag) != 16:
                    raise ValueError("Invalid or missing authentication tag")
                    
                ciphertext = f.read()
                if not ciphertext:
                    raise ValueError("No encrypted data found")
            
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            try:
                data = cipher.decrypt_and_verify(ciphertext, tag)
                
                # Hash verification - only if hash is present in metadata
                if 'hash' in metadata:
                    data_hash = hashlib.sha256(data).hexdigest()
                    if data_hash != metadata['hash']:
                        raise ValueError("Data hash mismatch")
                
                # Additional check: file should not be empty
                if len(data) == 0:
                    raise ValueError("Decrypted data is empty")
                
                with open(output_path, 'wb') as f:
                    f.write(data)
            except ValueError as e:
                if "authentication tag" in str(e):
                    raise ValueError("Incorrect key")
                raise
        except (ValueError, IOError) as e:
            # Provide more context with the specific error
            raise ValueError(f"Decryption failed: {str(e)}")
        except Exception as e:
            # Catch any other unexpected errors
            raise ValueError(f"Unexpected error during decryption: {str(e)}")
