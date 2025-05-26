import json
import hashlib
import base64
from typing import List, Tuple
from Crypto.Protocol.SecretSharing import Shamir

from src import VERSION
from src.shares.metadata import ShareMetadata

class ShareManager:
    def __init__(self, threshold: int, total_shares: int):
        """Initializes the share manager.
        
        Args:
            threshold (int): Minimum number of shares needed to reconstruct the secret
            total_shares (int): Total number of shares to generate
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not isinstance(threshold, int) or threshold < 2:
            raise ValueError("Threshold must be a positive integer greater than 1")
        if not isinstance(total_shares, int) or total_shares < threshold:
            raise ValueError("Total shares must be greater than or equal to threshold")
        if total_shares > 255:  # PyCryptodome limit
            raise ValueError("Total shares cannot exceed 255")
            
        self.threshold = threshold
        self.total_shares = total_shares
        self.version = VERSION

    def _prepare_secret(self, secret: bytes) -> bytes:
        """Prepares the secret for sharing by ensuring it's exactly 32 bytes.
        
        Args:
            secret (bytes): The secret to prepare
            
        Returns:
            bytes: The prepared 32-byte secret
            
        Raises:
            ValueError: If the secret is too long
        """
        if len(secret) > 32:
            raise ValueError("Secret cannot exceed 32 bytes")
        if len(secret) == 0:
            raise ValueError("Secret cannot be empty")
            
        # Padding with zeros if necessary
        return secret.ljust(32, b'\0')

    def generate_shares(self, secret: bytes, label: str) -> List[Tuple[int, bytes]]:
        """Generates shares from a secret.
        
        Args:
            secret (bytes): The secret to share
            label (str): Label to identify the shares
            
        Returns:
            List[Tuple[int, bytes]]: List of shares (share_index, share)
            
        Raises:
            ValueError: If the secret is invalid
        """
        if not isinstance(secret, bytes):
            raise ValueError("Secret must be in bytes")
        if not isinstance(label, str) or not label:
            raise ValueError("Label must be a non-empty string")
            
        prepared_secret = self._prepare_secret(secret)
        # Split the secret into two 16-byte parts for Shamir
        secret_part1 = prepared_secret[:16]
        secret_part2 = prepared_secret[16:]
        
        # Generate shares for each part
        shares1 = Shamir.split(self.threshold, self.total_shares, secret_part1)
        shares2 = Shamir.split(self.threshold, self.total_shares, secret_part2)
        
        # Combine shares
        combined_shares = []
        for i in range(self.total_shares):
            idx1, share1 = shares1[i]
            idx2, share2 = shares2[i]
            if idx1 != idx2:
                raise ValueError("Share share_index inconsistency")
            combined_shares.append((idx1, share1 + share2))
            
        return combined_shares

    def combine_shares(self, shares: List[Tuple[int, bytes]]) -> bytes:
        """Reconstructs the secret from shares.
        
        Args:
            shares (List[Tuple[int, bytes]]): List of shares to combine
            
        Returns:
            bytes: The reconstructed secret
            
        Raises:
            ValueError: If there are insufficient shares or invalid shares
        """
        if not isinstance(shares, list):
            raise ValueError("Shares must be provided as a list")
        if len(shares) < self.threshold:
            raise ValueError(f"Insufficient number of shares: {len(shares)} < {self.threshold}")
            
        # share_index verification
        indices = set(idx for idx, _ in shares)
        if len(indices) != len(shares):
            raise ValueError("Duplicate indices detected")
            
        try:
            # Split shares into two parts
            shares1 = [(idx, share[:16]) for idx, share in shares]
            shares2 = [(idx, share[16:]) for idx, share in shares]
            
            # Reconstruct each part
            secret_part1 = Shamir.combine(shares1[:self.threshold])
            secret_part2 = Shamir.combine(shares2[:self.threshold])
            
            # Combine parts
            return secret_part1 + secret_part2
        except Exception as e:
            raise ValueError(f"Error reconstructing secret: {str(e)}")

    def verify_shares(self, shares: List[Tuple[int, bytes]]) -> bool:
        """Verifies share validity without revealing the secret.
        
        Args:
            shares (List[Tuple[int, bytes]]): List of shares to verify
            
        Returns:
            bool: True if shares are valid, False otherwise
        """
        if not isinstance(shares, list):
            return False
        if len(shares) < self.threshold:
            return False
            
        try:
            # share_index verification
            indices = set(idx for idx, _ in shares)
            if len(indices) != len(shares):
                return False
                
            # Test reconstruction with a subset
            test_shares = shares[:self.threshold]
            Shamir.combine(test_shares)
            return True
        except:
            return False

    @staticmethod
    def load_shares(share_files: List[str]) -> Tuple[List[Tuple[int, bytes]], ShareMetadata]:
        """Loads shares from files."""
        shares = []
        metadata = None
        
        for share_file in share_files:
            with open(share_file, 'r') as f:
                share_info = json.load(f)
                
                if metadata is None:
                    metadata = ShareMetadata.from_share_info(share_info)
                else:
                    current_metadata = ShareMetadata.from_share_info(share_info)
                    if metadata.version != current_metadata.version:
                        raise ValueError(f"Incompatible version in {share_file}")
                    if metadata.label != current_metadata.label:
                        raise ValueError(f"Incompatible label in {share_file}")
                    if metadata.threshold != current_metadata.threshold:
                        raise ValueError(f"Incompatible threshold in {share_file}")
                    if metadata.total_shares != current_metadata.total_shares:
                        raise ValueError(f"Incompatible total shares in {share_file}")
                
                # Support both 'share_key' (new) and 'share' (legacy) for backward compatibility
                share_key = share_info.get('share_key', share_info.get('share'))
                if not share_key:
                    raise ValueError(f"No share key found in {share_file}")
                
                shares.append((
                    share_info['share_index'],
                    base64.b64decode(share_key)
                ))
        
        return shares, metadata

    def save_share(self, share: Tuple[int, bytes], label: str) -> str:
        """Saves a share to a file."""
        idx, share_data = share
        filename = f"share_{idx}.txt"
        
        metadata = ShareMetadata(
            version=self.version,
            label=label,
            threshold=self.threshold,
            total_shares=self.total_shares
        )
        metadata.validate()
        
        share_info = {
            **metadata.to_dict(),
            'share_index': idx,
            'share_key': base64.b64encode(share_data).decode(),
            'hash': hashlib.sha256(share_data).hexdigest()
        }
        
        with open(filename, 'w') as f:
            json.dump(share_info, f, indent=2)
            
        return filename
