from src import VERSION
from typing import Optional, Dict, Any

class ShareMetadata:
    """Centralized management of share metadata."""
    
    def __init__(self, version: str = VERSION, label: Optional[str] = None, threshold: int = 3, total_shares: int = 5):
        self.version = version
        self.label = label
        self.threshold = threshold
        self.total_shares = total_shares
        
    @classmethod
    def from_share_info(cls, share_info: Dict[str, Any]) -> 'ShareMetadata':
        """Creates a ShareMetadata instance from share information."""
        # Look for version in different places to maintain compatibility with old files
        # 1. In tool_integrity.shares_tool_version (new format)
        # 2. Directly in shares_tool_version (intermediate format)
        # 3. In version (old format)
        # 4. Default to current VERSION
        version = None
        if 'tool_integrity' in share_info and 'shares_tool_version' in share_info['tool_integrity']:
            version = share_info['tool_integrity']['shares_tool_version']
        elif 'shares_tool_version' in share_info:
            version = share_info['shares_tool_version']
        elif 'version' in share_info:
            version = share_info['version']
        else:
            version = VERSION
            
        return cls(
            version=version,
            label=share_info['label'],
            threshold=share_info.get('threshold', 3),
            total_shares=share_info.get('total_shares', 5)
        )
        
    def to_dict(self) -> Dict[str, Any]:
        """Converts metadata to dictionary."""
        metadata = {
            'version': self.version,
            'label': self.label,
            'threshold': self.threshold,
            'total_shares': self.total_shares
        }
        return metadata
        
    def validate(self) -> None:
        """Validates metadata."""
        if not isinstance(self.threshold, int) or self.threshold < 2:
            raise ValueError("Threshold must be a positive integer greater than 1")
        if not isinstance(self.total_shares, int) or self.total_shares < self.threshold:
            raise ValueError("Total shares must be greater than or equal to threshold")
        if self.total_shares > 255:
            raise ValueError("Total shares cannot exceed 255")
        if not self.label:
            raise ValueError("Label is required")
