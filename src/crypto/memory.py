import string
from typing import Union
from src.utils.integrity import get_enhanced_random_bytes

class SecureMemory:
    @staticmethod
    def secure_clear(data: Union[bytes, bytearray, str, list, memoryview]) -> None:
        """Securely clears sensitive data from memory with multiple overwrite patterns.
        
        Args:
            data: Data to securely clear, can be bytes, bytearray, str, list, or memoryview
        """
        import gc
        import sys
        
        # Different overwrite patterns for multiple passes
        patterns = [
            0x00, 0xFF, 0xAA, 0x55,  # Binary patterns: zeros, ones, alternating
            0xF0, 0x0F, 0xCC, 0x33   # More patterns for additional security
        ]
        
        if isinstance(data, str):
            # Convert string to bytearray for secure clearing
            byte_data = bytearray(data.encode())
            SecureMemory.secure_clear(byte_data)
            # Attempt to clear the original string from memory by filling variable with junk
            # This is not guaranteed but helps in some cases
            # Assign a new object with different id to variable
            data_len = len(data)
            del data
            # Create garbage with same size
            for _ in range(10):  # Multiple garbage creation attempts
                garbage = "X" * data_len
                del garbage
            
        elif isinstance(data, (bytes, memoryview)):
            # Convert immutable bytes to bytearray for clearing
            byte_data = bytearray(data)
            SecureMemory.secure_clear(byte_data)
            
        elif isinstance(data, bytearray):
            # Multiple overwrite passes with different patterns
            for pattern in patterns:
                for i in range(len(data)):
                    data[i] = pattern
                # Force Python to actually perform the memory writes
                sys.stderr.write("")
                sys.stderr.flush()
            
            # Final pass with zeros
            for i in range(len(data)):
                data[i] = 0
                
            # Attempt to release memory
            data_len = len(data)
            del data
            
            # Create and destroy some garbage to encourage memory reuse
            for _ in range(5):
                garbage = bytearray(data_len)
                del garbage
                
            # Force garbage collection multiple times
            for _ in range(3):
                gc.collect()
                
        elif isinstance(data, list):
            # For lists containing sensitive data
            for i in range(len(data)):
                if isinstance(data[i], (bytes, bytearray, str, list, memoryview)):
                    # Recursively clear complex elements
                    SecureMemory.secure_clear(data[i])
                else:
                    # For simple numeric types, just zero them
                    try:
                        data[i] = 0
                    except TypeError:
                        # If element is immutable, replace with None
                        data[i] = None
            
            # Clear the list itself
            data.clear()
            del data
            gc.collect()

    @classmethod
    def secure_context(cls, size: int = 32) -> 'SecureContext':
        """Creates a secure context manager for temporary sensitive data.
        
        Args:
            size: Size of the secure memory buffer
            
        Returns:
            A context manager for secure memory usage
        """
        return SecureContext(size)
            
    @staticmethod
    def secure_string() -> str:
        """Creates a secure string."""
        # Use cryptographically secure random bytes instead of random.choices
        random_bytes = get_enhanced_random_bytes(32)
        # Convert to alphanumeric characters
        charset = string.ascii_letters + string.digits
        # Map bytes to characters (without bias)
        result = ""
        for byte in random_bytes:
            # Ensure no modulo bias by rejecting values above the largest multiple of len(charset)
            max_value = 256 - (256 % len(charset))
            if byte < max_value:
                result += charset[byte % len(charset)]
                if len(result) >= 32:  # We want a 32-character result
                    break
        
        # If we don't have enough characters (unlikely), append more
        while len(result) < 32:
            more_bytes = get_enhanced_random_bytes(8)
            for byte in more_bytes:
                if byte < max_value and len(result) < 32:
                    result += charset[byte % len(charset)]
        
        return result

    @staticmethod
    def secure_bytes(length: int = 32) -> bytearray:
        """Creates a secure bytearray."""
        return bytearray(get_enhanced_random_bytes(length))

class SecureContext:
    """Context manager for securely handling sensitive data."""
    
    def __init__(self, size: int = 32):
        """Initialize secure context with memory buffer.
        
        Args:
            size: Size of the secure memory buffer
        """
        self.buffer = bytearray(size)
        self.size = size
        
    def __enter__(self) -> bytearray:
        """Enter the context and return secure buffer."""
        # Initialize with random data
        random_bytes = get_enhanced_random_bytes(self.size)
        for i in range(min(len(random_bytes), self.size)):
            self.buffer[i] = random_bytes[i]
        return self.buffer
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the context and securely clear the buffer."""
        SecureMemory.secure_clear(self.buffer)
        # The buffer object itself will be garbage collected, but we've cleared its contents
