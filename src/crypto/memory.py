from typing import Any, List, Union

from src.utils.integrity import get_enhanced_random_bytes


class SecureMemory:
    @staticmethod
    def secure_clear(data: Union[bytes, bytearray, str, List[Any], memoryview]) -> None:
        """Securely clears sensitive data from memory with multiple overwrite patterns.

        Args:
            data: Data to securely clear, can be bytes, bytearray, str, list, or memoryview
        """
        import gc

        # Different overwrite patterns for multiple passes
        patterns = [
            0x00,
            0xFF,
            0xAA,
            0x55,  # Binary patterns: zeros, ones, alternating
            0xF0,
            0x0F,
            0xCC,
            0x33,  # More patterns for additional security
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
    def secure_context(cls, size: int = 32) -> "SecureContext":
        """Creates a secure context manager for temporary sensitive data.

        Args:
            size: Size of the secure memory buffer

        Returns:
            A context manager for secure memory usage
        """
        return SecureContext(size)

    @staticmethod
    def _mlock(buf: bytearray) -> None:
        """Pin buf to RAM to prevent swap. No-op on failure."""
        try:
            import ctypes
            import ctypes.util

            lib = ctypes.util.find_library("c")
            if lib:
                libc = ctypes.CDLL(lib, use_errno=True)
                addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
                libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
        except Exception:
            pass

    @staticmethod
    def _munlock(buf: bytearray) -> None:
        """Unpin buf from RAM."""
        try:
            import ctypes
            import ctypes.util

            lib = ctypes.util.find_library("c")
            if lib:
                libc = ctypes.CDLL(lib, use_errno=True)
                addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
                libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
        except Exception:
            pass

    @staticmethod
    def secure_bytes(length: int = 32) -> bytearray:
        """Creates a secure bytearray."""
        buf = bytearray(get_enhanced_random_bytes(length))
        SecureMemory._mlock(buf)
        return buf


class SecureContext:
    """Context manager for securely handling sensitive data."""

    def __init__(self, size: int = 32) -> None:
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
        SecureMemory._mlock(self.buffer)
        return self.buffer

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the context and securely clear the buffer."""
        SecureMemory._munlock(self.buffer)
        SecureMemory.secure_clear(self.buffer)
