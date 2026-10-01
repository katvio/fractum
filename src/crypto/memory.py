from typing import Any, List, Union

from src.utils.integrity import get_enhanced_random_bytes


def disable_core_dumps() -> bool:
    """Stop the OS writing a core file if the process crashes.

    Measured before this existed: RLIMIT_CORE was (-1, -1), unlimited, for the whole
    time the process held the AES key. A crash at that moment writes the key to disk
    in a file that survives the process, and mlock does not help — it prevents
    swapping, not dumping.

    Two mechanisms, because either alone leaves a gap: RLIMIT_CORE stops the kernel
    writing a core file, and PR_SET_DUMPABLE additionally stops a ptrace attach from
    a process running as the same user, which is how a reader would get at the
    memory without a crash at all.

    Returns True when the core limit is confirmed at zero. Callers print a warning
    on False rather than aborting: refusing to run would be worse than running with
    a documented weakness on a platform that has no such control.
    """
    ok = False
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        ok = resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    except (ImportError, ValueError, OSError):
        # No resource module (Windows) or a hard limit that cannot be lowered.
        ok = False

    try:
        import ctypes
        import ctypes.util

        lib = ctypes.util.find_library("c")
        if lib:
            libc = ctypes.CDLL(lib, use_errno=True)
            PR_SET_DUMPABLE = 4
            libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:
        # Linux-only; absent elsewhere, and RLIMIT_CORE above carries the main job.
        pass

    return ok


class SecureMemory:
    @staticmethod
    def secure_clear(data: Union[bytearray, str, List[Any], memoryview]) -> None:
        """Overwrites a mutable buffer in place, several passes then zeros.

        Only mutable buffers can actually be cleared. Passing ``bytes`` used to be
        accepted: it copied the value into a bytearray, wiped the copy, and left
        the caller's object untouched, so the call looked correct and did nothing.
        It now raises, because a silent no-op on key material is worse than a
        crash. Hold secrets in a ``bytearray`` from the point they are created.

        ``str`` and ``list`` are still accepted for the non-secret bookkeeping the
        CLI passes in, but neither can be wiped: Python strings are immutable, so
        that path only drops the reference.

        ATTENTION, piege connu. Sur un `bytes` ou un `str`, qui sont immuables,
        cette methode ne peut qu'effacer une copie : l'original reste en
        memoire. Les appels de commands.py passent volontairement par
        `bytearray(share_bytes)`, donc ils n'effacent rien de reel aujourd'hui.

        Ne pas « corriger » cela en decodant les parts en bytearray sans revoir
        leur duree de vie : essaye le 2026-08-26, l'effacement devient effectif
        et casse 14 tests avec « MAC check failed », parce que les parts sont
        relues apres avoir ete effacees. Le correctif demande de deplacer
        l'effacement apres le dernier usage, pas de changer le type.

        Args:
            data: Buffer to clear. A bytearray, or a writable memoryview, is the
                only case where the original is really overwritten.

        Raises:
            TypeError: If data is ``bytes`` or a read-only memoryview, which
                cannot be cleared.
        """
        import gc

        if isinstance(data, bytes):
            raise TypeError(
                "secure_clear() cannot clear bytes: they are immutable, so wiping "
                "them is a no-op that silently leaves the secret in memory. Hold "
                "the value in a bytearray instead."
            )
        if isinstance(data, memoryview) and data.readonly:
            raise TypeError(
                "secure_clear() cannot clear a read-only memoryview: wiping it is "
                "a no-op. Pass a writable buffer instead."
            )

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

        elif isinstance(data, (bytearray, memoryview)):
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
                if isinstance(data[i], bytes) or (
                    isinstance(data[i], memoryview) and data[i].readonly
                ):
                    # Immutable element: it cannot be overwritten, so the most that
                    # can be done is drop the list's reference to it. Raising here
                    # would abort the whole list and leave the mutable elements
                    # after it untouched, which is strictly worse.
                    data[i] = None
                elif isinstance(data[i], (bytearray, str, list, memoryview)):
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
