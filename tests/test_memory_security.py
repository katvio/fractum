#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Memory security tests — axe 5 of the coverage audit.

Covers:
  - mlock: pages actually pinned in RAM (Linux /proc verification)
  - SecureContext/secure_clear: buffer zeroed on normal exit, exception, and
    when the traceback still holds a reference to the buffer
  - Key bytes never appear in exception messages or repr()
  - No temp files left on disk after encrypt/decrypt
  - secure_clear zeroes all bytes regardless of external references
"""

import base64
import gc
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

from src.config import VERSION
from src.crypto import FileEncryptor
from src.crypto.memory import SecureContext, SecureMemory
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes
from fixtures import (
    BITWARDEN_VAULT_EXPORT,
    BREAK_GLASS_CREDENTIALS,
    ENV_CREDENTIALS,
    HARDWARE_WALLET_SEED,
    PAYROLL_EXPORT,
)


# ── mlock — Linux /proc verification ─────────────────────────────────────────

class TestMlockLinux(unittest.TestCase):
    """Verify mlock integration on Linux via /proc/self/status."""

    @staticmethod
    def _vmlck_kb() -> int:
        """Return current VmLck (locked pages) in kB from /proc/self/status."""
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmLck:"):
                    return int(line.split()[1])
        return -1  # field absent

    def test_proc_self_status_has_vmlck_field(self):
        """Linux /proc/self/status must expose the VmLck field."""
        if platform.system() != "Linux":
            self.skipTest("Only meaningful on Linux")
        vmlck = self._vmlck_kb()
        self.assertGreaterEqual(vmlck, 0, "/proc/self/status must contain a VmLck line")

    def test_secure_bytes_does_not_crash_mlock(self):
        """secure_bytes() calls _mlock internally — must not raise even if mlock fails."""
        buf = SecureMemory.secure_bytes(512)
        self.assertIsInstance(buf, bytearray)
        self.assertEqual(len(buf), 512)
        SecureMemory.secure_clear(buf)

    def test_mlock_with_large_buffer_does_not_crash(self):
        """_mlock on a 64 KB buffer must not raise (mlock silently fails if RLIMIT hit)."""
        buf = bytearray(65536)
        SecureMemory._mlock(buf)   # no-op on RLIMIT, must not raise
        SecureMemory._munlock(buf)

    def test_mlock_vmlck_increases_or_stays_same(self):
        """After secure_bytes(4096), VmLck must not decrease (may stay same if RLIMIT = 0)."""
        if platform.system() != "Linux":
            self.skipTest("Only on Linux")
        before = self._vmlck_kb()
        buf = SecureMemory.secure_bytes(4096)
        after = self._vmlck_kb()
        SecureMemory.secure_clear(buf)
        self.assertGreaterEqual(after, before,
                                f"VmLck decreased after mlock: {before} → {after} kB")

    def test_munlock_called_after_secure_context_exit(self):
        """_munlock must be called when SecureContext exits (VmLck must not increase net)."""
        if platform.system() != "Linux":
            self.skipTest("Only on Linux")
        before = self._vmlck_kb()
        with SecureMemory.secure_context(4096) as buf:
            after_enter = self._vmlck_kb()
        after_exit = self._vmlck_kb()
        # VmLck after exit must be ≤ VmLck after enter (munlock released the pages)
        self.assertLessEqual(after_exit, after_enter,
                             f"VmLck not released: enter={after_enter} exit={after_exit}")


# ── secure_clear completeness ─────────────────────────────────────────────────

class TestSecureClearCompleteness(unittest.TestCase):
    """secure_clear must zero every byte regardless of buffer size or external references."""

    def test_secure_clear_zeros_all_bytes(self):
        """Every byte of a bytearray must be 0 after secure_clear."""
        buf = bytearray(b'DATABASE_URL=postgres://app:Zx9#mQ2@prod:5432/acme')
        SecureMemory.secure_clear(buf)
        self.assertTrue(all(b == 0 for b in buf),
                        f"Non-zero byte found after secure_clear: {bytes(buf[:8]).hex()}...")

    def test_secure_clear_zeros_via_external_reference(self):
        """A second variable pointing to the same bytearray must also see zeros."""
        buf = bytearray(b'STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXXXXXXXXXXX')
        alias = buf  # second reference, same object
        SecureMemory.secure_clear(buf)
        self.assertTrue(all(b == 0 for b in alias),
                        "External reference still shows non-zero bytes after secure_clear")

    def test_secure_clear_on_memoryview_does_not_crash(self):
        """secure_clear on a memoryview must not raise, even though it clears a copy."""
        buf = bytearray(b'GH_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXX')
        view = memoryview(buf)
        SecureMemory.secure_clear(view)  # must not raise

    def test_secure_clear_on_large_buffer(self):
        """secure_clear on a 1 MB buffer must zero all bytes."""
        buf = bytearray(get_enhanced_random_bytes(1024 * 1024))
        non_zero_before = sum(1 for b in buf if b != 0)
        self.assertGreater(non_zero_before, 0, "Test precondition: buffer has non-zero bytes")
        SecureMemory.secure_clear(buf)
        self.assertTrue(all(b == 0 for b in buf), "1 MB buffer not fully zeroed")

    def test_secure_clear_on_empty_bytearray_is_safe(self):
        """secure_clear on an empty bytearray must not raise."""
        buf = bytearray(0)
        SecureMemory.secure_clear(buf)  # must not raise

    def test_secure_context_zeros_buffer_on_normal_exit(self):
        """Buffer must be all-zero after normal SecureContext exit."""
        captured = None
        with SecureMemory.secure_context(32) as buf:
            buf[:] = b"jwt-secret:prod2025@katvio.io!!!"
            captured = buf
        self.assertTrue(all(b == 0 for b in captured))

    def test_secure_context_zeros_buffer_on_exception(self):
        """Buffer must be all-zero even when SecureContext exits via exception."""
        captured = None
        try:
            with SecureMemory.secure_context(32) as buf:
                buf[:] = b"aes256-enc-key:backup@prod-2025!"
                captured = buf
                raise RuntimeError("simulated mid-operation failure")
        except RuntimeError:
            pass
        self.assertIsNotNone(captured)
        self.assertTrue(all(b == 0 for b in captured),
                        f"Buffer not zeroed after exception: {bytes(captured[:8]).hex()}...")


# ── key not accessible via traceback ─────────────────────────────────────────

class TestKeyNotInTraceback(unittest.TestCase):
    """Key bytes must be unreachable after SecureContext exits, even via traceback locals."""

    def test_buffer_referenced_in_traceback_frame_is_zeroed(self):
        """After secure_context exits via exception, traceback locals must show zero buffer."""
        captured_tb = None
        captured_buf = None

        try:
            with SecureMemory.secure_context(32) as buf:
                buf[:] = b"prod-api-token:v2_xxxxxxxxxxx@!!"
                captured_buf = buf
                raise ValueError("deliberate error inside secure_context")
        except ValueError:
            captured_tb = sys.exc_info()[2]

        # The buffer itself must be zeroed
        self.assertTrue(all(b == 0 for b in captured_buf),
                        "Buffer still non-zero after context exit via exception")

        # Any bytearray in the traceback frame locals must also be zeroed
        if captured_tb is not None:
            frame = captured_tb.tb_frame
            for name, val in frame.f_locals.items():
                if isinstance(val, bytearray) and len(val) == 32:
                    self.assertTrue(
                        all(b == 0 for b in val),
                        f"Frame local {name!r} still contains non-zero bytes after context exit",
                    )

    def test_key_not_in_exception_str_after_secure_context(self):
        """The exception message must not contain the key bytes as hex or base64."""
        sentinel = b"KATVIO_PROD_SECRET_KEY_2025_v2_!"  # 32 bytes, unique pattern
        sentinel_hex = sentinel.hex()
        sentinel_b64 = base64.b64encode(sentinel).decode()

        captured_exc = None
        try:
            with SecureMemory.secure_context(32) as buf:
                buf[:] = sentinel
                raise RuntimeError("error with key in scope")
        except RuntimeError as e:
            captured_exc = e

        exc_str = str(captured_exc)
        self.assertNotIn(sentinel_hex, exc_str,
                         "Key hex appeared in exception string")
        self.assertNotIn(sentinel_b64, exc_str,
                         "Key base64 appeared in exception string")


# ── key not in decryption error messages ─────────────────────────────────────

class TestKeyNotInErrorMessages(unittest.TestCase):
    """Decryption error messages must never contain the key in any encoding."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.key = get_enhanced_random_bytes(32)
        self.key_hex = self.key.hex()
        self.key_b64 = base64.b64encode(self.key).decode()
        self.encryptor = FileEncryptor(self.key)

        src = self.tmp_dir / "plain.bin"
        self.enc = self.tmp_dir / "plain.bin.enc"
        src.write_bytes(BITWARDEN_VAULT_EXPORT)
        self.encryptor.encrypt_file(str(src), str(self.enc))
        src.unlink()

    def tearDown(self):
        self.tmp.cleanup()

    def _assert_no_key_in_message(self, msg: str) -> None:
        self.assertNotIn(self.key_hex, msg,
                         f"Key hex found in error message: {msg!r}")
        self.assertNotIn(self.key_b64, msg,
                         f"Key base64 found in error message: {msg!r}")

    def test_tampered_tag_error_does_not_leak_key(self):
        """MAC failure error must not contain the decryption key."""
        with open(self.enc, "rb") as f:
            raw = bytearray(f.read())

        # Flip tag bytes (nonce=16, metadata embedded)
        import json, struct
        with open(self.enc, "rb") as f:
            meta_len = struct.unpack(">I", f.read(4))[0]
            f.read(meta_len)
            f.read(16)  # nonce
            tag_offset = 4 + meta_len + 16
        raw[tag_offset] ^= 0xFF

        bad_enc = self.tmp_dir / "bad_tag.enc"
        bad_enc.write_bytes(bytes(raw))
        out = self.tmp_dir / "out.bin"

        try:
            self.encryptor.decrypt_file(str(bad_enc), str(out))
        except ValueError as e:
            self._assert_no_key_in_message(str(e))

    def test_wrong_key_error_does_not_leak_key(self):
        """GCM failure when wrong key used must not expose the key in the error."""
        wrong_key = get_enhanced_random_bytes(32)
        out = self.tmp_dir / "out.bin"
        try:
            FileEncryptor(wrong_key).decrypt_file(str(self.enc), str(out))
        except ValueError as e:
            msg = str(e)
            # The wrong key must not appear in the error either
            self.assertNotIn(wrong_key.hex(), msg)
            # And the real key must not appear
            self._assert_no_key_in_message(msg)

    def test_incompatible_version_error_does_not_leak_key(self):
        """Version mismatch error must not contain the key."""
        import json, struct
        with open(self.enc, "rb") as f:
            meta_len = struct.unpack(">I", f.read(4))[0]
            meta = json.loads(f.read(meta_len))
            nonce = f.read(16)
            tag = f.read(16)
            ct = f.read()

        meta["version"] = "0.0.1"
        bad_meta = json.dumps(meta).encode()
        bad_enc = self.tmp_dir / "bad_ver.enc"
        with open(bad_enc, "wb") as f:
            f.write(len(bad_meta).to_bytes(4, "big"))
            f.write(bad_meta)
            f.write(nonce)
            f.write(tag)
            f.write(ct)

        out = self.tmp_dir / "out.bin"
        try:
            self.encryptor.decrypt_file(str(bad_enc), str(out))
        except ValueError as e:
            self._assert_no_key_in_message(str(e))


# ── no temp files leaked ──────────────────────────────────────────────────────

class TestNoTempFilesLeaked(unittest.TestCase):
    """FileEncryptor must not leave temp files on disk after encrypt/decrypt."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _snapshot_tmp(self) -> set:
        """Return the set of paths currently under /tmp (immediate children only)."""
        try:
            return set(os.listdir(tempfile.gettempdir()))
        except OSError:
            return set()

    def test_encrypt_leaves_no_temp_files(self):
        """FileEncryptor.encrypt_file must not create files in /tmp."""
        before = self._snapshot_tmp()
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "src.bin"
        enc = self.tmp_dir / "src.bin.enc"
        src.write_bytes(PAYROLL_EXPORT)
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        after = self._snapshot_tmp()
        new_files = after - before
        self.assertEqual(new_files, set(),
                         f"encrypt_file left temp files: {new_files}")

    def test_decrypt_leaves_no_temp_files(self):
        """FileEncryptor.decrypt_file must not create files in /tmp."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "src.bin"
        enc = self.tmp_dir / "src.bin.enc"
        out = self.tmp_dir / "out.bin"
        src.write_bytes(HARDWARE_WALLET_SEED)
        FileEncryptor(key).encrypt_file(str(src), str(enc))

        before = self._snapshot_tmp()
        FileEncryptor(key).decrypt_file(str(enc), str(out))
        after = self._snapshot_tmp()
        new_files = after - before
        self.assertEqual(new_files, set(),
                         f"decrypt_file left temp files: {new_files}")

    def test_failed_decrypt_leaves_no_temp_files(self):
        """Failed decryption (wrong key) must not leave temp files in /tmp."""
        key = get_enhanced_random_bytes(32)
        wrong_key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "src.bin"
        enc = self.tmp_dir / "src.bin.enc"
        out = self.tmp_dir / "out.bin"
        src.write_bytes(ENV_CREDENTIALS)
        FileEncryptor(key).encrypt_file(str(src), str(enc))

        before = self._snapshot_tmp()
        try:
            FileEncryptor(wrong_key).decrypt_file(str(enc), str(out))
        except ValueError:
            pass
        after = self._snapshot_tmp()
        new_files = after - before
        self.assertEqual(new_files, set(),
                         f"Failed decrypt left temp files: {new_files}")

    def test_output_file_not_written_on_decrypt_failure(self):
        """When decryption fails (wrong key), the output file must not be created."""
        key = get_enhanced_random_bytes(32)
        wrong_key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "src.bin"
        enc = self.tmp_dir / "src.bin.enc"
        out = self.tmp_dir / "out.bin"
        src.write_bytes(BREAK_GLASS_CREDENTIALS)
        FileEncryptor(key).encrypt_file(str(src), str(enc))

        try:
            FileEncryptor(wrong_key).decrypt_file(str(enc), str(out))
        except ValueError:
            pass

        self.assertFalse(out.exists(),
                         "Output file must not exist after failed decryption")


if __name__ == "__main__":
    unittest.main()
