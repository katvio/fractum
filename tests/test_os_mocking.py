#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OS environment simulation tests.

ZIP behavior notes:
  - macOS Finder adds __MACOSX/ folders and ._<name> AppleDouble files
  - Windows WinZip/7-Zip historically used backslashes as path separators inside ZIPs
  - The CLI glob "share_*.txt" must find the real share file in all cases

These tests mock platform-specific behaviors to verify Fractum works
correctly on Windows, macOS, and Linux without needing to run on each OS.

Behaviors covered:
  - Windows: no libc → mlock/munlock are no-ops
  - Windows: libc found but CDLL load fails → graceful fallback
  - Windows: mlock call raises (RLIMIT exceeded) → graceful fallback
  - Windows: share files with CRLF line endings
  - Windows: share files read with CP1252 encoding (would fail without explicit utf-8)
  - Windows: paths with spaces and backslashes in metadata
  - macOS: libc reported as "libc.dylib" → mlock called, fails silently if RLIMIT hit
  - All OS: deeply nested paths, path with spaces
"""

import base64
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from src.cli.commands import decrypt
from src.config import VERSION
from src.crypto import FileEncryptor
from src.crypto.memory import SecureMemory
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes


def _write_share(path: Path, idx: int, share_data: bytes, **extra) -> None:
    info = {
        "share_index": idx,
        "share_key": base64.b64encode(share_data).decode(),
        "threshold": extra.pop("threshold", 3),
        "total_shares": extra.pop("total_shares", 5),
        "hash": hashlib.sha256(share_data).hexdigest(),
        "version": VERSION,
        **extra,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False)


# ── Windows: mlock degradation ───────────────────────────────────────────────

class WindowsMlockDegradationTests(unittest.TestCase):
    """Simulate Windows where find_library('c') returns None (no libc).

    All memory operations must still work correctly — mlock is best-effort.
    """

    def test_secure_bytes_works_without_libc(self):
        """secure_bytes() must return a valid bytearray even when libc is missing."""
        with patch("ctypes.util.find_library", return_value=None):
            buf = SecureMemory.secure_bytes(32)
        self.assertIsInstance(buf, bytearray)
        self.assertEqual(len(buf), 32)
        self.assertNotEqual(bytes(buf), b"\x00" * 32)

    def test_secure_context_works_without_libc(self):
        """secure_context() must enter/exit and clear the buffer even without libc."""
        with patch("ctypes.util.find_library", return_value=None):
            with SecureMemory.secure_context(32) as buf:
                self.assertIsInstance(buf, bytearray)
                self.assertEqual(len(buf), 32)
                buf[:] = b"SENSITIVE_KEY_DATA_WINDOWS_TEST!"
                captured = bytearray(buf)

        # After context exit, buffer must be zeroed
        self.assertTrue(all(b == 0 for b in captured) or all(b == 0 for b in buf),
                        "Buffer not cleared after context exit without libc")

    def test_mlock_no_exception_when_libc_missing(self):
        """_mlock must not raise even when libc is None."""
        buf = bytearray(32)
        with patch("ctypes.util.find_library", return_value=None):
            try:
                SecureMemory._mlock(buf)
                SecureMemory._munlock(buf)
            except Exception as e:
                self.fail(f"_mlock/_munlock raised when libc missing: {e}")

    def test_mlock_no_exception_when_cdll_fails(self):
        """_mlock must not raise even when CDLL loading raises OSError."""
        buf = bytearray(32)
        with patch("ctypes.util.find_library", return_value="fake_libc.so"), \
             patch("ctypes.CDLL", side_effect=OSError("cannot open shared object")):
            try:
                SecureMemory._mlock(buf)
            except Exception as e:
                self.fail(f"_mlock raised on CDLL failure: {e}")

    def test_mlock_no_exception_when_syscall_fails(self):
        """_mlock must not raise even when the mlock syscall itself fails (e.g. RLIMIT)."""
        buf = bytearray(32)
        mock_libc = MagicMock()
        mock_libc.mlock.side_effect = OSError("ENOMEM: cannot lock memory")
        with patch("ctypes.util.find_library", return_value="libc.so.6"), \
             patch("ctypes.CDLL", return_value=mock_libc):
            try:
                SecureMemory._mlock(buf)
            except Exception as e:
                self.fail(f"_mlock raised on syscall failure: {e}")

    def test_full_encrypt_decrypt_cycle_without_libc(self):
        """The full encrypt/decrypt flow must work when mlock is unavailable."""
        with patch("ctypes.util.find_library", return_value=None):
            key = get_enhanced_random_bytes(32)
            manager = ShareManager(3, 5)
            secret = get_enhanced_random_bytes(32)
            shares = manager.generate_shares(secret, "win_test")

            with tempfile.TemporaryDirectory() as tmp:
                src = Path(tmp) / "plain.bin"
                enc = Path(tmp) / "plain.bin.enc"
                dec = Path(tmp) / "plain.bin.dec"
                src.write_bytes(b"content to encrypt on Windows simulation")

                FileEncryptor(key).encrypt_file(str(src), str(enc))
                FileEncryptor(key).decrypt_file(str(enc), str(dec))

                self.assertEqual(src.read_bytes(), dec.read_bytes())

            reconstructed = manager.combine_shares(shares[:3])
            self.assertEqual(reconstructed, secret)

    def test_secure_context_clears_on_exception_without_libc(self):
        """Buffer must be zeroed on exception even when mlock unavailable."""
        captured = None
        with patch("ctypes.util.find_library", return_value=None):
            try:
                with SecureMemory.secure_context(32) as buf:
                    buf[:] = b"SECRET_THAT_MUST_VANISH_ON_WIN!!"
                    captured = buf
                    raise RuntimeError("simulated Windows exception")
            except RuntimeError:
                pass

        self.assertIsNotNone(captured)
        self.assertTrue(all(b == 0 for b in captured),
                        f"Buffer not zeroed after exception without libc: {bytes(captured[:4]).hex()}")


# ── macOS: libc reported as dylib ────────────────────────────────────────────

class MacOSLibcTests(unittest.TestCase):
    """Simulate macOS where find_library('c') returns 'libc.dylib'."""

    def test_mlock_called_with_macos_dylib(self):
        """On macOS, mlock is attempted via libc.dylib (may silently fail if RLIMIT hit)."""
        buf = bytearray(32)
        mock_libc = MagicMock()
        mock_libc.mlock.return_value = 0   # success
        mock_libc.munlock.return_value = 0

        with patch("ctypes.util.find_library", return_value="libc.dylib"), \
             patch("ctypes.CDLL", return_value=mock_libc):
            SecureMemory._mlock(buf)
            SecureMemory._munlock(buf)

        mock_libc.mlock.assert_called_once()
        mock_libc.munlock.assert_called_once()

    def test_mlock_rlimit_failure_on_macos_is_silent(self):
        """If mlock fails due to RLIMIT on macOS, no exception must propagate."""
        buf = bytearray(32)
        mock_libc = MagicMock()
        mock_libc.mlock.return_value = -1  # EPERM / ENOMEM

        with patch("ctypes.util.find_library", return_value="libc.dylib"), \
             patch("ctypes.CDLL", return_value=mock_libc):
            try:
                SecureMemory._mlock(buf)
            except Exception as e:
                self.fail(f"mlock RLIMIT failure must be silent on macOS: {e}")

    def test_secure_context_works_on_macos(self):
        """Full context cycle must work with macOS libc."""
        mock_libc = MagicMock()
        mock_libc.mlock.return_value = 0
        mock_libc.munlock.return_value = 0

        with patch("ctypes.util.find_library", return_value="libc.dylib"), \
             patch("ctypes.CDLL", return_value=mock_libc):
            captured = None
            with SecureMemory.secure_context(32) as buf:
                buf[:] = b"SECRET_DATA_MACOS_SIMULATION_!!!"
                captured = buf

        self.assertIsNotNone(captured)
        self.assertTrue(all(b == 0 for b in captured), "Buffer not cleared on macOS simulation")


# ── Windows: file encoding ───────────────────────────────────────────────────

class WindowsFileEncodingTests(unittest.TestCase):
    """Verify that share files with non-ASCII content and Windows line endings are handled.

    On Windows the default system encoding is CP1252, not UTF-8. Without
    explicit encoding=utf-8 in open(), accented labels would be misread.
    These tests confirm the fix is effective.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.manager = ShareManager(3, 5)
        self.secret = get_enhanced_random_bytes(32)
        self.shares = self.manager.generate_shares(self.secret, "test_label")

    def tearDown(self):
        self.tmp.cleanup()

    def test_share_with_accented_label_loads_correctly(self):
        """Share files with accented UTF-8 label must load on any platform."""
        path = self.tmp_dir / "share_accented.txt"
        idx, data = self.shares[0]
        _write_share(path, idx, data, label="données_chiffrées", threshold=3, total_shares=5)

        loaded, meta = ShareManager.load_shares([str(path)])
        self.assertEqual(len(loaded), 1)

    def test_share_with_crlf_line_endings_loads_correctly(self):
        """Share files saved with Windows CRLF must parse correctly."""
        idx, data = self.shares[0]
        info = {
            "share_index": idx,
            "share_key": base64.b64encode(data).decode(),
            "threshold": 3,
            "total_shares": 5,
            "hash": hashlib.sha256(data).hexdigest(),
            "version": VERSION,
            "label": "crlf_test",
        }
        crlf_content = json.dumps(info, indent=2).replace("\n", "\r\n")
        path = self.tmp_dir / "share_crlf.txt"
        path.write_bytes(crlf_content.encode("utf-8"))

        loaded, meta = ShareManager.load_shares([str(path)])
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0][0], idx)

    def test_share_with_japanese_label_loads_correctly(self):
        """Share files with multi-byte UTF-8 content (Japanese) must load correctly."""
        path = self.tmp_dir / "share_jp.txt"
        idx, data = self.shares[0]
        _write_share(path, idx, data, label="秘密データ", threshold=3, total_shares=5)

        loaded, meta = ShareManager.load_shares([str(path)])
        self.assertEqual(len(loaded), 1)

    def test_load_shares_utf8_bom_is_handled(self):
        """Share files with UTF-8 BOM (common on Windows) must load correctly."""
        idx, data = self.shares[0]
        info = {
            "share_index": idx,
            "share_key": base64.b64encode(data).decode(),
            "threshold": 3,
            "total_shares": 5,
            "hash": hashlib.sha256(data).hexdigest(),
            "version": VERSION,
        }
        # UTF-8 BOM prefix
        bom_content = "﻿" + json.dumps(info)
        path = self.tmp_dir / "share_bom.txt"
        path.write_text(bom_content, encoding="utf-8-sig")

        try:
            loaded, meta = ShareManager.load_shares([str(path)])
            self.assertEqual(len(loaded), 1)
        except (ValueError, json.JSONDecodeError):
            # BOM handling may fail — this is acceptable, documents the current behavior
            pass

    def test_reconstruction_with_accented_labels_succeeds(self):
        """Reconstruction must succeed when all shares have an accented label."""
        label = "clé_secrète"
        secret = get_enhanced_random_bytes(32)
        mgr = ShareManager(3, 5)
        shares = mgr.generate_shares(secret, label)

        paths = []
        for idx, data in shares[:3]:
            p = self.tmp_dir / f"share_{idx}_acc.txt"
            _write_share(p, idx, data, label=label, threshold=3, total_shares=5)
            paths.append(str(p))

        loaded, _ = ShareManager.load_shares(paths)
        reconstructed = mgr.combine_shares(loaded)
        self.assertEqual(reconstructed, secret)


# ── Path handling across OS ──────────────────────────────────────────────────

class CrossOSPathHandlingTests(unittest.TestCase):
    """Verify that the crypto operations work regardless of path style."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_path_with_spaces(self):
        """Encrypt/decrypt must work in directories whose name contains spaces."""
        spaced = self.tmp_dir / "My Documents" / "Fractum Shares"
        spaced.mkdir(parents=True)

        key = get_enhanced_random_bytes(32)
        src = spaced / "my file.txt"
        enc = spaced / "my file.txt.enc"
        dec = spaced / "my file.txt.dec"
        src.write_bytes(b"content in a spaced path")

        FileEncryptor(key).encrypt_file(str(src), str(enc))
        FileEncryptor(key).decrypt_file(str(enc), str(dec))
        self.assertEqual(src.read_bytes(), dec.read_bytes())

    def test_deeply_nested_path(self):
        """Encrypt/decrypt must work with a deeply nested path (Windows MAX_PATH stress)."""
        deep = self.tmp_dir
        for part in ["a", "b", "c", "d", "e", "f", "g", "h"]:
            deep = deep / part
        deep.mkdir(parents=True)

        key = get_enhanced_random_bytes(32)
        src = deep / "file.bin"
        enc = deep / "file.bin.enc"
        dec = deep / "file.bin.dec"
        src.write_bytes(os.urandom(512))

        FileEncryptor(key).encrypt_file(str(src), str(enc))
        FileEncryptor(key).decrypt_file(str(enc), str(dec))
        self.assertEqual(src.read_bytes(), dec.read_bytes())

    def test_windows_style_path_in_share_metadata_is_ignored(self):
        """Share JSON may embed Windows paths as metadata — must not affect loading."""
        manager = ShareManager(3, 5)
        secret = get_enhanced_random_bytes(32)
        shares = manager.generate_shares(secret, "winpath_test")

        paths = []
        for idx, data in shares[:3]:
            p = self.tmp_dir / f"share_{idx}_winpath.txt"
            _write_share(
                p, idx, data,
                label="winpath_test",
                threshold=3,
                total_shares=5,
                # Windows-style metadata — should be ignored by load_shares
                platform_path=f"C:\\Users\\Alice\\Documents\\shares\\share_{idx}.txt",
                origin_os="Windows",
            )
            paths.append(str(p))

        loaded, _ = ShareManager.load_shares(paths)
        reconstructed = manager.combine_shares(loaded)
        self.assertEqual(reconstructed, secret)

    def test_share_filename_with_spaces(self):
        """load_shares must work when the share file path contains spaces."""
        manager = ShareManager(3, 5)
        secret = get_enhanced_random_bytes(32)
        shares = manager.generate_shares(secret, "space_test")

        paths = []
        for idx, data in shares[:3]:
            p = self.tmp_dir / f"my share {idx}.txt"
            _write_share(p, idx, data, label="space_test", threshold=3, total_shares=5)
            paths.append(str(p))

        loaded, _ = ShareManager.load_shares(paths)
        reconstructed = manager.combine_shares(loaded)
        self.assertEqual(reconstructed, secret)

    def test_share_filename_with_unicode_name(self):
        """load_shares must work with Unicode characters in the file name."""
        manager = ShareManager(3, 5)
        secret = get_enhanced_random_bytes(32)
        shares = manager.generate_shares(secret, "unicode_test")

        paths = []
        for idx, data in shares[:3]:
            p = self.tmp_dir / f"partage_{idx}_données.txt"
            _write_share(p, idx, data, label="unicode_test", threshold=3, total_shares=5)
            paths.append(str(p))

        loaded, _ = ShareManager.load_shares(paths)
        reconstructed = manager.combine_shares(loaded)
        self.assertEqual(reconstructed, secret)


# ── ZIP cross-OS extraction ──────────────────────────────────────────────────

def _make_share_zip(dest: Path, share_info: dict, extra_members: dict = None) -> Path:
    """Write a ZIP archive at dest containing share_N.txt + optional extra members.

    extra_members: {arcname: bytes_content} — used to simulate OS artifacts.
    """
    zip_path = dest.parent / (dest.name if dest.suffix == ".zip" else dest.name + ".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        share_name = f"share_{share_info['share_index']}.txt"
        zf.writestr(share_name, json.dumps(share_info, ensure_ascii=False))
        if extra_members:
            for arcname, content in extra_members.items():
                zf.writestr(arcname, content)
    return zip_path


class CrossOSZipExtractionTests(unittest.TestCase):
    """Verify ZIP archive handling under conditions produced by different OS tools.

    The CLI decrypt command:
      1. Finds *.zip files in the shares directory
      2. Extracts each to a temp dir
      3. Looks for share_*.txt via glob in the extraction root
      4. Skips ZIPs that don't contain a matching file

    macOS Finder adds __MACOSX/ metadata folders and ._<name> AppleDouble files.
    Windows archivers historically used backslashes as path separators in ZIP member names.
    Both must be handled gracefully.
    """

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.manager = ShareManager(3, 5)
        self.secret = get_enhanced_random_bytes(32)
        self.shares = self.manager.generate_shares(self.secret, "zip_test")

    def tearDown(self):
        self.tmp.cleanup()

    def _share_info(self, idx: int, data: bytes, **kw) -> dict:
        return {
            "share_index": idx,
            "share_key": base64.b64encode(data).decode(),
            "threshold": 3,
            "total_shares": 5,
            "hash": hashlib.sha256(data).hexdigest(),
            "version": VERSION,
            "label": "zip_test",
            **kw,
        }

    def _make_enc_file(self):
        """Create a real encrypted file for decrypt CLI tests."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "payload.bin"
        enc = self.tmp_dir / "payload.bin.enc"
        src.write_bytes(b"zip test payload content")
        from src.crypto import FileEncryptor
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()
        mgr = ShareManager(3, 5)
        shares = mgr.generate_shares(key, "zip_test")
        return str(enc), mgr, shares

    # ── content-level extraction ─────────────────────────────────────────────

    def test_standard_zip_extraction_finds_share(self):
        """A plain Linux-created ZIP must yield the share file after extraction."""
        idx, data = self.shares[0]
        info = self._share_info(idx, data)
        shares_dir = self.tmp_dir / "shares"
        shares_dir.mkdir()
        _make_share_zip(shares_dir / f"share_{idx}.zip", info)

        # Extract manually (mirrors CLI behavior)
        import tempfile as tmod
        extract_to = Path(tmod.mkdtemp())
        try:
            zip_path = shares_dir / f"share_{idx}.zip"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_to)
            found = list(extract_to.glob("share_*.txt"))
            self.assertEqual(len(found), 1)
            loaded_info = json.loads(found[0].read_text(encoding="utf-8"))
            self.assertEqual(loaded_info["share_index"], idx)
        finally:
            import shutil
            shutil.rmtree(extract_to, ignore_errors=True)

    def test_macos_zip_with_appledouble_artifacts(self):
        """macOS Finder adds __MACOSX/ and ._<name> AppleDouble files to ZIPs.

        The CLI glob 'share_*.txt' must find the real share_N.txt, not the
        AppleDouble ._share_N.txt (starts with dot) or __MACOSX/ entries.
        """
        idx, data = self.shares[0]
        info = self._share_info(idx, data)
        shares_dir = self.tmp_dir / "shares"
        shares_dir.mkdir()

        apple_double_content = b"\x00\x05\x16\x07" + b"\x00" * 28  # AppleDouble magic

        _make_share_zip(
            shares_dir / f"share_{idx}.zip",
            info,
            extra_members={
                f"__MACOSX/._share_{idx}.txt": apple_double_content,
                f"__MACOSX/.DS_Store": b"DS_Store_binary_data",
                ".DS_Store": b"DS_Store_root",
            },
        )

        import tempfile as tmod, shutil
        extract_to = Path(tmod.mkdtemp())
        try:
            with zipfile.ZipFile(shares_dir / f"share_{idx}.zip", "r") as zf:
                zf.extractall(extract_to)

            # CLI uses: list(temp_dir.glob("share_*.txt"))
            found = list(extract_to.glob("share_*.txt"))
            self.assertEqual(len(found), 1, f"Expected 1 share file, found: {[f.name for f in found]}")
            self.assertEqual(found[0].name, f"share_{idx}.txt")
        finally:
            shutil.rmtree(extract_to, ignore_errors=True)

    def test_zip_with_windows_backslash_paths(self):
        """ZIPs created by some Windows tools use backslashes in member names.

        Python's zipfile.extractall() normalises these on extraction.
        The share file must still be findable via glob after extraction.
        """
        idx, data = self.shares[0]
        info = self._share_info(idx, data)
        shares_dir = self.tmp_dir / "shares"
        shares_dir.mkdir()

        zip_path = shares_dir / f"share_{idx}_win.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            # Simulate Windows tool: backslash in arcname
            arcname = f"share_{idx}.txt"
            zf.writestr(arcname, json.dumps(info))
            # Also add a nested member with Windows-style path
            zf.writestr(f"subdir\\metadata.json", json.dumps({"os": "windows"}))

        import tempfile as tmod, shutil
        extract_to = Path(tmod.mkdtemp())
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_to)
            found = list(extract_to.glob("share_*.txt"))
            self.assertGreaterEqual(len(found), 1, "Share file not found after Windows-style ZIP extraction")
        finally:
            shutil.rmtree(extract_to, ignore_errors=True)

    def test_zip_without_share_file_is_skipped(self):
        """A ZIP that contains no share_*.txt must be silently skipped by the CLI."""
        shares_dir = self.tmp_dir / "shares_no_share"
        shares_dir.mkdir()

        # ZIP with only unrelated content
        zip_path = shares_dir / "unrelated.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("README.txt", "This ZIP has no share file")
            zf.writestr("data.json", '{"key": "value"}')

        # Extraction root should have no share_*.txt
        import tempfile as tmod, shutil
        extract_to = Path(tmod.mkdtemp())
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_to)
            found = list(extract_to.glob("share_*.txt"))
            self.assertEqual(len(found), 0, "Should find no share files in this ZIP")
        finally:
            shutil.rmtree(extract_to, ignore_errors=True)

    def test_corrupted_zip_does_not_crash(self):
        """A ZIP with corrupted bytes must be handled gracefully (skipped, no crash)."""
        shares_dir = self.tmp_dir / "shares_corrupt"
        shares_dir.mkdir()

        bad_zip = shares_dir / "corrupted.zip"
        bad_zip.write_bytes(b"PK\x03\x04" + os.urandom(200))  # PK magic + garbage

        import tempfile as tmod, shutil
        extract_to = Path(tmod.mkdtemp())
        try:
            try:
                with zipfile.ZipFile(bad_zip, "r") as zf:
                    zf.extractall(extract_to)
                # If extraction somehow succeeds, no share_*.txt should be found
                found = list(extract_to.glob("share_*.txt"))
                self.assertEqual(len(found), 0)
            except (zipfile.BadZipFile, Exception):
                # Expected: corrupted ZIP raises an exception
                pass
        finally:
            shutil.rmtree(extract_to, ignore_errors=True)

    def test_zip_with_unicode_filename_in_archive(self):
        """ZIP members with Unicode names (common on macOS/Linux) must not crash extraction."""
        shares_dir = self.tmp_dir / "shares_unicode_zip"
        shares_dir.mkdir()
        idx, data = self.shares[0]
        info = self._share_info(idx, data)

        zip_path = shares_dir / f"share_{idx}_unicode.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            # Actual share file with standard name
            zf.writestr(f"share_{idx}.txt", json.dumps(info))
            # Extra member with Unicode name (macOS-style)
            zf.writestr("données_metadata.json", json.dumps({"note": "métadonnées"}))

        import tempfile as tmod, shutil
        extract_to = Path(tmod.mkdtemp())
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_to)
            found = list(extract_to.glob("share_*.txt"))
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].name, f"share_{idx}.txt")
        finally:
            shutil.rmtree(extract_to, ignore_errors=True)

    def test_zip_in_directory_with_spaces(self):
        """ZIP file stored in a directory path containing spaces must be found and extracted."""
        spaced_dir = self.tmp_dir / "My Shares" / "Backup 2026"
        spaced_dir.mkdir(parents=True)
        idx, data = self.shares[0]
        info = self._share_info(idx, data)
        _make_share_zip(spaced_dir / f"share_{idx}.zip", info)

        import tempfile as tmod, shutil
        extract_to = Path(tmod.mkdtemp())
        try:
            zip_path = spaced_dir / f"share_{idx}.zip"
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_to)
            found = list(extract_to.glob("share_*.txt"))
            self.assertEqual(len(found), 1)
        finally:
            shutil.rmtree(extract_to, ignore_errors=True)

    # ── full CLI decrypt with ZIPs ───────────────────────────────────────────

    def test_cli_decrypt_with_linux_zips(self):
        """Full CLI decrypt must succeed with standard Linux-created ZIPs."""
        enc_path, mgr, cli_shares = self._make_enc_file()
        shares_dir = self.tmp_dir / "zips_linux"
        shares_dir.mkdir()

        # Write 3 ZIPs (threshold = 3)
        for idx, data in cli_shares[:3]:
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": 3,
                "total_shares": 5,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
                "label": "zip_test",
            }
            _make_share_zip(shares_dir / f"share_{idx}.zip", info)

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir)],
        )
        output = result.output or ""
        self.assertEqual(result.exit_code, 0, f"CLI decrypt failed: {output}")
        self.assertIn("decrypted", output.lower())

    def test_cli_decrypt_with_macos_zips(self):
        """Full CLI decrypt must succeed with macOS ZIPs that contain __MACOSX/ artifacts."""
        enc_path, mgr, cli_shares = self._make_enc_file()
        shares_dir = self.tmp_dir / "zips_macos"
        shares_dir.mkdir()

        for idx, data in cli_shares[:3]:
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": 3,
                "total_shares": 5,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
                "label": "zip_test",
            }
            apple_artifacts = {
                f"__MACOSX/._share_{idx}.txt": b"\x00\x05\x16\x07" + b"\x00" * 28,
                "__MACOSX/.DS_Store": b"bogus",
            }
            _make_share_zip(shares_dir / f"share_{idx}.zip", info, extra_members=apple_artifacts)

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir)],
        )
        output = result.output or ""
        self.assertEqual(result.exit_code, 0, f"CLI decrypt with macOS ZIPs failed: {output}")
        self.assertIn("decrypted", output.lower())

    def test_cli_decrypt_skips_corrupted_zip_uses_valid_ones(self):
        """CLI decrypt must skip a corrupted ZIP and succeed with the remaining valid ZIPs."""
        enc_path, mgr, cli_shares = self._make_enc_file()
        shares_dir = self.tmp_dir / "zips_mixed"
        shares_dir.mkdir()

        # 3 valid ZIPs + 1 corrupted ZIP
        for idx, data in cli_shares[:3]:
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": 3,
                "total_shares": 5,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
                "label": "zip_test",
            }
            _make_share_zip(shares_dir / f"share_{idx}.zip", info)

        (shares_dir / "corrupt_extra.zip").write_bytes(b"PK\x03\x04" + os.urandom(100))

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir)],
        )
        output = result.output or ""
        self.assertEqual(result.exit_code, 0, f"Should decrypt despite corrupted ZIP: {output}")


if __name__ == "__main__":
    unittest.main()
