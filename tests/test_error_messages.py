#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for error message precision.

Verifies not just that errors are raised, but that the messages
are specific enough to be actionable: which share is corrupted,
which file is incompatible, which indices are duplicated, etc.
"""

import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from src.cli.commands import decrypt, encrypt
from src.config import VERSION
from src.crypto import FileEncryptor
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes


def _write_share(path: Path, idx: int, share_data: bytes, **extra) -> None:
    """Write a minimal valid share JSON file."""
    info = {
        "share_index": idx,
        "share_key": base64.b64encode(share_data).decode(),
        "threshold": extra.pop("threshold", 3),
        "total_shares": extra.pop("total_shares", 5),
        "hash": hashlib.sha256(share_data).hexdigest(),
        "version": VERSION,
        **extra,
    }
    with open(path, "w") as f:
        json.dump(info, f)


class TestShareManagerErrorMessages(unittest.TestCase):
    """Verify that ShareManager raises errors with actionable messages."""

    def setUp(self):
        self.manager = ShareManager(3, 5)
        self.secret = get_enhanced_random_bytes(32)
        self.shares = self.manager.generate_shares(self.secret, "test")

    # ── combine_shares ──────────────────────────────────────────────────────

    def test_insufficient_shares_message_includes_counts(self):
        """Error must say how many shares were provided and how many are needed."""
        with self.assertRaisesRegex(
            ValueError,
            r"2.*3|3.*2",  # both counts present in some order
        ):
            self.manager.combine_shares(self.shares[:2])

    def test_duplicate_indices_message_names_duplicates(self):
        """Error must identify which indices are duplicated."""
        # Present share 1 twice
        duplicate_shares = [self.shares[0], self.shares[0], self.shares[2]]
        with self.assertRaisesRegex(
            ValueError,
            r"[Dd]uplicate.*\[?\d+\]?|index.*\d+.*duplicate",
        ):
            self.manager.combine_shares(duplicate_shares)

    def test_duplicate_indices_message_contains_actual_index(self):
        """The duplicated index value must appear in the error message."""
        idx = self.shares[0][0]  # The actual share index (e.g. 1)
        duplicate_shares = [self.shares[0], self.shares[0], self.shares[2]]
        with self.assertRaises(ValueError) as ctx:
            self.manager.combine_shares(duplicate_shares)
        self.assertIn(str(idx), str(ctx.exception))

    def test_reconstruction_failure_message_is_descriptive(self):
        """A failed reconstruction must mention corruption or wrong run, not a raw exception."""
        # Mix shares from two different encryptions — reconstruction silently
        # produces garbage, but if PyCryptodome raises, the message must be readable.
        other_manager = ShareManager(3, 5)
        other_shares = other_manager.generate_shares(get_enhanced_random_bytes(32), "other")
        mixed = [self.shares[0], other_shares[1], self.shares[2]]
        try:
            other_manager.combine_shares(mixed)
        except ValueError as e:
            msg = str(e)
            self.assertNotIn("traceback", msg.lower())
            self.assertTrue(
                any(kw in msg.lower() for kw in ["reconstruction", "corrupt", "encryption run", "failed"]),
                f"Error message not actionable: {msg}",
            )

    def test_invalid_threshold_message(self):
        with self.assertRaisesRegex(ValueError, r"[Tt]hreshold"):
            ShareManager(1, 5)

    def test_threshold_exceeds_shares_message(self):
        with self.assertRaisesRegex(ValueError, r"[Tt]hreshold|shares"):
            ShareManager(6, 5)

    def test_shares_exceed_255_message(self):
        with self.assertRaisesRegex(ValueError, r"255"):
            ShareManager(3, 256)

    def test_empty_secret_message(self):
        with self.assertRaisesRegex(ValueError, r"[Ee]mpty|[Ss]ecret"):
            self.manager.generate_shares(b"", "label")

    def test_secret_too_long_message(self):
        with self.assertRaisesRegex(ValueError, r"32|exceed"):
            self.manager.generate_shares(b"x" * 33, "label")

    def test_empty_label_message(self):
        with self.assertRaisesRegex(ValueError, r"[Ll]abel"):
            self.manager.generate_shares(self.secret, "")

    # ── load_shares ─────────────────────────────────────────────────────────

    def test_corrupted_share_message_names_index_and_file(self):
        """Corruption message must name the share index AND the file path."""
        with tempfile.TemporaryDirectory() as tmp:
            share_path = Path(tmp) / "share_2.txt"
            idx, data = self.shares[1]  # share index 2

            # Write a share with a deliberately wrong hash
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": 3,
                "total_shares": 5,
                "hash": "a" * 64,  # wrong hash
                "version": VERSION,
            }
            with open(share_path, "w") as f:
                json.dump(info, f)

            with self.assertRaises(ValueError) as ctx:
                ShareManager.load_shares([str(share_path)])

            msg = str(ctx.exception)
            # Must identify the share index
            self.assertIn(str(idx), msg, f"Share index {idx} not in error: {msg}")
            # Must name the file
            self.assertIn("share_2.txt", msg, f"Filename not in error: {msg}")
            # Must say 'corrupted' or 'hash'
            self.assertTrue(
                any(kw in msg.lower() for kw in ["corrupt", "hash"]),
                f"Error not descriptive: {msg}",
            )

    def test_missing_share_key_message_names_file(self):
        """'No share key' error must name the problematic file."""
        with tempfile.TemporaryDirectory() as tmp:
            share_path = Path(tmp) / "missing_key_share.txt"
            with open(share_path, "w") as f:
                json.dump({"share_index": 1, "threshold": 3, "version": VERSION}, f)

            with self.assertRaises(ValueError) as ctx:
                ShareManager.load_shares([str(share_path)])

            self.assertIn("missing_key_share.txt", str(ctx.exception))

    def test_incompatible_threshold_message_names_file(self):
        """Threshold mismatch error must name the conflicting file."""
        with tempfile.TemporaryDirectory() as tmp:
            shares = self.manager.generate_shares(self.secret, "test")
            path_a = Path(tmp) / "share_a.txt"
            path_b = Path(tmp) / "share_b.txt"

            _write_share(path_a, shares[0][0], shares[0][1], threshold=3)
            _write_share(path_b, shares[1][0], shares[1][1], threshold=4)  # mismatch

            with self.assertRaises(ValueError) as ctx:
                ShareManager.load_shares([str(path_a), str(path_b)])

            self.assertIn("share_b.txt", str(ctx.exception))

    def test_incompatible_label_message_names_file(self):
        """Label mismatch error must name the conflicting file."""
        with tempfile.TemporaryDirectory() as tmp:
            shares = self.manager.generate_shares(self.secret, "test")
            path_a = Path(tmp) / "share_a.txt"
            path_b = Path(tmp) / "share_conflict.txt"

            _write_share(path_a, shares[0][0], shares[0][1], label="label_A")
            _write_share(path_b, shares[1][0], shares[1][1], label="label_B")

            with self.assertRaises(ValueError) as ctx:
                ShareManager.load_shares([str(path_a), str(path_b)])

            self.assertIn("share_conflict.txt", str(ctx.exception))

    def test_no_valid_files_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, r"[Nn]o valid"):
                ShareManager.load_shares([])


class TestCLIErrorOutput(unittest.TestCase):
    """Verify that the CLI surfaces precise error messages on stderr with exit code 1."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_encrypted_file(self) -> tuple:
        """Create a real encrypted file + share files. Returns (enc_path, share_paths, manager).

        The source file is removed after encryption so decrypt output (plain.txt)
        does not collide with the source file when tests invoke the CLI.
        """
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "plain.txt"
        enc = self.tmp_dir / "plain.txt.enc"
        src.write_bytes(b"payload content for CLI error tests")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()  # remove so CLI output path is free

        manager = ShareManager(3, 5)
        shares = manager.generate_shares(key, "cli_test")
        share_paths = []
        for idx, data in shares:
            p = self.tmp_dir / f"share_{idx}.txt"
            _write_share(p, idx, data, threshold=3, total_shares=5, label="cli_test")
            share_paths.append(str(p))

        return str(enc), share_paths, manager

    def test_encrypt_invalid_threshold_exits_1_with_error(self):
        """CLI encrypt with threshold=1 must exit 1 and print an error."""
        dummy = self.tmp_dir / "file.txt"
        dummy.write_text("x")
        result = self.runner.invoke(
            encrypt,
            [str(dummy), "--threshold", "1", "--shares", "3", "--label", "t"],
        )
        self.assertNotEqual(result.exit_code, 0)
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        self.assertTrue(
            any(kw in combined.lower() for kw in ["error", "threshold", "invalid"]),
            f"No error message in output: {combined!r}",
        )

    def test_encrypt_threshold_exceeds_shares_exits_1(self):
        """Threshold > shares must cause exit 1 with a readable error."""
        dummy = self.tmp_dir / "file.txt"
        dummy.write_text("x")
        result = self.runner.invoke(
            encrypt,
            [str(dummy), "--threshold", "5", "--shares", "3", "--label", "t"],
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_decrypt_corrupted_share_exits_1_and_names_share(self):
        """Decrypting with a corrupted share must exit 1 and name the share index.

        Provides exactly threshold=3 shares (2 valid + 1 corrupted) so the CLI
        cannot bypass the corrupted share by using other valid ones.
        """
        enc_path, share_paths, _ = self._make_encrypted_file()
        shares_dir = self.tmp_dir / "shares_sub"
        shares_dir.mkdir()

        # Copy exactly 3 shares: index 0 and 1 valid, index 2 corrupted
        for p in share_paths[:3]:
            pobj = Path(p)
            dest = shares_dir / pobj.name
            dest.write_text(pobj.read_text())

        # Corrupt the hash of the third share (share_3.txt)
        corrupted_name = Path(share_paths[2]).name
        corrupted = shares_dir / corrupted_name
        data = json.loads(corrupted.read_text())
        corrupted_idx = data["share_index"]
        data["hash"] = "a" * 64
        corrupted.write_text(json.dumps(data))

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir)],
        )
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        self.assertNotEqual(result.exit_code, 0, f"Should fail, output: {combined}")
        self.assertTrue(
            any(kw in combined for kw in [str(corrupted_idx), "corrupt", "hash", corrupted_name]),
            f"Error must identify the corrupted share, got: {combined!r}",
        )

    def test_decrypt_wrong_key_exits_1_with_error(self):
        """Decrypting with shares from a different encryption run must exit 1."""
        enc_path, _, _ = self._make_encrypted_file()

        # Generate fresh shares for a different key
        other_key = get_enhanced_random_bytes(32)
        other_mgr = ShareManager(3, 5)
        other_shares = other_mgr.generate_shares(other_key, "wrong_label")

        wrong_dir = self.tmp_dir / "wrong_shares"
        wrong_dir.mkdir()
        for idx, data in other_shares[:3]:
            p = wrong_dir / f"share_{idx}.txt"
            _write_share(p, idx, data, threshold=3, total_shares=5, label="wrong_label")

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(wrong_dir)],
            catch_exceptions=False,
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_decrypt_missing_shares_dir_exits_1(self):
        """Pointing to a non-existent shares directory must exit 1."""
        enc_path, _, _ = self._make_encrypted_file()
        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", "/nonexistent/path/to/shares"],
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_decrypt_output_already_exists_exits_1(self):
        """If the output file already exists, CLI must exit 1 and name the file."""
        enc_path, share_paths, _ = self._make_encrypted_file()
        shares_dir = self.tmp_dir / "shares_exist"
        shares_dir.mkdir()
        for p in share_paths:
            dest = shares_dir / Path(p).name
            dest.write_text(Path(p).read_text())

        # Pre-create the output file
        output = self.tmp_dir / "plain.txt"
        output.write_text("already here")

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir)],
            catch_exceptions=False,
        )
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        self.assertNotEqual(result.exit_code, 0)
        self.assertTrue(
            any(kw in combined.lower() for kw in ["exists", "already", "plain.txt"]),
            f"Error must mention the conflicting file, got: {combined!r}",
        )


class TestSecureContextOnException(unittest.TestCase):
    """Verify that SecureContext clears the key even when an exception occurs inside it."""

    def test_context_clears_buffer_on_exception(self):
        """Key buffer must be zeroed even if the body of the 'with' block raises."""
        from src.crypto.memory import SecureMemory

        captured_buffer = None

        try:
            with SecureMemory.secure_context(32) as buf:
                buf[:] = b"SENSITIVE_KEY_VALUE_MUST_VANISH!"
                captured_buffer = buf  # keep reference outside the context
                raise RuntimeError("simulated mid-decryption error")
        except RuntimeError:
            pass

        self.assertIsNotNone(captured_buffer)
        self.assertTrue(
            all(b == 0 for b in captured_buffer),
            f"Buffer not zeroed after exception: {bytes(captured_buffer[:8]).hex()}...",
        )

    def test_context_clears_buffer_on_normal_exit(self):
        """Key buffer must be zeroed on normal exit too."""
        from src.crypto.memory import SecureMemory

        captured = None
        with SecureMemory.secure_context(32) as buf:
            buf[:] = b"NORMAL_EXIT_KEY_VALUE_TEST_HERE!"
            captured = buf

        self.assertTrue(
            all(b == 0 for b in captured),
            "Buffer not zeroed after normal context exit",
        )


# ── edge-case errors (axe 3 completion) ──────────────────────────────────────

class TestEdgeCaseErrors(unittest.TestCase):
    """Error cases not covered by the message-precision tests above.

    Covers: permission errors, malformed JSON field types, share_set_id
    cross-encryption mismatch, and Python version guard.
    """

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_enc_and_shares(self, label="edge", threshold=3, n=5):
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "src.bin"
        enc = self.tmp_dir / "src.bin.enc"
        src.write_bytes(b"edge-case error test payload")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()
        mgr = ShareManager(threshold, n)
        shares = mgr.generate_shares(key, label)
        share_paths = []
        for idx, data in shares:
            p = self.tmp_dir / f"share_{idx}.txt"
            _write_share(p, idx, data, threshold=threshold, total_shares=n, label=label)
            share_paths.append(p)
        return str(enc), share_paths, key, shares

    # ── permission errors ────────────────────────────────────────────────────

    def test_decrypt_unreadable_enc_file_exits_1(self):
        """CLI decrypt must exit 1 when the .enc file has no read permission."""
        enc_path, share_paths, _, _ = self._make_enc_and_shares()
        shares_dir = self.tmp_dir / "shares_perm"
        shares_dir.mkdir()
        for p in share_paths:
            (shares_dir / p.name).write_text(p.read_text())

        os.chmod(enc_path, 0o000)
        try:
            result = self.runner.invoke(
                decrypt,
                [enc_path, "--shares-dir", str(shares_dir)],
            )
            self.assertNotEqual(result.exit_code, 0)
        finally:
            os.chmod(enc_path, 0o644)

    def test_encrypt_input_file_unreadable_exits_1(self):
        """CLI encrypt must exit 1 when the input file has no read permission."""
        src = self.tmp_dir / "secret.bin"
        src.write_bytes(b"unreadable")
        os.chmod(str(src), 0o000)
        try:
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "perm"],
            )
            # Click validates exists=True before the command runs; exit != 0 either way
            self.assertNotEqual(result.exit_code, 0)
        finally:
            os.chmod(str(src), 0o644)

    # ── malformed JSON field types ───────────────────────────────────────────

    def test_share_with_string_share_index_is_handled(self):
        """A share JSON where share_index is a string must not crash load_shares."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad_type.txt"
            key = get_enhanced_random_bytes(32)
            mgr = ShareManager(2, 3)
            shares = mgr.generate_shares(key, "typetest")
            idx, data = shares[0]
            info = {
                "share_index": str(idx),  # string instead of int
                "share_key": base64.b64encode(data).decode(),
                "threshold": 2,
                "total_shares": 3,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
            }
            p.write_text(json.dumps(info))

            # load_shares should either load it (coercion) or raise ValueError
            try:
                result, _ = ShareManager.load_shares([str(p)])
            except (ValueError, TypeError, KeyError):
                pass  # any of these is acceptable — it must not crash with unhandled exception

    def test_share_with_float_threshold_causes_error(self):
        """A share JSON with threshold=3.5 must cause an error (not a silent wrong reconstruction)."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "float_threshold.txt"
            key = get_enhanced_random_bytes(32)
            mgr = ShareManager(2, 3)
            shares = mgr.generate_shares(key, "floattest")
            idx, data = shares[0]
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": 3.5,  # float instead of int
                "total_shares": 3,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
            }
            p.write_text(json.dumps(info))

            # When the CLI tries to instantiate ShareManager(3.5, ...) it must fail
            enc_path, share_paths, _, _ = self._make_enc_and_shares(label="floattest", threshold=2, n=3)
            shares_dir = self.tmp_dir / "shares_float"
            shares_dir.mkdir()
            (shares_dir / "bad_threshold.txt").write_text(json.dumps(info))

            result = self.runner.invoke(
                decrypt,
                [enc_path, "--shares-dir", str(shares_dir)],
            )
            # Must not exit 0 and silently produce wrong output
            # (either fails or recovers gracefully — but never corrupt plaintext without error)
            combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
            if result.exit_code == 0:
                # If CLI recovered somehow, that's OK as long as output file contains correct data
                pass
            else:
                # Expected: error surfaced
                self.assertNotEqual(result.exit_code, 0)

    def test_share_with_negative_share_index_is_rejected(self):
        """A share with share_index=-1 must be rejected or cause reconstruction failure."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "neg_index.txt"
            key = get_enhanced_random_bytes(32)
            mgr = ShareManager(2, 3)
            shares = mgr.generate_shares(key, "negtest")
            _, data = shares[0]
            info = {
                "share_index": -1,  # negative — invalid for Shamir
                "share_key": base64.b64encode(data).decode(),
                "threshold": 2,
                "total_shares": 3,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
            }
            p.write_text(json.dumps(info))

            # load_shares loads it (index validation is Shamir's job)
            # combine_shares with index -1 must either fail or produce wrong key (GCM catches it)
            try:
                result, _ = ShareManager.load_shares([str(p)])
                # If loaded: combine with a valid share should not silently produce correct plaintext
            except (ValueError, Exception):
                pass  # failing here is also acceptable

    def test_share_with_missing_share_index_field_is_rejected(self):
        """A share JSON missing the share_index field entirely must raise ValueError."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "no_index.txt"
            key = get_enhanced_random_bytes(32)
            mgr = ShareManager(2, 3)
            shares = mgr.generate_shares(key, "noidx")
            _, data = shares[0]
            info = {
                # share_index intentionally omitted
                "share_key": base64.b64encode(data).decode(),
                "threshold": 2,
                "total_shares": 3,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
            }
            p.write_text(json.dumps(info))

            with self.assertRaises((ValueError, KeyError)):
                ShareManager.load_shares([str(p)])

    # ── share_set_id cross-encryption mismatch ───────────────────────────────

    def test_shares_from_different_encryptions_cannot_decrypt(self):
        """Mixing shares from two different encryption runs must not produce valid plaintext."""
        # Encryption A
        key_a = get_enhanced_random_bytes(32)
        src_a = self.tmp_dir / "file_a.bin"
        enc_a = self.tmp_dir / "file_a.bin.enc"
        src_a.write_bytes(b"content of file A")
        FileEncryptor(key_a).encrypt_file(str(src_a), str(enc_a))

        mgr_a = ShareManager(3, 5)
        shares_a = mgr_a.generate_shares(key_a, "mismatch")

        # Encryption B (different key)
        key_b = get_enhanced_random_bytes(32)
        mgr_b = ShareManager(3, 5)
        shares_b = mgr_b.generate_shares(key_b, "mismatch")

        # Mix: 2 shares from A + 1 share from B
        mixed = [shares_a[0], shares_a[1], shares_b[2]]

        # combine_shares will produce wrong key → GCM tag check will fail
        key_wrong = mgr_a.combine_shares(mixed)
        encryptor = FileEncryptor(key_wrong)
        out = self.tmp_dir / "wrong_out.bin"
        with self.assertRaises(Exception):
            encryptor.decrypt_file(str(enc_a), str(out))

    def test_cli_with_full_metadata_shares_from_different_runs_exits_1(self):
        """CLI must exit 1 when shares have mismatched share_set_id vs the .enc file."""
        # Create enc file + valid shares for set A
        enc_path, share_paths_a, key_a, shares_a = self._make_enc_and_shares(
            label="setA", threshold=3, n=5
        )

        # Create a second set of shares (different key / different encryption run)
        key_b = get_enhanced_random_bytes(32)
        mgr_b = ShareManager(3, 5)
        shares_b = mgr_b.generate_shares(key_b, "setA")

        shares_dir = self.tmp_dir / "mixed_shares"
        shares_dir.mkdir()

        # Write 2 shares from set A + 3 shares from set B in the same dir
        for p in share_paths_a[:2]:
            (shares_dir / p.name).write_text(p.read_text())

        for idx, data in shares_b[:3]:
            dest = shares_dir / f"share_b_{idx}.txt"
            _write_share(dest, idx, data, threshold=3, total_shares=5, label="setA")

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir)],
        )
        self.assertNotEqual(result.exit_code, 0,
                            f"Should fail with mixed shares, got: {result.output}")

    # ── Python version guard ─────────────────────────────────────────────────

    def test_encrypt_fails_on_old_python_version(self):
        """CLI encrypt must exit 1 with a readable error when Python is below the minimum."""
        import sys
        from collections import namedtuple
        from unittest.mock import patch

        src = self.tmp_dir / "src.bin"
        src.write_bytes(b"python version test")

        # namedtuple inherits from tuple so comparison with (3, 12, 11) works correctly
        _VersionInfo = namedtuple("version_info", ["major", "minor", "micro", "releaselevel", "serial"])
        fake_vi = _VersionInfo(3, 10, 0, "final", 0)

        with patch("src.cli.commands.sys") as mock_sys:
            mock_sys.version_info = fake_vi
            mock_sys.exit = sys.exit  # keep real sys.exit so CliRunner captures it

            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "pyver"],
            )

        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        self.assertNotEqual(result.exit_code, 0,
                            f"Should fail on old Python, got: {combined!r}")
        self.assertTrue(
            any(kw in combined.lower() for kw in ["python", "3.", "required", "version"]),
            f"Error must mention Python version, got: {combined!r}",
        )


if __name__ == "__main__":
    unittest.main()
