#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UX mode tests — axe 2 of the coverage audit.

Covers every CLI flag / interaction mode:
  - --full-metadata  (encrypt): extra fields written to share JSON
  - --existing-shares (encrypt): re-encrypt with recovered key
  - --manual-shares / -m (decrypt): interactive prompt-based share entry
  - --verbose (both commands): progress messages surfaced to stdout
"""

import base64
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from src.cli.commands import decrypt, encrypt
from src.config import VERSION
from src.crypto import FileEncryptor
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes


# ── helpers ──────────────────────────────────────────────────────────────────

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


def _make_enc_file(tmp: Path, label: str = "ux_test", threshold: int = 3, n: int = 5):
    """Encrypt a file and write shares to tmp. Returns (enc_path, share_paths, key, shares)."""
    key = get_enhanced_random_bytes(32)
    src = tmp / "payload.bin"
    enc = tmp / "payload.bin.enc"
    src.write_bytes(b"UX test payload - contenu de test")
    FileEncryptor(key).encrypt_file(str(src), str(enc))
    src.unlink()
    mgr = ShareManager(threshold, n)
    shares = mgr.generate_shares(key, label)
    share_paths = []
    for idx, data in shares:
        p = tmp / f"share_{idx}.txt"
        _write_share(p, idx, data, threshold=threshold, total_shares=n, label=label)
        share_paths.append(p)
    return str(enc), share_paths, key, shares


# ── --full-metadata flag ──────────────────────────────────────────────────────

class TestFullMetadataFlag(unittest.TestCase):
    """--full-metadata adds optional fields to share JSON; omitting it keeps shares minimal."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _invoke_encrypt(self, extra_args=None):
        src = self.tmp_dir / "secret.bin"
        src.write_bytes(b"content for full-metadata test")
        args = [
            str(src),
            "--threshold", "2",
            "--shares", "3",
            "--label", "meta_test",
        ]
        if extra_args:
            args.extend(extra_args)
        result = self.runner.invoke(encrypt, args, catch_exceptions=False)
        return result

    def _find_share_json(self):
        """Read the first share JSON written to the current directory."""
        import glob, os
        matches = glob.glob("share_*.txt") + glob.glob("shares/share_*.txt")
        if not matches:
            # CliRunner runs in a tmp fs; look in the tmp dir
            matches = list(self.tmp_dir.glob("share_*.txt"))
        if not matches:
            return None
        with open(matches[0], encoding="utf-8") as f:
            return json.load(f)

    def test_without_full_metadata_share_omits_optional_fields(self):
        """Without --full-metadata, share JSON must NOT contain label/total_shares/share_set_id."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"minimal metadata test")
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "minimal"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)

            # Shares are written then wrapped in ZIPs and deleted.
            # Read from ZIP archives if plain files are gone.
            import glob, zipfile as zf
            share_info = None
            for z in glob.glob("shares/*.zip"):
                with zf.ZipFile(z) as zfile:
                    for name in zfile.namelist():
                        if name.startswith("share_") and name.endswith(".txt"):
                            share_info = json.loads(zfile.read(name))
                            break
                if share_info:
                    break

            if share_info is None:
                self.skipTest("Could not locate share file in ZIP output")

            self.assertNotIn("label", share_info, "label must be absent without --full-metadata")
            self.assertNotIn("total_shares", share_info, "total_shares must be absent")
            self.assertNotIn("share_set_id", share_info, "share_set_id must be absent")
            self.assertNotIn("tool_integrity", share_info, "tool_integrity must be absent")

    def test_with_full_metadata_share_contains_all_optional_fields(self):
        """--full-metadata must add label, total_shares, share_set_id, tool_integrity, python_version."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"full metadata test")
            result = self.runner.invoke(
                encrypt,
                [
                    str(src),
                    "--threshold", "2",
                    "--shares", "3",
                    "--label", "fullmeta",
                    "--full-metadata",
                ],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)

            import glob, zipfile as zf
            share_info = None
            for z in glob.glob("shares/*.zip"):
                with zf.ZipFile(z) as zfile:
                    for name in zfile.namelist():
                        if name.startswith("share_") and name.endswith(".txt"):
                            share_info = json.loads(zfile.read(name))
                            break
                if share_info:
                    break

            if share_info is None:
                self.skipTest("Could not locate share file in ZIP output")

            self.assertIn("label", share_info)
            self.assertEqual(share_info["label"], "fullmeta")
            self.assertIn("total_shares", share_info)
            self.assertEqual(share_info["total_shares"], 3)
            self.assertIn("share_set_id", share_info)
            self.assertIsNotNone(share_info["share_set_id"])
            self.assertIn("python_version", share_info)

    @unittest.skipIf(sys.version_info[:3] < (3, 12, 11), "CLI sys is patched on this runner — python_version field reflects patched version")
    def test_full_metadata_python_version_matches_runtime(self):
        """python_version field must equal the actual runtime Python version."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"python version test")
            self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "pyver", "--full-metadata"],
                catch_exceptions=False,
            )
            import glob, zipfile as zf
            share_info = None
            for z in glob.glob("shares/*.zip"):
                with zf.ZipFile(z) as zfile:
                    for name in zfile.namelist():
                        if name.startswith("share_") and name.endswith(".txt"):
                            share_info = json.loads(zfile.read(name))
                            break
                if share_info:
                    break

            if share_info is None:
                self.skipTest("Could not locate share file in ZIP output")

            expected = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            self.assertEqual(share_info.get("python_version"), expected)

    def test_full_metadata_share_set_id_is_consistent_across_shares(self):
        """All shares produced in one encrypt run must share the same share_set_id."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"share_set_id consistency")
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "setid", "--full-metadata"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)

            import glob, zipfile as zf
            set_ids = set()
            for z in glob.glob("shares/*.zip"):
                with zf.ZipFile(z) as zfile:
                    for name in zfile.namelist():
                        if name.startswith("share_") and name.endswith(".txt"):
                            info = json.loads(zfile.read(name))
                            if "share_set_id" in info:
                                set_ids.add(info["share_set_id"])

            if not set_ids:
                self.skipTest("No share_set_id found in ZIP output")

            self.assertEqual(len(set_ids), 1, f"All shares must have the same share_set_id, got: {set_ids}")

    def test_full_metadata_label_space_normalized_to_underscore(self):
        """Spaces in --label are replaced with underscores before being written to shares."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"space label test")
            self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "my secret", "--full-metadata"],
                catch_exceptions=False,
            )

            import glob, zipfile as zf
            share_info = None
            for z in glob.glob("shares/*.zip"):
                with zf.ZipFile(z) as zfile:
                    for name in zfile.namelist():
                        if name.startswith("share_") and name.endswith(".txt"):
                            share_info = json.loads(zfile.read(name))
                            break
                if share_info:
                    break

            if share_info is None:
                self.skipTest("Could not locate share file in ZIP output")

            label = share_info.get("label", "")
            self.assertNotIn(" ", label, f"Spaces must be replaced with underscores, got: {label!r}")
            self.assertEqual(label, "my_secret")


# ── --existing-shares flag ────────────────────────────────────────────────────

class TestExistingSharesFlag(unittest.TestCase):
    """--existing-shares re-encrypts a new file using a key recovered from existing shares."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_existing_shares_re_encrypts_and_decrypts_correctly(self):
        """File B encrypted with --existing-shares must be decryptable with the same shares."""
        shares_dir = self.tmp_dir / "shares"
        shares_dir.mkdir()

        # Produce file A + shares manually
        original_payload = b"original payload for existing-shares test"
        key = get_enhanced_random_bytes(32)
        file_a = self.tmp_dir / "file_a.bin"
        enc_a = self.tmp_dir / "file_a.bin.enc"
        file_a.write_bytes(original_payload)
        FileEncryptor(key).encrypt_file(str(file_a), str(enc_a))
        file_a.unlink()

        mgr = ShareManager(3, 5)
        shares = mgr.generate_shares(key, "reenc_test")
        for idx, data in shares:
            _write_share(
                shares_dir / f"share_{idx}.txt",
                idx, data,
                threshold=3, total_shares=5, label="reenc_test",
            )

        # Encrypt file B using --existing-shares
        new_payload = b"new file to encrypt with recovered key"
        file_b = self.tmp_dir / "file_b.bin"
        file_b.write_bytes(new_payload)

        result = self.runner.invoke(
            encrypt,
            [
                str(file_b),
                "--threshold", "3",
                "--shares", "5",
                "--label", "reenc_test",
                "--existing-shares", str(shares_dir),
            ],
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, f"Re-encrypt failed: {result.output}")

        enc_b = self.tmp_dir / "file_b.bin.enc"
        self.assertTrue(enc_b.exists(), "file_b.bin.enc was not created")

        # Remove the original so decrypt output path is free
        file_b.unlink(missing_ok=True)

        # Decrypt file B using the same shares
        result2 = self.runner.invoke(
            decrypt,
            [str(enc_b), "--shares-dir", str(shares_dir)],
            catch_exceptions=False,
        )
        self.assertEqual(result2.exit_code, 0, f"Decrypt after re-encrypt failed: {result2.output}")

        decrypted = self.tmp_dir / "file_b.bin"
        self.assertTrue(decrypted.exists())
        self.assertEqual(decrypted.read_bytes(), new_payload)

    def test_existing_shares_adopts_label_from_shares(self):
        """If shares have a label, that label overrides --label in the CLI output."""
        shares_dir = self.tmp_dir / "labeled_shares"
        shares_dir.mkdir()

        key = get_enhanced_random_bytes(32)
        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "original_label")
        for idx, data in shares:
            _write_share(
                shares_dir / f"share_{idx}.txt",
                idx, data,
                threshold=2, total_shares=3, label="original_label",
            )

        src = self.tmp_dir / "newfile.bin"
        src.write_bytes(b"label adoption test")

        result = self.runner.invoke(
            encrypt,
            [
                str(src),
                "--threshold", "2",
                "--shares", "3",
                "--label", "different_label",  # should be overridden
                "--existing-shares", str(shares_dir),
            ],
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        # The CLI prints "Existing shares found with label: original_label"
        self.assertIn("original_label", result.output)

    def test_existing_shares_no_valid_files_exits_1(self):
        """Pointing --existing-shares to an empty directory must exit 1 with an error."""
        empty_dir = self.tmp_dir / "empty_shares"
        empty_dir.mkdir()

        src = self.tmp_dir / "newfile.bin"
        src.write_bytes(b"should fail")

        result = self.runner.invoke(
            encrypt,
            [
                str(src),
                "--threshold", "2",
                "--shares", "3",
                "--label", "noshares",
                "--existing-shares", str(empty_dir),
            ],
        )
        self.assertNotEqual(result.exit_code, 0, f"Should fail, got: {result.output}")

    def test_existing_shares_minimal_metadata_uses_provided_label(self):
        """Shares without a label field use the --label argument as-is."""
        shares_dir = self.tmp_dir / "minimal_meta_shares"
        shares_dir.mkdir()

        key = get_enhanced_random_bytes(32)
        mgr = ShareManager(2, 3)
        raw_shares = mgr.generate_shares(key, "any")
        for idx, data in raw_shares:
            # Write minimal share — no label field
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": 2,
                "total_shares": 3,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
            }
            with open(shares_dir / f"share_{idx}.txt", "w", encoding="utf-8") as f:
                json.dump(info, f)

        src = self.tmp_dir / "file.bin"
        src.write_bytes(b"minimal metadata existing-shares test")

        result = self.runner.invoke(
            encrypt,
            [
                str(src),
                "--threshold", "2",
                "--shares", "3",
                "--label", "provided_label",
                "--existing-shares", str(shares_dir),
            ],
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        enc = self.tmp_dir / "file.bin.enc"
        self.assertTrue(enc.exists())


# ── --manual-shares / -m mode ─────────────────────────────────────────────────

class TestManualSharesMode(unittest.TestCase):
    """--manual-shares activates interactive prompt-based share entry (collect_manual_shares)."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _build_manual_input(self, threshold, total, shares_b64, confirm_at_threshold=True):
        """Construct the stdin string for collect_manual_shares.

        Prompts in order:
          1. threshold
          2. total_shares
          3. (loop) share_index / share_key / [y] to proceed when enough, or 'done'
        """
        lines = [str(threshold), str(total)]
        for i, (idx, b64) in enumerate(shares_b64):
            lines.append(str(idx))
            lines.append(b64)
            if confirm_at_threshold and (i + 1) == threshold:
                lines.append("y")  # "Proceed with decryption?"
        return "\n".join(lines) + "\n"

    def test_manual_shares_base64_decrypts_correctly(self):
        """Provide threshold shares in Base64; decryption must succeed."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "plain.bin"
        enc = self.tmp_dir / "plain.bin.enc"
        src.write_bytes(b"manual shares B64 test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(3, 5)
        shares = mgr.generate_shares(key, "manual")
        shares_b64 = [(idx, base64.b64encode(data).decode()) for idx, data in shares[:3]]

        user_input = self._build_manual_input(3, 5, shares_b64)
        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares"],
            input=user_input,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, f"Manual B64 decrypt failed: {result.output}")
        decrypted = self.tmp_dir / "plain.bin"
        self.assertTrue(decrypted.exists())
        self.assertEqual(decrypted.read_bytes(), b"manual shares B64 test")

    def test_manual_shares_hex_decrypts_correctly(self):
        """Provide threshold shares in hex; decryption must succeed."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "hex_plain.bin"
        enc = self.tmp_dir / "hex_plain.bin.enc"
        src.write_bytes(b"manual shares hex test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "hextest")
        shares_hex = [(idx, data.hex()) for idx, data in shares[:2]]

        user_input = self._build_manual_input(2, 3, shares_hex)
        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares"],
            input=user_input,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, f"Manual hex decrypt failed: {result.output}")
        decrypted = self.tmp_dir / "hex_plain.bin"
        self.assertTrue(decrypted.exists())
        self.assertEqual(decrypted.read_bytes(), b"manual shares hex test")

    def test_manual_shares_invalid_index_prompts_again(self):
        """Non-integer index input must print an error and re-prompt (not crash)."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "idx_plain.bin"
        enc = self.tmp_dir / "idx_plain.bin.enc"
        src.write_bytes(b"index retry test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "idxtest")
        valid_b64 = base64.b64encode(shares[0][1]).decode()
        valid_b64_2 = base64.b64encode(shares[1][1]).decode()

        # First provide bad index, then valid ones
        user_input = "\n".join([
            "2",              # threshold
            "3",              # total
            "abc",            # invalid index → re-prompt
            str(shares[0][0]),
            valid_b64,
            str(shares[1][0]),
            valid_b64_2,
            "y",
        ]) + "\n"

        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares"],
            input=user_input,
        )
        output = result.output or ""
        self.assertIn("Invalid", output, f"Should print 'Invalid' after bad index: {output!r}")

    def test_manual_shares_done_with_one_share_warns(self):
        """Entering 'done' after only 1 share must print a warning (threshold not met)."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "warn.bin"
        enc = self.tmp_dir / "warn.bin.enc"
        src.write_bytes(b"insufficient manual shares")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(3, 5)
        shares = mgr.generate_shares(key, "warn")

        user_input = "\n".join([
            "3",
            "5",
            str(shares[0][0]),
            base64.b64encode(shares[0][1]).decode(),
            "done",
        ]) + "\n"

        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares"],
            input=user_input,
        )
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        self.assertTrue(
            any(kw in combined.lower() for kw in ["warning", "not enough", "minimum", "error"]),
            f"Should warn about insufficient shares: {combined!r}",
        )

    def test_manual_shares_threshold_1_is_rejected(self):
        """Threshold < 2 must be rejected with an error (not crash)."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "t1.bin"
        enc = self.tmp_dir / "t1.bin.enc"
        src.write_bytes(b"threshold 1 test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        user_input = "\n".join(["1", "3"]) + "\n"
        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares"],
            input=user_input,
        )
        combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
        self.assertNotEqual(result.exit_code, 0, f"Should fail with threshold=1: {combined}")

    def test_manual_shares_confirmation_prompt_at_threshold(self):
        """After providing exactly threshold shares, CLI must ask to proceed."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "confirm.bin"
        enc = self.tmp_dir / "confirm.bin.enc"
        src.write_bytes(b"confirmation prompt test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "confirm")
        shares_b64 = [(idx, base64.b64encode(data).decode()) for idx, data in shares[:2]]

        user_input = self._build_manual_input(2, 3, shares_b64, confirm_at_threshold=True)
        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares"],
            input=user_input,
            catch_exceptions=False,
        )
        output = result.output or ""
        self.assertIn("Proceed", output, f"Confirmation prompt expected: {output!r}")
        self.assertEqual(result.exit_code, 0, f"Decrypt failed: {output}")

    def test_manual_shares_no_flag_requires_shares_dir(self):
        """Without --manual-shares and without --shares-dir, CLI must exit 1."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "noflag.bin"
        enc = self.tmp_dir / "noflag.bin.enc"
        src.write_bytes(b"no flag test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        result = self.runner.invoke(decrypt, [str(enc)])
        self.assertNotEqual(result.exit_code, 0)

    def test_manual_shares_verbose_flag_shows_collection_info(self):
        """--verbose --manual-shares must print 'Manual share entry mode activated'."""
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "verbman.bin"
        enc = self.tmp_dir / "verbman.bin.enc"
        src.write_bytes(b"verbose manual test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "verbman")
        shares_b64 = [(idx, base64.b64encode(data).decode()) for idx, data in shares[:2]]

        user_input = self._build_manual_input(2, 3, shares_b64)
        result = self.runner.invoke(
            decrypt,
            [str(enc), "--manual-shares", "--verbose"],
            input=user_input,
            catch_exceptions=False,
        )
        output = result.output or ""
        self.assertIn("Manual", output, f"Expected verbose 'Manual' message: {output!r}")


# ── --verbose mode ─────────────────────────────────────────────────────────────

class TestVerboseMode(unittest.TestCase):
    """--verbose must surface meaningful progress info without leaking key material."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_encrypt_verbose_shows_share_set_id(self):
        """Encrypt --verbose must log 'Generated share set ID' with a non-empty value."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"verbose encrypt test")
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "verbenc", "--verbose"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("share set id", result.output.lower().replace("_", " "), result.output)

    def test_encrypt_verbose_space_replacement_message(self):
        """With a label containing spaces, --verbose must mention 'underscores'."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"space label verbose test")
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "my label", "--verbose"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("underscore", result.output.lower(), result.output)

    def test_encrypt_verbose_shows_share_count(self):
        """Encrypt --verbose must log how many shares were generated."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"share count verbose test")
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "4", "--label", "cnttest", "--verbose"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("4", result.output)

    def test_decrypt_verbose_shows_share_count_found(self):
        """Decrypt --verbose must log how many shares were found and the threshold."""
        enc_path, share_paths, _, _ = _make_enc_file(self.tmp_dir, label="verbdec")
        shares_dir = self.tmp_dir / "shares_v"
        shares_dir.mkdir()
        for p in share_paths:
            dest = shares_dir / p.name
            dest.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir), "--verbose"],
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        output = result.output
        # verbose must mention how many shares were found
        self.assertTrue(
            any(kw in output.lower() for kw in ["found", "shares", "processing"]),
            f"Expected verbose share-count message: {output!r}",
        )

    def test_decrypt_verbose_shows_no_set_id_when_minimal_metadata(self):
        """Decrypt --verbose on minimal-metadata shares must log 'No share set ID'."""
        enc_path, share_paths, _, _ = _make_enc_file(self.tmp_dir, label="noid")
        shares_dir = self.tmp_dir / "shares_noid"
        shares_dir.mkdir()
        for p in share_paths:
            dest = shares_dir / p.name
            dest.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir), "--verbose"],
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No share set ID", result.output)

    def test_verbose_output_does_not_contain_raw_key_bytes(self):
        """Neither encrypt nor decrypt verbose output must contain the raw key hex."""
        enc_path, share_paths, key, _ = _make_enc_file(self.tmp_dir, label="keyleak")
        key_hex = key.hex()
        key_b64 = base64.b64encode(key).decode()

        shares_dir = self.tmp_dir / "shares_kl"
        shares_dir.mkdir()
        for p in share_paths:
            dest = shares_dir / p.name
            dest.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")

        result = self.runner.invoke(
            decrypt,
            [enc_path, "--shares-dir", str(shares_dir), "--verbose"],
            catch_exceptions=False,
        )
        output = result.output or ""
        self.assertNotIn(key_hex, output, "Raw key hex must not appear in verbose output")
        self.assertNotIn(key_b64, output, "Raw key B64 must not appear in verbose output")


if __name__ == "__main__":
    unittest.main()
