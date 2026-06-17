#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File corruption tests — axe 4 of the coverage audit.


Each test crafts a deterministic .enc file corruption and verifies that
FileEncryptor.decrypt_file raises ValueError with a specific, actionable
message. No random bytes — every corruption is reproducible.

.enc binary format:
  [4 bytes big-endian: metadata_length]
  [metadata_length bytes: JSON metadata (AAD)]
  [16 bytes: AES-GCM nonce]
  [16 bytes: AES-GCM authentication tag]
  [N bytes: ciphertext]
"""

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.config import VERSION
from src.crypto import FileEncryptor
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes
from fixtures import BITWARDEN_VAULT_EXPORT


class FileCorruptionBase(unittest.TestCase):
    """Shared setup: one valid .enc file, its parsed components, and helpers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        self.key = get_enhanced_random_bytes(32)
        self.plaintext = BITWARDEN_VAULT_EXPORT
        self.encryptor = FileEncryptor(self.key)

        src = self.tmp_dir / "plain.bin"
        self.enc = self.tmp_dir / "plain.bin.enc"
        src.write_bytes(self.plaintext)
        self.encryptor.encrypt_file(str(src), str(self.enc))

        with open(self.enc, "rb") as f:
            self.meta_len = int.from_bytes(f.read(4), "big")
            self.meta_bytes = f.read(self.meta_len)
            self.nonce = f.read(16)
            self.tag = f.read(16)
            self.ciphertext = f.read()

    def tearDown(self):
        self.tmp.cleanup()

    def _write_enc(self, header: bytes, meta: bytes, nonce: bytes, tag: bytes, ct: bytes) -> Path:
        """Write a fully assembled (potentially crafted) .enc file."""
        p = self.tmp_dir / f"crafted_{len(header)}_{len(meta)}.enc"
        counter = 0
        while p.exists():
            counter += 1
            p = p.with_stem(p.stem + f"_{counter}")
        with open(p, "wb") as f:
            f.write(header)
            f.write(meta)
            f.write(nonce)
            f.write(tag)
            f.write(ct)
        return p

    def _expect_error(self, path: Path, *keywords) -> str:
        """Assert decrypt raises ValueError and that its message contains at least one keyword."""
        out = self.tmp_dir / f"out_{path.stem}.bin"
        with self.assertRaises(ValueError) as ctx:
            self.encryptor.decrypt_file(str(path), str(out))
        msg = str(ctx.exception)
        if keywords:
            self.assertTrue(
                any(kw.lower() in msg.lower() for kw in keywords),
                f"None of {keywords!r} found in error: {msg!r}",
            )
        return msg

    @property
    def _valid_header(self) -> bytes:
        return self.meta_len.to_bytes(4, "big")


# ── structural truncation ─────────────────────────────────────────────────────

class TestStructuralTruncation(FileCorruptionBase):
    """Truncated files at each boundary must each produce a distinct, named error."""

    def test_empty_file_raises_truncated_header_error(self):
        """An empty file must report that the header is incomplete."""
        p = self.tmp_dir / "empty.enc"
        p.write_bytes(b"")
        self._expect_error(p, "Truncated", "header")

    def test_two_byte_header_raises_truncated_error(self):
        """Only 2 of 4 header bytes → header incomplete."""
        p = self.tmp_dir / "2bytes.enc"
        p.write_bytes(b"\x00\x00")
        self._expect_error(p, "Truncated", "header")

    def test_truncated_metadata_raises_incomplete_error(self):
        """Header claims 100 bytes of metadata but only 10 are present."""
        p = self.tmp_dir / "trunc_meta.enc"
        with open(p, "wb") as f:
            f.write((100).to_bytes(4, "big"))
            f.write(b"\x00" * 10)  # only 10 of 100 declared bytes
        self._expect_error(p, "Truncated", "metadata", "incomplete")

    def test_truncated_nonce_raises_nonce_error(self):
        """Only 8 of 16 nonce bytes present → nonce error."""
        p = self.tmp_dir / "trunc_nonce.enc"
        with open(p, "wb") as f:
            f.write(self._valid_header)
            f.write(self.meta_bytes)
            f.write(b"\x00" * 8)  # 8 instead of 16
        self._expect_error(p, "nonce")

    def test_truncated_tag_raises_tag_error(self):
        """Only 8 of 16 authentication tag bytes present → tag error."""
        p = self.tmp_dir / "trunc_tag.enc"
        with open(p, "wb") as f:
            f.write(self._valid_header)
            f.write(self.meta_bytes)
            f.write(self.nonce)
            f.write(b"\x00" * 8)  # 8 instead of 16
        self._expect_error(p, "tag")

    def test_missing_ciphertext_raises_no_data_error(self):
        """File ends after the tag with no ciphertext bytes → 'No encrypted data'."""
        p = self.tmp_dir / "no_ct.enc"
        with open(p, "wb") as f:
            f.write(self._valid_header)
            f.write(self.meta_bytes)
            f.write(self.nonce)
            f.write(self.tag)
            # intentionally no ciphertext
        msg = self._expect_error(p, "No encrypted data", "empty")
        self.assertIn("No encrypted data", msg)


# ── metadata_length boundary values ──────────────────────────────────────────

class TestMetadataLengthBoundaries(FileCorruptionBase):
    """metadata_length edge values at the 4-byte header field."""

    def test_metadata_length_zero_raises_corrupt_metadata(self):
        """metadata_length = 0 → json.loads('') fails → Corrupt metadata."""
        p = self.tmp_dir / "meta_len_0.enc"
        with open(p, "wb") as f:
            f.write(b"\x00\x00\x00\x00")
            f.write(self.nonce)  # next bytes; json.loads("") will fail first
        self._expect_error(p, "Corrupt metadata", "json", "metadata")

    def test_metadata_length_uint32_max_raises_too_large(self):
        """metadata_length = 0xFFFFFFFF (4 294 967 295) → exceeds 65536 guard."""
        p = self.tmp_dir / "meta_len_max.enc"
        p.write_bytes(b"\xff\xff\xff\xff")
        msg = self._expect_error(p, "too large", "Metadata")
        self.assertIn("too large", msg.lower())

    def test_metadata_length_exactly_65537_raises_too_large(self):
        """metadata_length = 65537 (one above the guard) → too large error."""
        p = self.tmp_dir / "meta_len_65537.enc"
        p.write_bytes((65537).to_bytes(4, "big"))
        self._expect_error(p, "too large")

    def test_metadata_length_65536_reads_metadata(self):
        """metadata_length = 65536 (at the guard limit) is allowed; corrupt JSON raises parse error."""
        p = self.tmp_dir / "meta_len_65536.enc"
        with open(p, "wb") as f:
            f.write((65536).to_bytes(4, "big"))
            f.write(b"X" * 65536)  # not valid JSON
        self._expect_error(p, "Corrupt metadata", "json")


# ── cryptographic tampering ───────────────────────────────────────────────────

class TestCryptographicTampering(FileCorruptionBase):
    """Tampered nonce, tag, or ciphertext — all caught by GCM authentication."""

    def test_nonce_all_zeros_causes_mac_failure(self):
        """Nonce replaced with 16 zero bytes → GCM MAC check fails."""
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            b"\x00" * 16, self.tag, self.ciphertext,
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_nonce_all_ones_causes_mac_failure(self):
        """Nonce replaced with 16 0xFF bytes → GCM MAC check fails."""
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            b"\xff" * 16, self.tag, self.ciphertext,
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_tag_all_zeros_causes_authentication_failure(self):
        """GCM tag replaced with 16 zero bytes → authentication fails."""
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            self.nonce, b"\x00" * 16, self.ciphertext,
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_tag_single_bit_flip_causes_authentication_failure(self):
        """One bit flipped in the GCM tag → authentication fails."""
        corrupted_tag = bytearray(self.tag)
        corrupted_tag[7] ^= 0x80
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            self.nonce, bytes(corrupted_tag), self.ciphertext,
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_ciphertext_first_byte_flipped_causes_authentication_failure(self):
        """One bit flipped at the start of ciphertext → GCM authentication fails."""
        corrupted = bytearray(self.ciphertext)
        corrupted[0] ^= 0x01
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            self.nonce, self.tag, bytes(corrupted),
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_ciphertext_last_byte_flipped_causes_authentication_failure(self):
        """One bit flipped at the end of ciphertext → GCM authentication fails."""
        corrupted = bytearray(self.ciphertext)
        corrupted[-1] ^= 0xFF
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            self.nonce, self.tag, bytes(corrupted),
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_ciphertext_all_zeros_causes_authentication_failure(self):
        """Ciphertext replaced with same-length zero bytes → GCM tag invalid."""
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            self.nonce, self.tag, b"\x00" * len(self.ciphertext),
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_swapped_nonce_and_tag_causes_authentication_failure(self):
        """Swapping nonce and tag bytes → GCM authentication fails."""
        p = self._write_enc(
            self._valid_header, self.meta_bytes,
            self.tag, self.nonce,  # swapped
            self.ciphertext,
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")


# ── metadata content tampering ────────────────────────────────────────────────

class TestMetadataContentTampering(FileCorruptionBase):
    """Metadata bytes altered while keeping metadata_length correct."""

    def test_unknown_version_raises_incompatible_error_naming_version(self):
        """version field set to '9.9.9' → error names both expected and found versions."""
        meta = json.loads(self.meta_bytes.decode())
        meta["version"] = "9.9.9"
        bad_meta = json.dumps(meta).encode()
        p = self._write_enc(
            len(bad_meta).to_bytes(4, "big"),
            bad_meta, self.nonce, self.tag, self.ciphertext,
        )
        msg = self._expect_error(p, "Incompatible version", "9.9.9")
        self.assertIn("9.9.9", msg)
        self.assertIn(VERSION, msg)

    def test_metadata_replaced_with_plain_string_raises_corrupt_error(self):
        """JSON replaced with a plain ASCII string → Corrupt metadata."""
        bad_meta = b"this is not json"
        p = self._write_enc(
            len(bad_meta).to_bytes(4, "big"),
            bad_meta, self.nonce, self.tag, self.ciphertext,
        )
        self._expect_error(p, "Corrupt metadata")

    def test_metadata_replaced_with_binary_garbage_raises_corrupt_error(self):
        """Binary garbage bytes as metadata → Corrupt metadata."""
        bad_meta = bytes(range(128)) * 2  # 256 bytes of non-UTF-8
        p = self._write_enc(
            len(bad_meta).to_bytes(4, "big"),
            bad_meta, self.nonce, self.tag, self.ciphertext,
        )
        self._expect_error(p, "Corrupt metadata")

    def test_metadata_modified_causes_aad_mismatch_and_mac_failure(self):
        """Metadata bytes changed (valid JSON, wrong AAD) → GCM MAC fails.

        The metadata is the AAD (Additional Authenticated Data). Any change
        to it invalidates the GCM tag even if the ciphertext is intact.
        """
        meta = json.loads(self.meta_bytes.decode())
        meta["tampered"] = "injected_field"
        tampered_meta = json.dumps(meta).encode()
        p = self._write_enc(
            len(tampered_meta).to_bytes(4, "big"),
            tampered_meta, self.nonce, self.tag, self.ciphertext,
        )
        self._expect_error(p, "MAC", "mac", "decrypt", "verify", "tag")

    def test_metadata_with_control_characters_raises_corrupt_error(self):
        """JSON with control characters (invalid per JSON spec) → Corrupt metadata."""
        bad_meta = b'{"version": "' + VERSION.encode() + b'", "note": "\x00\x01\x02"}'
        p = self._write_enc(
            len(bad_meta).to_bytes(4, "big"),
            bad_meta, self.nonce, self.tag, self.ciphertext,
        )
        self._expect_error(p, "Corrupt metadata")


# ── share key encoding error ──────────────────────────────────────────────────

class TestShareKeyEncoding(unittest.TestCase):
    """share_key stored in the wrong encoding produces a wrong key → GCM fails."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_share_key_stored_as_hex_is_caught_before_decrypt(self):
        """share_key in hex (not base64) → b64decode produces wrong-length bytes.

        Two acceptable outcomes:
        - combine_shares raises ValueError (wrong share byte length for Shamir)
        - OR wrong key reconstructed → GCM authentication fails on decrypt
        Either way, the plaintext is never produced silently.
        """
        key = get_enhanced_random_bytes(32)
        src = self.tmp_dir / "plain.bin"
        enc = self.tmp_dir / "plain.bin.enc"
        src.write_bytes(b"share key encoding test")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()

        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "hexkey")

        shares_dir = self.tmp_dir / "hex_shares"
        shares_dir.mkdir()

        for idx, data in shares[:2]:
            info = {
                "share_index": idx,
                "share_key": data.hex(),   # hex instead of base64
                "threshold": 2,
                "total_shares": 3,
                # no hash field → load_shares won't detect the wrong encoding
                "version": VERSION,
                "label": "hexkey",
            }
            (shares_dir / f"share_{idx}.txt").write_text(json.dumps(info))

        share_files = [str(f) for f in shares_dir.glob("share_*.txt")]
        loaded_shares, _ = ShareManager.load_shares(share_files)

        # Attempt reconstruction + decrypt; at least one step must fail
        out = self.tmp_dir / "plain.bin"
        raised = False
        try:
            wrong_key = mgr.combine_shares(loaded_shares)
            FileEncryptor(wrong_key).decrypt_file(str(enc), str(out))
        except (ValueError, Exception):
            raised = True

        self.assertTrue(raised, "Hex-encoded share_key must cause an error before producing plaintext")
        self.assertFalse(out.exists(), "Plaintext output must not be written when share_key is corrupt")

    def test_share_key_with_invalid_base64_chars_raises_error(self):
        """share_key containing non-base64 characters must raise an error on load."""
        key = get_enhanced_random_bytes(32)
        mgr = ShareManager(2, 3)
        shares = mgr.generate_shares(key, "badkey")
        idx, data = shares[0]

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad_b64.txt"
            info = {
                "share_index": idx,
                "share_key": "!!!NOT_VALID_BASE64???",
                "threshold": 2,
                "total_shares": 3,
                "version": VERSION,
            }
            p.write_text(json.dumps(info))

            with self.assertRaises((ValueError, Exception)):
                ShareManager.load_shares([str(p)])


if __name__ == "__main__":
    unittest.main()
