#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
End-to-end encrypt -> decrypt roundtrip tests.

These drive the *real* ``fractum`` console script as a subprocess, so they
exercise the full path a user actually hits: argument parsing, key generation,
AES-256-GCM encryption, Shamir share splitting, per-share ZIP archive creation,
share discovery, key reconstruction and decryption.

Design notes
------------
* The CLI writes the ``shares/`` directory and the ``.enc`` file relative to its
  own working directory, so every case runs inside an isolated temp dir passed
  via ``cwd=`` -- nothing touches the repo tree.
* Default (minimal-metadata) shares carry no ``share_set_id``/``label``, so
  decryption goes through the label-fallback brute-force path. ``--full-metadata``
  exercises the ``share_set_id`` routing path instead. Both are covered.
* The console script is resolved next to the running interpreter, which makes the
  test work unchanged under the native ``.venv`` and inside the Docker test image
  (``pip install -e`` puts ``fractum`` in the same bin dir as ``python``).

Auto-discovered by ``run_tests.py`` (file name matches ``test_*.py``); written as
stdlib ``unittest`` per the project convention (no pytest).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


def _resolve_fractum():
    """Locate the fractum CLI, preferring the one next to this interpreter."""
    sibling = Path(sys.executable).parent / "fractum"
    if sibling.exists():
        return [str(sibling)]
    found = shutil.which("fractum")
    if found:
        return [found]
    # Last resort: invoke the package entry point directly.
    return [sys.executable, "-c", "from src import cli; cli()"]


FRACTUM = _resolve_fractum()
TIMEOUT = 180


class _RoundtripBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            res = subprocess.run(
                FRACTUM + ["--version"], capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise unittest.SkipTest(f"fractum CLI not runnable: {exc}")
        if res.returncode != 0:
            raise unittest.SkipTest(
                f"fractum --version failed (rc={res.returncode}): "
                f"{res.stderr or res.stdout}"
            )

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="fractum_e2e_"))
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)

    # -- low-level helpers -------------------------------------------------

    def _fresh(self) -> Path:
        """An isolated working dir for one CLI invocation.

        The CLI writes ``shares/`` and ``<file>.enc`` into its cwd, so every
        encrypt must run in its own dir -- otherwise the archiver's collision
        handling renames a second run's archives to ``share_1_2.zip`` etc.
        """
        return Path(tempfile.mkdtemp(dir=self.workdir))

    def _run(self, base: Path, args):
        return subprocess.run(
            FRACTUM + args,
            cwd=str(base),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )

    def _write_plaintext(self, base: Path, name, data: bytes) -> Path:
        path = base / name
        path.write_bytes(data)
        return path

    def _encrypt(
        self,
        base,
        name,
        threshold,
        shares,
        label=None,
        full_metadata=False,
        bundle_encrypted=False,
    ):
        args = ["encrypt", name, "-t", str(threshold), "-n", str(shares)]
        if label is not None:
            args += ["-l", label]
        if full_metadata:
            args += ["--full-metadata"]
        if bundle_encrypted:
            args += ["--bundle-encrypted"]
        res = self._run(base, args)
        self.assertEqual(
            res.returncode,
            0,
            msg=f"encrypt failed (args={args})\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
        )
        enc = base / f"{name}.enc"
        self.assertTrue(
            enc.exists(), msg=f"missing {enc.name}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
        archives = sorted((base / "shares").glob("share_*.zip"))
        self.assertEqual(
            len(archives),
            shares,
            msg=f"expected {shares} share archives, got {len(archives)}: "
            f"{[a.name for a in archives]}",
        )
        return enc, archives

    def _stage_shares(self, base, archives, count):
        """Copy ``count`` share archives into a fresh decrypt-input directory."""
        dec_dir = base / "dec_shares"
        if dec_dir.exists():
            shutil.rmtree(dec_dir)
        dec_dir.mkdir()
        for archive in archives[:count]:
            shutil.copy(archive, dec_dir / archive.name)
        return dec_dir

    def _decrypt(self, base, enc_path: Path, dec_dir: Path):
        return self._run(base, ["decrypt", enc_path.name, "-s", str(dec_dir)])

    def _roundtrip(
        self,
        data: bytes,
        threshold: int,
        shares: int,
        use_count=None,
        label=None,
        full_metadata=False,
        name="secret.bin",
    ):
        """Encrypt then decrypt and assert byte-for-byte recovery."""
        use_count = threshold if use_count is None else use_count
        base = self._fresh()
        self._write_plaintext(base, name, data)
        enc, archives = self._encrypt(
            base, name, threshold, shares, label=label, full_metadata=full_metadata
        )
        dec_dir = self._stage_shares(base, archives, use_count)
        # Remove the original so the decrypt no-overwrite guard (N4) doesn't trip.
        (base / name).unlink()
        res = self._decrypt(base, enc, dec_dir)
        self.assertEqual(
            res.returncode,
            0,
            msg=f"decrypt failed\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
        )
        recovered = base / name
        self.assertTrue(
            recovered.exists(),
            msg=f"plaintext not recreated\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
        )
        self.assertEqual(
            recovered.read_bytes(),
            data,
            msg="decrypted content does not match the original plaintext",
        )
        return enc, archives


class EndToEndRoundtripTests(_RoundtripBase):
    def test_threshold_combinations_minimal_metadata(self):
        """2-of-3, 3-of-5 and 5-of-10 each roundtrip with exactly threshold shares."""
        for threshold, shares in [(2, 3), (3, 5), (5, 10)]:
            with self.subTest(threshold=threshold, shares=shares):
                data = os.urandom(2048) + b"\n-- end of payload --\n"
                self._roundtrip(data, threshold, shares, name="secret.bin")

    def test_full_metadata_uses_share_set_id_path(self):
        """--full-metadata embeds share_set_id; decrypt routes via it and still recovers."""
        data = b"full-metadata path exercises share_set_id routing\n" * 64
        self._roundtrip(data, 3, 5, full_metadata=True)

    def test_decrypt_with_more_than_threshold_shares(self):
        """Supplying all N shares (above threshold) must also reconstruct correctly."""
        data = os.urandom(4096)
        self._roundtrip(data, 3, 5, use_count=5)

    def test_binary_file_roundtrip(self):
        """A 256 KiB random binary payload survives the roundtrip unchanged."""
        data = os.urandom(256 * 1024)
        self._roundtrip(data, 3, 5, name="payload.bin")

    def test_tiny_file_roundtrip(self):
        """A 1-byte file roundtrips (smallest non-empty input)."""
        self._roundtrip(b"x", 2, 3, name="tiny.txt")

    def test_utf8_text_file_roundtrip(self):
        """Non-ASCII UTF-8 text content roundtrips byte-for-byte."""
        data = "héllo wörld — fractum e2e check ✓\n".encode("utf-8")
        self._roundtrip(data, 2, 3, name="note.txt")

    def test_label_with_spaces_is_normalized(self):
        """Spaces in --label become underscores, and the file still roundtrips."""
        data = os.urandom(1024)
        name = "labeled.bin"
        base = self._fresh()
        self._write_plaintext(base, name, data)
        enc, archives = self._encrypt(
            base, name, 2, 3, label="my secret label", full_metadata=True
        )
        with zipfile.ZipFile(archives[0]) as zf:
            share_entry = next(
                n
                for n in zf.namelist()
                if Path(n).name.startswith("share_") and n.endswith(".txt")
            )
            info = json.loads(zf.read(share_entry))
        self.assertEqual(info.get("label"), "my_secret_label")

        dec_dir = self._stage_shares(base, archives, 2)
        (base / name).unlink()
        res = self._decrypt(base, enc, dec_dir)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertEqual((base / name).read_bytes(), data)

    def test_decrypt_insufficient_shares_fails(self):
        """Fewer than threshold shares must fail and must not emit any plaintext."""
        data = os.urandom(2048)
        name = "secret.bin"
        base = self._fresh()
        self._write_plaintext(base, name, data)
        enc, archives = self._encrypt(base, name, 3, 5)
        dec_dir = self._stage_shares(base, archives, 2)  # one below threshold
        (base / name).unlink()
        res = self._decrypt(base, enc, dec_dir)
        self.assertNotEqual(
            res.returncode,
            0,
            msg=f"decrypt unexpectedly succeeded with too few shares\n"
            f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
        )
        self.assertFalse(
            (base / name).exists(),
            msg="plaintext must not be reconstructed from insufficient shares",
        )

    def test_decrypt_refuses_to_overwrite_existing_output(self):
        """The N4 no-overwrite guard must protect an existing plaintext file."""
        data = os.urandom(1024)
        name = "secret.bin"
        base = self._fresh()
        self._write_plaintext(base, name, data)
        enc, archives = self._encrypt(base, name, 2, 3)
        dec_dir = self._stage_shares(base, archives, 2)
        # Intentionally keep the original plaintext in place.
        res = self._decrypt(base, enc, dec_dir)
        self.assertNotEqual(res.returncode, 0, msg="decrypt should refuse to overwrite")
        self.assertIn("already exists", (res.stdout + res.stderr).lower())
        # The original file must be left byte-for-byte intact.
        self.assertEqual((base / name).read_bytes(), data)

    def test_share_zip_omits_encrypted_file_by_default(self):
        """By default the .enc file must not be duplicated into every share ZIP."""
        data = os.urandom(1024)
        name = "secret.bin"
        base = self._fresh()
        self._write_plaintext(base, name, data)
        enc, archives = self._encrypt(base, name, 2, 3)
        for archive in archives:
            with zipfile.ZipFile(archive) as zf:
                self.assertFalse(
                    any(n.endswith(".enc") for n in zf.namelist()),
                    msg=f"{archive.name} unexpectedly bundles the .enc file",
                )

    def test_bundle_encrypted_flag_includes_enc_in_each_zip(self):
        """--bundle-encrypted must embed a working copy of the .enc in every ZIP."""
        data = os.urandom(1024)
        name = "secret.bin"
        base = self._fresh()
        self._write_plaintext(base, name, data)
        enc, archives = self._encrypt(base, name, 2, 3, bundle_encrypted=True)

        with zipfile.ZipFile(archives[0]) as zf:
            enc_entries = [n for n in zf.namelist() if n.endswith(".enc")]
            self.assertEqual(
                len(enc_entries),
                1,
                msg=f"expected exactly one bundled .enc in {archives[0].name}, found {enc_entries}",
            )
            extract_dir = base / "extracted_from_zip"
            extract_dir.mkdir()
            zf.extract(enc_entries[0], extract_dir)
            bundled_enc = extract_dir / enc_entries[0]

        # The bundled copy must be byte-for-byte identical to the original .enc,
        # and usable on its own to decrypt with shares pulled from the same ZIPs.
        self.assertEqual(bundled_enc.read_bytes(), enc.read_bytes())

        dec_dir = self._stage_shares(base, archives, 2)
        res = self._run(base, ["decrypt", str(bundled_enc), "-s", str(dec_dir)])
        self.assertEqual(res.returncode, 0, msg=f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
        recovered = extract_dir / name
        self.assertTrue(recovered.exists())
        self.assertEqual(recovered.read_bytes(), data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
