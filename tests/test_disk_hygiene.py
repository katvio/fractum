#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disk hygiene tests: what a run leaves behind on the filesystem.

The rest of the suite asks whether decryption returns the right bytes. It never
asks what the run left on disk afterwards, which is how FSB-2026-02-A and
FSB-2026-02-B survived every release: the faulty lines were executed by the
existing tests, but nothing asserted on their side effects.

Two properties are checked here, on the success path and on every error path:

  A. no extracted share material is left in a temporary directory
  B. every file carrying secret material is created owner-only (0600)

Both assertions fail against the pre-fix code and pass against v1.4.2.
"""

import base64
import glob
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from click.testing import CliRunner

from src.cli.commands import decrypt, encrypt
from src.config import VERSION
from src.crypto import FileEncryptor
from src.shares import ShareManager
from src.utils import get_enhanced_random_bytes

WINDOWS = sys.platform.startswith("win")


def _mode(path) -> int:
    """Permission bits of path, e.g. 0o600."""
    return stat.S_IMODE(os.stat(path).st_mode)


def _temp_share_dirs():
    """Leftover extraction directories, both historical naming schemes."""
    found = list(glob.glob(os.path.join(tempfile.gettempdir(), "fractum_share_*")))
    found += list(glob.glob("temp_share_*"))
    return found


class _EncryptedFixture(unittest.TestCase):
    """Builds a real encrypted file plus its shares inside an isolated directory."""

    threshold = 2
    total = 3

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self.tmp.name)
        for leftover in _temp_share_dirs():
            self.addCleanup(lambda p=leftover: None)

    def tearDown(self):
        self.tmp.cleanup()

    def _build(self, tmp: Path):
        key = get_enhanced_random_bytes(32)
        src = tmp / "payload.bin"
        enc = tmp / "payload.bin.enc"
        src.write_bytes(b"disk hygiene payload")
        FileEncryptor(key).encrypt_file(str(src), str(enc))
        src.unlink()
        mgr = ShareManager(self.threshold, self.total)
        share_paths = []
        for idx, data in mgr.generate_shares(key, "hygiene"):
            p = tmp / f"share_{idx}.txt"
            info = {
                "share_index": idx,
                "share_key": base64.b64encode(data).decode(),
                "threshold": self.threshold,
                "total_shares": self.total,
                "hash": hashlib.sha256(data).hexdigest(),
                "version": VERSION,
                "label": "hygiene",
            }
            p.write_text(json.dumps(info), encoding="utf-8")
            share_paths.append(p)
        return enc, share_paths


@unittest.skipIf(WINDOWS, "POSIX permission bits are meaningless on Windows")
class TestOutputPermissions(_EncryptedFixture):
    """FSB-2026-02-B: outputs must not inherit a permissive umask."""

    def test_encrypted_file_is_owner_only(self):
        """encrypt must create the .enc file as 0600, not -rw-r--r--."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"permission test payload")
            os.umask(0o022)  # the permissive default that exposed the bug
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "perm"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)

            enc_files = glob.glob("*.enc") + glob.glob("**/*.enc", recursive=True)
            self.assertTrue(enc_files, "no .enc file produced")
            for f in enc_files:
                self.assertEqual(
                    _mode(f), 0o600,
                    f"{f} is {oct(_mode(f))}, expected 0o600, readable by other local users",
                )

    def test_share_archives_are_owner_only(self):
        """Every share archive carries key material and must be 0600."""
        with self.runner.isolated_filesystem():
            src = Path("secret.bin")
            src.write_bytes(b"share permission payload")
            os.umask(0o022)
            result = self.runner.invoke(
                encrypt,
                [str(src), "--threshold", "2", "--shares", "3", "--label", "perm"],
                catch_exceptions=False,
            )
            self.assertEqual(result.exit_code, 0, result.output)

            archives = glob.glob("**/*.zip", recursive=True)
            self.assertTrue(archives, "no share archive produced")
            for a in archives:
                self.assertEqual(
                    _mode(a), 0o600,
                    f"{a} is {oct(_mode(a))}, expected 0o600, share material world-readable",
                )

    def test_recovered_plaintext_is_owner_only(self):
        """The recovered file IS the secret, in the clear. Strictest case."""
        with self.runner.isolated_filesystem():
            tmp = Path(".")
            enc, shares = self._build(tmp)
            sdir = tmp / "shares"
            sdir.mkdir()
            for p in shares[: self.threshold]:
                p.rename(sdir / p.name)
            os.umask(0o022)
            result = self.runner.invoke(
                decrypt, [str(enc), "--shares-dir", str(sdir)], catch_exceptions=False
            )
            self.assertEqual(result.exit_code, 0, result.output)
            recovered = [
                f for f in glob.glob("**/*", recursive=True)
                if os.path.isfile(f) and not f.endswith((".enc", ".zip", ".txt"))
            ]
            self.assertTrue(recovered, f"decrypt produced no output file: {result.output}")
            for f in recovered:
                self.assertEqual(
                    _mode(f), 0o600,
                    f"recovered plaintext {f} is {oct(_mode(f))}, expected 0o600",
                )


class TestNoShareMaterialLeftBehind(_EncryptedFixture):
    """FSB-2026-02-A: no extraction directory may survive, on any path."""

    def _zip_shares(self, tmp: Path, share_paths):
        import zipfile
        archives = []
        for p in share_paths:
            z = tmp / f"{p.stem}.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.write(p, arcname=p.name)
            archives.append(z)
            p.unlink()
        return archives

    def _as_dir(self, tmp: Path, archives):
        """decrypt takes a directory of shares, not a list of files."""
        sdir = tmp / "sharesdir"
        sdir.mkdir(exist_ok=True)
        for a in archives:
            a.rename(sdir / a.name)
        return sdir

    def test_no_leftovers_after_successful_decrypt(self):
        with self.runner.isolated_filesystem():
            tmp = Path(".")
            enc, shares = self._build(tmp)
            archives = self._zip_shares(tmp, shares)
            sdir = self._as_dir(tmp, archives[: self.threshold])
            before = set(_temp_share_dirs())
            self.runner.invoke(
                decrypt, [str(enc), "--shares-dir", str(sdir)], catch_exceptions=False
            )
            new = set(_temp_share_dirs()) - before
            self.assertEqual(new, set(), f"extraction directories left behind: {new}")

    def test_no_leftovers_after_corrupt_share(self):
        """The exact path that leaked: a share whose JSON does not parse."""
        with self.runner.isolated_filesystem():
            tmp = Path(".")
            enc, shares = self._build(tmp)
            shares[0].write_text("{ this is not valid json", encoding="utf-8")
            archives = self._zip_shares(tmp, shares)
            sdir = self._as_dir(tmp, archives)
            before = set(_temp_share_dirs())
            self.runner.invoke(
                decrypt, [str(enc), "--shares-dir", str(sdir)], catch_exceptions=True
            )
            new = set(_temp_share_dirs()) - before
            self.assertEqual(
                new, set(),
                f"a failed decrypt left extracted share material on disk: {new}",
            )

    def test_no_leftovers_after_hash_mismatch(self):
        """The other error path: a share that parses but fails validation."""
        with self.runner.isolated_filesystem():
            tmp = Path(".")
            enc, shares = self._build(tmp)
            info = json.loads(shares[0].read_text(encoding="utf-8"))
            info["hash"] = "0" * 64
            shares[0].write_text(json.dumps(info), encoding="utf-8")
            archives = self._zip_shares(tmp, shares)
            sdir = self._as_dir(tmp, archives)
            before = set(_temp_share_dirs())
            self.runner.invoke(
                decrypt, [str(enc), "--shares-dir", str(sdir)], catch_exceptions=True
            )
            new = set(_temp_share_dirs()) - before
            self.assertEqual(
                new, set(),
                f"an invalid share left extracted material on disk: {new}",
            )


class TestPlaintextShareFileLifetime(_EncryptedFixture):
    """FSB-2026-02-D, fixed in 1.4.2. Found by re-auditing the whole write
    surface rather than only the sites FSB-2026-02 had already fixed.

    encrypt writes each share as a plaintext JSON file, archives it, then deletes
    it. Two problems with that window:
      - the file is created with the process umask, so 0644 while it exists
      - the deletion sits in the loop body, so any archiving error leaves every
        plaintext share on disk, which is the same shape as FSB-2026-02-A
    """

    def test_plaintext_share_file_is_owner_only_while_it_exists(self):
        """The share file holds share_key in the clear. It must never be 0644."""
        import src.shares.archiver as archiver_mod

        seen = {}
        original = archiver_mod.ShareArchiver.create_share_archive

        def spy(self_, share_file, *args, **kwargs):
            seen[str(share_file)] = _mode(share_file)
            return original(self_, share_file, *args, **kwargs)

        with self.runner.isolated_filesystem():
            Path("secret.bin").write_bytes(b"share lifetime payload")
            os.umask(0o022)
            with unittest.mock.patch.object(
                archiver_mod.ShareArchiver, "create_share_archive", spy
            ):
                result = self.runner.invoke(
                    encrypt,
                    ["secret.bin", "--threshold", "2", "--shares", "3", "--label", "life"],
                    catch_exceptions=False,
                )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(seen, "no share file reached the archiver")
            for path, mode in seen.items():
                self.assertEqual(
                    mode, 0o600,
                    f"plaintext share {path} is {oct(mode)} while it exists on disk",
                )

    def test_no_plaintext_shares_left_when_archiving_fails(self):
        """An archiving error must not leave plaintext shares behind.

        The failure is injected on the second archive, as a full disk would
        raise it. Making the destination read-only would tie the test to how
        encrypt picks its shares directory, which changed in 1.4.2, and a run
        that silently picked a writable directory would pass without the failure
        path ever being reached. The call count below guards against that.
        """
        import src.shares.archiver as archiver_mod

        original = archiver_mod.ShareArchiver.create_share_archive
        calls = []

        def fail_on_second(self_, *args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise OSError(28, "No space left on device")
            return original(self_, *args, **kwargs)

        with self.runner.isolated_filesystem():
            Path("secret.bin").write_bytes(b"archiving failure payload")
            with unittest.mock.patch.object(
                archiver_mod.ShareArchiver, "create_share_archive", fail_on_second
            ):
                result = self.runner.invoke(
                    encrypt,
                    ["secret.bin", "--threshold", "2", "--shares", "3", "--label", "fail"],
                    catch_exceptions=True,
                )
            self.assertEqual(len(calls), 2, "the injected failure was never reached")
            self.assertNotEqual(result.exit_code, 0, result.output)
            leftovers = sorted(str(p) for p in Path(".").rglob("share_*.txt"))
            self.assertEqual(
                leftovers, [],
                f"plaintext shares left on disk after a failed archiving: {leftovers}",
            )

if __name__ == "__main__":
    unittest.main(verbosity=2)
