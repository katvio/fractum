"""Tests for the three changes going into 1.4.2.

Each one fails on the code as it stood before its fix, which is the property
that makes it worth keeping:

- bytearray port: secure_clear() used to accept bytes, copy them into a
  bytearray, wipe the copy and return. The caller's secret was untouched, so
  the call read as correct and did nothing.
- core dumps: RLIMIT_CORE was unlimited for the whole time the process held the
  AES key. A crash at that moment writes the key to a file that outlives the
  process, and mlock does not help: it stops swapping, not dumping.
- shares directory: a second run reused shares/, mixing two sets in one place
  with nothing in the file names to tell them apart. The next set now goes to
  shares/set-2/, set-3/..., still under shares/.
"""

import os
import resource
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from click.testing import CliRunner

from src.cli.commands import decrypt, encrypt
from src.crypto.memory import SecureMemory, disable_core_dumps
from src.shares.manager import ShareManager


class TestSecureClearRefusesImmutable(unittest.TestCase):
    """Wiping an immutable object is a no-op, and a silent one is worse than a crash."""

    def test_bytes_are_refused(self):
        with self.assertRaises(TypeError) as ctx:
            SecureMemory.secure_clear(b"CANARY-MATERIAL-0123456789ABCDEF")
        self.assertIn("bytes", str(ctx.exception))

    def test_readonly_memoryview_is_refused(self):
        with self.assertRaises(TypeError):
            SecureMemory.secure_clear(memoryview(b"CANARY-0123456789ABCDEF01234567"))

    def test_bytearray_is_really_wiped(self):
        tampon = bytearray(b"CANARY-MATERIAL-0123456789ABCDEF")
        SecureMemory.secure_clear(tampon)
        self.assertEqual(bytes(tampon), bytes(len(tampon)))

    def test_writable_memoryview_is_wiped(self):
        source = bytearray(b"CANARY-MATERIAL-0123456789ABCDEF")
        SecureMemory.secure_clear(memoryview(source))
        self.assertEqual(bytes(source), bytes(len(source)))

    def test_immutable_list_element_is_dropped_not_raised(self):
        """A bytes inside a list must not abort the wipe of the elements after it.

        Raising here would leave every mutable element further down the list
        untouched, which is strictly worse than dropping the reference.
        """
        mutable = bytearray(b"SECRET-0123456789ABCDEF012345678")
        elements = [b"immuable", mutable, bytearray(b"encore")]
        SecureMemory.secure_clear(elements)  # ne doit pas lever
        self.assertEqual(
            bytes(mutable),
            bytes(len(mutable)),
            "the mutable element after the immutable one was left untouched",
        )


class TestReconstructedKeyIsWipeable(unittest.TestCase):
    """combine_shares returned bytes, i.e. an AES key nobody could wipe."""

    def test_combine_returns_a_wipeable_buffer(self):
        secret = os.urandom(32)
        m = ShareManager(3, 5)
        parts = m.generate_shares(secret, "essai")
        cle = m.combine_shares(parts[:3])

        self.assertIsInstance(
            cle, bytearray, "the AES key came back as an unwipeable bytes object"
        )
        self.assertEqual(bytes(cle), secret)

        SecureMemory.secure_clear(cle)
        self.assertEqual(bytes(cle), bytes(32))

    def test_loaded_shares_are_wipeable(self):
        """load_shares() feeds the wipe path, so its buffers must be mutable."""
        import base64
        import json

        dossier = tempfile.mkdtemp()
        try:
            chemin = os.path.join(dossier, "share_1.txt")
            with open(chemin, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "share_index": 1,
                        "share_key": base64.b64encode(os.urandom(32)).decode(),
                        "threshold": 2,
                        "total_shares": 3,
                    },
                    f,
                )
            parts, _ = ShareManager.load_shares([chemin])
            for _, donnees in parts:
                self.assertIsInstance(
                    donnees, bytearray, "a loaded share cannot be wiped"
                )
                SecureMemory.secure_clear(donnees)
        finally:
            shutil.rmtree(dossier, ignore_errors=True)


class TestCoreDumpsAreDisabled(unittest.TestCase):
    """A crash while the key is in memory used to write it to disk."""

    def test_limit_is_lowered_to_zero(self):
        """Run in a subprocess: the limit is process-wide and must not leak out."""
        code = (
            "import resource, sys;"
            "sys.path.insert(0, %r);"
            "resource.setrlimit(resource.RLIMIT_CORE, (-1, -1));"
            "avant = resource.getrlimit(resource.RLIMIT_CORE)[0];"
            "from src.crypto.memory import disable_core_dumps;"
            "ok = disable_core_dumps();"
            "apres = resource.getrlimit(resource.RLIMIT_CORE)[0];"
            "print(avant, apres, ok)" % str(Path(__file__).resolve().parent.parent)
        )
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        avant, apres, ok = r.stdout.split()
        self.assertEqual(avant, "-1", "the limit did not start unlimited")
        self.assertEqual(apres, "0", "core dumps are still allowed")
        self.assertEqual(ok, "True", "the function did not report success")

    def test_the_cli_calls_it_before_any_command(self):
        """Including --version: no path may skip it."""
        code = (
            "import resource, sys;"
            "sys.path.insert(0, %r);"
            "from click.testing import CliRunner;"
            "from src.cli.core import cli;"
            "CliRunner().invoke(cli, ['--version']);"
            "print(resource.getrlimit(resource.RLIMIT_CORE)[0])"
            % str(Path(__file__).resolve().parent.parent)
        )
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            r.stdout.strip(), "0", "the CLI ran a command with core dumps enabled"
        )

    def test_returns_a_boolean(self):
        """Callers warn on False rather than aborting, so the type matters.

        In a subprocess like the others: the call lowers the hard limit, which
        cannot be raised again, and every later test would inherit it."""
        code = (
            "import sys;"
            "sys.path.insert(0, %r);"
            "from src.crypto.memory import disable_core_dumps;"
            "print(type(disable_core_dumps()).__name__)"
            % str(Path(__file__).resolve().parent.parent)
        )
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "bool")


class TestSharesDirectoryIsNeverReused(unittest.TestCase):
    """A second run used to write into the same shares/, mixing two sets.

    Every set must stay under shares/: with Docker, shares/ is the mounted
    volume, and anything written beside it is lost with the container.
    """

    def setUp(self):
        self.runner = CliRunner()
        self.tmp = tempfile.mkdtemp()
        self.previous_cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self.previous_cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _encrypt(self, name: str):
        Path(name).write_text("content of " + name, encoding="utf-8")
        result = self.runner.invoke(encrypt, [name, "-t", "2", "-n", "3", "-l", name])
        self.assertEqual(result.exit_code, 0, result.output)
        return result

    def _zips(self, directory: str) -> list:
        return sorted(p.name for p in Path(directory).glob("*.zip"))

    def test_each_run_gets_its_own_directory_under_shares(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        self._encrypt("three.txt")
        for expected in ("shares", "shares/set-2", "shares/set-3"):
            with self.subTest(directory=expected):
                self.assertEqual(len(self._zips(expected)), 3, expected)

    def test_nothing_is_written_beside_shares(self):
        """The Docker case: only shares/ is mounted, so a sibling such as
        shares-2/ would never reach the host."""
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        siblings = sorted(p.name for p in Path(".").iterdir()
                          if p.is_dir() and p.name != "shares")
        self.assertEqual(siblings, [])

    def test_an_empty_shares_directory_is_used_as_is(self):
        """A fresh Docker mount is an existing, empty shares/."""
        Path("shares").mkdir()
        self._encrypt("one.txt")
        self.assertEqual(len(self._zips("shares")), 3)
        self.assertFalse(Path("shares/set-2").exists())

    def test_the_user_is_told_where_the_second_set_went(self):
        self._encrypt("one.txt")
        result = self._encrypt("two.txt")
        self.assertIn("set-2", result.output)

    def test_no_set_is_mixed_into_another(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        self.assertEqual(len(self._zips("shares")), 3)
        self.assertEqual(len(self._zips("shares/set-2")), 3)

    def test_an_existing_numbered_directory_is_not_overwritten(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        before = sorted(p.name for p in Path("shares/set-2").iterdir())
        self._encrypt("three.txt")
        self.assertEqual(sorted(p.name for p in Path("shares/set-2").iterdir()), before)
        self.assertTrue(Path("shares/set-3").is_dir())

    def test_each_set_decrypts_from_its_own_directory(self):
        self._encrypt("one.txt")
        self._encrypt("two.txt")
        os.remove("one.txt")
        os.remove("two.txt")
        for name, directory in (("one.txt", "shares"), ("two.txt", "shares/set-2")):
            with self.subTest(directory=directory):
                result = self.runner.invoke(
                    decrypt, [name + ".enc", "--shares-dir", directory]
                )
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(
                    Path(name).read_text(encoding="utf-8"), "content of " + name
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
