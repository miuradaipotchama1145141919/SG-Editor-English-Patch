import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.errors import TranslationError
from src.resources import applyBitmapPatch


class BitmapPatch(unittest.TestCase):
    def setUp(self):
        self.dib = bytes(range(32))
        self.patch = {"sha256": hashlib.sha256(self.dib).hexdigest(), "runs": []}

    def test_patch_runs(self):
        self.patch["runs"] = [[0, "ff00"], [30, "aabb"]]
        patched = applyBitmapPatch(self.dib, self.patch)

        self.assertEqual(patched[:2], bytes([255, 0]))
        self.assertEqual(patched[30:], bytes([0xAA, 0xBB]))
        self.assertEqual(patched[2:30], self.dib[2:30])

    def test_hash_mismatch(self):
        self.patch["sha256"] = "0" * 64

        with self.assertRaises(TranslationError):
            applyBitmapPatch(self.dib, self.patch)

    def test_run_out_of_range(self):
        self.patch["runs"] = [[31, "0000"]]

        with self.assertRaises(TranslationError):
            applyBitmapPatch(self.dib, self.patch)


if __name__ == "__main__":
    unittest.main()
