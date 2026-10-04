import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.code_strings import Lookup, looseKey


class LookupTiers(unittest.TestCase):
    def setUp(self):
        self.lookup = Lookup(
            {
                "ＮｏｔｅＯｆｆ～": "NoteOff ~",
                "PhoneSEQデータがありません": "There is no PhoneSEQ data",
                "PhoneSEQバルクを\n\n 『 %s 』 に挿入しました\n": "inserted into %s",
            }
        )

    def testExact(self):
        self.assertEqual(self.lookup.find("ＮｏｔｅＯｆｆ～")[2], "exact")

    def testNfkcHalfWidth(self):
        self.assertEqual(self.lookup.find("NoteOff~")[2], "nfkc")

    def testLooseFullStopAndCrlf(self):
        self.assertEqual(self.lookup.find("PhoneSEQデータがありません。")[2], "loose")
        hit = self.lookup.find("PhoneSEQバルクを\r\n\r\n 『 %s 』 に挿入しました。\r\n")
        self.assertEqual(hit[2], "loose")

    def testNoSubstringMatch(self):
        self.assertIsNone(self.lookup.find("発音時間"))

    def testLooseKey(self):
        self.assertEqual(looseKey("あ。\r\nい。"), "あ\nい")


if __name__ == "__main__":
    unittest.main()
