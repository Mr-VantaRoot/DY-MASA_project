from __future__ import annotations

from pathlib import Path
import unittest

from dynamic.logcat.classify import classify, discover_target_pids, merge_tiers_in_order
from dynamic.logcat.crashes import detect_crashes


PACKAGE = "b3nac.injuredandroid"
FIXTURE = Path(__file__).parent / "fixtures" / "logcat-injuredandroid.txt"


class RealLogcatFixtureTests(unittest.TestCase):
    def test_injuredandroid_capture_classification_and_order(self) -> None:
        raw_bytes = FIXTURE.read_bytes()
        raw_lines = raw_bytes.decode("utf-8").splitlines()
        self.assertEqual(raw_lines[0], "--------- beginning of main")

        pids, uids = discover_target_pids(raw_lines, PACKAGE)
        self.assertEqual(pids, [31093])
        self.assertEqual(uids, [10825])

        tier_a, tier_b, tier_c = classify(raw_lines, PACKAGE, pids, uids)
        self.assertEqual(len(tier_a), 24)
        self.assertEqual(len(tier_b), 19)
        self.assertEqual(len(tier_c), 35)

        merged = merge_tiers_in_order(raw_lines, tier_a, tier_b)
        self.assertEqual(len(merged), 43)
        raw_byte_lines = [line.rstrip(b"\r\n") for line in raw_bytes.splitlines(keepends=True)]
        self.assertTrue(all(line.encode("utf-8") in raw_byte_lines for line in merged))

        cursor = -1
        for line in merged:
            encoded = line.encode("utf-8")
            cursor = next(index for index in range(cursor + 1, len(raw_byte_lines)) if raw_byte_lines[index] == encoded)

        self.assertEqual(detect_crashes(raw_lines, PACKAGE, pids), [])
        self.assertFalse(any("(31023)" in line for line in tier_a + tier_b))
        self.assertFalse(any("FirebaseCrashlytics" in line for line in tier_a + tier_b))
        self.assertFalse(any("process gone or crashing" in line for line in tier_a + tier_b))


if __name__ == "__main__":
    unittest.main()
