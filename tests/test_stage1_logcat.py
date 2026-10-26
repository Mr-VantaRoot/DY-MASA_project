from __future__ import annotations

import unittest
from pathlib import Path

from fastapi import HTTPException

from dynamic.adb.client import AdbClient, AdbResult
from dynamic.logcat.classify import classify, code_risk_matches, discover_target_pids, merge_tiers_in_order
from dynamic.logcat.crashes import detect_crashes
from dynamic.logcat.parser import parse_line


PACKAGE = "b3nac.injuredandroid"


def line(pid: int, tag: str, message: str, uid: str = "u0_a825") -> str:
    return f"06-12 10:20:30.123 {pid} {pid} {uid} I {tag}: {message}"


class Stage1LogcatTests(unittest.TestCase):
    def test_parser_supports_time_threadtime_and_year_uid(self) -> None:
        self.assertEqual(parse_line("06-12 10:20:30.123 I/Tag 7(31093): x").pid, 31093)
        self.assertEqual(parse_line(line(31093, "Tag", "x")).uid, 10825)
        parsed = parse_line("2026-06-12 10:20:30.123 31093 31093 u0_a825 I Tag 7: x")
        self.assertEqual(parsed.pid, 31093)
        self.assertEqual(parsed.uid, 10825)
        self.assertEqual(parsed.tag, "Tag 7")

    def test_threadtime_year_without_uid_keeps_pid(self) -> None:
        parsed = parse_line("2026-10-23 10:42:57.133 31093 31093 I FirebaseApp: init")
        self.assertEqual(parsed.pid, 31093)
        self.assertIsNone(parsed.uid)

    def test_uid_first_numeric_layout_is_not_misclassified(self) -> None:
        parsed = parse_line("2026-10-23 10:42:57.133 10825 31093 31093 I FirebaseApp: init")
        self.assertIsNone(parsed.pid)
        self.assertIsNone(parsed.uid)

    def test_uid_first_named_layout_is_not_misclassified(self) -> None:
        parsed = parse_line("2026-10-23 10:42:57.133 u0_a825 31093 31093 I FirebaseApp: init")
        self.assertIsNone(parsed.pid)
        self.assertIsNone(parsed.uid)

    def test_sanitized_year_uid_fixture_supports_uid_field_variants(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "logcat-threadtime-uid-year.txt"
        lines = fixture.read_text(encoding="utf-8").splitlines()
        first = parse_line(lines[0])
        second = parse_line(lines[1])
        self.assertEqual((first.pid, first.uid, first.tag), (31093, 10825, "ActivityManager"))
        self.assertEqual((second.pid, second.uid, second.tag), (31093, 10825, "MainActivity 7"))

    def test_pid_restart_and_reuse_windows(self) -> None:
        lines = [
            line(31093, "ActivityManager", f"Start proc 31093:{PACKAGE}/u0a825 for activity"),
            line(31093, "Target", "first"),
            line(31093, "ActivityManager", f"Process {PACKAGE} (pid 31093) has died"),
            line(31093, "ActivityManager", "Start proc 31093:other.app/u0a825 for activity"),
            line(31093, "Other", "other process"),
            line(31094, "ActivityManager", f"Start proc 31094:{PACKAGE}:worker/u0a825 for service"),
            line(31094, "Target", "second"),
        ]
        pids, uids = discover_target_pids(lines, PACKAGE)
        self.assertEqual(pids, [31093, 31094])
        self.assertEqual(uids, [10825])
        tier_a, _, _ = classify(lines, PACKAGE, pids, uids)
        self.assertIn(lines[1], tier_a)
        self.assertNotIn(lines[4], tier_a)
        self.assertIn(lines[6], tier_a)

    def test_tiers_preserve_order_and_crashes_are_target_only(self) -> None:
        raw = [
            line(31093, "Target", "one"),
            line(31023, "Crashlytics", "crash in com.transsion.childmode"),
            line(1000, "ActivityManager", f"Displayed {PACKAGE}/.MainActivity: +1s"),
            line(1000, "ServiceManager", "uid=10825 pid=31093"),
            line(1000, "Launcher", f"launching {PACKAGE}"),
            line(31000, "AndroidRuntime", "FATAL EXCEPTION: main"),
            line(31093, "AndroidRuntime", "FATAL EXCEPTION: main"),
            line(31093, "AndroidRuntime", f"Process: {PACKAGE}, PID: 31093"),
        ]
        pids, uids = discover_target_pids(raw, PACKAGE, seed_pids=[31093])
        tier_a, tier_b, tier_c = classify(raw, PACKAGE, pids, uids)
        self.assertEqual(tier_a, [raw[0], raw[6], raw[7]])
        self.assertEqual(tier_b, [raw[2], raw[3]])
        self.assertEqual(tier_c, [raw[4]])
        self.assertEqual(merge_tiers_in_order(raw, tier_a, tier_b), [raw[0], raw[2], raw[3], raw[6], raw[7]])
        crashes = detect_crashes(raw, PACKAGE, pids)
        self.assertEqual(len(crashes), 1)
        self.assertEqual(crashes[0]["type"], "fatal_exception")

    def test_specific_code_risk_patterns_do_not_match_classloader_ssl(self) -> None:
        self.assertEqual(code_risk_matches([line(31093, "ClassLoader", "loaded ssl provider")]), [])
        self.assertEqual(len(code_risk_matches([line(31093, "Network", "SSLHandshakeException") ])), 1)
        self.assertEqual(code_risk_matches([line(31093, "Schema", "http://schemas.android.com/apk/res/android")]), [])

    def test_destructive_adb_block_is_token_aware(self) -> None:
        client = AdbClient(Path("/does/not/exist"))
        self.assertNotEqual(client.run(["shell", "log", "-t", "DYMASA", "format-check"], device="x").exit_code, 126)
        self.assertEqual(client.run(["shell", "pm", "clear", PACKAGE], device="x").exit_code, 126)
        self.assertEqual(client.run(["uninstall", PACKAGE], device="x").exit_code, 126)
        self.assertEqual(client.run(["shell", "rm", "-rf", "/data/local/tmp"], device="x").exit_code, 126)

    def test_am_start_requires_status_ok_and_rejects_errors(self) -> None:
        good = AdbResult(["adb"], 0, "Starting: Intent\nStatus: ok\nActivity: x", "")
        bad = AdbResult(["adb"], 0, "Status: ok\nError: Activity class does not exist", "")
        denial = AdbResult(["adb"], 0, "", "Permission Denial: not allowed")
        self.assertTrue(AdbClient.am_start_succeeded(good))
        self.assertFalse(AdbClient.am_start_succeeded(bad))
        self.assertFalse(AdbClient.am_start_succeeded(denial))


if __name__ == "__main__":
    unittest.main()
