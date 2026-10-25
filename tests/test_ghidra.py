from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import unittest

from analysis.ghidra import GhidraAnalyzer


class FakeProcess:
    _next_pid = 1000

    def __init__(self, returncode=0, cancel_event=None):
        self.returncode = None
        self.final_returncode = returncode
        self.pid = FakeProcess._next_pid
        FakeProcess._next_pid += 1
        self.poll_count = 0
        self.cancel_event = cancel_event
        self.communicate_count = 0

    def poll(self):
        self.poll_count += 1
        if self.poll_count > 1 and self.returncode is None:
            self.returncode = self.final_returncode
        return self.returncode

    def communicate(self, timeout=None):
        self.communicate_count += 1
        if self.cancel_event is not None and self.communicate_count == 1:
            self.cancel_event.set()
            raise subprocess.TimeoutExpired(["ghidra"], timeout or 1)
        return "stdout", "stderr"

    def wait(self, timeout=None):
        self.returncode = self.final_returncode
        return self.returncode

    def kill(self):
        self.returncode = -9


class GhidraTests(unittest.TestCase):
    def settings(self, headless: Path, overall=30, per_library=10):
        return SimpleNamespace(
            ghidra_enabled=True,
            ghidra_headless_path=headless,
            ghidra_timeout_seconds=overall,
            ghidra_library_timeout_seconds=per_library,
        )

    def libraries(self, root: Path, names=("liba.so", "libb.so")) -> Path:
        apktool = root / "apktool"
        for index, name in enumerate(names):
            path = apktool / "lib" / f"arch{index}" / name
            path.parent.mkdir(parents=True)
            path.write_bytes(bytes([index + 1]) * (10 + index))
        return apktool

    def test_multiple_libraries_emit_start_and_completion_events(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            headless = root / "analyzeHeadless"
            headless.touch()
            processes = [FakeProcess(), FakeProcess()]
            events = []
            with patch("analysis.ghidra.subprocess.Popen", side_effect=processes) as popen:
                result = GhidraAnalyzer(self.settings(headless)).run(apktool, root, progress_callback=events.append)
            self.assertEqual(result.status, "completed")
            self.assertEqual(len(result.library_results), 2)
            self.assertEqual([event["status"] for event in events], ["running", "completed", "running", "completed"])
            self.assertIn("-analysisTimeoutPerFile", popen.call_args.args[0])
            self.assertTrue(next((root / "ghidra").glob("01-arch0-liba-*.log")).exists())
            self.assertNotEqual(popen.call_args_list[0].args[0][2], popen.call_args_list[1].args[0][2])

    def test_missing_executable_is_skipped_with_libraries_retained(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            result = GhidraAnalyzer(self.settings(root / "missing")).run(apktool, root)
            self.assertEqual(result.status, "skipped")
            self.assertEqual(len(result.native_libraries), 2)

    def test_nonzero_exit_is_recorded_and_next_library_continues(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            headless = root / "analyzeHeadless"
            headless.touch()
            processes = [FakeProcess(returncode=7), FakeProcess(returncode=0)]
            with patch("analysis.ghidra.subprocess.Popen", side_effect=processes):
                result = GhidraAnalyzer(self.settings(headless)).run(apktool, root)
            self.assertEqual(result.status, "partial")
            self.assertEqual([item["status"] for item in result.library_results], ["failed", "completed"])
            self.assertEqual(result.library_results[0]["exit_code"], 7)

    def test_timeout_terminates_process_and_continues(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            headless = root / "analyzeHeadless"
            headless.touch()
            process = FakeProcess(returncode=None)
            events = []
            analyzer = GhidraAnalyzer(self.settings(headless, per_library=1))
            with patch("analysis.ghidra.subprocess.Popen", return_value=process), patch.object(analyzer, "_terminate_process", side_effect=lambda item: setattr(item, "returncode", -9)):
                result = analyzer.run(apktool, root, progress_callback=events.append)
            self.assertEqual(result.library_results[0]["status"], "timed_out")
            self.assertEqual(result.status, "failed")
            self.assertIn("timeout", result.library_results[0]["detail"])

    def test_cancellation_terminates_active_process(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so",))
            headless = root / "analyzeHeadless"
            headless.touch()
            cancel = Event()
            process = FakeProcess(returncode=None, cancel_event=cancel)
            analyzer = GhidraAnalyzer(self.settings(headless))
            with patch("analysis.ghidra.subprocess.Popen", return_value=process), patch.object(analyzer, "_terminate_process", side_effect=lambda item: setattr(item, "returncode", -15)) as terminate:
                result = analyzer.run(apktool, root, cancel_event=cancel)
            self.assertEqual(result.status, "cancelled")
            terminate.assert_called_once_with(process)

    def test_partial_failure_preserves_each_library_result(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so", "libb.so", "libc.so"))
            headless = root / "analyzeHeadless"
            headless.touch()
            processes = [FakeProcess(returncode=3), FakeProcess(returncode=4), FakeProcess(returncode=0)]
            with patch("analysis.ghidra.subprocess.Popen", side_effect=processes):
                result = GhidraAnalyzer(self.settings(headless)).run(apktool, root)
            self.assertEqual(result.status, "partial")
            self.assertEqual(len(result.library_results), 3)
            self.assertEqual(result.library_results[-1]["status"], "completed")

    def test_overall_budget_skips_unstarted_libraries_instead_of_calling_them_timeouts(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so", "libb.so"))
            headless = root / "analyzeHeadless"
            headless.touch()
            analyzer = GhidraAnalyzer(self.settings(headless, overall=2, per_library=10))
            clock = iter((0.0, 0.0, 0.5, 0.1, 1.9, 1.95))
            with patch("analysis.ghidra.time.monotonic", side_effect=lambda: next(clock)), patch.object(
                analyzer, "_run_library", return_value=("completed", 0, "", "", "Ghidra completed successfully.")
            ) as run_library:
                result = analyzer.run(apktool, root)
            self.assertEqual([item["status"] for item in result.library_results], ["completed", "skipped"])
            self.assertEqual([item["started"] for item in result.library_results], [True, False])
            self.assertEqual(run_library.call_count, 1)
            self.assertIn("1 completed", result.detail)
            self.assertIn("1 skipped", result.detail)

    def test_timeout_values_fall_back_to_safe_defaults(self):
        self.assertEqual(GhidraAnalyzer._positive_timeout(0, 300), 300)
        self.assertEqual(GhidraAnalyzer._positive_timeout("invalid", 300), 300)
        self.assertEqual(GhidraAnalyzer._positive_timeout(float("inf"), 300), 300)

    def test_timeout_then_next_library_has_independent_attempt(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so", "libb.so"))
            headless = root / "analyzeHeadless"
            headless.touch()
            analyzer = GhidraAnalyzer(self.settings(headless, overall=30, per_library=1))
            with patch.object(
                analyzer,
                "_run_library",
                side_effect=[
                    ("timed_out", -1, "", "", "Per-library timeout exceeded"),
                    ("completed", 0, "", "", "Ghidra completed successfully."),
                ],
            ) as run_library:
                result = analyzer.run(apktool, root)
            self.assertEqual([item["status"] for item in result.library_results], ["timed_out", "completed"])
            self.assertEqual([item["started"] for item in result.library_results], [True, True])
            self.assertEqual(run_library.call_count, 2)
            self.assertIn("1 timed out", result.detail)
            self.assertIn("1 completed", result.detail)

    def test_ghidra_reported_analysis_timeout_is_not_success(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so",))
            headless = root / "analyzeHeadless"
            headless.touch()
            analyzer = GhidraAnalyzer(self.settings(headless, overall=30, per_library=30))
            process = FakeProcess(returncode=0)
            with patch("analysis.ghidra.subprocess.Popen", return_value=process), patch.object(
                process, "communicate", return_value=("ERROR REPORT: Analysis timed out at 30 seconds", "")
            ):
                result = analyzer.run(apktool, root)
            self.assertEqual(result.library_results[0]["status"], "timed_out")


if __name__ == "__main__":
    unittest.main()
