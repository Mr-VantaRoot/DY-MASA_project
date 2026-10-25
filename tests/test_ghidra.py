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

    @staticmethod
    def batch_output(paths: list[Path], succeeded: set[Path] | None = None, timed_out: set[Path] | None = None) -> str:
        succeeded = succeeded or set()
        timed_out = timed_out or set()
        lines = []
        for path in paths:
            lines.append(f"INFO IMPORTING: file://{path} (HeadlessAnalyzer)")
            if path in succeeded:
                lines.append(f"INFO REPORT: Analysis succeeded for file: file://{path} (HeadlessAnalyzer)")
            elif path in timed_out:
                lines.append(f"ERROR REPORT: Analysis timed out at 300 seconds. Processing not completed for file: file://{path} (HeadlessAnalyzer)")
        return "\n".join(lines)

    def test_multiple_libraries_emit_start_and_completion_events(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            headless = root / "analyzeHeadless"
            headless.touch()
            events = []
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths, set(paths))
            analyzer = GhidraAnalyzer(self.settings(headless))
            with patch.object(analyzer, "_run_batch", return_value=("completed", 0, output, "", "Ghidra batch completed.")) as run_batch:
                result = analyzer.run(apktool, root, progress_callback=events.append)
            self.assertEqual(result.status, "completed")
            self.assertEqual(len(result.library_results), 2)
            self.assertEqual([event["status"] for event in events], ["queued", "queued", "completed", "completed"])
            self.assertIn("-analysisTimeoutPerFile", run_batch.call_args.args[0])
            self.assertTrue(next((root / "ghidra").glob("01-arch0-liba-*.log")).exists())
            self.assertIn("-import", run_batch.call_args.args[0])

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
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths, succeeded={paths[1]})
            analyzer = GhidraAnalyzer(self.settings(headless))
            with patch.object(analyzer, "_run_batch", return_value=("failed", 7, output, "", "Ghidra batch returned exit code 7.")):
                result = analyzer.run(apktool, root)
            self.assertEqual(result.status, "partial")
            self.assertEqual([item["status"] for item in result.library_results], ["failed", "completed"])
            self.assertEqual(result.library_results[0]["exit_code"], 7)

    def test_timeout_terminates_process_and_continues(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            headless = root / "analyzeHeadless"
            headless.touch()
            events = []
            analyzer = GhidraAnalyzer(self.settings(headless, per_library=1))
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths[:1], timed_out={paths[0]})
            with patch.object(analyzer, "_run_batch", return_value=("completed", 0, output, "", "Ghidra batch completed.")):
                result = analyzer.run(apktool, root, progress_callback=events.append)
            self.assertEqual(result.library_results[0]["status"], "timed_out")
            self.assertEqual(result.status, "failed")
            self.assertIn("timed out", result.library_results[0]["detail"])

    def test_cancellation_terminates_active_process(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so",))
            headless = root / "analyzeHeadless"
            headless.touch()
            cancel = Event()
            analyzer = GhidraAnalyzer(self.settings(headless))
            with patch.object(analyzer, "_run_batch", return_value=("cancelled", -2, "", "", "Ghidra batch process terminated after cancellation.")):
                result = analyzer.run(apktool, root, cancel_event=cancel)
            self.assertEqual(result.status, "cancelled")

    def test_cancellation_before_batch_start_is_not_reported_as_skipped_only(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so", "libb.so"))
            headless = root / "analyzeHeadless"
            headless.touch()
            cancel = Event()
            cancel.set()
            result = GhidraAnalyzer(self.settings(headless)).run(apktool, root, cancel_event=cancel)
            self.assertEqual(result.status, "cancelled")
            self.assertEqual([item["status"] for item in result.library_results], ["cancelled", "skipped"])
            self.assertFalse(any(item["started"] for item in result.library_results))

    def test_partial_failure_preserves_each_library_result(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so", "libb.so", "libc.so"))
            headless = root / "analyzeHeadless"
            headless.touch()
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths, succeeded={paths[2]})
            analyzer = GhidraAnalyzer(self.settings(headless))
            with patch.object(analyzer, "_run_batch", return_value=("failed", 4, output, "", "Ghidra batch returned exit code 4.")):
                result = analyzer.run(apktool, root)
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
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths[:1], succeeded={paths[0]})
            with patch.object(
                analyzer, "_run_batch", return_value=("timed_out", -1, output, "", "Overall Ghidra batch timeout exceeded")
            ) as run_batch:
                result = analyzer.run(apktool, root)
            self.assertEqual([item["status"] for item in result.library_results], ["completed", "skipped"])
            self.assertEqual([item["started"] for item in result.library_results], [True, False])
            self.assertEqual(run_batch.call_count, 1)
            self.assertIn("1 skipped", result.detail)
            self.assertIn("1 skipped", result.detail)

    def test_timeout_values_fall_back_to_safe_defaults(self):
        self.assertEqual(GhidraAnalyzer._positive_timeout(0, 300), 300)
        self.assertEqual(GhidraAnalyzer._positive_timeout("invalid", 300), 300)
        self.assertEqual(GhidraAnalyzer._positive_timeout(float("inf"), 300), 300)

    def test_auto_extended_batch_budget_covers_each_configured_library_limit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root)
            headless = root / "analyzeHeadless"
            headless.touch()
            settings = self.settings(headless, overall=2, per_library=3)
            settings.ghidra_auto_extend_timeout = True
            analyzer = GhidraAnalyzer(settings)
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths, succeeded=set(paths))
            with patch.object(analyzer, "_run_batch", return_value=("completed", 0, output, "", "Ghidra batch completed.")) as run_batch:
                result = analyzer.run(apktool, root)
            self.assertEqual(result.status, "completed")
            self.assertEqual(run_batch.call_args.args[1], 66.0)
            self.assertIn("effective_batch_timeout=66.0", (root / "logs" / "ghidra.log").read_text())

    def test_batch_records_match_ghidra_resolved_paths(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real" / "liba.so"
            real.parent.mkdir()
            real.write_bytes(b"native")
            link = root / "apktool" / "lib" / "arch" / "liba.so"
            link.parent.mkdir(parents=True)
            link.symlink_to(real)
            headless = root / "analyzeHeadless"
            headless.touch()
            output = f"INFO IMPORTING: file://{real} (HeadlessAnalyzer)\nINFO REPORT: Analysis succeeded for file: file://{real} (HeadlessAnalyzer)"
            analyzer = GhidraAnalyzer(self.settings(headless))
            with patch.object(analyzer, "_run_batch", return_value=("completed", 0, output, "", "Ghidra batch completed.")):
                result = analyzer.run(root / "apktool", root)
            self.assertEqual(result.library_results[0]["status"], "completed")
            self.assertTrue(result.library_results[0]["started"])

    def test_timeout_then_next_library_has_independent_attempt(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so", "libb.so"))
            headless = root / "analyzeHeadless"
            headless.touch()
            analyzer = GhidraAnalyzer(self.settings(headless, overall=30, per_library=1))
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths, succeeded={paths[1]}, timed_out={paths[0]})
            with patch.object(
                analyzer, "_run_batch", return_value=("completed", 0, output, "", "Ghidra batch completed.")
            ) as run_batch:
                result = analyzer.run(apktool, root)
            self.assertEqual([item["status"] for item in result.library_results], ["timed_out", "completed"])
            self.assertEqual([item["started"] for item in result.library_results], [True, True])
            self.assertEqual(run_batch.call_count, 1)
            self.assertIn("1 timed out", result.detail)
            self.assertIn("1 completed", result.detail)

    def test_ghidra_reported_analysis_timeout_is_not_success(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = self.libraries(root, ("liba.so",))
            headless = root / "analyzeHeadless"
            headless.touch()
            analyzer = GhidraAnalyzer(self.settings(headless, overall=30, per_library=30))
            paths = sorted(apktool.glob("lib/**/*.so"))
            output = self.batch_output(paths, timed_out={paths[0]})
            with patch.object(analyzer, "_run_batch", return_value=("completed", 0, output, "", "Ghidra batch completed.")):
                result = analyzer.run(apktool, root)
            self.assertEqual(result.library_results[0]["status"], "timed_out")


if __name__ == "__main__":
    unittest.main()
