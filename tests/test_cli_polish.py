from pathlib import Path
from io import StringIO
import tempfile
import unittest
from unittest.mock import patch

from app.cli.dymasa.cli import DatabaseNotReadyError, _banner, _interactive_dynamic, _interactive_history, _interactive_records, _interactive_scan, _overview_command, _safe_database_url, check, interactive, main
from app.cli.dymasa.runner import run_analysis
from app.cli.dymasa.ui import TerminalUI


class _Output:
    def __init__(self):
        self.messages = []

    def print(self, value=""):
        self.messages.append(str(value))

    def screen(self, title, subtitle=None):
        self.messages.append(f"{title}: {subtitle or ''}")


class _InteractiveOutput:
    quiet = True
    rich = False

    def __init__(self, choices):
        self.choices = iter(choices)
        self.messages = []
        self.menu_calls = 0

    def print(self, value=""):
        self.messages.append(str(value))

    def status_line(self, value):
        self.messages.append(str(value))

    def welcome(self, version, workspace, database, ghidra):
        self.messages.append(f"MASA welcome {version} {workspace} {database} {ghidra}")

    def screen(self, title, subtitle=None):
        self.messages.append(f"{title}: {subtitle or ''}")

    def menu(self, options):
        self.menu_calls += 1

    def prompt(self, message, default=""):
        self.messages.append(str(message))
        return next(self.choices)

    def panel(self, title, body, style="cyan", markup=False):
        self.messages.append(f"{title}: {body}")

    def notice(self, message, kind="info"):
        self.messages.append(str(message))

    def table(self, title, columns, rows):
        self.messages.append(title)
        self.messages.extend(" | ".join(str(value) for value in row) for row in rows)


class CliPolishTests(unittest.TestCase):
    def test_startup_banner_contains_masa_identity_and_subtitle(self):
        output = _InteractiveOutput([])
        output.quiet = False
        _banner(output)
        rendered = "\n".join(output.messages)
        self.assertIn("MASA welcome", rendered)

    def test_plain_startup_fallback_contains_logo_and_subtitle(self):
        stream = StringIO()
        with patch("app.cli.dymasa.ui.Console", None), patch("sys.stdout", stream):
            TerminalUI(no_color=True).welcome("0.1.0", "MASA", "SQLite", "OFF")
        rendered = stream.getvalue()
        self.assertIn("M     M   AAAAA   SSSSS   AAAAA", rendered)
        self.assertIn("Mobile Application Security Analyzer", rendered)
        self.assertNotIn("[1] Overview", rendered)
        self.assertNotIn("\x1b[", rendered)

        lines = rendered.splitlines()
        box_lines = [line for line in lines if line.startswith(("+", "|"))]
        self.assertTrue(box_lines)
        self.assertEqual(len({len(line) for line in box_lines}), 1)

    def test_database_display_redacts_credentials(self):
        displayed = _safe_database_url("postgresql+psycopg://postgres:secret@localhost:5432/MASA_DB")
        self.assertNotIn("secret", displayed)
        self.assertEqual(displayed, "postgresql+psycopg://postgres:<redacted>@localhost:5432/MASA_DB")

    def test_check_marks_missing_required_items_and_returns_not_ready(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            settings = type(
                "Settings",
                (),
                {
                    "database_url": "sqlite:///" + str(root / "masa.sqlite3"),
                    "java_path": root / "java",
                    "apktool_jar_path": root / "apktool.jar",
                    "jadx_jar_path": root / "jadx.jar",
                    "storage_root": root / "storage",
                    "ghidra_headless_path": None,
                    "adb_path": root / "adb",
                    "emulator_path": root / "emulator",
                },
            )()
            output = _Output()
            with patch("app.core.config.get_settings", return_value=settings):
                self.assertEqual(check(output), 3)
            rendered = "\n".join(output.messages)
            self.assertIn("MISSING", rendered)
            self.assertIn("REQUIRED", rendered)
            self.assertIn("NOT CONFIGURED", rendered)

    def test_interactive_scan_prompts_for_path_and_starts_real_runner(self):
        with tempfile.NamedTemporaryFile(suffix=".apk") as apk:
            with patch("builtins.input", side_effect=["2", apk.name, "off", "0"]), patch(
                "app.cli.dymasa.runner.run_analysis", return_value=1
            ) as run:
                self.assertEqual(main(["--no-color"]), 0)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], Path(apk.name))

    def test_invalid_apk_path_returns_failure_without_fabricating_a_job(self):
        output = _Output()
        settings = object()
        self.assertEqual(run_analysis(Path("/tmp/definitely-missing-dy-masa.apk"), settings, output, 0.01), 2)
        self.assertTrue(any("could not be started" in message for message in output.messages))

    def test_invalid_analyze_path_returns_usage_code_before_database_access(self):
        self.assertEqual(main(["--quiet", "analyze", "/tmp/no-such-dy-masa.apk"]), 2)

    def test_uninitialized_database_returns_not_ready_code(self):
        with patch(
            "app.cli.dymasa.cli._require_analysis_tables",
            side_effect=DatabaseNotReadyError("Database is not initialized"),
        ):
            self.assertEqual(main(["--quiet", "jobs"]), 3)

    def test_init_command_dispatches_to_schema_initializer(self):
        with patch("app.cli.dymasa.cli.init_database", return_value=0) as init:
            self.assertEqual(main(["--quiet", "init"]), 0)
        init.assert_called_once()

    def test_interactive_scan_rejects_invalid_path_before_configuration(self):
        output = _InteractiveOutput(["/tmp/no-such-file.apk"])
        self.assertEqual(_interactive_scan(output), 1)
        self.assertTrue(any("does not exist" in message for message in output.messages))

    def test_help_remains_non_interactive(self):
        with self.assertRaises(SystemExit) as raised:
            main(["--help"])
        self.assertEqual(raised.exception.code, 0)

    def test_interactive_menu_is_not_redrawn_after_each_action(self):
        output = _InteractiveOutput(["h", "q"])
        with patch("app.cli.dymasa.cli._banner"), patch("app.cli.dymasa.cli._read_command") as read:
            self.assertEqual(interactive(output), 0)
        self.assertEqual(output.menu_calls, 2)  # startup plus explicit h
        read.assert_not_called()

    def test_overview_pages_through_all_jobs(self):
        def job(name):
            return type(
                "Job",
                (),
                {
                    "original_filename": name,
                    "status": type("Status", (), {"value": "completed"})(),
                    "progress": 100,
                    "current_step": "Complete",
                },
            )()

        totals = {"total": 6, "findings": 0, "evidence": 0, "reports": 0, "completed": 6, "running": 0, "queued": 0, "failed": 0, "cancelled": 0}
        output = _InteractiveOutput(["n", "x"])
        with patch(
            "app.cli.dymasa.cli._with_session",
            side_effect=[totals, ([job("one.apk")] * 5, 6), ([job("six.apk")], 6)],
        ):
            self.assertEqual(_overview_command(output), 0)
        rendered = "\n".join(output.messages)
        self.assertIn("page 1", rendered)
        self.assertIn("page 2", rendered)
        self.assertIn("six.apk", rendered)

    def test_letter_shortcuts_dispatch_to_existing_views(self):
        output = _InteractiveOutput(["f", "e", "r", "j", "s", "q"])
        with patch("app.cli.dymasa.cli._banner"), patch(
            "app.cli.dymasa.cli._interactive_records", return_value=0
        ) as records, patch("app.cli.dymasa.cli._config_command", return_value=0) as config:
            self.assertEqual(interactive(output), 0)
        self.assertEqual([call.args[1] for call in records.call_args_list], ["findings", "evidence", "reports", "jobs"])
        config.assert_called_once_with(output)

    def test_interactive_findings_filter_prompt_exposes_numbered_choices(self):
        output = _InteractiveOutput(["1", "0", "0", "x"])
        with patch("app.cli.dymasa.cli._read_command", return_value=0) as read, patch(
            "app.cli.dymasa.cli._with_session", return_value=0
        ):
            self.assertEqual(_interactive_records(output, "findings"), 0)
        prompts = "\n".join(output.messages)
        self.assertIn("1 Critical", prompts)
        self.assertIn("2 High", prompts)
        self.assertIn("0 All", prompts)
        args = read.call_args.args[0]
        self.assertEqual(args.severity, "critical")
        self.assertIsNone(getattr(args, "search", None))
        self.assertIsNone(getattr(args, "category", None))

    def test_interactive_findings_l_lists_categories_and_returns_to_filter(self):
        output = _InteractiveOutput(["1", "0", "l", "1", "x"])
        with patch("app.cli.dymasa.cli._read_command", return_value=0), patch(
            "app.cli.dymasa.cli._with_session", side_effect=[["Application Configuration", "Code Review"], 0]
        ):
            self.assertEqual(_interactive_records(output, "findings"), 0)
        rendered = "\n".join(output.messages)
        self.assertIn("FINDING CATEGORIES", rendered)
        self.assertIn("Application Configuration", rendered)
        self.assertIn("Code Review", rendered)

    def test_interactive_findings_search_l_lists_search_targets(self):
        output = _InteractiveOutput(["1", "l", "needle", "0", "x"])
        with patch("app.cli.dymasa.cli._read_command", return_value=0) as read, patch(
            "app.cli.dymasa.cli._with_session", return_value=0
        ):
            self.assertEqual(_interactive_records(output, "findings"), 0)
        rendered = "\n".join(output.messages)
        self.assertIn("SEARCH TARGETS", rendered)
        self.assertIn("1. Finding title", rendered)
        self.assertIn("2. Rule ID", rendered)
        args = read.call_args.args[0]
        self.assertEqual(args.search, "needle")

    def test_interactive_jobs_prompts_for_search_and_status(self):
        output = _InteractiveOutput(["sample", "3", "x"])
        with patch("app.cli.dymasa.cli._read_command", return_value=0) as read, patch(
            "app.cli.dymasa.cli._with_session", return_value=0
        ):
            self.assertEqual(_interactive_records(output, "jobs"), 0)
        prompts = "\n".join(output.messages)
        self.assertIn("Job search", prompts)
        self.assertIn("1 queued", prompts)
        args = read.call_args.args[0]
        self.assertEqual(args.search, "sample")
        self.assertEqual(args.status, "completed")

    def test_interactive_evidence_lists_dynamic_categories(self):
        output = _InteractiveOutput(["0", "l", "1", "x"])
        with patch("app.cli.dymasa.cli._read_command", return_value=0), patch(
            "app.cli.dymasa.cli._with_session", side_effect=[["manifest", "runtime"], 0]
        ):
            self.assertEqual(_interactive_records(output, "evidence"), 0)
        rendered = "\n".join(output.messages)
        self.assertIn("EVIDENCE CATEGORIES", rendered)
        self.assertIn("manifest", rendered)

    def test_history_opens_selected_scan_and_supports_new_scan(self):
        first = type("Job", (), {"id": "job-1", "original_filename": "one.apk", "status": type("S", (), {"value": "completed"})(), "ghidra_enabled": False, "created_at": "now"})()
        output = _InteractiveOutput(["1", "x"])
        with patch("app.cli.dymasa.cli._with_session", return_value=([first], 1)), patch(
            "app.cli.dymasa.cli._history_overview", return_value=0
        ), patch("app.cli.dymasa.cli._history_detail", return_value=0
        ) as detail:
            self.assertEqual(_interactive_history(output), 0)
        detail.assert_called_once_with(output, "job-1")
        self.assertTrue(any("New scan" in message for message in output.messages))

    def test_history_rejects_zero_and_out_of_range_selection(self):
        first = type("Job", (), {"id": "job-1", "original_filename": "one.apk", "status": type("S", (), {"value": "completed"})(), "ghidra_enabled": False, "created_at": "now"})()
        output = _InteractiveOutput(["0", "99", "x"])
        with patch("app.cli.dymasa.cli._with_session", return_value=([first], 1)):
            self.assertEqual(_interactive_history(output), 0)
        self.assertGreaterEqual(sum("Choose a scan number" in message for message in output.messages), 2)

    def test_dynamic_submenu_has_separate_unique_sections(self):
        output = _InteractiveOutput(["v", "x"])
        with patch("app.cli.dymasa.cli._interactive_dynamic_records", return_value=0) as dynamic:
            self.assertEqual(_interactive_dynamic(output, "job-1"), 0)
        dynamic.assert_called_once()
        self.assertEqual(dynamic.call_args.args, (output, "job-1", "evidence"))
        prompt = next(message for message in output.messages if message.startswith("dynamic"))
        self.assertIn("Runtime Status", prompt)
        self.assertIn("Dynamic Events", prompt)
        self.assertIn("Runtime Evidence", prompt)
        self.assertIn("Runtime Artifacts", prompt)
        self.assertNotIn("Evidence + Artifacts", prompt)


if __name__ == "__main__":
    unittest.main()
