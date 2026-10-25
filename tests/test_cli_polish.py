from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.cli.dymasa.cli import _interactive_dynamic, _interactive_history, _interactive_scan, interactive, main
from app.cli.dymasa.runner import run_analysis


class _Output:
    def __init__(self):
        self.messages = []

    def print(self, value=""):
        self.messages.append(str(value))


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
        self.assertEqual(run_analysis(Path("/tmp/definitely-missing-dy-masa.apk"), settings, output, 0.01), 1)
        self.assertTrue(any("could not be started" in message for message in output.messages))

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

    def test_letter_shortcuts_dispatch_to_existing_views(self):
        output = _InteractiveOutput(["f", "e", "r", "j", "s", "q"])
        with patch("app.cli.dymasa.cli._banner"), patch(
            "app.cli.dymasa.cli._interactive_records", return_value=0
        ) as records, patch("app.cli.dymasa.cli._config_command", return_value=0) as config:
            self.assertEqual(interactive(output), 0)
        self.assertEqual([call.args[1] for call in records.call_args_list], ["findings", "evidence", "reports", "jobs"])
        config.assert_called_once_with(output)

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
