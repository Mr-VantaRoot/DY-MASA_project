import os
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.cli.dymasa import database
from app.cli.dymasa.cli import main


class CliStageATests(unittest.TestCase):
    def test_sqlite_fallback_is_project_root_independent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.object(database, "postgres_is_ready", return_value=False), patch.dict(
                os.environ, {}, clear=True
            ):
                selected = database.configure_database_environment(root)
                self.assertEqual(os.environ["MOBILE_PENTEST_DATABASE_URL"], selected)
            self.assertEqual(selected, f"sqlite:///{(root / 'storage' / 'masa.sqlite3').resolve()}")

    def test_existing_database_url_is_retained_when_postgres_is_ready(self):
        configured = "postgresql+psycopg://user:pass@localhost/db"
        with patch.object(database, "postgres_is_ready", return_value=True), patch.dict(
            os.environ, {"MOBILE_PENTEST_DATABASE_URL": configured}, clear=True
        ):
            self.assertEqual(database.configure_database_environment(Path("/tmp/project")), configured)

    def test_explicit_database_url_is_retained_when_postgres_is_unavailable(self):
        configured = "sqlite:///custom/masa.sqlite3"
        with patch.object(database, "postgres_is_ready", return_value=False), patch.dict(
            os.environ, {"MOBILE_PENTEST_DATABASE_URL": configured}, clear=True
        ):
            self.assertEqual(database.configure_database_environment(Path("/tmp/project")), configured)
            self.assertEqual(os.environ["MOBILE_PENTEST_DATABASE_URL"], configured)

    def test_check_command_starts_without_database_import(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            java = root / "java"
            apktool = root / "apktool.jar"
            jadx = root / "jadx.jar"
            storage = root / "storage"
            java.touch()
            java.chmod(0o755)
            apktool.touch()
            jadx.touch()
            storage.mkdir()
            env = {
                "MOBILE_PENTEST_JAVA_PATH": str(java),
                "MOBILE_PENTEST_APKTOOL_JAR_PATH": str(apktool),
                "MOBILE_PENTEST_JADX_JAR_PATH": str(jadx),
                "MOBILE_PENTEST_STORAGE_ROOT": str(storage),
                "MOBILE_PENTEST_DATABASE_URL": f"sqlite:///{root / 'masa.sqlite3'}",
            }
            from app.core.config import get_settings

            get_settings.cache_clear()
            try:
                with patch.dict(os.environ, env, clear=True):
                    self.assertEqual(main(["--quiet", "check"]), 0)
            finally:
                get_settings.cache_clear()

    def test_check_reports_missing_required_apktool(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            java = root / "java"
            jadx = root / "jadx.jar"
            storage = root / "storage"
            java.touch()
            java.chmod(0o755)
            jadx.touch()
            storage.mkdir()
            env = {
                "MOBILE_PENTEST_JAVA_PATH": str(java),
                "MOBILE_PENTEST_APKTOOL_JAR_PATH": str(root / "missing-apktool.jar"),
                "MOBILE_PENTEST_JADX_JAR_PATH": str(jadx),
                "MOBILE_PENTEST_STORAGE_ROOT": str(storage),
                "MOBILE_PENTEST_DATABASE_URL": f"sqlite:///{root / 'masa.sqlite3'}",
            }
            from app.core.config import get_settings

            get_settings.cache_clear()
            try:
                stream = StringIO()
                with patch.dict(os.environ, env, clear=True), redirect_stdout(stream):
                    self.assertEqual(main(["--quiet", "--no-color", "check"]), 3)
                self.assertIn("MISSING", stream.getvalue())
            finally:
                get_settings.cache_clear()

    def test_launcher_exists_and_is_shell_executable(self):
        launcher = Path(__file__).parents[1] / "work" / "dy-masa"
        self.assertTrue(launcher.is_file())
        self.assertTrue(os.access(launcher, os.X_OK))


if __name__ == "__main__":
    unittest.main()
