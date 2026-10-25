import unittest
from pathlib import Path
from types import SimpleNamespace

from app.cli.dymasa.read import report_path


class CliStageBTests(unittest.TestCase):
    def test_report_path_accepts_file_inside_storage(self):
        with self.subTest("inside"):
            path, exists = report_path("/tmp/masa-storage/report.html", Path("/tmp/masa-storage"))
            self.assertEqual(path, "/tmp/masa-storage/report.html")
            self.assertFalse(exists)

    def test_report_path_rejects_outside_storage(self):
        path, exists = report_path("/tmp/other/report.html", Path("/tmp/masa-storage"))
        self.assertEqual(path, "[outside approved storage]")
        self.assertFalse(exists)

    def test_report_path_rejects_symlink_escape_when_supported(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "storage"
            outside = Path(temp) / "outside.html"
            root.mkdir()
            outside.write_text("private")
            link = root / "report.html"
            try:
                link.symlink_to(outside)
            except OSError:
                self.skipTest("Symlinks unavailable")
            path, exists = report_path(str(link), root)
            self.assertEqual(path, "[outside approved storage]")
            self.assertFalse(exists)


if __name__ == "__main__":
    unittest.main()
