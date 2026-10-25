import unittest
from types import SimpleNamespace

from app.cli.dymasa.runner import final_exit_code


class CliStageCTests(unittest.TestCase):
    def test_completed_job_requires_both_reports(self):
        job = SimpleNamespace(status="completed")
        self.assertEqual(final_exit_code({"job": job, "reports": []}), 1)
        reports = [SimpleNamespace(report_type="html"), SimpleNamespace(report_type="pdf")]
        self.assertEqual(final_exit_code({"job": job, "reports": reports}), 0)

    def test_failed_and_cancelled_jobs_fail(self):
        for status in ("failed", "cancelled", "queued", "running"):
            with self.subTest(status=status):
                self.assertEqual(final_exit_code({"job": SimpleNamespace(status=status), "reports": []}), 1)


if __name__ == "__main__":
    unittest.main()
