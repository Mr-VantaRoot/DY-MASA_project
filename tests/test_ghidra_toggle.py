import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from analysis.ghidra import GhidraAnalyzer
from app.core.config import Settings
from app.db.base import Base
from app.services.job_service import JobService
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from reports.generator import (
    DYNAMIC_NOT_PERFORMED_NOTICE,
    GHIDRA_DISABLED_NOTICE,
    HtmlReportGenerator,
    PdfReportGenerator,
)


class GhidraToggleTests(unittest.TestCase):
    def test_global_default_is_off_without_env_file(self):
        self.assertFalse(Settings(_env_file=None).ghidra_enabled)

    def test_disabled_run_does_not_start_ghidra(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            apktool = root / "apktool" / "lib" / "arm64-v8a"
            apktool.mkdir(parents=True)
            (apktool / "libnative.so").write_bytes(b"ELF")
            settings = Settings(_env_file=None, ghidra_enabled=True, ghidra_headless_path=root / "missing")
            analyzer = GhidraAnalyzer(settings)
            with patch.object(analyzer, "_run_batch") as run_batch:
                result = analyzer.run(apktool.parent.parent, root, enabled=False)
            run_batch.assert_not_called()
            self.assertEqual(result.status, "skipped")
            self.assertIn("disabled", result.detail.lower())

    def test_job_records_global_default_and_per_scan_override(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            engine = create_engine(f"sqlite+pysqlite:///{root / 'jobs.db'}")
            Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            apk = root / "sample.apk"
            apk.write_bytes(b"not-an-apk")
            settings = Settings(_env_file=None, ghidra_enabled=False, upload_dir=root / "uploads")
            with Session() as db:
                service = JobService(db, settings)
                default_job = service._create_job_record("job-default", "sample.apk", "default.apk", apk)
                enabled_job = service._create_job_record("job-enabled", "sample.apk", "enabled.apk", apk, True)
                self.assertFalse(default_job.ghidra_enabled)
                self.assertTrue(enabled_job.ghidra_enabled)

    def test_static_report_discloses_both_exclusions(self):
        job = SimpleNamespace(
            id="toggle-report", original_filename="sample.apk", sha256="abc", file_size_bytes=1,
            ghidra_enabled=False,
        )
        with TemporaryDirectory() as temp:
            html_path = HtmlReportGenerator().generate(job, [], [], [], Path(temp) / "html")
            pdf_path = PdfReportGenerator().generate(job, [], [], [], Path(temp) / "pdf")
            html = html_path.read_text(encoding="utf-8")
            self.assertTrue(pdf_path.exists())
        self.assertIn(GHIDRA_DISABLED_NOTICE, html)
        self.assertIn(DYNAMIC_NOT_PERFORMED_NOTICE, html)

    def test_completed_native_and_dynamic_evidence_do_not_claim_exclusion(self):
        job = SimpleNamespace(
            id="included-report", original_filename="sample.apk", sha256="abc", file_size_bytes=1,
            ghidra_enabled=True,
        )
        category = SimpleNamespace(value="runtime")
        native = SimpleNamespace(
            category=SimpleNamespace(value="code_risk"), evidence_type="ghidra_analysis",
            value_json=json.dumps({"status": "completed", "detail": "done", "coverage": {"discovered": 1, "completed": 1}}),
            id="n1", label="Ghidra", source_path="ghidra.log",
        )
        runtime = SimpleNamespace(
            category=category, evidence_type="dynamic_logcat", value_json="{}", id="r1",
            label="Runtime logcat", source_path="logcat.txt",
        )
        with TemporaryDirectory() as temp:
            output = HtmlReportGenerator().generate(job, [native, runtime], [], [], Path(temp))
            html = output.read_text(encoding="utf-8")
        self.assertNotIn(GHIDRA_DISABLED_NOTICE, html)
        self.assertNotIn(DYNAMIC_NOT_PERFORMED_NOTICE, html)
        self.assertIn("Ghidra (completed)", html)

    def test_failed_dynamic_stage_is_not_reported_as_static_only(self):
        job = SimpleNamespace(
            id="failed-dynamic", original_filename="sample.apk", sha256="abc", file_size_bytes=1,
            ghidra_enabled=False,
        )
        stage = SimpleNamespace(stage="dynamic_run", status="failed")
        with TemporaryDirectory() as temp:
            output = HtmlReportGenerator().generate(job, [], [], [], Path(temp), stages=[stage])
            html = output.read_text(encoding="utf-8")
        self.assertIn("Dynamic analysis was attempted but did not complete successfully", html)
        self.assertNotIn(DYNAMIC_NOT_PERFORMED_NOTICE, html)


if __name__ == "__main__":
    unittest.main()
