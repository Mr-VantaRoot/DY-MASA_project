from __future__ import annotations

from datetime import datetime, timedelta
from tempfile import TemporaryDirectory
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes.jobs import list_job_findings, list_jobs
from app.core.config import Settings
from app.db.base import AnalysisFinding, AnalysisJob, AnalysisJobStatus, Base, FindingSeverity


class ApiPaginationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.engine = create_engine(f"sqlite+pysqlite:///{self.temp.name}/pagination.db")
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.settings = Settings()
        self.job_one = AnalysisJob(
            id="job-one", original_filename="one.apk", stored_filename="one.apk",
            apk_path="/tmp/one.apk", file_size_bytes=1, status=AnalysisJobStatus.completed,
            created_at=datetime(2026, 1, 1), updated_at=datetime(2026, 1, 1),
        )
        self.job_two = AnalysisJob(
            id="job-two", original_filename="two.apk", stored_filename="two.apk",
            apk_path="/tmp/two.apk", file_size_bytes=1, status=AnalysisJobStatus.completed,
            created_at=datetime(2026, 1, 2), updated_at=datetime(2026, 1, 2),
        )
        self.db.add_all([self.job_one, self.job_two])
        base = datetime(2026, 1, 3)
        for index, severity in enumerate((FindingSeverity.critical, FindingSeverity.high, FindingSeverity.medium)):
            self.db.add(AnalysisFinding(
                id=f"finding-{index}", job_id="job-one", rule_id=f"rule-{index}",
                title=f"Finding {index}", severity=severity, category="code-risk",
                description="description", remediation="remediation", evidence_ids_json="[]",
                created_at=base + timedelta(seconds=index),
            ))
        self.db.add(AnalysisFinding(
            id="finding-other-job", job_id="job-two", rule_id="other", title="Other",
            severity=FindingSeverity.critical, category="other", description="description",
            remediation="remediation", evidence_ids_json="[]", created_at=base,
        ))
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.engine.dispose()
        self.temp.cleanup()

    def test_job_pagination_is_opt_in_and_stable(self) -> None:
        first = list_jobs(self.db, self.settings, page=1, page_size=1)
        second = list_jobs(self.db, self.settings, page=2, page_size=1)
        unpaged = list_jobs(self.db, self.settings)
        self.assertEqual((first.total, first.page, first.page_size), (2, 1, 1))
        self.assertEqual([job.id for job in first.jobs], ["job-two"])
        self.assertEqual([job.id for job in second.jobs], ["job-one"])
        self.assertEqual(len(unpaged.jobs), 2)
        self.assertIsNone(unpaged.total)

    def test_findings_page_filters_and_isolates_job(self) -> None:
        page = list_job_findings(
            "job-one", self.db, self.settings, page=1, page_size=1,
            severity="HIGH", search="Finding", category="code-risk",
        )
        self.assertEqual((page.total, page.page, page.page_size), (1, 1, 1))
        self.assertEqual([finding.id for finding in page.findings], ["finding-1"])
        other_job = list_job_findings("job-two", self.db, self.settings, page=1, page_size=10)
        self.assertEqual(other_job.total, 1)
        self.assertEqual([finding.id for finding in other_job.findings], ["finding-other-job"])


if __name__ == "__main__":
    unittest.main()
