from datetime import datetime
import unittest

from sqlalchemy import create_engine
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

from app.cli.dymasa import read
from app.db.base import (
    AnalysisEvidence,
    AnalysisFinding,
    AnalysisJob,
    AnalysisJobStatus,
    Base,
    EvidenceCategory,
    FindingSeverity,
)


class CliDataReaderTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", future=True)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.job = AnalysisJob(
            id="job-cli-data",
            original_filename="sample.apk",
            stored_filename="sample.apk",
            apk_path="/tmp/sample.apk",
            file_size_bytes=1,
            status=AnalysisJobStatus.completed,
            current_step="Complete",
        )
        self.session.add(self.job)

    def tearDown(self):
        self.session.close()

    def test_runtime_evidence_keeps_valid_non_dynamic_type(self):
        item = AnalysisEvidence(
            id="runtime-1",
            job_id=self.job.id,
            category=EvidenceCategory.runtime,
            evidence_type="runtime_storage_breakdown",
            label="Device storage",
            value_json='{"free": 123}',
            source_path="dynamic/storage.json",
        )
        self.session.add(item)
        self.session.commit()
        self.assertEqual(read.list_runtime_evidence(self.session, self.job.id), [item])

    def test_findings_use_explicit_severity_order_and_database_pages(self):
        for index, severity in enumerate((FindingSeverity.info, FindingSeverity.critical, FindingSeverity.high)):
            self.session.add(
                AnalysisFinding(
                    id=f"finding-{index}",
                    job_id=self.job.id,
                    rule_id=f"rule-{index}",
                    title=severity.value,
                    severity=severity,
                    category="test",
                    description="description",
                    remediation="remediation",
                    evidence_ids_json="[]",
                    created_at=datetime(2026, 1, 1, 0, index),
                )
            )
        self.session.commit()
        first = read.list_findings(self.session, self.job.id, offset=0, limit=2)
        second = read.list_findings(self.session, self.job.id, offset=2, limit=2)
        self.assertEqual(len(read.list_findings(self.session, self.job.id)), 3)
        self.assertEqual([item.severity.value for item in first], ["critical", "high"])
        self.assertEqual([item.severity.value for item in second], ["info"])
        self.assertEqual({item.id for item in first} | {item.id for item in second}, {"finding-0", "finding-1", "finding-2"})
        with self.assertRaises(ValueError):
            read.normalize_severity("urgent")

    def test_finding_search_category_and_combined_filters_match_platform(self):
        rows = (
            ("title-match", FindingSeverity.high, "Network Security", "rule-other", "needle title"),
            ("rule-match", FindingSeverity.high, "Code Review", "needle-rule", "other title"),
            ("category-only", FindingSeverity.high, "Network Security", "rule-other", "other title"),
        )
        for finding_id, severity, category, rule_id, title in rows:
            self.session.add(AnalysisFinding(
                id=finding_id,
                job_id=self.job.id,
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=category,
                description="description",
                remediation="remediation",
                evidence_ids_json="[]",
            ))
        self.session.commit()

        self.assertEqual(
            {item.id for item in read.list_findings(self.session, self.job.id, search="needle")},
            {"title-match", "rule-match"},
        )
        self.assertEqual(
            {item.id for item in read.list_findings(self.session, self.job.id, category="Network Security")},
            {"title-match", "category-only"},
        )
        self.assertEqual(
            [item.id for item in read.list_findings(self.session, self.job.id, severity="HIGH", search="needle", category="Network Security")],
            ["title-match"],
        )
        self.assertEqual(read.list_finding_categories(self.session, self.job.id), ["Code Review", "Network Security"])
        self.assertEqual(read.list_findings(self.session, self.job.id, category="Unknown Category"), [])

    def test_enum_filters_are_cast_for_postgresql(self):
        class Capture:
            def scalars(self, statement):
                self.statement = statement
                return self

            def all(self):
                return []

        capture = Capture()
        read.list_findings(capture, severity="high", limit=12)
        sql = str(capture.statement.compile(dialect=postgresql.dialect()))
        self.assertIn("CAST", sql)
        self.assertIn("analysis_finding_severity", sql)

        capture = Capture()
        read.list_jobs(capture, status="running", limit=12)
        sql = str(capture.statement.compile(dialect=postgresql.dialect()))
        self.assertIn("analysis_job_status", sql)

    def test_evidence_search_category_and_count_match_page(self):
        for index, category in enumerate((EvidenceCategory.manifest, EvidenceCategory.runtime, EvidenceCategory.runtime)):
            self.session.add(
                AnalysisEvidence(
                    id=f"evidence-{index}",
                    job_id=self.job.id,
                    category=category,
                    evidence_type="runtime_observation" if category == EvidenceCategory.runtime else "manifest_component",
                    label="needle" if index else "other",
                    value_json="{}",
                    source_path="source.xml",
                )
            )
        self.session.commit()
        page = read.list_evidence(self.session, self.job.id, search="needle", category="runtime", offset=0, limit=1)
        self.assertEqual(len(page), 1)
        self.assertEqual(read.count_evidence(self.session, self.job.id, search="needle", category="runtime"), 2)

    def test_evidence_categories_are_discovered_from_scoped_records(self):
        for index, category in enumerate((EvidenceCategory.runtime, EvidenceCategory.manifest)):
            self.session.add(
                AnalysisEvidence(
                    id=f"category-evidence-{index}",
                    job_id=self.job.id,
                    category=category,
                    evidence_type="observation",
                    label="label",
                    value_json="{}",
                    source_path="source.xml",
                )
            )
        self.session.commit()
        self.assertEqual(read.list_evidence_categories(self.session, self.job.id), ["manifest", "runtime"])
        self.assertEqual(read.list_evidence_categories(self.session, "other-job"), [])


if __name__ == "__main__":
    unittest.main()
