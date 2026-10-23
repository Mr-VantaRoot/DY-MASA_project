from datetime import datetime
import json
import tempfile
from pathlib import Path

from app.db.base import (
    AnalysisEvidence,
    AnalysisFinding,
    AnalysisJob,
    AnalysisReasoning,
    EvidenceCategory,
    FindingSeverity,
)
from reports.generator import HtmlReportGenerator, PdfReportGenerator


def main() -> None:
    job = AnalysisJob(
        id="phase7-smoke",
        original_filename="demo.apk",
        stored_filename="phase7-smoke.apk",
        apk_path="storage/uploads/phase7-smoke.apk",
        file_size_bytes=1234,
        sha256="abc123",
        completed_at=datetime.utcnow(),
    )
    evidence = [
        AnalysisEvidence(
            id="evidence-1",
            job_id=job.id,
            category=EvidenceCategory.application_flag,
            evidence_type="application_flags",
            label="Application security flags",
            value_json=json.dumps({"debuggable": "true"}),
            source_path="AndroidManifest.xml",
            source_node="application",
        )
    ]
    findings = [
        AnalysisFinding(
            id="finding-1",
            job_id=job.id,
            rule_id="android-debuggable-enabled",
            title="Application is debuggable",
            severity=FindingSeverity.high,
            category="Application Configuration",
            description="The manifest explicitly enables Android debugging for the application.",
            remediation="Disable android:debuggable for release builds.",
            evidence_ids_json=json.dumps(["evidence-1"]),
        )
    ]
    reasoning = [
        AnalysisReasoning(
            id="reasoning-1",
            job_id=job.id,
            provider="deterministic-structured-summary",
            summary="Generated 1 evidence-backed finding.",
            attack_paths_json=json.dumps(
                [
                    {
                        "title": "Validation path for Application is debuggable",
                        "steps": ["Validate the extracted evidence."],
                        "evidence_ids": ["evidence-1"],
                    }
                ]
            ),
            limitations="Limited to extracted APK evidence.",
        )
    ]

    with tempfile.TemporaryDirectory() as temp_dir:
        report_path = HtmlReportGenerator().generate(
            job=job,
            evidence=evidence,
            findings=findings,
            reasoning=reasoning,
            report_dir=Path(temp_dir),
        )
        content = report_path.read_text(encoding="utf-8")
        pdf_path = PdfReportGenerator().generate(
            job=job,
            evidence=evidence,
            findings=findings,
            reasoning=reasoning,
            report_dir=Path(temp_dir),
        )
        print(f"exists={report_path.exists()}")
        print(f"has_finding={'Application is debuggable' in content}")
        print(f"has_evidence_id={'evidence-1' in content}")
        print(f"has_reasoning={'deterministic-structured-summary' in content}")
        print(f"pdf_exists={pdf_path.exists()}")
        print(f"pdf_header={pdf_path.read_bytes()[:4].decode('ascii')}")


if __name__ == "__main__":
    main()
