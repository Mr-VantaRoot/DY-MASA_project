from pathlib import Path
import argparse
import json

from app.core.config import get_settings
from app.db.base import AnalysisArtifact, AnalysisEvidence, AnalysisFinding, AnalysisReasoning, AnalysisReport
from app.db.session import SessionLocal, init_db
from app.services.job_service import JobRunner, JobService


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local APK analysis pipeline for one APK.")
    parser.add_argument("apk_path", help="Full path to an APK you are authorized to test.")
    args = parser.parse_args()

    settings = get_settings()
    init_db()

    with SessionLocal() as db:
        job = JobService(db, settings).create_job_from_path(Path(args.apk_path))
        print(f"created_job={job.id}")

    JobRunner(settings).prepare_uploaded_apk(job.id)

    with SessionLocal() as db:
        refreshed = JobService(db, settings).get_job(job.id)
        if refreshed is None:
            raise RuntimeError("Job disappeared during analysis.")

        summary = {
            "job_id": refreshed.id,
            "status": refreshed.status.value,
            "progress": refreshed.progress,
            "step": refreshed.current_step,
            "error": refreshed.error_message,
            "evidence": db.query(AnalysisEvidence).filter(AnalysisEvidence.job_id == refreshed.id).count(),
            "findings": db.query(AnalysisFinding).filter(AnalysisFinding.job_id == refreshed.id).count(),
            "artifacts": db.query(AnalysisArtifact).filter(AnalysisArtifact.job_id == refreshed.id).count(),
            "reasoning": db.query(AnalysisReasoning).filter(AnalysisReasoning.job_id == refreshed.id).count(),
            "reports": [
                {"type": report.report_type, "path": report.path}
                for report in db.query(AnalysisReport).filter(AnalysisReport.job_id == refreshed.id).all()
            ],
        }
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
