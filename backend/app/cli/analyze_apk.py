from pathlib import Path
import argparse
import json
import sys

from app.core.config import get_settings
from app.db.base import AnalysisArtifact, AnalysisEvidence, AnalysisFinding, AnalysisReasoning, AnalysisReport
from app.db.session import SessionLocal, init_db
from app.services.job_service import JobRunner, JobService


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local APK analysis pipeline for one APK.")
    parser.add_argument("apk_path", help="Full path to an APK you are authorized to test.")
    ghidra = parser.add_mutually_exclusive_group()
    ghidra.add_argument("--ghidra", dest="ghidra_enabled", action="store_true", help="Enable Ghidra native analysis for this scan.")
    ghidra.add_argument("--no-ghidra", dest="ghidra_enabled", action="store_false", help="Disable Ghidra native analysis for this scan.")
    parser.set_defaults(ghidra_enabled=None)
    args = parser.parse_args()

    try:
        settings = get_settings()
        init_db()

        with SessionLocal() as db:
            job = JobService(db, settings).create_job_from_path(Path(args.apk_path), ghidra_enabled=args.ghidra_enabled)
            print(f"created_job={job.id}")

        JobRunner(settings).prepare_uploaded_apk(job.id)

        with SessionLocal() as db:
            refreshed = JobService(db, settings).get_job(job.id)
            if refreshed is None:
                raise RuntimeError("Job disappeared during analysis.")

            reports = [
                {"type": report.report_type, "path": report.path}
                for report in db.query(AnalysisReport).filter(AnalysisReport.job_id == refreshed.id).all()
            ]
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
                "reports": reports,
            }
            print(json.dumps(summary, indent=2))
            if refreshed.status.value != "completed":
                return 1
            expected_types = {"html", "pdf"}
            if {report["type"] for report in reports} != expected_types:
                print("Analysis completed without both HTML and PDF reports.", file=sys.stderr)
                return 1
            missing = [report["path"] for report in reports if not Path(report["path"]).is_file()]
            if missing:
                print(f"Generated report files are missing: {', '.join(missing)}", file=sys.stderr)
                return 1
            return 0
    except Exception as exc:
        print(f"CLI analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
