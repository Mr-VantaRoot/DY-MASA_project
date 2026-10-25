"""Shared dynamic-run acceptance logic for HTTP and CLI callers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.db.base import AnalysisJobStage
from app.services.job_service import JobService, submit_dynamic_job


@dataclass(frozen=True)
class DynamicStartError(RuntimeError):
    detail: str
    status_code: int

    def __str__(self) -> str:
        return self.detail


def start_dynamic_run(db: Session, settings: Any, job_id: str, submitter=None) -> dict[str, str]:
    """Validate and enqueue one dynamic run without bypassing route safety rules."""

    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise DynamicStartError("Analysis job not found.", 404)
    if not job.sha256:
        raise DynamicStartError(
            "Run static analysis first; package metadata is required before DY-MASA can launch the APK.",
            409,
        )

    active_run = (
        db.query(AnalysisJobStage)
        .filter(
            AnalysisJobStage.job_id == job_id,
            AnalysisJobStage.stage == "dynamic_run",
            AnalysisJobStage.status.in_(["running", "queued"]),
        )
        .first()
    )
    if active_run is not None:
        raise DynamicStartError("A DY-MASA analysis is already running for this job.", 409)

    run_stage = AnalysisJobStage(
        job_id=job.id,
        stage="dynamic_run",
        status="running",
        message="DY-MASA analysis queued",
        detail="Runtime analysis has been accepted and is starting.",
    )
    db.add(run_stage)
    db.commit()
    db.refresh(run_stage)
    if not (submitter or submit_dynamic_job)(settings, job_id, run_stage.id):
        run_stage.status = "queued"
        run_stage.message = "DY-MASA analysis queued"
        run_stage.detail = "Waiting for an available analysis worker."
        db.commit()
    return {"status": "accepted", "job_id": job_id}
