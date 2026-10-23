import json
import asyncio
import time
from pathlib import Path
from threading import Thread

from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.db.session import SessionLocal, get_db
from app.db.base import (
    AnalysisArtifact,
    AnalysisEvidence,
    AnalysisFinding,
    AnalysisJobEvent,
    AnalysisJob,
    AnalysisJobStage,
    AnalysisJobStatus,
    AnalysisReasoning,
    AnalysisReport,
)
from app.schemas.jobs import (
    AnalysisArtifactListResponse,
    AnalysisArtifactResponse,
    AnalysisEvidenceListResponse,
    AnalysisEvidenceResponse,
    AnalysisFindingListResponse,
    AnalysisFindingResponse,
    AnalysisJobListResponse,
    AnalysisJobResponse,
    AnalysisJobStageListResponse,
    AnalysisJobStageResponse,
    AnalysisReportListResponse,
    AnalysisReportResponse,
    AnalysisReasoningListResponse,
    AnalysisReasoningResponse,
)
from app.services.job_events import JobStageEvent, as_event_payload, job_event_store
from app.services.job_service import JobRunner, JobService


router = APIRouter(prefix="/jobs", tags=["jobs"])
TERMINAL_EVENT_STAGES = frozenset({"job_completed", "job_failed", "job_cancelled"})
TERMINAL_EVENT_GRACE_SECONDS = 2.0


def _resolve_storage_file(path: Path, storage_root: Path, resource_name: str) -> Path:
    """Resolve a stored file and reject traversal or symlink escapes."""
    try:
        resolved = path.resolve()
        resolved.relative_to(storage_root.resolve())
    except (OSError, ValueError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"{resource_name} path is outside MASA storage.")
    if not resolved.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} file not found.")
    return resolved


def _persistent_events(job_id: str, after_event_id: int = 0) -> list[JobStageEvent]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(AnalysisJobEvent)
            .where(AnalysisJobEvent.job_id == job_id, AnalysisJobEvent.event_id > after_event_id)
            .order_by(AnalysisJobEvent.event_id.asc())
        ).all()
    return [
        JobStageEvent(
            event_id=row.event_id,
            stage=row.stage,
            status=row.status,
            message=row.message,
            detail=row.detail,
            timestamp=row.created_at.isoformat(timespec="seconds"),
        )
        for row in rows
    ]


def _events_after(job_id: str, after_event_id: int = 0) -> list[JobStageEvent]:
    """Merge durable history and the live cache without duplicate event IDs."""
    events_by_id = {event.event_id: event for event in _persistent_events(job_id, after_event_id)}
    for event in job_event_store.snapshot(job_id, after_event_id=after_event_id):
        events_by_id.setdefault(event.event_id, event)
    return [events_by_id[event_id] for event_id in sorted(events_by_id)]


def _sse_event(event: JobStageEvent) -> str:
    return f"id: {event.event_id}\ndata: {json.dumps(as_event_payload(event))}\n\n"


@router.post("", response_model=AnalysisJobResponse, status_code=status.HTTP_202_ACCEPTED)
def upload_apk(
    apk: UploadFile = File(...),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisJobResponse:
    service = JobService(db, settings)
    try:
        job = service.create_upload_job(apk)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if job.status == AnalysisJobStatus.queued:
        Thread(
            target=JobRunner(settings).prepare_uploaded_apk,
            args=(job.id,),
            daemon=True,
            name=f"analysis-job-{job.id}",
        ).start()
    return AnalysisJobResponse.model_validate(job)


@router.get("", response_model=AnalysisJobListResponse)
def list_jobs(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisJobListResponse:
    jobs = JobService(db, settings).list_jobs()
    return AnalysisJobListResponse(jobs=[AnalysisJobResponse.model_validate(job) for job in jobs])


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_job(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> None:
    JobService(db, settings).delete_job(job_id)


@router.get("/{job_id}", response_model=AnalysisJobResponse)
def get_job(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisJobResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")
    return AnalysisJobResponse.model_validate(job)


@router.get("/{job_id}/timeline", response_model=AnalysisJobStageListResponse)
def list_job_timeline(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisJobStageListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    stages = (
        db.query(AnalysisJobStage)
        .filter(AnalysisJobStage.job_id == job_id)
        .order_by(AnalysisJobStage.created_at.asc())
        .all()
    )
    return AnalysisJobStageListResponse(
        stages=[AnalysisJobStageResponse.model_validate(stage) for stage in stages]
    )


@router.get("/{job_id}/events")
def stream_job_events(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    last_event_id: int | None = Header(default=None, alias="Last-Event-ID"),
) -> StreamingResponse:
    if JobService(db, settings).get_job(job_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    async def event_stream() -> object:
        current_event_id = max(0, last_event_id if isinstance(last_event_id, int) else 0)
        terminal_event_seen = False
        terminal_deadline: float | None = None
        initial_events = _events_after(job_id, current_event_id)
        for event in initial_events:
            current_event_id = max(current_event_id, event.event_id)
            terminal_event_seen = terminal_event_seen or event.stage in TERMINAL_EVENT_STAGES
            yield _sse_event(event)
        if terminal_event_seen:
            return

        while True:
            # Wait on the live condition store off the ASGI event loop. The timeout
            # gives durable storage a chance to surface events published elsewhere.
            await asyncio.to_thread(job_event_store.wait_for, job_id, current_event_id, 2.0)
            new_events = _events_after(job_id, current_event_id)
            for event in new_events:
                current_event_id = max(current_event_id, event.event_id)
                terminal_event_seen = terminal_event_seen or event.stage in TERMINAL_EVENT_STAGES
                yield _sse_event(event)
            if terminal_event_seen:
                return
            with SessionLocal() as state_db:
                job = state_db.get(AnalysisJob, job_id)
            if job is None:
                return
            if job.status in {
                AnalysisJobStatus.completed,
                AnalysisJobStatus.failed,
                AnalysisJobStatus.cancelled,
            }:
                if terminal_event_seen:
                    return
                if terminal_deadline is None:
                    terminal_deadline = time.monotonic() + TERMINAL_EVENT_GRACE_SECONDS
                elif time.monotonic() >= terminal_deadline:
                    fallback = JobStageEvent(
                        event_id=current_event_id + 1,
                        stage=f"job_{job.status.value}",
                        status=job.status.value,
                        message=job.current_step,
                        detail=job.error_message,
                    )
                    yield _sse_event(fallback)
                    return

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/{job_id}/artifacts", response_model=AnalysisArtifactListResponse)
def list_job_artifacts(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisArtifactListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    artifacts = (
        db.query(AnalysisArtifact)
        .filter(AnalysisArtifact.job_id == job_id)
        .order_by(AnalysisArtifact.created_at.asc())
        .all()
    )
    return AnalysisArtifactListResponse(
        artifacts=[AnalysisArtifactResponse.model_validate(artifact) for artifact in artifacts]
    )


@router.get("/{job_id}/artifacts/{artifact_id}/view")
def view_job_artifact(
    job_id: str,
    artifact_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    """Open a generated artifact without exposing arbitrary filesystem paths."""
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")
    artifact = (
        db.query(AnalysisArtifact)
        .filter(AnalysisArtifact.job_id == job_id, AnalysisArtifact.id == artifact_id)
        .first()
    )
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found.")

    resolved_path = _resolve_storage_file(Path(artifact.path), settings.storage_root, "Artifact")

    media_types = {".json": "application/json", ".txt": "text/plain", ".log": "text/plain", ".png": "image/png"}
    return FileResponse(resolved_path, media_type=media_types.get(resolved_path.suffix.lower(), "application/octet-stream"))


@router.get("/{job_id}/evidence", response_model=AnalysisEvidenceListResponse)
def list_job_evidence(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisEvidenceListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    evidence = (
        db.query(AnalysisEvidence)
        .filter(AnalysisEvidence.job_id == job_id)
        .order_by(AnalysisEvidence.category.asc(), AnalysisEvidence.created_at.asc())
        .all()
    )
    return AnalysisEvidenceListResponse(
        evidence=[AnalysisEvidenceResponse.model_validate(item) for item in evidence]
    )


@router.get("/{job_id}/findings", response_model=AnalysisFindingListResponse)
def list_job_findings(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisFindingListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    findings = (
        db.query(AnalysisFinding)
        .filter(AnalysisFinding.job_id == job_id)
        .order_by(AnalysisFinding.severity.desc(), AnalysisFinding.created_at.asc())
        .all()
    )
    return AnalysisFindingListResponse(
        findings=[AnalysisFindingResponse.model_validate(finding) for finding in findings]
    )


@router.get("/{job_id}/reasoning", response_model=AnalysisReasoningListResponse)
def list_job_reasoning(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisReasoningListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    reasoning = (
        db.query(AnalysisReasoning)
        .filter(AnalysisReasoning.job_id == job_id)
        .order_by(AnalysisReasoning.created_at.asc())
        .all()
    )
    return AnalysisReasoningListResponse(
        reasoning=[AnalysisReasoningResponse.model_validate(item) for item in reasoning]
    )


@router.get("/{job_id}/reports", response_model=AnalysisReportListResponse)
def list_job_reports(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisReportListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    reports = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.job_id == job_id)
        .order_by(AnalysisReport.created_at.desc())
        .all()
    )
    return AnalysisReportListResponse(
        reports=[AnalysisReportResponse.model_validate(report) for report in reports]
    )


@router.get("/{job_id}/reports/{report_id}/download")
def download_job_report(
    job_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    report = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.job_id == job_id, AnalysisReport.id == report_id)
        .first()
    )
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")

    resolved_report_path = _resolve_storage_file(Path(report.path), settings.storage_root, "Report")

    media_type = "application/pdf" if report.report_type == "pdf" else "text/html"
    extension = "pdf" if report.report_type == "pdf" else "html"
    return FileResponse(
        resolved_report_path,
        media_type=media_type,
        filename=f"{Path(job.original_filename).stem}-pentest-report.{extension}",
    )
