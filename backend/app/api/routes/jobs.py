import json
import asyncio
import time
from dataclasses import replace
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import cast, literal, select

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
from app.services.job_service import JobService, submit_analysis_job


router = APIRouter(prefix="/jobs", tags=["jobs"])
TERMINAL_EVENT_STAGES = frozenset({"job_completed", "job_failed", "job_cancelled"})
TERMINAL_EVENT_GRACE_SECONDS = 2.0


def _page_args(page: int | None, page_size: int | None) -> tuple[int, int] | None:
    """Return validated pagination values, or None for legacy unpaged responses."""
    # Direct Python callers (including lightweight service tests) see FastAPI's
    # Query sentinel when they omit a dependency-injected argument.
    if not isinstance(page, int):
        page = None
    if not isinstance(page_size, int):
        page_size = None
    if page is None and page_size is None:
        return None
    return page or 1, page_size or 100


def _paged(query, page: int | None, page_size: int | None):
    paging = _page_args(page, page_size)
    if paging is None:
        return query.all(), None
    current_page, current_size = paging
    total = query.order_by(None).count()
    rows = query.offset((current_page - 1) * current_size).limit(current_size).all()
    return rows, (total, current_page, current_size)


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


def _parse_event_cursor(value: int | str | None) -> tuple[int, int]:
    if isinstance(value, int):
        return (value, 0) if value >= 0 else (0, abs(value))
    if not isinstance(value, (int, str)) or not value:
        return 0, 0
    try:
        if value.startswith("p:"):
            parts = dict(part.split(":", 1) for part in value.split(";") if ":" in part)
            return int(parts.get("p", 0)), int(parts.get("m", 0))
    except (TypeError, ValueError):
        pass
    try:
        return (int(value), 0) if int(value) >= 0 else (0, abs(int(value)))
    except (TypeError, ValueError):
        return 0, 0


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
    """Merge history using a composite cursor: persisted DB ID plus cache ordinal."""
    persisted_after, memory_after = _parse_event_cursor(after_event_id)
    events_by_id = {event.event_id: event for event in _persistent_events(job_id, persisted_after)}
    for event in job_event_store.snapshot(job_id, after_event_id=0):
        if (event.event_id < 0 and abs(event.event_id) > memory_after) or (event.event_id >= 0 and event.event_id > persisted_after):
            events_by_id.setdefault(event.event_id, event)
    ordered = sorted(
        events_by_id.values(),
        key=lambda event: (-event.event_id if event.event_id < 0 else event.event_id, event.event_id < 0),
    )
    current_persisted, current_memory = persisted_after, memory_after
    result: list[JobStageEvent] = []
    for event in ordered:
        if event.event_id < 0:
            current_memory = max(current_memory, abs(event.event_id))
        else:
            current_persisted = max(current_persisted, event.event_id)
        result.append(replace(event, cursor=f"p:{current_persisted};m:{current_memory}"))
    return result


def _sse_event(event: JobStageEvent) -> str:
    return f"id: {event.cursor or event.event_id}\ndata: {json.dumps(as_event_payload(event))}\n\n"


@router.post("", response_model=AnalysisJobResponse, status_code=status.HTTP_202_ACCEPTED)
def upload_apk(
    apk: UploadFile = File(...),
    ghidra_enabled: bool | None = Form(default=None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AnalysisJobResponse:
    service = JobService(db, settings)
    try:
        job = service.create_upload_job(apk, ghidra_enabled=ghidra_enabled)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if job.status == AnalysisJobStatus.queued:
        submit_analysis_job(settings, job.id)
    return AnalysisJobResponse.model_validate(job)


@router.get("", response_model=AnalysisJobListResponse, response_model_exclude_none=True)
def list_jobs(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisJobListResponse:
    query = db.query(AnalysisJob).order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
    jobs, metadata = _paged(query, page, page_size)
    response = AnalysisJobListResponse(jobs=[AnalysisJobResponse.model_validate(job) for job in jobs])
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


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


@router.get("/{job_id}/timeline", response_model=AnalysisJobStageListResponse, response_model_exclude_none=True)
def list_job_timeline(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisJobStageListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    stages = (
        db.query(AnalysisJobStage)
        .filter(AnalysisJobStage.job_id == job_id)
        .order_by(AnalysisJobStage.created_at.asc(), AnalysisJobStage.id.asc())
    )
    stages, metadata = _paged(stages, page, page_size)
    response = AnalysisJobStageListResponse(
        stages=[AnalysisJobStageResponse.model_validate(stage) for stage in stages]
    )
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


@router.get("/{job_id}/events")
def stream_job_events(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
) -> StreamingResponse:
    if JobService(db, settings).get_job(job_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    async def event_stream() -> object:
        current_event_id: int | str = last_event_id if isinstance(last_event_id, (int, str)) else 0
        terminal_event_seen = False
        terminal_deadline: float | None = None
        initial_events = _events_after(job_id, current_event_id)
        for event in initial_events:
            current_event_id = event.cursor
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
                current_event_id = event.cursor
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
                    fallback_persisted, fallback_memory = _parse_event_cursor(current_event_id)
                    fallback = JobStageEvent(
                        event_id=fallback_persisted + 1,
                        stage=f"job_{getattr(job.status, 'value', job.status)}",
                        status=getattr(job.status, "value", job.status),
                        message=job.current_step,
                        detail=job.error_message,
                        cursor=f"p:{fallback_persisted + 1};m:{fallback_memory}",
                    )
                    yield _sse_event(fallback)
                    return

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/{job_id}/artifacts", response_model=AnalysisArtifactListResponse, response_model_exclude_none=True)
def list_job_artifacts(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisArtifactListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    artifacts = (
        db.query(AnalysisArtifact)
        .filter(AnalysisArtifact.job_id == job_id)
        .order_by(AnalysisArtifact.created_at.asc(), AnalysisArtifact.id.asc())
    )
    artifacts, metadata = _paged(artifacts, page, page_size)
    response = AnalysisArtifactListResponse(
        artifacts=[AnalysisArtifactResponse.model_validate(artifact) for artifact in artifacts]
    )
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


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

    if artifact.tool_name == "adb-logcat-step" and resolved_path.stat().st_size == 0:
        return PlainTextResponse(
            "No target-matching logcat lines were captured for this validation step.\n"
            "The step completed, but no Tier A or Tier B lines were emitted by the target application.\n"
            "This is an empty filtered step log, not a missing artifact."
        )

    media_types = {".json": "application/json", ".txt": "text/plain", ".log": "text/plain", ".png": "image/png"}
    return FileResponse(resolved_path, media_type=media_types.get(resolved_path.suffix.lower(), "application/octet-stream"))


@router.get("/{job_id}/evidence", response_model=AnalysisEvidenceListResponse, response_model_exclude_none=True)
def list_job_evidence(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisEvidenceListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    evidence = (
        db.query(AnalysisEvidence)
        .filter(AnalysisEvidence.job_id == job_id)
        .order_by(AnalysisEvidence.category.asc(), AnalysisEvidence.created_at.asc(), AnalysisEvidence.id.asc())
    )
    evidence, metadata = _paged(evidence, page, page_size)
    response = AnalysisEvidenceListResponse(
        evidence=[AnalysisEvidenceResponse.model_validate(item) for item in evidence]
    )
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


@router.get("/{job_id}/findings", response_model=AnalysisFindingListResponse, response_model_exclude_none=True)
def list_job_findings(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
    severity: str | None = None,
    category: str | None = None,
    search: str | None = None,
) -> AnalysisFindingListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    findings = (
        db.query(AnalysisFinding)
        .filter(AnalysisFinding.job_id == job_id)
        .order_by(AnalysisFinding.severity.desc(), AnalysisFinding.created_at.asc(), AnalysisFinding.id.asc())
    )
    if severity:
        findings = findings.filter(
            AnalysisFinding.severity == cast(literal(severity.lower()), AnalysisFinding.severity.type)
        )
    if category:
        findings = findings.filter(AnalysisFinding.category == category)
    if search:
        term = f"%{search.strip()}%"
        findings = findings.filter((AnalysisFinding.title.ilike(term)) | (AnalysisFinding.rule_id.ilike(term)))
    findings, metadata = _paged(findings, page, page_size)
    response = AnalysisFindingListResponse(
        findings=[AnalysisFindingResponse.model_validate(finding) for finding in findings]
    )
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


@router.get("/{job_id}/reasoning", response_model=AnalysisReasoningListResponse, response_model_exclude_none=True)
def list_job_reasoning(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisReasoningListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    reasoning = (
        db.query(AnalysisReasoning)
        .filter(AnalysisReasoning.job_id == job_id)
        .order_by(AnalysisReasoning.created_at.asc(), AnalysisReasoning.id.asc())
    )
    reasoning, metadata = _paged(reasoning, page, page_size)
    response = AnalysisReasoningListResponse(
        reasoning=[AnalysisReasoningResponse.model_validate(item) for item in reasoning]
    )
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


@router.get("/{job_id}/reports", response_model=AnalysisReportListResponse, response_model_exclude_none=True)
def list_job_reports(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisReportListResponse:
    job = JobService(db, settings).get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")

    reports = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.job_id == job_id)
        .order_by(AnalysisReport.created_at.desc(), AnalysisReport.id.desc())
    )
    reports, metadata = _paged(reports, page, page_size)
    response = AnalysisReportListResponse(
        reports=[AnalysisReportResponse.model_validate(report) for report in reports]
    )
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


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
