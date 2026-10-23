import json
from pathlib import Path
from threading import Thread

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.db.base import (
    AnalysisArtifact,
    AnalysisEvidence,
    AnalysisFinding,
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
from app.services.job_events import as_event_payload, job_event_store
from app.services.job_service import JobRunner, JobService


router = APIRouter(prefix="/jobs", tags=["jobs"])


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
def stream_job_events(job_id: str) -> StreamingResponse:
    def event_stream() -> object:
        last_event_id = 0
        initial_events = job_event_store.snapshot(job_id)
        for event in initial_events:
            payload = json.dumps(as_event_payload(event))
            last_event_id = max(last_event_id, event.event_id)
            yield f"data: {payload}\n\n"

        while True:
            new_events = job_event_store.wait_for(job_id, after_event_id=last_event_id)
            for event in new_events:
                payload = json.dumps(as_event_payload(event))
                last_event_id = max(last_event_id, event.event_id)
                yield f"data: {payload}\n\n"

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

    artifact_path = Path(artifact.path)
    storage_root = settings.storage_root.resolve()
    try:
        resolved_path = artifact_path.resolve()
        resolved_path.relative_to(storage_root)
    except (OSError, ValueError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Artifact path is outside MASA storage.")
    if not resolved_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact file not found.")

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

    report_path = Path(report.path)
    if not report_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found.")

    media_type = "application/pdf" if report.report_type == "pdf" else "text/html"
    extension = "pdf" if report.report_type == "pdf" else "html"
    return FileResponse(
        report_path,
        media_type=media_type,
        filename=f"{Path(job.original_filename).stem}-pentest-report.{extension}",
    )
