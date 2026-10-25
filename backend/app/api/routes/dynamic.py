from __future__ import annotations


from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.base import AnalysisEvidence, AnalysisJobStage, EvidenceCategory
from app.db.session import get_db
from app.schemas.jobs import AnalysisEvidenceListResponse, AnalysisEvidenceResponse, AnalysisJobStageListResponse, AnalysisJobStageResponse
from app.services.job_events import emit_job_event
from app.services.job_service import JobService, submit_dynamic_job
from app.services.dynamic_service import DynamicStartError, start_dynamic_run
from app.api.routes.jobs import _paged
from dynamic.emulator.manager import EmulatorManager, EmulatorStatus
from dynamic.runtime.orchestrator import DynamicAnalysisError, DynamicRuntimeOrchestrator

router = APIRouter(tags=["dynamic"])


def _manager(settings: Settings) -> EmulatorManager:
    return EmulatorManager(
        sdk_path=settings.android_sdk_path,
        adb_path=settings.adb_path,
        emulator_path=settings.emulator_path,
        avd_name=settings.avd_name,
        boot_timeout_seconds=settings.emulator_boot_timeout_seconds,
        status_timeout_seconds=settings.dynamic_status_timeout_seconds,
        avd_home=settings.android_avd_home,
        device_serial=settings.dynamic_device_serial,
        allow_physical_device=settings.dynamic_allow_physical_device,
    )


@router.get("/dynamic/status")
def dynamic_status(settings: Settings = Depends(get_settings)) -> EmulatorStatus:
    return _manager(settings).status()


@router.get("/dynamic/storage")
def dynamic_storage(settings: Settings = Depends(get_settings)) -> dict:
    """Return read-only storage totals and shared-media estimates for the ready device."""
    manager = _manager(settings)
    device = manager.ready_device()
    if device is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No ready Android device is connected.")
    report = manager.adb.storage_breakdown(device.serial, scan_personal=settings.dynamic_scan_personal_storage)
    volume = report.volume
    return {
        "device": device.serial,
        "storage": {
            "path": volume.path if volume else "/sdcard",
            "total_bytes": volume.total_bytes if volume else 0,
            "used_bytes": volume.used_bytes if volume else 0,
            "available_bytes": volume.available_bytes if volume else 0,
            "used_percent": volume.used_percent if volume else 0,
            "is_full": bool(volume and (volume.available_bytes <= 0 or volume.used_percent >= 95)),
        },
        "categories": {
            "video_bytes": report.video_bytes,
            "image_bytes": report.image_bytes,
            "other_bytes": report.other_bytes,
        },
        "scanned_paths": report.scanned_paths,
        "detail": report.detail,
        "read_only": True,
    }


def _run_dynamic(job_id: str, run_stage_id: str, settings: Settings) -> None:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        job = JobService(db, settings).get_job(job_id)
        if job is None:
            return
        try:
            DynamicRuntimeOrchestrator(settings).run(db, job)
            db.add(AnalysisJobStage(job_id=job.id, stage="dynamic_report", status="running", message="Refreshing reports with DY-MASA evidence", detail="Rebuilding HTML and PDF reports"))
            db.commit()
            JobService(db, settings).regenerate_reports(job)
            db.add(AnalysisJobStage(job_id=job.id, stage="dynamic_report", status="completed", message="Reports refreshed with DY-MASA evidence", detail="HTML and PDF reports now include runtime evidence"))
            run_stage = db.get(AnalysisJobStage, run_stage_id)
            if run_stage is not None:
                run_stage.status = "completed"
                run_stage.message = "DY-MASA analysis completed"
                run_stage.detail = "Runtime evidence and reports were refreshed"
            db.commit()
            emit_job_event(job.id, "job_completed", "completed", "DY-MASA analysis completed", "Runtime evidence and reports were refreshed", db=db)
        except DynamicAnalysisError as exc:
            db.add(AnalysisJobStage(job_id=job.id, stage="dynamic_error", status="failed", message="DY-MASA analysis failed", detail=str(exc)))
            run_stage = db.get(AnalysisJobStage, run_stage_id)
            if run_stage is not None:
                run_stage.status = "failed"
                run_stage.message = "DY-MASA analysis failed"
                run_stage.detail = str(exc)
            job.error_message = str(exc)
            job.current_step = "DY-MASA analysis failed"
            db.commit()
            emit_job_event(job.id, "job_failed", "failed", "DY-MASA analysis failed", str(exc), db=db)
        except Exception as exc:
            db.add(AnalysisJobStage(job_id=job.id, stage="dynamic_error", status="failed", message="DY-MASA analysis failed", detail=str(exc)))
            run_stage = db.get(AnalysisJobStage, run_stage_id)
            if run_stage is not None:
                run_stage.status = "failed"
                run_stage.message = "DY-MASA analysis failed"
                run_stage.detail = str(exc)
            job.error_message = str(exc)
            job.current_step = "DY-MASA analysis failed"
            db.commit()
            emit_job_event(job.id, "job_failed", "failed", "DY-MASA analysis failed", str(exc), db=db)


@router.post("/jobs/{job_id}/dynamic/start", status_code=status.HTTP_202_ACCEPTED)
def start_dynamic_analysis(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    try:
        return start_dynamic_run(db, settings, job_id, submitter=submit_dynamic_job)
    except DynamicStartError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/jobs/{job_id}/dynamic/events", response_model=AnalysisJobStageListResponse, response_model_exclude_none=True)
def list_dynamic_events(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisJobStageListResponse:
    if JobService(db, settings).get_job(job_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")
    stages = (
        db.query(AnalysisJobStage)
        .filter(AnalysisJobStage.job_id == job_id, AnalysisJobStage.stage.like("dynamic_%"))
        .order_by(AnalysisJobStage.created_at.asc(), AnalysisJobStage.id.asc())
    )
    stages, metadata = _paged(stages, page, page_size)
    response = AnalysisJobStageListResponse(stages=[AnalysisJobStageResponse.model_validate(stage) for stage in stages])
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response


@router.get("/jobs/{job_id}/dynamic/evidence", response_model=AnalysisEvidenceListResponse, response_model_exclude_none=True)
def list_dynamic_evidence(
    job_id: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=1000),
) -> AnalysisEvidenceListResponse:
    if JobService(db, settings).get_job(job_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis job not found.")
    evidence = (
        db.query(AnalysisEvidence)
        .filter(AnalysisEvidence.job_id == job_id, AnalysisEvidence.category == EvidenceCategory.runtime)
        .order_by(AnalysisEvidence.created_at.asc(), AnalysisEvidence.id.asc())
    )
    evidence, metadata = _paged(evidence, page, page_size)
    response = AnalysisEvidenceListResponse(evidence=[AnalysisEvidenceResponse.model_validate(item) for item in evidence])
    if metadata:
        response.total, response.page, response.page_size = metadata
    return response
