"""CLI execution adapter for the existing persisted analysis pipeline."""

from __future__ import annotations

import time
import os
from pathlib import Path
from typing import Any

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _invalid_apk_path(path: Path) -> str | None:
    if not path.exists():
        return f"APK does not exist: {path}"
    if not path.is_file():
        return f"APK path is not a file: {path}"
    if path.suffix.lower() != ".apk":
        return f"Input must have a .apk extension: {path}"
    if not os.access(path, os.R_OK):
        return f"APK is not readable: {path}"
    return None


def final_exit_code(details: dict[str, Any]) -> int:
    """Return success only when the persisted job and both reports are valid."""

    job = details["job"]
    if getattr(job.status, "value", job.status) != "completed":
        return 1
    reports = {report.report_type: report for report in details["reports"]}
    if {"html", "pdf"} - reports.keys():
        return 1
    return 0


def _database_session():
    from app.db.session import SessionLocal

    return SessionLocal()


def run_analysis(
    apk_path: Path,
    settings: Any,
    output: Any,
    poll_interval: float = 1.0,
    ghidra_enabled: bool | None = None,
) -> int:
    """Create one job and monitor the existing worker until a terminal state."""

    from .database import analysis_tables_exist
    from app.services.job_service import JobService, submit_analysis_job
    from app.services.job_control import job_cancellation_registry

    invalid = _invalid_apk_path(apk_path)
    if invalid:
        output.print(f"Analysis could not be started: {invalid}")
        return 2
    if not analysis_tables_exist():
        output.print(
            "Database is not initialized (no analysis tables found). "
            "Run `dy-masa init`, or start the web backend once."
        )
        return 3

    try:
        from . import read

        with _database_session() as db:
            job = JobService(db, settings).create_job_from_path(apk_path, ghidra_enabled=ghidra_enabled)
    except Exception as exc:
        output.print(f"Analysis could not be started: {exc}")
        return 1

    output.print(f"Job ID: {job.id}")
    output.print(f"Ghidra native analysis: {'ENABLED' if getattr(job, 'ghidra_enabled', False) else 'DISABLED'}")
    if getattr(job.status, "value", job.status) != "queued":
        output.print(f"Analysis rejected: {job.error_message or job.current_step}")
        return 1

    try:
        submitted = submit_analysis_job(settings, job.id)
        if not submitted:
            output.print("Job queued; waiting for an available analysis worker.")
        last_state: tuple[object, ...] | None = None
        with output.progress_context() as progress:
            task_id = progress.add_task("Starting analysis", total=100) if progress else None
            while True:
                with _database_session() as db:
                    details = read.job_details(db, job.id)
                current = details["job"]
                status = getattr(current.status, "value", current.status)
                latest_stage = details["stages"][-1] if details["stages"] else None
                state = (
                    status,
                    current.progress,
                    current.current_step,
                    latest_stage.stage if latest_stage else None,
                    latest_stage.status if latest_stage else None,
                )
                stage_text = f"{current.current_step} // {status}"
                if latest_stage:
                    stage_text = f"{stage_text} // {latest_stage.stage} ({latest_stage.status})"
                if progress and task_id is not None:
                    progress.update(task_id, completed=max(0, min(100, current.progress)), description=stage_text)
                elif state != last_state:
                    output.print(f"[{status}] {current.progress}% {stage_text}")
                last_state = state
                if status in TERMINAL_STATUSES:
                    break
                time.sleep(max(0.1, poll_interval))
    except KeyboardInterrupt:
        job_cancellation_registry.cancel(job.id)
        output.print("Cancellation requested; waiting for the worker to record the final state.")
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline:
                with _database_session() as db:
                    details = read.job_details(db, job.id)
                status = getattr(details["job"].status, "value", details["job"].status)
                if status in TERMINAL_STATUSES:
                    break
                time.sleep(max(0.1, poll_interval))
            else:
                output.print("The job state may still read 'running' in the database; exiting without changing it.")
                return 130
        except KeyboardInterrupt:
            output.print("The job state may still read 'running' in the database; exiting without changing it.")
            return 130
    except Exception as exc:
        output.print(f"Analysis monitoring failed: {exc}")
        return 1

    details = details
    current = details["job"]
    output.print(f"Final status: {getattr(current.status, 'value', current.status)}")
    if current.error_message:
        output.print(f"Error: {current.error_message}")
    for report in details["reports"]:
        path, exists = read.report_path(report.path, settings.storage_root)
        output.print(f"Report [{report.report_type}]: {path} ({'present' if exists else 'missing'})")
    return final_exit_code(details)
