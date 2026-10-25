"""Read-only views over the existing DY-MASA database."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.db.base import (
    AnalysisArtifact,
    AnalysisEvidence,
    AnalysisFinding,
    AnalysisJob,
    AnalysisJobStage,
    AnalysisReasoning,
    AnalysisReport,
)


def list_jobs(db: Any, limit: int = 50) -> list[AnalysisJob]:
    return list(db.scalars(select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(limit)).all())


def get_job(db: Any, job_id: str) -> AnalysisJob:
    job = db.get(AnalysisJob, job_id)
    if job is None:
        raise LookupError(f"Analysis job not found: {job_id}")
    return job


def job_details(db: Any, job_id: str) -> dict[str, Any]:
    job = get_job(db, job_id)
    stages = list(
        db.scalars(
            select(AnalysisJobStage)
            .where(AnalysisJobStage.job_id == job_id)
            .order_by(AnalysisJobStage.created_at.asc())
        ).all()
    )
    artifacts = list(
        db.scalars(
            select(AnalysisArtifact)
            .where(AnalysisArtifact.job_id == job_id)
            .order_by(AnalysisArtifact.created_at.asc())
        ).all()
    )
    findings = list(
        db.scalars(
            select(AnalysisFinding)
            .where(AnalysisFinding.job_id == job_id)
            .order_by(AnalysisFinding.created_at.asc())
        ).all()
    )
    evidence = list(
        db.scalars(
            select(AnalysisEvidence)
            .where(AnalysisEvidence.job_id == job_id)
            .order_by(AnalysisEvidence.created_at.asc())
        ).all()
    )
    reasoning = list(
        db.scalars(
            select(AnalysisReasoning)
            .where(AnalysisReasoning.job_id == job_id)
            .order_by(AnalysisReasoning.created_at.asc())
        ).all()
    )
    reports = list(
        db.scalars(
            select(AnalysisReport)
            .where(AnalysisReport.job_id == job_id)
            .order_by(AnalysisReport.created_at.asc())
        ).all()
    )
    return {
        "job": job,
        "stages": stages,
        "artifacts": artifacts,
        "findings": findings,
        "evidence": evidence,
        "reasoning": reasoning,
        "reports": reports,
    }


def list_findings(db: Any, job_id: str | None = None, severity: str | None = None) -> list[AnalysisFinding]:
    query = select(AnalysisFinding).order_by(AnalysisFinding.created_at.desc())
    if job_id:
        query = query.where(AnalysisFinding.job_id == job_id)
    if severity:
        query = query.where(AnalysisFinding.severity == severity)
    return list(db.scalars(query).all())


def list_evidence(db: Any, job_id: str | None = None) -> list[AnalysisEvidence]:
    query = select(AnalysisEvidence).order_by(AnalysisEvidence.created_at.desc())
    if job_id:
        query = query.where(AnalysisEvidence.job_id == job_id)
    return list(db.scalars(query).all())


def list_reports(db: Any, job_id: str | None = None) -> list[AnalysisReport]:
    query = select(AnalysisReport).order_by(AnalysisReport.created_at.desc())
    if job_id:
        query = query.where(AnalysisReport.job_id == job_id)
    return list(db.scalars(query).all())


def report_path(path: str, storage_root: Path) -> tuple[str, bool]:
    """Return a readable report path and existence without exposing escapes."""

    candidate = Path(path)
    try:
        resolved = candidate.resolve()
        resolved.relative_to(storage_root.resolve())
    except (OSError, ValueError):
        return "[outside approved storage]", False
    return str(resolved), resolved.is_file()
