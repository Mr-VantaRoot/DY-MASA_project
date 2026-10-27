"""Read-only views over the existing DY-MASA database."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import case, cast, func, literal, select

from app.db.base import (
    AnalysisArtifact,
    AnalysisEvidence,
    AnalysisFinding,
    AnalysisJob,
    AnalysisJobStage,
    AnalysisReasoning,
    AnalysisReport,
    AnalysisJobStatus,
    ArtifactType,
    EvidenceCategory,
    FindingSeverity,
)


SEVERITY_ORDER = {
    severity.value: rank
    for rank, severity in enumerate(
        (FindingSeverity.critical, FindingSeverity.high, FindingSeverity.medium, FindingSeverity.low, FindingSeverity.info)
    )
}
JOB_STATUSES = tuple(status.value for status in AnalysisJobStatus)


def _enum_literal(column: Any, value: str) -> Any:
    """Bind a value as the PostgreSQL enum type instead of VARCHAR."""

    return cast(literal(value), column.type)


def normalize_severity(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip().lower()
    if normalized not in SEVERITY_ORDER:
        raise ValueError("Severity must be one of: critical, high, medium, low, info.")
    return normalized


def list_jobs(db: Any, limit: int | None = None, offset: int = 0, search: str | None = None, status: str | None = None) -> list[AnalysisJob]:
    query = select(AnalysisJob).order_by(AnalysisJob.created_at.desc(), AnalysisJob.id.desc())
    if search:
        query = query.where(AnalysisJob.original_filename.ilike(f"%{search.strip()}%"))
    if status:
        normalized_status = status.strip().lower()
        if normalized_status not in JOB_STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(JOB_STATUSES)}.")
        query = query.where(AnalysisJob.status == _enum_literal(AnalysisJob.status, normalized_status))
    if offset:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query).all())


def count_jobs(db: Any, search: str | None = None, status: str | None = None) -> int:
    query = select(func.count(AnalysisJob.id))
    if search:
        query = query.where(AnalysisJob.original_filename.ilike(f"%{search.strip()}%"))
    if status:
        normalized_status = status.strip().lower()
        if normalized_status not in JOB_STATUSES:
            raise ValueError(f"Status must be one of: {', '.join(JOB_STATUSES)}.")
        query = query.where(AnalysisJob.status == _enum_literal(AnalysisJob.status, normalized_status))
    return int(db.scalar(query) or 0)


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


def list_findings(
    db: Any,
    job_id: str | None = None,
    severity: str | None = None,
    offset: int = 0,
    limit: int | None = None,
    search: str | None = None,
    category: str | None = None,
) -> list[AnalysisFinding]:
    normalized = normalize_severity(severity)
    severity_rank = case(
        *(
            (AnalysisFinding.severity == _enum_literal(AnalysisFinding.severity, value), rank)
            for value, rank in SEVERITY_ORDER.items()
        ),
        else_=99,
    )
    query = select(AnalysisFinding).order_by(severity_rank.asc(), AnalysisFinding.created_at.asc(), AnalysisFinding.id.asc())
    if job_id:
        query = query.where(AnalysisFinding.job_id == job_id)
    if normalized:
        query = query.where(AnalysisFinding.severity == _enum_literal(AnalysisFinding.severity, normalized))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            AnalysisFinding.title.ilike(pattern)
            | AnalysisFinding.rule_id.ilike(pattern)
        )
    if category:
        query = query.where(AnalysisFinding.category == category.strip())
    if offset:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query).all())


def list_finding_categories(db: Any, job_id: str | None = None) -> list[str]:
    """Return the category options present in the same findings scope as the UI."""

    query = select(AnalysisFinding.category).distinct().order_by(AnalysisFinding.category.asc())
    if job_id:
        query = query.where(AnalysisFinding.job_id == job_id)
    return [category for category in db.scalars(query).all() if category]


def list_evidence(
    db: Any,
    job_id: str | None = None,
    offset: int = 0,
    limit: int | None = None,
    search: str | None = None,
    category: str | None = None,
) -> list[AnalysisEvidence]:
    query = select(AnalysisEvidence).order_by(AnalysisEvidence.category.asc(), AnalysisEvidence.created_at.asc(), AnalysisEvidence.id.asc())
    if job_id:
        query = query.where(AnalysisEvidence.job_id == job_id)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(AnalysisEvidence.label.ilike(pattern) | AnalysisEvidence.value_json.ilike(pattern))
    if category:
        query = query.where(AnalysisEvidence.category == _enum_literal(AnalysisEvidence.category, category.strip().lower()))
    if offset:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query).all())


def list_evidence_categories(db: Any, job_id: str | None = None) -> list[str]:
    """Return evidence categories present in the requested job scope."""

    query = select(AnalysisEvidence.category).distinct().order_by(AnalysisEvidence.category.asc())
    if job_id:
        query = query.where(AnalysisEvidence.job_id == job_id)
    return [getattr(category, "value", category) for category in db.scalars(query).all() if category]


def list_reports(db: Any, job_id: str | None = None) -> list[AnalysisReport]:
    query = select(AnalysisReport).order_by(AnalysisReport.created_at.desc(), AnalysisReport.id.desc())
    if job_id:
        query = query.where(AnalysisReport.job_id == job_id)
    return list(db.scalars(query).all())


def list_dynamic_stages(db: Any, job_id: str) -> list[AnalysisJobStage]:
    query = (
        select(AnalysisJobStage)
        .where(AnalysisJobStage.job_id == job_id, AnalysisJobStage.stage.like("dynamic_%"))
        .order_by(AnalysisJobStage.created_at.asc())
    )
    return list(db.scalars(query).all())


def list_runtime_evidence(db: Any, job_id: str, offset: int = 0, limit: int | None = None) -> list[AnalysisEvidence]:
    query = (
        select(AnalysisEvidence)
        .where(
            AnalysisEvidence.job_id == job_id,
            AnalysisEvidence.category == _enum_literal(AnalysisEvidence.category, EvidenceCategory.runtime.value),
        )
        .order_by(AnalysisEvidence.created_at.asc(), AnalysisEvidence.id.asc())
    )
    if offset:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query).all())


def dynamic_result_message(db: Any, job_id: str, kind: str) -> str | None:
    stages = list_dynamic_stages(db, job_id)
    if not stages:
        return "Dynamic analysis was not performed for this scan."
    if any(stage.status == "failed" for stage in stages):
        return "Dynamic analysis failed for this scan; no complete runtime data is available."
    if any(stage.status in {"running", "queued"} for stage in stages):
        return "Dynamic analysis is still in progress for this scan."
    messages = {
        "events": "Dynamic analysis produced no events for this scan.",
        "evidence": "Dynamic analysis completed without runtime evidence for this scan.",
        "artifacts": "Dynamic analysis completed without runtime artifacts for this scan.",
    }
    return messages[kind]


def list_runtime_artifacts(db: Any, job_id: str, offset: int = 0, limit: int | None = None) -> list[AnalysisArtifact]:
    query = (
        select(AnalysisArtifact)
        .where(AnalysisArtifact.job_id == job_id, AnalysisArtifact.artifact_type == _enum_literal(AnalysisArtifact.artifact_type, ArtifactType.dynamic_artifact.value))
        .order_by(AnalysisArtifact.created_at.asc(), AnalysisArtifact.id.asc())
    )
    if offset:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return list(db.scalars(query).all())


def count_runtime_evidence(db: Any, job_id: str) -> int:
    return int(
        db.scalar(
            select(func.count(AnalysisEvidence.id)).where(
                AnalysisEvidence.job_id == job_id,
                AnalysisEvidence.category == _enum_literal(AnalysisEvidence.category, EvidenceCategory.runtime.value),
            )
        )
        or 0
    )


def count_runtime_artifacts(db: Any, job_id: str) -> int:
    return int(
        db.scalar(
            select(func.count(AnalysisArtifact.id)).where(
                AnalysisArtifact.job_id == job_id,
                AnalysisArtifact.artifact_type == _enum_literal(AnalysisArtifact.artifact_type, ArtifactType.dynamic_artifact.value),
            )
        )
        or 0
    )


def list_reasoning(db: Any, job_id: str | None = None) -> list[AnalysisReasoning]:
    query = select(AnalysisReasoning).order_by(AnalysisReasoning.created_at.asc(), AnalysisReasoning.id.asc())
    if job_id:
        query = query.where(AnalysisReasoning.job_id == job_id)
    return list(db.scalars(query).all())


def count_findings(
    db: Any,
    job_id: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    category: str | None = None,
) -> int:
    normalized = normalize_severity(severity)
    query = select(func.count(AnalysisFinding.id))
    if job_id:
        query = query.where(AnalysisFinding.job_id == job_id)
    if normalized:
        query = query.where(AnalysisFinding.severity == _enum_literal(AnalysisFinding.severity, normalized))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            AnalysisFinding.title.ilike(pattern)
            | AnalysisFinding.rule_id.ilike(pattern)
        )
    if category:
        query = query.where(AnalysisFinding.category == category.strip())
    return int(db.scalar(query) or 0)


def count_evidence(db: Any, job_id: str | None = None, search: str | None = None, category: str | None = None) -> int:
    query = select(func.count(AnalysisEvidence.id))
    if job_id:
        query = query.where(AnalysisEvidence.job_id == job_id)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(AnalysisEvidence.label.ilike(pattern) | AnalysisEvidence.value_json.ilike(pattern))
    if category:
        query = query.where(AnalysisEvidence.category == _enum_literal(AnalysisEvidence.category, category.strip().lower()))
    return int(db.scalar(query) or 0)


def overview(db: Any) -> dict[str, int]:
    rows = db.execute(select(AnalysisJob.status, func.count(AnalysisJob.id)).group_by(AnalysisJob.status)).all()
    result = {"total": 0, "queued": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0}
    for status, count in rows:
        key = getattr(status, "value", status)
        result[key] = int(count)
        result["total"] += int(count)
    result["findings"] = int(db.scalar(select(func.count(AnalysisFinding.id))) or 0)
    result["evidence"] = int(db.scalar(select(func.count(AnalysisEvidence.id))) or 0)
    result["reports"] = int(db.scalar(select(func.count(AnalysisReport.id))) or 0)
    return result


def report_path(path: str, storage_root: Path) -> tuple[str, bool]:
    """Return a readable report path and existence without exposing escapes."""

    candidate = Path(path)
    try:
        resolved = candidate.resolve()
        resolved.relative_to(storage_root.resolve())
    except (OSError, ValueError):
        return "[outside approved storage]", False
    return str(resolved), resolved.is_file()


def safe_source_path(path: str, storage_root: Path) -> str:
    """Render an evidence source without exposing the host workspace root."""
    candidate = Path(path)
    try:
        relative = candidate.resolve().relative_to(storage_root.resolve())
    except (OSError, ValueError):
        name = candidate.name or "unknown-source"
        return f"[external source]/{name}"
    return str(Path("storage") / relative)
