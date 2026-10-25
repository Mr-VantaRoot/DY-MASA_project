from datetime import datetime

from pydantic import BaseModel

from app.db.base import AnalysisJobStatus, ArtifactType, EvidenceCategory, FindingSeverity


class AnalysisJobResponse(BaseModel):
    id: str
    original_filename: str
    file_size_bytes: int
    sha256: str | None
    ghidra_enabled: bool
    status: AnalysisJobStatus
    progress: int
    current_step: str
    error_message: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class AnalysisJobListResponse(BaseModel):
    jobs: list[AnalysisJobResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


class AnalysisArtifactResponse(BaseModel):
    id: str
    job_id: str
    artifact_type: ArtifactType
    tool_name: str
    path: str
    exit_code: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisArtifactListResponse(BaseModel):
    artifacts: list[AnalysisArtifactResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


class AnalysisJobStageResponse(BaseModel):
    id: str
    job_id: str
    stage: str
    status: str
    message: str
    detail: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisJobStageListResponse(BaseModel):
    stages: list[AnalysisJobStageResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


class AnalysisEvidenceResponse(BaseModel):
    id: str
    job_id: str
    category: EvidenceCategory
    evidence_type: str
    label: str
    value_json: str
    source_path: str
    source_node: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisEvidenceListResponse(BaseModel):
    evidence: list[AnalysisEvidenceResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


class AnalysisFindingResponse(BaseModel):
    id: str
    job_id: str
    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str
    evidence_ids_json: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisFindingListResponse(BaseModel):
    findings: list[AnalysisFindingResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


class AnalysisReasoningResponse(BaseModel):
    id: str
    job_id: str
    provider: str
    summary: str
    attack_paths_json: str
    limitations: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisReasoningListResponse(BaseModel):
    reasoning: list[AnalysisReasoningResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None


class AnalysisReportResponse(BaseModel):
    id: str
    job_id: str
    report_type: str
    path: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalysisReportListResponse(BaseModel):
    reports: list[AnalysisReportResponse]
    total: int | None = None
    page: int | None = None
    page_size: int | None = None
