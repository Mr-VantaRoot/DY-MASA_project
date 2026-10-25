from datetime import datetime
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4
import hashlib
import json
import shutil
from concurrent.futures import Future, ThreadPoolExecutor
from threading import RLock
import zipfile

from fastapi import UploadFile
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ai.reasoning import DeterministicReasoningEngine, ReasoningResult
from analysis.code_risk import CodeRiskEvidenceExtractor
from analysis.decompilation import ApkDecompiler, DecompilationCancelled, DecompilationError, DecompilationResult
from analysis.evidence import CodeSecretEvidenceExtractor, EvidenceItem, ManifestEvidenceExtractor, normalize_evidence_items
from analysis.findings import EvidenceFindingGenerator, FindingCandidate
from analysis.ghidra import GhidraAnalyzer, NativeAnalysisResult, evidence_for_native_analysis
from app.core.config import Settings
from app.db.base import (
    AnalysisArtifact,
    AnalysisEvidence,
    AnalysisFinding,
    AnalysisJob,
    AnalysisJobStage,
    AnalysisJobStatus,
    AnalysisReasoning,
    AnalysisReport,
    ArtifactType,
    EvidenceCategory,
)
from app.services.job_control import JobCancelled, job_cancellation_registry
from app.services.job_events import emit_job_event, job_event_store
from reports.generator import HtmlReportGenerator, PdfReportGenerator


_analysis_executors: dict[int, ThreadPoolExecutor] = {}
_submitted_jobs: set[str] = set()
_executor_lock = RLock()


def analysis_executor(settings: Settings) -> ThreadPoolExecutor:
    """Return a bounded worker pool; queued jobs remain durable in PostgreSQL."""
    limit = max(1, int(settings.max_concurrent_analysis_jobs))
    with _executor_lock:
        executor = _analysis_executors.get(limit)
        if executor is None:
            executor = ThreadPoolExecutor(max_workers=limit, thread_name_prefix="masa-analysis")
            _analysis_executors[limit] = executor
        return executor


def _queued_work(settings: Settings) -> tuple[str, str, str | None] | None:
    from app.db.session import SessionLocal

    with _executor_lock:
        submitted = set(_submitted_jobs)
    statement = select(AnalysisJob.id, AnalysisJob.created_at).where(AnalysisJob.status == AnalysisJobStatus.queued)
    if submitted:
        statement = statement.where(~AnalysisJob.id.in_(submitted))
    with SessionLocal() as db:
        static = db.execute(statement.order_by(AnalysisJob.created_at.asc()).limit(1)).first()
        dynamic = db.execute(
            select(AnalysisJobStage.id, AnalysisJobStage.job_id, AnalysisJobStage.created_at)
            .where(
                AnalysisJobStage.stage == "dynamic_run",
                AnalysisJobStage.status == "queued",
                ~AnalysisJobStage.job_id.in_(submitted) if submitted else True,
            )
            .order_by(AnalysisJobStage.created_at.asc())
            .limit(1)
        ).first()
    if static is None and dynamic is None:
        return None
    if dynamic is not None and (static is None or dynamic.created_at < static.created_at):
        return "dynamic", dynamic.job_id, dynamic.id
    return "static", static.id, None


def _dispatch_available(settings: Settings) -> int:
    """Fill only currently available worker slots from durable queued jobs."""
    submitted = 0
    limit = max(1, int(settings.max_concurrent_analysis_jobs))
    while True:
        with _executor_lock:
            if len(_submitted_jobs) >= limit:
                return submitted
        work = _queued_work(settings)
        if work is None:
            return submitted
        kind, job_id, stage_id = work
        with _executor_lock:
            if job_id in _submitted_jobs or len(_submitted_jobs) >= limit:
                continue
            _submitted_jobs.add(job_id)
            if kind == "dynamic":
                from app.api.routes.dynamic import _run_dynamic

                future = analysis_executor(settings).submit(_run_dynamic, job_id, stage_id, settings)
            else:
                future = analysis_executor(settings).submit(JobRunner(settings).prepare_uploaded_apk, job_id)
            future.add_done_callback(lambda _future, completed=job_id, config=settings: _job_finished(completed, config))
            submitted += 1


def _job_finished(job_id: str, settings: Settings) -> None:
    with _executor_lock:
        _submitted_jobs.discard(job_id)
    _dispatch_available(settings)


def submit_analysis_job(settings: Settings, job_id: str) -> bool:
    before = job_id in _submitted_jobs
    _dispatch_available(settings)
    return not before and job_id in _submitted_jobs


def submit_dynamic_job(settings: Settings, job_id: str, stage_id: int) -> bool:
    from app.api.routes.dynamic import _run_dynamic

    with _executor_lock:
        if job_id in _submitted_jobs or len(_submitted_jobs) >= max(1, int(settings.max_concurrent_analysis_jobs)):
            return False
        _submitted_jobs.add(job_id)
        future: Future[object] = analysis_executor(settings).submit(_run_dynamic, job_id, stage_id, settings)
        future.add_done_callback(lambda _future: _job_finished(job_id, settings))
        return True


@dataclass(frozen=True)
class DecompilationOutputs:
    apktool: DecompilationResult
    jadx: DecompilationResult
    ghidra: NativeAnalysisResult


def record_job_stage(
    job: AnalysisJob,
    stage: str,
    status: str,
    message: str,
    detail: str | None = None,
) -> None:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        db.add(
            AnalysisJobStage(
                job_id=job.id,
                stage=stage,
                status=status,
                message=message,
                detail=detail,
            )
        )
        db.commit()


class _JobStorageHelpers:
    @staticmethod
    def _load_evidence(db: Session, job: AnalysisJob) -> list[AnalysisEvidence]:
        return list(db.scalars(select(AnalysisEvidence).where(AnalysisEvidence.job_id == job.id).order_by(AnalysisEvidence.created_at.asc())).all())

    @staticmethod
    def _load_findings(db: Session, job: AnalysisJob) -> list[AnalysisFinding]:
        return list(db.scalars(select(AnalysisFinding).where(AnalysisFinding.job_id == job.id).order_by(AnalysisFinding.created_at.asc())).all())

    @staticmethod
    def _load_reasoning(db: Session, job: AnalysisJob) -> list[AnalysisReasoning]:
        return list(db.scalars(select(AnalysisReasoning).where(AnalysisReasoning.job_id == job.id).order_by(AnalysisReasoning.created_at.asc())).all())

    @staticmethod
    def _record_report(db: Session, job: AnalysisJob, report_type: str, report_path: Path) -> None:
        report = db.scalars(select(AnalysisReport).where(AnalysisReport.job_id == job.id, AnalysisReport.report_type == report_type).order_by(AnalysisReport.created_at.desc())).first()
        if report is None:
            db.add(AnalysisReport(job_id=job.id, report_type=report_type, path=str(report_path)))
        else:
            report.path = str(report_path)
            report.created_at = datetime.utcnow()
        db.commit()

    def _cleanup_job_files(self, job_id: str, apk_path: Path | None, workspace_path: Path | None) -> None:
        candidates = [apk_path, workspace_path, self._settings.report_dir / f"{job_id}.html", self._settings.report_dir / f"{job_id}.pdf"]
        for candidate in candidates:
            if candidate is not None:
                self._remove_within_storage(candidate)

    def _remove_within_storage(self, path: Path) -> None:
        resolved = path.resolve()
        storage_root = self._settings.storage_root.resolve()
        if resolved != storage_root and storage_root not in resolved.parents:
            return
        if resolved.is_dir():
            shutil.rmtree(resolved, ignore_errors=True)
        else:
            resolved.unlink(missing_ok=True)


class JobService(_JobStorageHelpers):
    def __init__(self, db: Session, settings: Settings) -> None:
        self._db = db
        self._settings = settings

    def create_upload_job(self, upload: UploadFile, ghidra_enabled: bool | None = None) -> AnalysisJob:
        self._validate_apk_filename(upload.filename)
        self._settings.upload_dir.mkdir(parents=True, exist_ok=True)

        original_filename = Path(upload.filename or "").name
        job_id = str(uuid4())
        stored_filename = f"{job_id}.apk"
        apk_path = self._settings.upload_dir / stored_filename

        total_bytes = 0
        try:
            with apk_path.open("wb") as destination:
                while chunk := upload.file.read(1024 * 1024):
                    total_bytes += len(chunk)
                    if total_bytes > self._settings.max_upload_bytes:
                        raise ValueError(
                            f"Uploaded APK exceeds the maximum size of {self._settings.max_upload_bytes} bytes."
                        )
                    destination.write(chunk)
        except Exception:
            apk_path.unlink(missing_ok=True)
            raise

        job = self._create_job_record(job_id, original_filename, stored_filename, apk_path, ghidra_enabled)
        record_job_stage(job, "upload_received", "completed", "Upload received and validated", f"Stored as {stored_filename}")
        emit_job_event(job.id, "upload_received", "completed", "Upload received and validated", f"Stored as {stored_filename}", db=self._db)
        if job.status == AnalysisJobStatus.failed:
            emit_job_event(job.id, "job_failed", "failed", job.current_step, job.error_message, db=self._db)
        return job

    def create_job_from_path(self, source_path: Path, ghidra_enabled: bool | None = None) -> AnalysisJob:
        if not source_path.exists():
            raise ValueError(f"APK does not exist: {source_path}")
        self._validate_apk_filename(source_path.name)
        self._settings.upload_dir.mkdir(parents=True, exist_ok=True)

        job_id = str(uuid4())
        stored_filename = f"{job_id}.apk"
        apk_path = self._settings.upload_dir / stored_filename
        if source_path.stat().st_size > self._settings.max_upload_bytes:
            raise ValueError(f"APK exceeds the maximum size of {self._settings.max_upload_bytes} bytes.")
        shutil.copyfile(source_path, apk_path)

        job = self._create_job_record(job_id, source_path.name, stored_filename, apk_path, ghidra_enabled)
        record_job_stage(job, "upload_received", "completed", "Upload received and validated", f"Stored as {stored_filename}")
        emit_job_event(job.id, "upload_received", "completed", "Upload received and validated", f"Stored as {stored_filename}", db=self._db)
        if job.status == AnalysisJobStatus.failed:
            emit_job_event(job.id, "job_failed", "failed", job.current_step, job.error_message, db=self._db)
        return job

    def _create_job_record(
        self,
        job_id: str,
        original_filename: str,
        stored_filename: str,
        apk_path: Path,
        ghidra_enabled: bool | None = None,
    ) -> AnalysisJob:
        file_size = apk_path.stat().st_size
        validation_error = self._apk_validation_error(apk_path, file_size)

        job = AnalysisJob(
            id=job_id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            apk_path=str(apk_path),
            file_size_bytes=file_size,
            status=AnalysisJobStatus.failed if validation_error else AnalysisJobStatus.queued,
            progress=0,
            current_step="Upload validation failed" if validation_error else "Queued for APK preparation",
            error_message=validation_error,
            ghidra_enabled=self._settings.ghidra_enabled if ghidra_enabled is None else bool(ghidra_enabled),
        )
        self._db.add(job)
        self._db.commit()
        self._db.refresh(job)
        return job

    def get_job(self, job_id: str) -> AnalysisJob | None:
        return self._db.get(AnalysisJob, job_id)

    def delete_job(self, job_id: str) -> bool:
        job_cancellation_registry.cancel(job_id)
        job = self._db.get(AnalysisJob, job_id)
        if job is None:
            self._cleanup_job_files(job_id, None, None)
            job_event_store.clear(job_id)
            return False

        apk_path = Path(job.apk_path) if job.apk_path else None
        workspace_path = Path(job.workspace_path) if job.workspace_path else None
        self._db.delete(job)
        self._db.commit()
        self._cleanup_job_files(job_id, apk_path, workspace_path)
        job_event_store.clear(job_id)
        return True

    def list_jobs(self) -> list[AnalysisJob]:
        statement = select(AnalysisJob).order_by(AnalysisJob.created_at.desc())
        return list(self._db.scalars(statement).all())

    def regenerate_reports(self, job: AnalysisJob) -> None:
        """Rebuild the existing report pair after additional evidence is recorded."""
        evidence = self._load_evidence(self._db, job)
        findings = self._load_findings(self._db, job)
        reasoning = self._load_reasoning(self._db, job)
        stages = list(self._db.scalars(select(AnalysisJobStage).where(AnalysisJobStage.job_id == job.id).order_by(AnalysisJobStage.created_at.asc())).all())
        html_report_path = HtmlReportGenerator().generate(
            job=job, evidence=evidence, findings=findings, reasoning=reasoning, report_dir=self._settings.report_dir, stages=stages
        )
        self._record_report(self._db, job, "html", html_report_path)
        pdf_report_path = PdfReportGenerator().generate(
            job=job, evidence=evidence, findings=findings, reasoning=reasoning, report_dir=self._settings.report_dir, stages=stages
        )
        self._record_report(self._db, job, "pdf", pdf_report_path)

    @staticmethod
    def _validate_apk_filename(filename: str | None) -> None:
        if not filename:
            raise ValueError("Upload must include a filename.")
        if Path(filename).suffix.lower() != ".apk":
            raise ValueError("Only .apk files are accepted.")

    @staticmethod
    def _apk_validation_error(apk_path: Path, file_size: int) -> str | None:
        if file_size == 0:
            return "Uploaded APK is empty. The file was saved, but analysis was not started."
        if not zipfile.is_zipfile(apk_path):
            return (
                "Uploaded file is not a valid APK ZIP container. The file was saved, but analysis was not started. "
                "Re-download the APK and avoid XAPK/APKM/split bundles renamed as .apk."
            )
        try:
            with zipfile.ZipFile(apk_path) as archive:
                corrupt_member = archive.testzip()
                if corrupt_member is not None:
                    return f"Uploaded APK contains a corrupt ZIP entry ({corrupt_member}). The file was saved, but analysis was not started."
                names = set(archive.namelist())
        except (OSError, zipfile.BadZipFile) as exc:
            return f"Uploaded APK ZIP contents could not be read ({exc}). The file was saved, but analysis was not started."
        if "AndroidManifest.xml" not in names:
            return "Uploaded file is missing AndroidManifest.xml and is not a complete APK. The file was saved, but analysis was not started."
        return None


class JobRunner(_JobStorageHelpers):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def prepare_uploaded_apk(self, job_id: str) -> None:
        from app.db.session import SessionLocal

        with SessionLocal() as db:
            job = db.get(AnalysisJob, job_id)
            if job is None or job.status != AnalysisJobStatus.queued:
                return
            if not self._claim_job(db, job_id):
                return
            db.expire_all()
            job = db.get(AnalysisJob, job_id)
            if job is None or job.status != AnalysisJobStatus.running:
                return

            cancel_event = job_cancellation_registry.register(job_id)
            try:
                self._raise_if_cancelled(job.id)
                workspace_path = self._prepare_workspace(db, job)
                self._raise_if_cancelled(job.id)
                self._record_upload_metadata(db, job, workspace_path)
                self._raise_if_cancelled(job.id)
                decompilation = self._decompile_apk(db, job, workspace_path, cancel_event)
                self._raise_if_cancelled(job.id)
                persisted_evidence = self._extract_and_record_evidence(db, job, decompilation)
                self._raise_if_cancelled(job.id)
                persisted_findings = self._generate_and_record_findings(db, job, persisted_evidence)
                self._raise_if_cancelled(job.id)
                persisted_reasoning = self._generate_and_record_reasoning(
                    db, job, persisted_evidence, persisted_findings
                )
                self._raise_if_cancelled(job.id)
                self._generate_and_record_reports(db, job, persisted_evidence, persisted_findings, persisted_reasoning)
                self._raise_if_cancelled(job.id)
                self._complete_job(db, job)
            except (JobCancelled, DecompilationCancelled):
                self._cancel_job(db, job_id)
            except DecompilationError as exc:
                self._fail_decompilation(db, job, exc)
            except Exception as exc:
                if job_cancellation_registry.is_cancelled(job_id):
                    self._cancel_job(db, job_id)
                else:
                    self._fail_job(db, job, "APK analysis preparation failed", str(exc))
            finally:
                job_cancellation_registry.clear(job_id)

    @staticmethod
    def _claim_job(db: Session, job_id: str) -> bool:
        """Atomically reserve a queued job for one worker across dispatchers."""
        result = db.execute(
            update(AnalysisJob)
            .where(AnalysisJob.id == job_id, AnalysisJob.status == AnalysisJobStatus.queued)
            .values(status=AnalysisJobStatus.running, current_step="Analysis worker claimed job", updated_at=datetime.utcnow())
        )
        if result.rowcount != 1:
            db.rollback()
            return False
        db.commit()
        return True

    def _prepare_workspace(self, db: Session, job: AnalysisJob) -> Path:
        self._mark(db, job, AnalysisJobStatus.running, 20, "Creating analysis workspace")
        record_job_stage(job, "workspace_created", "running", "Workspace created", "Analysis workspace directory initialized")
        emit_job_event(job.id, "workspace_created", "running", "Workspace created", "Analysis workspace directory initialized", db=db)
        workspace_path = self._settings.workspace_dir / job.id
        workspace_path.mkdir(parents=True, exist_ok=True)
        job.workspace_path = str(workspace_path)
        db.commit()
        record_job_stage(job, "workspace_created", "completed", "Workspace created", f"Workspace: {workspace_path}")
        emit_job_event(job.id, "workspace_created", "completed", "Workspace created", f"Workspace: {workspace_path}", db=db)
        return workspace_path

    def _record_upload_metadata(self, db: Session, job: AnalysisJob, workspace_path: Path) -> None:
        self._mark(db, job, AnalysisJobStatus.running, 55, "Computing APK SHA-256")
        record_job_stage(job, "sha256_computed", "running", "SHA-256 computed", "Computing file fingerprint")
        emit_job_event(job.id, "sha256_computed", "running", "SHA-256 computed", "Computing file fingerprint", db=db)
        job.sha256 = self._sha256(Path(job.apk_path))
        db.commit()
        record_job_stage(job, "sha256_computed", "completed", "SHA-256 computed", f"Fingerprint: {job.sha256}")
        emit_job_event(job.id, "sha256_computed", "completed", "SHA-256 computed", f"Fingerprint: {job.sha256}", db=db)

        self._mark(db, job, AnalysisJobStatus.running, 85, "Recording upload metadata")
        metadata_path = workspace_path / "upload-metadata.txt"
        metadata_path.write_text(
            "\n".join(
                [
                    f"original_filename={job.original_filename}",
                    f"stored_filename={job.stored_filename}",
                    f"file_size_bytes={job.file_size_bytes}",
                    f"sha256={job.sha256}",
                ]
            ),
            encoding="utf-8",
        )

    def _decompile_apk(self, db: Session, job: AnalysisJob, workspace_path: Path, cancel_event: object | None = None) -> DecompilationOutputs:
        decompiler = ApkDecompiler(self._settings)

        self._mark(db, job, AnalysisJobStatus.running, 88, "Running apktool decompilation")
        record_job_stage(job, "apktool_decode", "running", "apktool decode running", "Running apktool decode")
        emit_job_event(job.id, "apktool_decode", "running", "apktool decode running", "Running apktool decode", db=db)
        apktool_result = decompiler.run_apktool(Path(job.apk_path), workspace_path, cancel_event)
        self._record_decompilation_artifacts(db, job, apktool_result, ArtifactType.apktool_output)
        record_job_stage(job, "apktool_decode", "completed", "apktool decode complete", f"Exit code {apktool_result.exit_code}")
        emit_job_event(job.id, "apktool_decode", "completed", "apktool decode complete", f"Exit code {apktool_result.exit_code}", db=db)

        self._mark(db, job, AnalysisJobStatus.running, 94, "Running JADX decompilation")
        record_job_stage(job, "jadx_decompile", "running", "JADX decompile running", "Running JADX decompilation")
        emit_job_event(job.id, "jadx_decompile", "running", "JADX decompile running", "Running JADX decompilation", db=db)
        jadx_result = decompiler.run_jadx(Path(job.apk_path), workspace_path, cancel_event)
        self._record_decompilation_artifacts(db, job, jadx_result, ArtifactType.jadx_output)
        record_job_stage(job, "jadx_decompile", "completed", "JADX decompile complete", f"Exit code {jadx_result.exit_code}")
        emit_job_event(job.id, "jadx_decompile", "completed", "JADX decompile complete", f"Exit code {jadx_result.exit_code}", db=db)

        ghidra_selected = bool(getattr(job, "ghidra_enabled", False))
        if ghidra_selected:
            self._mark(db, job, AnalysisJobStatus.running, 96, "Running optional Ghidra native analysis")
            record_job_stage(job, "ghidra_analysis", "running", "Ghidra native analysis running", "Inspecting embedded native libraries when available")
            emit_job_event(job.id, "ghidra_analysis", "running", "Ghidra native analysis running", "Inspecting embedded native libraries when available", db=db)
        def ghidra_progress(event: dict[str, object]) -> None:
            library = str(event.get("library", "native library"))
            state = str(event.get("status", "unknown"))
            detail = (
                f"{library}: {state}; size={event.get('size_bytes')} bytes; "
                f"elapsed={event.get('elapsed_seconds', 0)}s"
            )
            job.current_step = f"Ghidra {state}: {library}"
            job.progress = min(97, 96 + int((int(event.get("index", 1)) / max(1, int(event.get("total", 1)))) * 2))
            db.commit()
            record_job_stage(job, "ghidra_library", state, f"Ghidra library {state}", detail)
            emit_job_event(job.id, "ghidra_library", state, f"Ghidra library {state}: {library}", detail, db=db)

        ghidra_result = GhidraAnalyzer(self._settings).run(
            apktool_result.output_path,
            workspace_path,
            cancel_event,
            progress_callback=ghidra_progress,
            enabled=ghidra_selected,
        )
        summary_path = GhidraAnalyzer.write_summary(ghidra_result)
        self._record_analysis_artifacts(db, job, ghidra_result, summary_path)
        stage_status = "completed" if ghidra_result.status == "completed" else "skipped" if ghidra_result.status == "skipped" else "failed"
        record_job_stage(job, "ghidra_analysis", stage_status, f"Ghidra native analysis {ghidra_result.status}", ghidra_result.detail)
        emit_job_event(job.id, "ghidra_analysis", stage_status, f"Ghidra native analysis {ghidra_result.status}", ghidra_result.detail, db=db)
        return DecompilationOutputs(apktool=apktool_result, jadx=jadx_result, ghidra=ghidra_result)

    def _extract_and_record_evidence(
        self,
        db: Session,
        job: AnalysisJob,
        decompilation: DecompilationOutputs,
    ) -> list[AnalysisEvidence]:
        self._mark(db, job, AnalysisJobStatus.running, 98, "Extracting APK evidence")
        record_job_stage(job, "evidence_extraction", "running", "Evidence extraction running", "Extracting manifest, code, and secret evidence")
        emit_job_event(job.id, "evidence_extraction", "running", "Evidence extraction running", "Extracting manifest, code, and secret evidence", db=db)
        evidence_items = self._extract_evidence(decompilation)
        self._record_evidence(db, job, evidence_items)
        record_job_stage(job, "evidence_extraction", "completed", "Evidence extraction complete", f"Extracted {len(evidence_items)} evidence records")
        emit_job_event(job.id, "evidence_extraction", "completed", "Evidence extraction complete", f"Extracted {len(evidence_items)} evidence records", db=db)
        return self._load_evidence(db, job)

    @staticmethod
    def _extract_evidence(decompilation: DecompilationOutputs) -> list[EvidenceItem]:
        evidence_items = ManifestEvidenceExtractor().extract(decompilation.apktool.output_path)
        secret_extractor = CodeSecretEvidenceExtractor()
        risk_extractor = CodeRiskEvidenceExtractor()
        evidence_items.extend(secret_extractor.extract(decompilation.apktool.output_path, decompilation.jadx.output_path))
        evidence_items.extend(risk_extractor.extract(decompilation.apktool.output_path, decompilation.jadx.output_path))
        evidence_items.extend(evidence_for_native_analysis(decompilation.ghidra))
        limits_path = decompilation.apktool.output_path.parent / "extraction-limits.json"
        limits = {"code_secret": secret_extractor.limit_metadata, "code_risk": risk_extractor.limit_metadata}
        normalized, normalization = normalize_evidence_items(evidence_items)
        limits["normalization"] = normalization
        limits_path.write_text(json.dumps(limits, indent=2, sort_keys=True), encoding="utf-8")
        normalized.append(EvidenceItem(
            category=EvidenceCategory.runtime,
            evidence_type="extraction_limits",
            label="Evidence extraction limits (informational)",
            value={**limits, "note": "Counts distinguish raw extractor output from normalized persisted evidence."},
            source_path=limits_path,
            source_node="extraction-limits.json",
        ))
        return normalized

    def _generate_and_record_findings(
        self,
        db: Session,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
    ) -> list[AnalysisFinding]:
        self._mark(db, job, AnalysisJobStatus.running, 99, "Generating evidence-backed findings")
        record_job_stage(job, "rule_analysis", "running", "Rule-based analysis running", "Generating findings from extracted evidence")
        emit_job_event(job.id, "rule_analysis", "running", "Rule-based analysis running", "Generating findings from extracted evidence", db=db)
        findings = EvidenceFindingGenerator().generate(evidence)
        self._record_findings(db, job, findings)
        record_job_stage(job, "rule_analysis", "completed", "Rule-based analysis complete", f"Generated {len(findings)} findings")
        emit_job_event(job.id, "rule_analysis", "completed", "Rule-based analysis complete", f"Generated {len(findings)} findings", db=db)
        return self._load_findings(db, job)

    def _generate_and_record_reasoning(
        self,
        db: Session,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
        findings: list[AnalysisFinding],
    ) -> list[AnalysisReasoning]:
        self._mark(db, job, AnalysisJobStatus.running, 99, "Generating rule-based reasoning summary")
        reasoning = DeterministicReasoningEngine().reason(findings, evidence)
        self._record_reasoning(db, job, reasoning)
        return self._load_reasoning(db, job)

    def _generate_and_record_reports(
        self,
        db: Session,
        job: AnalysisJob,
        evidence: list[AnalysisEvidence],
        findings: list[AnalysisFinding],
        reasoning: list[AnalysisReasoning],
    ) -> None:
        self._mark(db, job, AnalysisJobStatus.running, 99, "Generating professional reports")
        record_job_stage(job, "report_generation", "running", "Report generation running", "Creating HTML and PDF reports")
        emit_job_event(job.id, "report_generation", "running", "Report generation running", "Creating HTML and PDF reports", db=db)
        stages = list(db.scalars(select(AnalysisJobStage).where(AnalysisJobStage.job_id == job.id).order_by(AnalysisJobStage.created_at.asc())).all())
        html_report_path = HtmlReportGenerator().generate(
            job=job,
            evidence=evidence,
            findings=findings,
            reasoning=reasoning,
            report_dir=self._settings.report_dir,
            stages=stages,
        )
        self._record_report(db, job, "html", html_report_path)
        pdf_report_path = PdfReportGenerator().generate(
            job=job,
            evidence=evidence,
            findings=findings,
            reasoning=reasoning,
            report_dir=self._settings.report_dir,
            stages=stages,
        )
        self._record_report(db, job, "pdf", pdf_report_path)
        record_job_stage(job, "report_generation", "completed", "Report generation complete", f"Generated {html_report_path.name} and {pdf_report_path.name}")
        emit_job_event(job.id, "report_generation", "completed", "Report generation complete", f"Generated {html_report_path.name} and {pdf_report_path.name}", db=db)

    @staticmethod
    def _complete_job(db: Session, job: AnalysisJob) -> None:
        job.status = AnalysisJobStatus.completed
        job.progress = 100
        job.current_step = "Professional reports generated"
        job.completed_at = datetime.utcnow()
        job.updated_at = datetime.utcnow()
        db.commit()
        emit_job_event(job.id, "job_completed", "completed", job.current_step, None, db=db)

    @staticmethod
    def _cancel_job(db: Session, job_id: str) -> None:
        db.expire_all()
        job = db.get(AnalysisJob, job_id)
        if job is None:
            return
        job.status = AnalysisJobStatus.cancelled
        job.progress = 0
        job.current_step = "Analysis cancelled by user"
        job.error_message = "Analysis cancelled by user."
        job.updated_at = datetime.utcnow()
        db.commit()
        emit_job_event(job.id, "job_cancelled", "cancelled", "Analysis cancelled", "The job was stopped by the user.", db=db)

    def _fail_decompilation(self, db: Session, job: AnalysisJob, exc: DecompilationError) -> None:
        self._record_decompilation_artifacts(
            db,
            job,
            exc.result,
            ArtifactType.apktool_output if exc.result.tool_name == "apktool" else ArtifactType.jadx_output,
        )
        self._fail_job(db, job, f"{exc.result.tool_name} decompilation failed", str(exc))

    @staticmethod
    def _fail_job(db: Session, job: AnalysisJob, current_step: str, error_message: str) -> None:
        job.status = AnalysisJobStatus.failed
        job.error_message = error_message
        job.current_step = current_step
        job.updated_at = datetime.utcnow()
        db.commit()
        emit_job_event(job.id, "job_failed", "failed", current_step, error_message, db=db)

    @staticmethod
    def _mark(
        db: Session,
        job: AnalysisJob,
        status: AnalysisJobStatus,
        progress: int,
        current_step: str,
    ) -> None:
        job.status = status
        job.progress = progress
        job.current_step = current_step
        job.updated_at = datetime.utcnow()
        db.commit()

    @staticmethod
    def _record_evidence(db: Session, job: AnalysisJob, evidence_items: list[EvidenceItem]) -> None:
        existing = {
            (item.evidence_type, item.label, item.value_json, item.source_path, item.source_node)
            for item in db.scalars(select(AnalysisEvidence).where(AnalysisEvidence.job_id == job.id)).all()
        }
        for item in evidence_items:
            key = (item.evidence_type, item.label, item.value_json, str(item.source_path), item.source_node)
            if key in existing:
                continue
            db.add(
                AnalysisEvidence(
                    job_id=job.id,
                    category=item.category,
                    evidence_type=item.evidence_type,
                    label=item.label,
                    value_json=item.value_json,
                    source_path=str(item.source_path),
                    source_node=item.source_node,
                )
            )
            existing.add(key)
        db.commit()
        db.refresh(job)

    @staticmethod
    def _record_findings(db: Session, job: AnalysisJob, findings: list[FindingCandidate]) -> None:
        existing = {
            (item.rule_id, item.title, item.severity, item.category, item.description, item.remediation, item.evidence_ids_json)
            for item in db.scalars(select(AnalysisFinding).where(AnalysisFinding.job_id == job.id)).all()
        }
        for finding in findings:
            key = (finding.rule_id, finding.title, finding.severity, finding.category, finding.description, finding.remediation, finding.evidence_ids_json)
            if key in existing:
                continue
            db.add(
                AnalysisFinding(
                    job_id=job.id,
                    rule_id=finding.rule_id,
                    title=finding.title,
                    severity=finding.severity,
                    category=finding.category,
                    description=finding.description,
                    remediation=finding.remediation,
                    evidence_ids_json=finding.evidence_ids_json,
                )
            )
            existing.add(key)
        db.commit()

    @staticmethod
    def _record_reasoning(db: Session, job: AnalysisJob, reasoning: ReasoningResult) -> None:
        duplicate = db.scalars(
            select(AnalysisReasoning).where(
                AnalysisReasoning.job_id == job.id,
                AnalysisReasoning.provider == reasoning.provider,
                AnalysisReasoning.summary == reasoning.summary,
                AnalysisReasoning.attack_paths_json == reasoning.attack_paths_json,
                AnalysisReasoning.limitations == reasoning.limitations,
            )
        ).first()
        if duplicate is not None:
            return
        db.add(
            AnalysisReasoning(
                job_id=job.id,
                provider=reasoning.provider,
                summary=reasoning.summary,
                attack_paths_json=reasoning.attack_paths_json,
                limitations=reasoning.limitations,
            )
        )
        db.commit()

    @staticmethod
    def _raise_if_cancelled(job_id: str) -> None:
        if job_cancellation_registry.is_cancelled(job_id):
            raise JobCancelled("Analysis cancelled by user.")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _record_decompilation_artifacts(
        db: Session,
        job: AnalysisJob,
        result: DecompilationResult,
        output_artifact_type: ArtifactType,
    ) -> None:
        existing = {
            (item.artifact_type, item.tool_name, item.path, item.exit_code)
            for item in db.scalars(select(AnalysisArtifact).where(AnalysisArtifact.job_id == job.id)).all()
        }
        records = [
            (output_artifact_type, result.tool_name, str(result.output_path), result.exit_code),
            (ArtifactType.tool_log, result.tool_name, str(result.log_path), result.exit_code),
        ]
        for artifact_type, tool_name, path, exit_code in records:
            if (artifact_type, tool_name, path, exit_code) in existing:
                continue
            db.add(AnalysisArtifact(job_id=job.id, artifact_type=artifact_type, tool_name=tool_name, path=path, exit_code=exit_code))
            existing.add((artifact_type, tool_name, path, exit_code))
        db.commit()

    @staticmethod
    def _record_analysis_artifacts(
        db: Session,
        job: AnalysisJob,
        result: NativeAnalysisResult,
        summary_path: Path,
    ) -> None:
        existing = {
            (item.artifact_type, item.tool_name, item.path, item.exit_code)
            for item in db.scalars(select(AnalysisArtifact).where(AnalysisArtifact.job_id == job.id)).all()
        }
        for path in (result.log_path, summary_path):
            key = (ArtifactType.tool_log, result.tool_name, str(path), result.exit_code)
            if key in existing:
                continue
            db.add(
                AnalysisArtifact(
                    job_id=job.id,
                    artifact_type=ArtifactType.tool_log,
                    tool_name=result.tool_name,
                    path=str(path),
                    exit_code=result.exit_code,
                )
            )
            existing.add(key)
        db.commit()


def cleanup_interrupted_jobs(settings: Settings) -> int:
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        jobs = list(
            db.scalars(
                select(AnalysisJob).where(
                    AnalysisJob.status == AnalysisJobStatus.running
                )
            ).all()
        )
        dynamic_stages = list(
            db.scalars(
                select(AnalysisJobStage).where(
                    AnalysisJobStage.stage == "dynamic_run",
                    AnalysisJobStage.status == "running",
                )
            ).all()
        )
        for job in jobs:
            job.status = AnalysisJobStatus.queued
            job.error_message = "Interrupted by backend restart; queued for resumption"
            job.current_step = "Queued after backend restart"
            job.progress = 0
            job.completed_at = None
            job.updated_at = datetime.utcnow()
        for stage in dynamic_stages:
            stage.status = "failed"
            stage.message = "DY-MASA analysis interrupted by backend restart"
            stage.detail = "The previous runtime worker stopped before completion; a new DY-MASA run may be started."
        db.commit()
        for job in jobs:
            emit_job_event(job.id, "job_requeued", "queued", job.current_step, job.error_message, db=db)
        for stage in dynamic_stages:
            emit_job_event(
                stage.job_id,
                "dynamic_run_recovered",
                "failed",
                stage.message,
                stage.detail,
                db=db,
            )
        return len(jobs) + len(dynamic_stages)


def dispatch_queued_jobs(settings: Settings) -> int:
    """Resume only available durable queued work; remaining jobs stay in the DB."""
    return _dispatch_available(settings)
