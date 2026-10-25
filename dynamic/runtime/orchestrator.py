from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
import hashlib
import json
import re
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.base import AnalysisArtifact, AnalysisEvidence, AnalysisFinding, AnalysisJob, AnalysisJobStage, ArtifactType, EvidenceCategory
from app.services.job_events import emit_job_event
from dynamic.adb.client import AdbClient, AdbResult
from dynamic.emulator.manager import EmulatorManager
from dynamic.logcat.classify import classify, code_risk_matches, discover_target_pids, merge_tiers_in_order
from dynamic.logcat.crashes import detect_crashes


@dataclass(frozen=True)
class DynamicRunSummary:
    job_id: str
    package_name: str | None
    device: str | None
    installed: bool
    launched: bool
    logcat_path: str | None
    screenshot_path: str | None


class DynamicAnalysisError(RuntimeError):
    pass


class DynamicRuntimeOrchestrator:
    def __init__(self, settings: Settings, adb: AdbClient | None = None, manager: EmulatorManager | None = None) -> None:
        self.settings = settings
        self.command_log: list[dict[str, object]] = []
        self.manager = manager or EmulatorManager(
            sdk_path=settings.android_sdk_path,
            adb_path=settings.adb_path,
            emulator_path=settings.emulator_path,
            avd_name=settings.avd_name,
            boot_timeout_seconds=settings.emulator_boot_timeout_seconds,
            avd_home=settings.android_avd_home,
            device_serial=settings.dynamic_device_serial,
            allow_physical_device=settings.dynamic_allow_physical_device,
        )
        self.adb = adb or AdbClient(settings.adb_path, settings.dynamic_timeout_seconds, self.command_log)

    def run(self, db: Session, job: AnalysisJob) -> DynamicRunSummary:
        package_name = self._package_name(db, job.id)
        if not package_name:
            raise DynamicAnalysisError("Package name was not found in static manifest evidence. Run static analysis first.")

        workspace = self._dynamic_workspace(db, job)
        dynamic_dir = workspace / "dynamic"
        dynamic_dir.mkdir(parents=True, exist_ok=True)

        self._stage(db, job, "dynamic_environment", "running", "Preparing DY-MASA runtime", "Checking ADB/emulator state")
        device = self.manager.ensure_ready_device()
        if device is None:
            raise DynamicAnalysisError("No ready Android emulator/device found. Start the Dy-MASA AVD and confirm adb devices shows state=device.")
        self._stage(db, job, "dynamic_environment", "completed", "Runtime device ready", device.serial)

        self._record_evidence(db, job, "dynamic_device", "Android runtime device", {
            "device": device.serial,
            "device_type": "emulator" if device.serial.startswith("emulator-") else "physical",
            "android_version": self.adb.getprop("ro.build.version.release", device.serial),
            "sdk": self.adb.getprop("ro.build.version.sdk", device.serial),
            "model": self.adb.getprop("ro.product.model", device.serial),
            "manufacturer": self.adb.getprop("ro.product.manufacturer", device.serial),
            "result": "informational",
            "source": "adb",
        })

        self._stage(db, job, "dynamic_baseline", "running", "Capturing baseline logcat", package_name)
        self.adb.clear_logcat(device.serial)
        time.sleep(self.settings.dynamic_baseline_seconds)
        baseline = self.adb.dump_logcat(device.serial, timeout=45)
        baseline_path = dynamic_dir / "baseline-logcat.txt"
        self._write_preserving_bytes(baseline_path, baseline.stdout)
        self._record_artifact(db, job, baseline_path, "adb-baseline-logcat", baseline.exit_code)
        baseline_seed_pids = self._package_pids(device.serial, package_name)
        baseline_capture = self._save_logcat_capture(db, job, dynamic_dir, baseline, package_name, baseline_seed_pids, "baseline")
        self._record_evidence(db, job, "dynamic_baseline", "Baseline logcat captured", {
            "path": str(baseline_path),
            "tier_a_line_count": len(baseline_capture["tier_a"]),
            "tier_b_line_count": len(baseline_capture["tier_b"]),
            "tier_c_line_count": len(baseline_capture["tier_c"]),
            "logcat_format": baseline.logcat_format,
            "result": "confirmed" if baseline.ok else "not_reproducible",
            "source": "adb logcat baseline",
        })
        self._stage(db, job, "dynamic_baseline", "completed", "Baseline logcat captured", str(baseline_path))
        self.adb.clear_logcat(device.serial)

        self._stage(db, job, "dynamic_install", "running", "Installing APK into Android device", package_name)
        install = self.adb.install(self._apk_path(db, job), device.serial, timeout=self.settings.dynamic_timeout_seconds)
        storage = self.adb.storage_summary(device.serial)
        self._record_command_artifact(db, job, dynamic_dir / "install.json", "adb-install", install)
        self._record_evidence(db, job, "dynamic_install", "APK installation result", {
            "package": package_name,
            "exit_code": install.exit_code,
            "stdout": install.stdout[-2000:],
            "stderr": install.stderr[-2000:],
            "storage": storage[-2000:],
            "installed": install.ok and "Success" in install.stdout,
            "result": "confirmed" if install.ok and "Success" in install.stdout else "not_reproducible",
            "source": "adb install",
        })
        if not install.ok or "Success" not in install.stdout:
            detail = install.stderr or install.stdout or "ADB returned no error text."
            lowered = detail.lower()
            if "not enough space" in lowered or "insufficient storage" in lowered:
                detail = (
                    "Android has insufficient internal storage for this APK. "
                    "Free space on the selected phone/emulator, then retry. "
                    f"Storage report: {storage or 'unavailable'}."
                )
            elif "unauthorized" in lowered:
                detail = "The Android device is unauthorized. Unlock it and accept the USB debugging prompt, then retry."
            elif "offline" in lowered:
                detail = "The Android device is offline. Reconnect it or restart ADB, then retry."
            raise DynamicAnalysisError(f"ADB install failed: {detail}")
        self._stage(db, job, "dynamic_install", "completed", "APK installed", package_name)

        self.adb.clear_logcat(device.serial)
        self._stage(db, job, "dynamic_launch", "running", "Launching APK", package_name)
        launch = self.adb.launch_package(package_name, device.serial)
        self._record_command_artifact(db, job, dynamic_dir / "launch.json", "adb-launch", launch)
        self._record_evidence(db, job, "dynamic_launch", "Application launch result", {
            "package": package_name,
            "exit_code": launch.exit_code,
            "stdout": launch.stdout[-2000:],
            "stderr": launch.stderr[-2000:],
            "launched": launch.ok,
            "result": "confirmed" if launch.ok else "not_reproducible",
            "source": "adb monkey",
        })
        if not launch.ok:
            raise DynamicAnalysisError(f"Application launch failed: {launch.stderr or launch.stdout}")
        self._stage(db, job, "dynamic_launch", "completed", "APK launch command completed", package_name)

        self._stage(db, job, "dynamic_render", "running", "Waiting for application UI", "Waiting for package process and rendered surface")
        screenshot_path = dynamic_dir / "launch-screenshot.png"
        screenshot = self.adb.capture_ready_screenshot(package_name, device.serial, screenshot_path)
        screenshot_result = "observed" if screenshot.ok else "not_reproducible"
        self._record_evidence(db, job, "dynamic_screenshot", "Launch screenshot capture", {
            "path": str(screenshot_path),
            "source": "adb exec-out screencap",
            "result": screenshot_result,
            "detail": screenshot.stderr or screenshot.stdout,
            "render_validated": screenshot.ok,
        })
        if screenshot.ok:
            self._record_artifact(db, job, screenshot_path, "adb-screenshot")
            self._stage(db, job, "dynamic_render", "completed", "Application UI rendered", screenshot.stdout)
        else:
            self._stage(db, job, "dynamic_render", "failed", "Application UI was not rendered", screenshot.stderr or screenshot.stdout)

        self._stage(db, job, "dynamic_logcat", "running", "Collecting runtime logcat", package_name)
        launch_logcat = self.adb.dump_logcat(device.serial, timeout=45)
        launch_seed_pids = self._package_pids(device.serial, package_name)
        launch_capture = self._save_logcat_capture(
            db, job, dynamic_dir, launch_logcat, package_name, launch_seed_pids, "launch"
        )
        self._record_evidence(db, job, "dynamic_logcat", "Runtime logcat collected", {
            "package": package_name,
            "line_count": len(launch_logcat.stdout.splitlines()),
            "tier_a_line_count": len(launch_capture["tier_a"]),
            "tier_b_line_count": len(launch_capture["tier_b"]),
            "tier_c_line_count": len(launch_capture["tier_c"]),
            "package_related_line_count": len(launch_capture["tier_a"]) + len(launch_capture["tier_b"]),
            "target_pids": launch_capture["pids"],
            "target_uids": launch_capture["uids"],
            "crash_events": launch_capture["crashes"],
            "baseline_noise_count": {
                "tier_a": len(baseline_capture["tier_a"]),
                "tier_b": len(baseline_capture["tier_b"]),
                "tier_c": len(baseline_capture["tier_c"]),
            },
            "logcat_format": launch_logcat.logcat_format,
            "logcat_path": str(dynamic_dir / "logcat.txt"),
            "filtered_logcat_path": str(dynamic_dir / "logcat-filtered.txt"),
            "result": "confirmed" if launch_logcat.ok else "not_reproducible",
            "source": "adb logcat capture",
        })
        self._stage(db, job, "dynamic_logcat", "completed", "Runtime logcat collected", f"{len(launch_capture['tier_a']) + len(launch_capture['tier_b'])} target lines")

        self._validate_static_attack_surface(db, job, device.serial, package_name, dynamic_dir)
        self._write_capture_metadata(db, job, dynamic_dir, device.serial, package_name, launch_capture, launch_logcat, baseline_capture)
        self._write_adb_audit(db, job, dynamic_dir)

        return DynamicRunSummary(
            job_id=job.id,
            package_name=package_name,
            device=device.serial,
            installed=True,
            launched=True,
            logcat_path=str(dynamic_dir / "logcat.txt"),
            screenshot_path=str(screenshot_path) if screenshot.ok else None,
        )

    def _package_name(self, db: Session, job_id: str) -> str | None:
        evidence = db.scalars(select(AnalysisEvidence).where(AnalysisEvidence.job_id == job_id, AnalysisEvidence.evidence_type == "manifest_metadata")).first()
        if not evidence:
            return None
        try:
            payload = json.loads(evidence.value_json)
        except json.JSONDecodeError:
            return None
        package = payload.get("package")
        return str(package) if package else None

    def _dynamic_workspace(self, db: Session, job: AnalysisJob) -> Path:
        current_workspace = self.settings.workspace_dir / job.id
        stored_workspace = Path(job.workspace_path) if job.workspace_path else None
        storage_root = self.settings.storage_root.resolve()

        if stored_workspace is not None:
            try:
                resolved = stored_workspace.resolve()
                if resolved.exists() and (resolved == storage_root or storage_root in resolved.parents):
                    return stored_workspace
            except OSError:
                pass

        current_workspace.mkdir(parents=True, exist_ok=True)
        job.workspace_path = str(current_workspace)
        db.commit()
        return current_workspace

    def _apk_path(self, db: Session, job: AnalysisJob) -> Path:
        stored_path = Path(job.apk_path)
        if stored_path.exists():
            return stored_path

        current_path = self.settings.upload_dir / job.stored_filename
        if current_path.exists():
            job.apk_path = str(current_path)
            db.commit()
            return current_path

        recovered_path = self._recover_apk_by_sha256(job.sha256)
        if recovered_path is not None:
            job.apk_path = str(recovered_path)
            job.stored_filename = recovered_path.name
            db.commit()
            return recovered_path

        raise DynamicAnalysisError(f"Uploaded APK file is missing: {stored_path}")

    def _recover_apk_by_sha256(self, expected_sha256: str | None) -> Path | None:
        if not expected_sha256 or not self.settings.upload_dir.exists():
            return None
        for candidate in self.settings.upload_dir.glob("*.apk"):
            if self._sha256(candidate) == expected_sha256:
                return candidate
        return None

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _stage(self, db: Session, job: AnalysisJob, stage: str, status: str, message: str, detail: str | None = None) -> None:
        db.add(AnalysisJobStage(job_id=job.id, stage=stage, status=status, message=message, detail=detail))
        job.current_step = message
        job.updated_at = datetime.utcnow()
        db.commit()
        emit_job_event(job.id, stage, status, message, detail, db=db)

    def _record_evidence(self, db: Session, job: AnalysisJob, evidence_type: str, label: str, value: dict[str, object]) -> None:
        value_json = json.dumps(value, sort_keys=True)
        source_path = str(value.get("path") or value.get("logcat_path") or "adb")
        identity = (evidence_type, label, value_json, source_path, "dynamic-runtime")
        existing = {
            (item.evidence_type, item.label, item.value_json, item.source_path, item.source_node)
            for item in db.scalars(
                select(AnalysisEvidence).where(
                    AnalysisEvidence.job_id == job.id,
                    AnalysisEvidence.category == EvidenceCategory.runtime,
                )
            ).all()
        }
        if identity not in existing:
            db.add(AnalysisEvidence(
                job_id=job.id,
                category=EvidenceCategory.runtime,
                evidence_type=evidence_type,
                label=label,
                value_json=value_json,
                source_path=source_path,
                source_node="dynamic-runtime",
            ))
        db.commit()

    def _record_command_artifact(self, db: Session, job: AnalysisJob, path: Path, tool_name: str, result: AdbResult) -> None:
        path.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
        self._record_artifact(db, job, path, tool_name, result.exit_code)

    def _record_artifact(self, db: Session, job: AnalysisJob, path: Path, tool_name: str, exit_code: int | None = 0) -> None:
        identity = (ArtifactType.dynamic_artifact, tool_name, str(path), exit_code)
        duplicate = db.scalars(
            select(AnalysisArtifact).where(
                AnalysisArtifact.job_id == job.id,
                AnalysisArtifact.artifact_type == ArtifactType.dynamic_artifact,
                AnalysisArtifact.tool_name == tool_name,
                AnalysisArtifact.path == str(path),
                AnalysisArtifact.exit_code == exit_code,
            )
        ).first()
        if duplicate is None:
            db.add(AnalysisArtifact(
                job_id=job.id,
                artifact_type=identity[0],
                tool_name=identity[1],
                path=identity[2],
                exit_code=identity[3],
            ))
        db.commit()

    @staticmethod
    def _write_preserving_bytes(path: Path, value: str) -> None:
        path.write_bytes(value.encode("utf-8", errors="surrogateescape"))

    @staticmethod
    def _write_lines(path: Path, lines: list[str]) -> None:
        content = "\n".join(lines) + ("\n" if lines else "")
        DynamicRuntimeOrchestrator._write_preserving_bytes(path, content)

    def _package_pids(self, device: str, package_name: str) -> list[int]:
        result = self.adb.shell(["pidof", package_name], device=device, timeout=10)
        return [int(value) for value in result.stdout.split() if value.isdigit()]

    def _save_logcat_capture(
        self,
        db: Session,
        job: AnalysisJob,
        dynamic_dir: Path,
        capture: AdbResult,
        package_name: str,
        seed_pids: list[int],
        prefix: str,
    ) -> dict[str, object]:
        lines = capture.stdout.splitlines()
        pids, uids = discover_target_pids(lines, package_name, seed_pids)
        tier_a, tier_b, tier_c = classify(lines, package_name, pids, uids)
        crashes = detect_crashes(lines, package_name, pids)
        if prefix == "launch":
            paths = {
                "raw": dynamic_dir / "logcat.txt",
                "stderr": dynamic_dir / "logcat-stderr.txt",
                "filtered": dynamic_dir / "logcat-filtered.txt",
                "tier_a": dynamic_dir / "logcat-tier-a.txt",
                "tier_b": dynamic_dir / "logcat-tier-b.txt",
                "tier_c": dynamic_dir / "logcat-tier-c.txt",
            }
            self._write_preserving_bytes(paths["raw"], capture.stdout)
            self._write_preserving_bytes(paths["stderr"], capture.stderr)
            self._write_lines(paths["filtered"], merge_tiers_in_order(lines, tier_a, tier_b))
            self._write_lines(paths["tier_a"], tier_a)
            self._write_lines(paths["tier_b"], tier_b)
            self._write_lines(paths["tier_c"], tier_c)
            for tool_name, path in (
                ("adb-logcat", paths["raw"]),
                ("adb-logcat-stderr", paths["stderr"]),
                ("adb-logcat-filtered", paths["filtered"]),
                ("adb-logcat-tier-a", paths["tier_a"]),
                ("adb-logcat-tier-b", paths["tier_b"]),
                ("adb-logcat-tier-c", paths["tier_c"]),
            ):
                self._record_artifact(db, job, path, tool_name, capture.exit_code)
        return {
            "tier_a": tier_a,
            "tier_b": tier_b,
            "tier_c": tier_c,
            "pids": pids,
            "uids": uids,
            "crashes": crashes,
            "lines": lines,
        }

    def _write_capture_metadata(
        self,
        db: Session,
        job: AnalysisJob,
        dynamic_dir: Path,
        device: str,
        package_name: str,
        launch_capture: dict[str, object],
        launch_logcat: AdbResult,
        baseline_capture: dict[str, object],
    ) -> None:
        manifest = db.scalars(
            select(AnalysisEvidence).where(
                AnalysisEvidence.job_id == job.id,
                AnalysisEvidence.evidence_type == "manifest_metadata",
            )
        ).first()
        manifest_value: dict[str, object] = {}
        if manifest:
            try:
                manifest_value = json.loads(manifest.value_json)
            except json.JSONDecodeError:
                pass
        adb_version = self.adb.run(["version"], timeout=10)
        sample_formats: list[str] = []
        sample_dir = dynamic_dir / "logcat-samples"
        sample_dir.mkdir(parents=True, exist_ok=True)
        dump_format = getattr(self.adb, "dump_logcat_format", None)
        if dump_format is not None:
            for logcat_format in ("threadtime,uid,year", "threadtime", "time"):
                sample = dump_format(device, logcat_format, timeout=20)
                sample_path = sample_dir / f"{logcat_format.replace(',', '-')}.txt"
                self._write_lines(sample_path, sample.stdout.splitlines()[:20])
                self._record_artifact(db, job, sample_path, "adb-logcat-sample", sample.exit_code)
                sample_formats.append(logcat_format if sample.ok else f"{logcat_format}:unverified")
        metadata = {
            "device_serial": device,
            "device_type": "emulator" if device.startswith("emulator-") else "physical",
            "model": self.adb.getprop("ro.product.model", device),
            "manufacturer": self.adb.getprop("ro.product.manufacturer", device),
            "android_version": self.adb.getprop("ro.build.version.release", device),
            "sdk": self.adb.getprop("ro.build.version.sdk", device),
            "adb_version": adb_version.stdout or adb_version.stderr,
            "logcat_format": launch_logcat.logcat_format,
            "logcat_buffers": ["all"],
            "parser_sample_formats": sample_formats or ["unverified: no sample client"],
            "target_pids": launch_capture["pids"],
            "target_uids": launch_capture["uids"],
            "apk_sha256": job.sha256,
            "package": package_name,
            "version_name": manifest_value.get("version_name"),
            "version_code": manifest_value.get("version_code"),
            "target_sdk": manifest_value.get("target_sdk"),
            "line_counts": {
                "launch": {
                    "tier_a": len(launch_capture["tier_a"]),
                    "tier_b": len(launch_capture["tier_b"]),
                    "tier_c": len(launch_capture["tier_c"]),
                },
                "baseline": {
                    "tier_a": len(baseline_capture["tier_a"]),
                    "tier_b": len(baseline_capture["tier_b"]),
                    "tier_c": len(baseline_capture["tier_c"]),
                },
            },
        }
        metadata_path = dynamic_dir / "capture-metadata.json"
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
        self._record_artifact(db, job, metadata_path, "masa-capture-metadata")

    def _write_adb_audit(self, db: Session, job: AnalysisJob, dynamic_dir: Path) -> None:
        audit_path = dynamic_dir / "adb-audit.json"
        audit_path.write_text(json.dumps(getattr(self.adb, "command_log", []), indent=2), encoding="utf-8")
        self._record_artifact(db, job, audit_path, "adb-audit")

    def _validate_static_attack_surface(
        self,
        db: Session,
        job: AnalysisJob,
        device: str,
        package_name: str,
        dynamic_dir: Path,
    ) -> None:
        static_evidence = list(
            db.scalars(
                select(AnalysisEvidence).where(
                    AnalysisEvidence.job_id == job.id,
                    AnalysisEvidence.category != EvidenceCategory.runtime,
                )
            ).all()
        )
        findings = list(db.scalars(select(AnalysisFinding).where(AnalysisFinding.job_id == job.id)).all())
        finding_links: dict[str, list[str]] = {}
        for finding in findings:
            try:
                evidence_ids = json.loads(finding.evidence_ids_json)
            except json.JSONDecodeError:
                evidence_ids = []
            for evidence_id in evidence_ids:
                finding_links.setdefault(str(evidence_id), []).append(finding.id)

        validations: list[dict[str, object]] = []
        runtime_step_count = 0
        steps_dir = dynamic_dir / "steps"
        steps_dir.mkdir(parents=True, exist_ok=True)
        static_evidence.sort(
            key=lambda item: (
                0 if item.category == EvidenceCategory.component or item.evidence_type == "deep_link" else
                1 if item.evidence_type == "application_flags" else
                2 if item.category == EvidenceCategory.code_risk else 3
            )
        )
        for item in static_evidence:
            if runtime_step_count >= 40:
                break
            try:
                value = json.loads(item.value_json)
            except json.JSONDecodeError:
                value = {}
            result: AdbResult | None = None
            action = ""
            action_kind = ""
            component_name = ""
            status = "potential"
            detail = "Static evidence was not safely exercised during this runtime pass."

            if item.category == EvidenceCategory.component and (value.get("exported_effective") is True or value.get("exported") == "true"):
                component_type = str(value.get("component_type") or "component")
                component_name = self._qualified_component(package_name, str(value.get("name") or ""))
                action = f"Validate exported {component_type}: {component_name}"
                if component_type in {"activity", "activity_alias"} and component_name:
                    action_kind = "activity"
                elif component_type == "service" and component_name:
                    action_kind = "service"
                elif component_type == "content_provider" and value.get("authorities"):
                    action_kind = "provider"
                else:
                    detail = "Receiver/provider invocation was intentionally skipped; static exposure remains a potential risk."
            elif item.evidence_type == "deep_link":
                uri = self._runtime_uri(value)
                action = f"Validate deep link: {uri}" if uri else "Validate deep link"
                if uri:
                    action_kind = "deep_link"
            elif item.category == EvidenceCategory.code_risk:
                action = f"Observe runtime signal for {item.evidence_type}"
                action_kind = "code_risk"
            elif item.evidence_type == "application_flags":
                action = "Compare installed package metadata with manifest flags"
                action_kind = "application_flags"
            else:
                continue

            if item.evidence_type == "deep_link" and not action_kind:
                record = {
                    "static_evidence_id": item.id,
                    "related_finding_ids": finding_links.get(item.id, []),
                    "action": action,
                    "result": "inconclusive",
                    "detail": "No valid scheme/host combination could be generated from this intent filter; reachability was not inferred.",
                    "command": [],
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "exploitability_claim": "none",
                    "source": "DY-MASA safe runtime validation",
                    "validation_skipped": True,
                    "skip_reason": "intent-filter constraints were incomplete or unsupported",
                    "step_log_path": None,
                    "tier_a_line_count": 0,
                    "crash_events": [],
                    "permission_denial_or_security_exception_lines": [],
                }
                validations.append(record)
                self._record_evidence(db, job, "dynamic_validation", f"Runtime validation: {action}", record)
                continue
            if not action_kind:
                continue
            if action_kind == "code_risk":
                record = {
                    "static_evidence_id": item.id,
                    "related_finding_ids": finding_links.get(item.id, []),
                    "action": action,
                    "result": "potential",
                    "detail": "not exercised at runtime; code-risk evidence is preserved without spending a device step on a no-op command.",
                    "command": [],
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "",
                    "exploitability_claim": "none",
                    "source": "DY-MASA safe runtime validation",
                    "validation_skipped": True,
                    "skip_reason": "code-risk runtime execution is not a meaningful validation action",
                    "step_log_path": None,
                    "tier_a_line_count": 0,
                    "crash_events": [],
                    "permission_denial_or_security_exception_lines": [],
                }
                validations.append(record)
                self._record_evidence(db, job, "dynamic_validation", f"Runtime validation: {action}", record)
                continue
            step_number = runtime_step_count + 1
            slug = re.sub(r"[^a-z0-9]+", "-", action.lower()).strip("-")[:70] or "validation"
            marker = f"DYMASA_STEP {step_number} {slug}"
            self.adb.clear_logcat(device)
            self.adb.log_marker(device, marker)
            if action_kind == "activity":
                explicit_component = self._explicit_activity_component(package_name, component_name)
                if explicit_component is None:
                    result = AdbResult([], 2, "", "Invalid Android activity component name; validation was not attempted.")
                    status = "not_attempted"
                else:
                    result = self.adb.start_activity(explicit_component, device)
            elif action_kind == "service":
                result = self.adb.resolve_service(component_name, device)
            elif action_kind == "provider":
                result = self.adb.resolve_provider(str(value.get("authorities")), device)
            elif action_kind == "deep_link":
                result = self.adb.open_deep_link(self._runtime_uri(value) or "", package_name, device)
            elif action_kind == "application_flags":
                result = self.adb.shell(["dumpsys", "package", package_name], device=device, timeout=20)
            else:
                result = self.adb.shell(["true"], device=device, timeout=10)
            time.sleep(1.5)
            step_capture = self.adb.dump_logcat(device, timeout=45)
            seed_pids = self._package_pids(device, package_name)
            capture = self._save_logcat_capture(db, job, dynamic_dir, step_capture, package_name, seed_pids, f"step-{step_number}")
            step_lines = merge_tiers_in_order(step_capture.stdout.splitlines(), capture["tier_a"], capture["tier_b"])
            step_path = steps_dir / f"{step_number:02d}-{slug}.txt"
            self._write_lines(step_path, step_lines)
            self._record_artifact(db, job, step_path, "adb-logcat-step", step_capture.exit_code)

            if action_kind in {"activity", "deep_link"}:
                if status != "not_attempted":
                    if result.exit_code == -1:
                        status = "timed_out"
                    elif self.adb.am_start_succeeded(result):
                        status = "launch_succeeded"
                    else:
                        status = "launch_failed"
                detail = "The Android start command completed successfully; this confirms reachability only." if status == "launch_succeeded" else result.stderr or result.stdout or "The Android start command did not establish reachability."
            elif action_kind == "service":
                status = "observed" if result.ok and component_name in result.stdout else "not_reproducible"
                detail = "The exported service resolved through the package manager; invocation was intentionally skipped for safety." if status == "observed" else result.stderr or result.stdout
            elif action_kind == "provider":
                status = "observed" if result.ok and package_name in result.stdout else "not_reproducible"
                detail = "The content provider authority resolved through the package manager; data access was intentionally skipped for safety." if status == "observed" else result.stderr or result.stdout
            elif action_kind == "application_flags":
                status = "observed" if result.ok and package_name in result.stdout else "not_reproducible"
                detail = "Installed package metadata was readable; runtime metadata does not prove exploitability." if status == "observed" else result.stderr or result.stdout
            else:
                matches = code_risk_matches(step_lines)
                status = "observed" if matches else "potential"
                detail = "A specific related runtime signal was present in this validation step." if matches else "not exercised at runtime"

            permission_lines = [line for line in step_capture.stdout.splitlines() if package_name in line and re.search(r"Permission Denial|SecurityException", line)]

            record = {
                "static_evidence_id": item.id,
                "related_finding_ids": finding_links.get(item.id, []),
                "action": action,
                "result": status,
                "detail": detail,
                "command": result.command if result else [],
                "exit_code": result.exit_code if result else None,
                "stdout": (result.stdout[-2000:] if result else ""),
                "stderr": (result.stderr[-2000:] if result else ""),
                "exploitability_claim": "none",
                "source": "DY-MASA safe runtime validation",
                "step_log_path": str(step_path),
                "tier_a_line_count": len(capture["tier_a"]),
                "crash_events": capture["crashes"],
                "permission_denial_or_security_exception_lines": permission_lines,
            }
            validations.append(record)
            runtime_step_count += 1
            self._record_evidence(db, job, "dynamic_validation", f"Runtime validation: {action}", record)

        validation_path = dynamic_dir / "runtime-validations.json"
        validation_path.write_text(json.dumps(validations, indent=2, sort_keys=True), encoding="utf-8")
        self._record_artifact(db, job, validation_path, "masa-runtime-validation")

    @staticmethod
    def _qualified_component(package_name: str, component_name: str) -> str:
        if not component_name:
            return ""
        if component_name.startswith("."):
            return package_name + component_name
        if "." not in component_name:
            return package_name + "." + component_name
        return component_name

    @staticmethod
    def _explicit_activity_component(package_name: str, component_name: str) -> str | None:
        """Build the package/class form required by `am start -n`."""
        if not package_name or not component_name or any(char.isspace() for char in component_name):
            return None
        if "/" in package_name or "/" in component_name:
            return None
        if not component_name.startswith(package_name + "."):
            return None
        return f"{package_name}/{component_name}"

    @staticmethod
    def _runtime_uri(value: dict[str, object]) -> str | None:
        routes = value.get("routes")
        candidates = routes if isinstance(routes, list) else [value]
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            scheme = str(candidate.get("scheme") or "")
            host = str(candidate.get("host") or "")
            if not scheme or not host or scheme == "*" or host == "*":
                continue
            if host.startswith("*."):
                host = "runtime." + host[2:]
            if "*" in host or "*" in scheme:
                continue
            path = str(candidate.get("path") or "/runtime-check")
            path = path.replace(".*", "/runtime-check").replace("*", "runtime-check")
            if not path.startswith("/"):
                path = "/" + path
            return f"{scheme}://{host}{path}"
        return None

    @staticmethod
    def _filter_logcat(logcat: str, package_name: str) -> list[str]:
        lines = logcat.splitlines()
        pids, uids = discover_target_pids(lines, package_name)
        tier_a, tier_b, _ = classify(lines, package_name, pids, uids)
        return merge_tiers_in_order(lines, tier_a, tier_b)
