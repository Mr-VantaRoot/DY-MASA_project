from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
import hashlib
import json
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.base import AnalysisArtifact, AnalysisEvidence, AnalysisFinding, AnalysisJob, AnalysisJobStage, ArtifactType, EvidenceCategory
from app.services.job_events import emit_job_event
from dynamic.adb.client import AdbClient, AdbResult
from dynamic.emulator.manager import EmulatorManager


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
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.manager = EmulatorManager(
            sdk_path=settings.android_sdk_path,
            adb_path=settings.adb_path,
            emulator_path=settings.emulator_path,
            avd_name=settings.avd_name,
            boot_timeout_seconds=settings.emulator_boot_timeout_seconds,
            avd_home=settings.android_avd_home,
        )
        self.adb = AdbClient(settings.adb_path, settings.dynamic_timeout_seconds)

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
            "android_version": self.adb.getprop("ro.build.version.release", device.serial),
            "sdk": self.adb.getprop("ro.build.version.sdk", device.serial),
            "model": self.adb.getprop("ro.product.model", device.serial),
            "manufacturer": self.adb.getprop("ro.product.manufacturer", device.serial),
            "result": "informational",
            "source": "adb",
        })

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
        logcat = self.adb.dump_logcat(device.serial, timeout=45)
        logcat_path = dynamic_dir / "logcat.txt"
        logcat_path.write_text(logcat.stdout + ("\n[stderr]\n" + logcat.stderr if logcat.stderr else ""), encoding="utf-8", errors="ignore")
        self._record_artifact(db, job, logcat_path, "adb-logcat")
        filtered_lines = self._filter_logcat(logcat.stdout, package_name)
        filtered_path = dynamic_dir / "logcat-filtered.txt"
        filtered_path.write_text("\n".join(filtered_lines), encoding="utf-8", errors="ignore")
        self._record_artifact(db, job, filtered_path, "adb-logcat-filtered")
        self._record_evidence(db, job, "dynamic_logcat", "Runtime logcat collected", {
            "package": package_name,
            "line_count": len(logcat.stdout.splitlines()),
            "package_related_line_count": len(filtered_lines),
            "logcat_path": str(logcat_path),
            "filtered_logcat_path": str(filtered_path),
            "result": "confirmed" if logcat.ok else "not_reproducible",
            "source": "adb logcat -d -v time",
        })
        self._stage(db, job, "dynamic_logcat", "completed", "Runtime logcat collected", f"{len(filtered_lines)} package-related lines")

        self._validate_static_attack_surface(db, job, device.serial, package_name, logcat.stdout, dynamic_dir)

        return DynamicRunSummary(
            job_id=job.id,
            package_name=package_name,
            device=device.serial,
            installed=True,
            launched=True,
            logcat_path=str(logcat_path),
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
        emit_job_event(job.id, stage, status, message, detail)

    def _record_evidence(self, db: Session, job: AnalysisJob, evidence_type: str, label: str, value: dict[str, object]) -> None:
        db.add(AnalysisEvidence(
            job_id=job.id,
            category=EvidenceCategory.runtime,
            evidence_type=evidence_type,
            label=label,
            value_json=json.dumps(value, sort_keys=True),
            source_path=value.get("path") or value.get("logcat_path") or "adb",
            source_node="dynamic-runtime",
        ))
        db.commit()

    def _record_command_artifact(self, db: Session, job: AnalysisJob, path: Path, tool_name: str, result: AdbResult) -> None:
        path.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
        self._record_artifact(db, job, path, tool_name, result.exit_code)

    def _record_artifact(self, db: Session, job: AnalysisJob, path: Path, tool_name: str, exit_code: int | None = 0) -> None:
        db.add(AnalysisArtifact(
            job_id=job.id,
            artifact_type=ArtifactType.dynamic_artifact,
            tool_name=tool_name,
            path=str(path),
            exit_code=exit_code,
        ))
        db.commit()

    def _validate_static_attack_surface(
        self,
        db: Session,
        job: AnalysisJob,
        device: str,
        package_name: str,
        logcat: str,
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
        for item in static_evidence:
            if len(validations) >= 40:
                break
            try:
                value = json.loads(item.value_json)
            except json.JSONDecodeError:
                value = {}
            result: AdbResult | None = None
            action = ""
            status = "potential"
            detail = "Static evidence was not safely exercised during this runtime pass."

            if item.category == EvidenceCategory.component and value.get("exported") == "true":
                component_type = str(value.get("component_type") or "component")
                component_name = self._qualified_component(package_name, str(value.get("name") or ""))
                action = f"Validate exported {component_type}: {component_name}"
                if component_type == "activity" and component_name:
                    result = self.adb.start_activity(component_name, device)
                    status = "observed" if result.ok and "Error" not in result.stdout else "not_reproducible"
                    detail = "The exported activity accepted an explicit launch command; this confirms reachability only." if status == "observed" else result.stderr or result.stdout
                elif component_type == "service" and component_name:
                    result = self.adb.resolve_service(component_name, device)
                    status = "observed" if result.ok and component_name in result.stdout else "not_reproducible"
                    detail = "The exported service resolved through the package manager; invocation was intentionally skipped for safety."
                elif component_type == "content_provider" and value.get("authorities"):
                    result = self.adb.resolve_provider(str(value.get("authorities")), device)
                    status = "observed" if result.ok and package_name in result.stdout else "not_reproducible"
                    detail = "The content provider authority resolved through the package manager; data access was intentionally skipped for safety."
                else:
                    detail = "Receiver/provider invocation was intentionally skipped; static exposure remains a potential risk."
            elif item.evidence_type == "deep_link":
                uri = self._runtime_uri(value)
                action = f"Validate deep link: {uri}" if uri else "Validate deep link"
                if uri:
                    result = self.adb.open_deep_link(uri, package_name, device)
                    status = "observed" if result.ok and "No Activity" not in result.stdout else "not_reproducible"
                    detail = "The deep-link dispatch command completed; this does not prove authorization or exploitability." if status == "observed" else result.stderr or result.stdout
            elif item.category == EvidenceCategory.code_risk:
                action = f"Observe runtime signal for {item.evidence_type}"
                lowered = logcat.lower()
                signal = any(token in lowered for token in ("cleartext", "webview", "ssl", "http://"))
                status = "observed" if signal else "potential"
                detail = "A related runtime signal was present in logcat." if signal else "No related startup logcat signal was observed; static evidence remains a potential risk."
            elif item.evidence_type == "application_flags":
                action = "Compare installed package metadata with manifest flags"
                package_dump = self.adb.shell(["dumpsys", "package", package_name], device=device, timeout=20)
                result = package_dump
                status = "observed" if package_dump.ok and package_name in package_dump.stdout else "not_reproducible"
                detail = "Installed package metadata was readable; runtime metadata does not prove exploitability." if status == "observed" else package_dump.stderr or package_dump.stdout
            else:
                continue

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
            }
            validations.append(record)
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
    def _runtime_uri(value: dict[str, object]) -> str | None:
        scheme = str(value.get("scheme") or "masa").replace("*", "masa")
        host = str(value.get("host") or "masa.test").replace("*", "masa.test")
        path = str(value.get("path") or "/runtime-check")
        if not path.startswith("/"):
            path = "/" + path
        return f"{scheme}://{host}{path}"

    @staticmethod
    def _filter_logcat(logcat: str, package_name: str) -> list[str]:
        package_hint = package_name.lower()
        filtered = []
        for line in logcat.splitlines():
            lowered = line.lower()
            if package_hint in lowered or "fatal exception" in lowered or " anr " in lowered or "crash" in lowered:
                filtered.append(line)
        return filtered[:500]
