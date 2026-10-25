from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import hashlib
import os
import signal
import subprocess
import time
from threading import Event
from typing import Callable

from app.core.config import Settings
from app.db.base import EvidenceCategory
from analysis.evidence import EvidenceItem


@dataclass(frozen=True)
class NativeAnalysisResult:
    tool_name: str
    status: str
    output_path: Path
    log_path: Path
    exit_code: int | None
    native_libraries: tuple[Path, ...]
    detail: str
    library_results: tuple[dict[str, object], ...] = ()


LibraryEvent = Callable[[dict[str, object]], None]


class GhidraAnalyzer:
    """Optional native-code analysis for ELF libraries embedded in an APK."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def run(
        self,
        apktool_output_path: Path,
        workspace_path: Path,
        cancel_event: Event | None = None,
        progress_callback: LibraryEvent | None = None,
    ) -> NativeAnalysisResult:
        native_libraries = tuple(sorted(apktool_output_path.glob("lib/**/*.so")))
        output_path = workspace_path / "ghidra"
        log_path = workspace_path / "logs" / "ghidra.log"
        output_path.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if not native_libraries:
            detail = "No native .so libraries were found; Ghidra analysis was skipped."
            self._write_log(log_path, detail)
            return NativeAnalysisResult("ghidra", "skipped", output_path, log_path, None, (), detail)

        if not self._settings.ghidra_enabled:
            detail = "Ghidra analysis is disabled by configuration."
            self._write_log(log_path, detail)
            results = tuple(self._library_result(library, "skipped", "Ghidra analysis is disabled by configuration.") for library in native_libraries)
            return NativeAnalysisResult("ghidra", "skipped", output_path, log_path, None, native_libraries, detail, results)

        headless = self._settings.ghidra_headless_path
        if headless is None or not headless.exists():
            detail = "Ghidra headless executable is not configured or was not found. Native libraries were retained for manual analysis."
            self._write_log(log_path, detail)
            results = tuple(self._library_result(library, "skipped", detail) for library in native_libraries)
            return NativeAnalysisResult("ghidra", "skipped", output_path, log_path, None, native_libraries, detail, results)

        project_path = output_path / "project"
        project_path.mkdir(parents=True, exist_ok=True)
        log_parts = [f"headless={headless}", f"libraries={len(native_libraries)}"]
        last_exit_code = 0
        library_results: list[dict[str, object]] = []
        failed = False
        deadline = time.monotonic() + self._settings.ghidra_timeout_seconds

        for index, library in enumerate(native_libraries, start=1):
            size_bytes = library.stat().st_size
            started = time.monotonic()
            event_base = {
                "library": library.name,
                "path": str(library),
                "size_bytes": size_bytes,
                "sha256": self._sha256(library),
                "index": index,
                "total": len(native_libraries),
            }
            if cancel_event and cancel_event.is_set():
                detail = "Ghidra analysis was cancelled."
                self._write_log(log_path, "\n".join(log_parts + [detail]))
                return NativeAnalysisResult("ghidra", "cancelled", output_path, log_path, -2, native_libraries, detail, tuple(library_results))
            self._notify(progress_callback, {**event_base, "status": "running", "elapsed_seconds": 0.0})
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                result = {**event_base, "status": "skipped", "exit_code": None, "elapsed_seconds": 0.0, "detail": "Overall Ghidra timeout was exhausted before this library started."}
                library_results.append(result)
                self._notify(progress_callback, result)
                continue
            per_library_timeout = max(1, int(getattr(self._settings, "ghidra_library_timeout_seconds", remaining)))
            timeout = min(remaining, per_library_timeout)
            launcher = ["cmd.exe", "/c", str(headless)] if headless.suffix.lower() in {".bat", ".cmd"} else [str(headless)]
            command = launcher + [
                str(project_path),
                "masa-native",
                "-analysisTimeoutPerFile",
                str(timeout),
                "-import",
                str(library),
                "-overwrite",
            ]
            status, exit_code, stdout, stderr, reason = self._run_library(command, timeout, cancel_event)
            elapsed = round(time.monotonic() - started, 3)
            last_exit_code = exit_code if exit_code not in (None, 0) else last_exit_code
            if status != "completed":
                failed = True
            result = {**event_base, "status": status, "exit_code": exit_code, "elapsed_seconds": elapsed, "detail": reason}
            library_results.append(result)
            log_parts.extend([f"command={' '.join(command)}", f"library={library}", f"status={status}", f"elapsed_seconds={elapsed}", f"exit_code={exit_code}", stdout[-4000:], stderr[-4000:], reason])
            self._write_log(log_path, "\n".join(log_parts))
            self._write_log(output_path / f"{library.parent.name}-{library.stem}.log", "\n".join([f"command={' '.join(command)}", f"status={status}", f"elapsed_seconds={elapsed}", stdout, stderr, reason]))
            self._notify(progress_callback, result)
            if status == "cancelled":
                detail = "Ghidra analysis was cancelled; active process was terminated safely."
                return NativeAnalysisResult("ghidra", "cancelled", output_path, log_path, -2, native_libraries, detail, tuple(library_results))

        completed_count = sum(item["status"] == "completed" for item in library_results)
        timed_out_count = sum(item["status"] == "timed_out" for item in library_results)
        failed_count = sum(item["status"] == "failed" for item in library_results)
        skipped_count = sum(item["status"] == "skipped" for item in library_results)
        if completed_count == len(native_libraries):
            status = "completed"
        elif completed_count == 0 and skipped_count == len(native_libraries):
            status = "skipped"
        elif completed_count:
            status = "partial"
        else:
            status = "failed"
        detail = (
            f"Ghidra discovered {len(native_libraries)} native library file(s): "
            f"{completed_count} completed, {timed_out_count} timed out, {failed_count} failed, "
            f"{skipped_count} skipped. Results are static analysis evidence, not proof of exploitability."
        )
        log_parts.append(detail)
        self._write_log(log_path, "\n".join(log_parts))
        return NativeAnalysisResult("ghidra", status, output_path, log_path, 0 if not failed else last_exit_code, native_libraries, detail, tuple(library_results))

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _library_result(self, library: Path, status: str, detail: str) -> dict[str, object]:
        return {
            "library": library.name,
            "path": str(library),
            "sha256": self._sha256(library) if library.exists() else None,
            "size_bytes": library.stat().st_size if library.exists() else None,
            "status": status,
            "exit_code": None,
            "elapsed_seconds": 0.0,
            "detail": detail,
        }

    @staticmethod
    def _notify(callback: LibraryEvent | None, event: dict[str, object]) -> None:
        if callback is None:
            return
        try:
            callback(event)
        except Exception:
            # Diagnostics must never make native analysis fail.
            return

    @staticmethod
    def _terminate_process(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, check=False, timeout=5)
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass

    def _run_library(
        self,
        command: list[str],
        timeout: int,
        cancel_event: Event | None,
    ) -> tuple[str, int | None, str, str, str]:
        try:
            kwargs: dict[str, object] = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True}
            if os.name != "nt":
                kwargs["start_new_session"] = True
            else:
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(command, **kwargs)
        except OSError as exc:
            return "failed", 127, "", str(exc), f"Unable to start Ghidra: {exc}"

        started = time.monotonic()
        while process.poll() is None:
            if cancel_event and cancel_event.is_set():
                self._terminate_process(process)
                stdout, stderr = process.communicate()
                return "cancelled", -2, stdout or "", stderr or "", "Ghidra process terminated after cancellation."
            if time.monotonic() - started >= timeout:
                self._terminate_process(process)
                stdout, stderr = process.communicate()
                return "timed_out", -1, stdout or "", stderr or "", f"Per-library timeout of {timeout} seconds exceeded; Ghidra process terminated."
            try:
                stdout, stderr = process.communicate(timeout=0.25)
            except subprocess.TimeoutExpired:
                continue
        stdout, stderr = process.communicate()
        exit_code = process.returncode
        if exit_code == 0:
            return "completed", exit_code, stdout or "", stderr or "", "Ghidra completed successfully."
        return "failed", exit_code, stdout or "", stderr or "", f"Ghidra returned exit code {exit_code}."

    @staticmethod
    def write_summary(result: NativeAnalysisResult) -> Path:
        summary_path = result.output_path / "summary.json"
        summary_path.write_text(
            json.dumps(
                {
                    "tool": result.tool_name,
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "native_libraries": [str(path) for path in result.native_libraries],
                    "detail": result.detail,
                    "library_results": list(result.library_results),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return summary_path

    @staticmethod
    def _write_log(path: Path, content: str) -> None:
        path.write_text(content + "\n", encoding="utf-8")


def evidence_for_native_analysis(result: NativeAnalysisResult) -> list[EvidenceItem]:
    coverage = {
        "discovered": len(result.native_libraries),
        "completed": sum(item.get("status") == "completed" for item in result.library_results),
        "timed_out": sum(item.get("status") == "timed_out" for item in result.library_results),
        "failed": sum(item.get("status") == "failed" for item in result.library_results),
        "skipped": sum(item.get("status") == "skipped" for item in result.library_results),
        "partial": sum(item.get("status") == "partial" for item in result.library_results),
    }
    evidence = [
        EvidenceItem(
            category=EvidenceCategory.code_risk,
            evidence_type="ghidra_analysis",
            label=f"Ghidra native analysis: {result.status}",
            value={
                "tool": result.tool_name,
                "status": result.status,
                "exit_code": result.exit_code,
                "library_count": len(result.native_libraries),
                "coverage": coverage,
                "library_results": list(result.library_results),
                "detail": result.detail,
            },
            source_path=result.log_path,
            source_node="ghidra",
        )
    ]
    for library in result.native_libraries:
        identity = next((item for item in result.library_results if item.get("path") == str(library)), None)
        evidence.append(
            EvidenceItem(
                category=EvidenceCategory.code_risk,
                evidence_type="native_library",
                label=f"Native library: {library.name} ({identity.get('status') if identity else result.status})",
                value={
                    "file": str(library),
                    "architecture": library.parent.name,
                    "size_bytes": library.stat().st_size if library.exists() else None,
                    "sha256": identity.get("sha256") if identity else None,
                    "analysis_status": identity.get("status") if identity else result.status,
                    "analysis_detail": identity.get("detail") if identity else result.detail,
                },
                source_path=library,
                source_node="native-library",
            )
        )
    return evidence
