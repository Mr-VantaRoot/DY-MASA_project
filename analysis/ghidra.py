from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import hashlib
import math
import os
import re
import signal
import subprocess
import time
from threading import Event
from typing import Callable
from urllib.parse import unquote, urlparse

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
        enabled: bool | None = None,
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

        if not (self._settings.ghidra_enabled if enabled is None else enabled):
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
        overall_timeout = self._positive_timeout(getattr(self._settings, "ghidra_timeout_seconds", 900), 900)
        per_library_limit = self._positive_timeout(getattr(self._settings, "ghidra_library_timeout_seconds", 300), 300)
        auto_extend = bool(getattr(self._settings, "ghidra_auto_extend_timeout", False))
        budget_margin = 60.0
        effective_overall_timeout = max(
            overall_timeout,
            per_library_limit * len(native_libraries) + budget_margin,
        ) if auto_extend else overall_timeout
        hashes = [self._sha256(library) for library in native_libraries]
        batch_identity = hashlib.sha256("".join(hashes).encode("ascii")).hexdigest()[:12]
        project_name = f"masa-native-batch-{batch_identity}"
        library_output_path = project_path / f"{project_name}.rep"
        event_bases = [
            {
                "library": library.name,
                "path": str(library),
                "size_bytes": library.stat().st_size,
                "sha256": hashes[index - 1],
                "index": index,
                "total": len(native_libraries),
                "output_path": str(library_output_path),
            }
            for index, library in enumerate(native_libraries, start=1)
        ]
        for event in event_bases:
            self._notify(progress_callback, {**event, "status": "queued", "started": False, "elapsed_seconds": 0.0})
        launcher = ["cmd.exe", "/c", str(headless)] if headless.suffix.lower() in {".bat", ".cmd"} else [str(headless)]
        command = launcher + [str(project_path), project_name, "-import", *(str(path) for path in native_libraries), "-overwrite", "-analysisTimeoutPerFile", str(max(1, math.ceil(per_library_limit)))]
        batch_started = time.monotonic()
        batch_status, exit_code, stdout, stderr, reason = self._run_batch(command, effective_overall_timeout, cancel_event)
        elapsed = round(time.monotonic() - batch_started, 3)
        started_paths = self._paths_from_log(stdout, "IMPORTING: ")
        completed_paths = self._paths_from_log(stdout, "Analysis succeeded for file: ")
        timed_out_paths = self._paths_from_log(stdout, "Processing not completed for file: ")
        cancelled_before_start = batch_status == "cancelled" and not started_paths
        if auto_extend and effective_overall_timeout > overall_timeout:
            log_parts.append(f"configured_overall_timeout={overall_timeout}; effective_batch_timeout={effective_overall_timeout} (per-library budget plus {budget_margin:.0f}s margin)")
        log_parts.extend([f"command={' '.join(command)}", f"batch_status={batch_status}", f"elapsed_seconds={elapsed}", f"exit_code={exit_code}", stdout[-12000:], stderr[-12000:], reason])
        self._write_log(log_path, "\n".join(log_parts))
        library_results: list[dict[str, object]] = []
        failed = batch_status == "failed"
        for index, (library, event_base) in enumerate(zip(native_libraries, event_bases), start=1):
            path = str(library)
            path_key = str(library.resolve())
            if path_key in completed_paths:
                status = "completed"
                started = True
                detail = "Ghidra completed successfully in the shared batch session."
            elif path_key in timed_out_paths or (path_key in started_paths and batch_status == "timed_out"):
                status = "timed_out"
                started = True
                detail = "Ghidra per-file analysis timed out in the shared batch session." if path_key in timed_out_paths else "The shared Ghidra batch exceeded its overall timeout while this library was running."
                failed = True
            elif path_key in started_paths:
                status = "cancelled" if batch_status == "cancelled" else "failed"
                started = True
                detail = "Ghidra batch was cancelled while this library was being processed." if status == "cancelled" else "Ghidra did not produce a successful or timeout record for this imported library."
                failed = failed or status == "failed"
            elif cancelled_before_start and index == 1:
                status = "cancelled"
                started = False
                detail = "Cancellation was requested before the Ghidra batch started."
            else:
                status = "skipped"
                started = False
                if batch_status == "cancelled":
                    detail = "Not started because Ghidra analysis was cancelled."
                elif batch_status == "timed_out":
                    detail = "Not started because the overall Ghidra batch timeout was exhausted."
                elif batch_status == "failed":
                    detail = "Not reached because the shared Ghidra batch failed before importing this library."
                else:
                    detail = "Not imported by Ghidra; no per-file import record was found."
            partial = library_output_path.exists() and status in {"timed_out", "failed", "cancelled"}
            segment = self._log_segment(stdout, path)
            result = {
                **event_base,
                "status": status,
                "started": started,
                "partial": partial,
                "exit_code": exit_code if started else None,
                "elapsed_seconds": self._elapsed_from_segment(segment, elapsed) if started else 0.0,
                "detail": detail,
            }
            library_results.append(result)
            per_library_log = "\n".join([f"command={' '.join(command)}", f"status={status}", f"elapsed_seconds={result['elapsed_seconds']}", segment, stderr[-4000:], detail])
            self._write_log(output_path / f"{index:02d}-{library.parent.name}-{library.stem}-{hashes[index - 1][:12]}.log", per_library_log)
            self._notify(progress_callback, result)
        if batch_status == "cancelled":
            final_status = "cancelled"
            final_exit_code = -2
        elif any(item["status"] == "completed" for item in library_results) and any(item["status"] in {"failed", "timed_out"} for item in library_results):
            final_status = "partial"
            final_exit_code = exit_code if failed else 0
        elif all(item["status"] == "skipped" for item in library_results):
            final_status = "skipped" if batch_status != "failed" else "failed"
            final_exit_code = exit_code if failed else 0
        elif batch_status == "completed" and all(item["status"] == "completed" for item in library_results):
            final_status = "completed"
            final_exit_code = 0
        else:
            final_status = "failed"
            final_exit_code = exit_code

        completed_count = sum(item["status"] == "completed" for item in library_results)
        timed_out_count = sum(item["status"] == "timed_out" for item in library_results)
        failed_count = sum(item["status"] == "failed" for item in library_results)
        skipped_count = sum(item["status"] == "skipped" for item in library_results)
        cancelled_count = sum(item["status"] == "cancelled" for item in library_results)
        partial_count = sum(bool(item.get("partial")) or item["status"] == "partial" for item in library_results)
        attempted_count = sum(bool(item.get("started")) for item in library_results)
        detail = (
            f"Ghidra discovered {len(native_libraries)} native library file(s): "
            f"{completed_count} completed, {timed_out_count} timed out, {failed_count} failed, "
            f"{skipped_count} skipped, {cancelled_count} cancelled, {partial_count} partial; "
            f"{attempted_count} started. Batch elapsed time: {elapsed}s. Results are static analysis evidence, not proof of exploitability."
        )
        log_parts.append(detail)
        self._write_log(log_path, "\n".join(log_parts))
        return NativeAnalysisResult("ghidra", final_status, output_path, log_path, final_exit_code, native_libraries, detail, tuple(library_results))

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _positive_timeout(value: object, default: float) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return parsed if math.isfinite(parsed) and parsed > 0 else default

    @staticmethod
    def _path_from_ghidra_record(value: str) -> str:
        raw = value.strip().split(" (", 1)[0]
        if raw.startswith("file://"):
            parsed = urlparse(raw)
            raw = unquote(parsed.path)
        return str(Path(raw))

    @classmethod
    def _paths_from_log(cls, output: str, marker: str) -> set[str]:
        paths: set[str] = set()
        for line in output.splitlines():
            if marker not in line:
                continue
            value = line.split(marker, 1)[1].strip()
            if value:
                paths.add(cls._path_from_ghidra_record(value))
        return paths

    @staticmethod
    def _log_segment(output: str, library_path: str) -> str:
        lines = output.splitlines()
        canonical_path = str(Path(library_path).resolve())
        starts = [index for index, line in enumerate(lines) if "IMPORTING: file://" in line and (library_path in line or canonical_path in line)]
        if not starts:
            return "No library-specific Ghidra output was captured before the batch ended."
        start = starts[0]
        end = next((index for index in range(start + 1, len(lines)) if "IMPORTING: file://" in lines[index]), len(lines))
        return "\n".join(lines[start:end])

    @staticmethod
    def _elapsed_from_segment(segment: str, fallback: float) -> float:
        match = re.search(r"Total Time\s+(\d+(?:\.\d+)?)\s+secs", segment)
        return float(match.group(1)) if match else fallback

    def _run_batch(
        self,
        command: list[str],
        timeout: float,
        cancel_event: Event | None,
    ) -> tuple[str, int | None, str, str, str]:
        if cancel_event and cancel_event.is_set():
            return "cancelled", -2, "", "", "Cancellation was requested before the Ghidra batch started."
        try:
            kwargs: dict[str, object] = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True}
            if os.name != "nt":
                kwargs["start_new_session"] = True
            else:
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(command, **kwargs)
        except OSError as exc:
            return "failed", 127, "", str(exc), f"Unable to start Ghidra batch: {exc}"

        started = time.monotonic()
        while process.poll() is None:
            if cancel_event and cancel_event.is_set():
                self._terminate_process(process)
                stdout, stderr = process.communicate()
                return "cancelled", -2, stdout or "", stderr or "", "Ghidra batch process terminated after cancellation."
            if time.monotonic() - started >= timeout:
                self._terminate_process(process)
                stdout, stderr = process.communicate()
                return "timed_out", -1, stdout or "", stderr or "", f"Overall Ghidra batch timeout of {timeout} seconds exceeded; process terminated."
            try:
                stdout, stderr = process.communicate(timeout=0.25)
            except subprocess.TimeoutExpired:
                continue
        stdout, stderr = process.communicate()
        exit_code = process.returncode
        if exit_code == 0:
            return "completed", exit_code, stdout or "", stderr or "", "Ghidra batch completed."
        return "failed", exit_code, stdout or "", stderr or "", f"Ghidra batch returned exit code {exit_code}."

    def _unstarted_results(
        self,
        libraries: tuple[Path, ...],
        detail: str,
        start_index: int,
        progress_callback: LibraryEvent | None,
    ) -> list[dict[str, object]]:
        results = []
        total = start_index + len(libraries) - 1
        for offset, library in enumerate(libraries):
            result = self._library_result(library, "skipped", detail)
            result.update({"index": start_index + offset, "total": total})
            results.append(result)
            self._notify(progress_callback, result)
        return results

    def _library_result(self, library: Path, status: str, detail: str) -> dict[str, object]:
        return {
            "library": library.name,
            "path": str(library),
            "sha256": self._sha256(library) if library.exists() else None,
            "size_bytes": library.stat().st_size if library.exists() else None,
            "status": status,
            "started": False,
            "output_path": None,
            "partial": False,
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
        if "Analysis timed out" in stdout or "Analysis timed out" in stderr:
            return "timed_out", exit_code, stdout or "", stderr or "", "Ghidra reported that per-file analysis timed out; imported output was preserved when available."
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
        "attempted": sum(bool(item.get("started")) for item in result.library_results),
        "completed": sum(item.get("status") == "completed" for item in result.library_results),
        "timed_out": sum(item.get("status") == "timed_out" for item in result.library_results),
        "failed": sum(item.get("status") == "failed" for item in result.library_results),
        "skipped": sum(item.get("status") == "skipped" for item in result.library_results),
        "cancelled": sum(item.get("status") == "cancelled" for item in result.library_results),
        "partial": sum(bool(item.get("partial")) or item.get("status") == "partial" for item in result.library_results),
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
