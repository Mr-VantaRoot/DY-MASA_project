from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import subprocess
import time
from threading import Event

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


class GhidraAnalyzer:
    """Optional native-code analysis for ELF libraries embedded in an APK."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def run(
        self,
        apktool_output_path: Path,
        workspace_path: Path,
        cancel_event: Event | None = None,
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
            return NativeAnalysisResult("ghidra", "skipped", output_path, log_path, None, native_libraries, detail)

        headless = self._settings.ghidra_headless_path
        if headless is None or not headless.exists():
            detail = "Ghidra headless executable is not configured or was not found. Native libraries were retained for manual analysis."
            self._write_log(log_path, detail)
            return NativeAnalysisResult("ghidra", "skipped", output_path, log_path, None, native_libraries, detail)

        project_path = output_path / "project"
        project_path.mkdir(parents=True, exist_ok=True)
        log_parts = [f"headless={headless}", f"libraries={len(native_libraries)}"]
        last_exit_code = 0
        deadline = time.monotonic() + self._settings.ghidra_timeout_seconds

        for library in native_libraries:
            if cancel_event and cancel_event.is_set():
                detail = "Ghidra analysis was cancelled."
                self._write_log(log_path, "\n".join(log_parts + [detail]))
                return NativeAnalysisResult("ghidra", "cancelled", output_path, log_path, -2, native_libraries, detail)
            remaining = max(1, int(deadline - time.monotonic()))
            launcher = ["cmd.exe", "/c", str(headless)] if headless.suffix.lower() in {".bat", ".cmd"} else [str(headless)]
            command = launcher + [
                str(project_path),
                "masa-native",
                "-import",
                str(library),
                "-overwrite",
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=remaining,
                    check=False,
                )
                last_exit_code = completed.returncode
                log_parts.extend(
                    [
                        f"command={' '.join(command)}",
                        f"exit_code={completed.returncode}",
                        completed.stdout[-4000:],
                        completed.stderr[-4000:],
                    ]
                )
            except subprocess.TimeoutExpired as exc:
                detail = "Ghidra analysis timed out; native libraries remain available for manual review."
                log_parts.extend([f"command={' '.join(command)}", str(exc), detail])
                self._write_log(log_path, "\n".join(log_parts))
                return NativeAnalysisResult("ghidra", "failed", output_path, log_path, -1, native_libraries, detail)
            if last_exit_code != 0:
                detail = f"Ghidra returned exit code {last_exit_code}; native libraries remain available for manual review."
                self._write_log(log_path, "\n".join(log_parts))
                return NativeAnalysisResult("ghidra", "failed", output_path, log_path, last_exit_code, native_libraries, detail)

        detail = f"Ghidra analyzed {len(native_libraries)} native library file(s). Results are static analysis evidence, not proof of exploitability."
        log_parts.append(detail)
        self._write_log(log_path, "\n".join(log_parts))
        return NativeAnalysisResult("ghidra", "completed", output_path, log_path, 0, native_libraries, detail)

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
                "detail": result.detail,
            },
            source_path=result.log_path,
            source_node="ghidra",
        )
    ]
    for library in result.native_libraries:
        evidence.append(
            EvidenceItem(
                category=EvidenceCategory.code_risk,
                evidence_type="native_library",
                label=f"Native library: {library.name}",
                value={
                    "file": str(library),
                    "architecture": library.parent.name,
                    "size_bytes": library.stat().st_size if library.exists() else None,
                    "analysis_status": result.status,
                },
                source_path=library,
                source_node="native-library",
            )
        )
    return evidence
