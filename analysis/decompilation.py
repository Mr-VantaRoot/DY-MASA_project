from dataclasses import dataclass
from pathlib import Path
import subprocess
import time
from threading import Event

from app.core.config import Settings


@dataclass(frozen=True)
class DecompilationResult:
    tool_name: str
    output_path: Path
    log_path: Path
    exit_code: int
    succeeded: bool


class DecompilationError(RuntimeError):
    def __init__(self, result: DecompilationResult) -> None:
        super().__init__(f"{result.tool_name} failed with exit code {result.exit_code}. See {result.log_path}")
        self.result = result


class DecompilationCancelled(RuntimeError):
    def __init__(self, tool_name: str) -> None:
        super().__init__(f"{tool_name} was cancelled by the user.")
        self.tool_name = tool_name


class ApkDecompiler:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def run_apktool(self, apk_path: Path, workspace_path: Path, cancel_event: Event | None = None) -> DecompilationResult:
        output_path = workspace_path / "apktool"
        log_path = workspace_path / "logs" / "apktool.log"
        command = [
            str(self._settings.java_path),
            "-jar",
            str(self._settings.apktool_jar_path),
            "d",
            "-f",
            "-o",
            str(output_path),
            str(apk_path),
        ]
        try:
            return self._run_tool("apktool", command, output_path, log_path, cancel_event=cancel_event)
        except DecompilationError:
            fallback_log_path = workspace_path / "logs" / "apktool-no-src.log"
            fallback_command = [
                str(self._settings.java_path),
                "-jar",
                str(self._settings.apktool_jar_path),
                "d",
                "-f",
                "-s",
                "--keep-broken-res",
                "-o",
                str(output_path),
                str(apk_path),
            ]
            return self._run_tool("apktool", fallback_command, output_path, fallback_log_path, cancel_event=cancel_event)

    def run_jadx(self, apk_path: Path, workspace_path: Path, cancel_event: Event | None = None) -> DecompilationResult:
        output_path = workspace_path / "jadx"
        log_path = workspace_path / "logs" / "jadx.log"
        command = [
            str(self._settings.java_path),
            "-cp",
            str(self._settings.jadx_jar_path),
            "jadx.cli.JadxCLI",
            "--log-level",
            "ERROR",
            "-d",
            str(output_path),
            str(apk_path),
        ]
        return self._run_tool("jadx", command, output_path, log_path, allow_partial_output=True, cancel_event=cancel_event)

    def _run_tool(
        self,
        tool_name: str,
        command: list[str],
        output_path: Path,
        log_path: Path,
        allow_partial_output: bool = False,
        cancel_event: Event | None = None,
    ) -> DecompilationResult:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        if cancel_event and cancel_event.is_set():
            raise DecompilationCancelled(tool_name)

        process: subprocess.Popen[str] | None = None
        stdout = ""
        stderr = ""
        exit_code = -1
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + self._settings.tool_timeout_seconds
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        process.kill()
                        stdout, stderr = process.communicate()
                        stderr = (stderr or "") + "\nTool execution timed out."
                        exit_code = -1
                        break
                    if cancel_event and cancel_event.is_set():
                        process.terminate()
                        try:
                            stdout, stderr = process.communicate(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            stdout, stderr = process.communicate()
                        log_path.write_text(
                            self._format_log(command, -2, stdout or "", (stderr or "") + "\nTool execution cancelled."),
                            encoding="utf-8",
                        )
                        raise DecompilationCancelled(tool_name)
                    try:
                        stdout, stderr = process.communicate(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        continue
                if not stdout and not stderr:
                    stdout, stderr = process.communicate()
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                stderr = (stderr or "") + "\nTool execution timed out."
                exit_code = -1
            log_path.write_text(
                self._format_log(command, exit_code, stdout or "", stderr or ""),
                encoding="utf-8",
            )
            succeeded = exit_code == 0 or (
                allow_partial_output and output_path.exists() and any(output_path.rglob("*"))
            )
            result = DecompilationResult(
                tool_name=tool_name,
                output_path=output_path,
                log_path=log_path,
                exit_code=exit_code,
                succeeded=succeeded,
            )
        except DecompilationCancelled:
            raise

        if not result.succeeded:
            raise DecompilationError(result)
        return result

    @staticmethod
    def _format_log(command: list[str], exit_code: int, stdout: str, stderr: str) -> str:
        return "\n".join(
            [
                f"command={' '.join(command)}",
                f"exit_code={exit_code}",
                "",
                "[stdout]",
                stdout,
                "",
                "[stderr]",
                stderr,
            ]
        )
