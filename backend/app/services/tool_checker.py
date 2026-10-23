from dataclasses import dataclass
from pathlib import Path
import subprocess

from app.core.config import Settings


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    command: list[str]
    version: str | None = None
    error: str | None = None


class ToolChecker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def check_configured_paths(self) -> list[ToolStatus]:
        return [
            self._path_status("java", self._settings.java_path, [str(self._settings.java_path), "-version"]),
            self._path_status(
                "apktool",
                self._settings.apktool_jar_path,
                [str(self._settings.java_path), "-jar", str(self._settings.apktool_jar_path), "--version"],
            ),
            self._path_status(
                "jadx",
                self._settings.jadx_jar_path,
                [str(self._settings.java_path), "-cp", str(self._settings.jadx_jar_path), "jadx.cli.JadxCLI", "--version"],
            ),
        ]

    @staticmethod
    def _path_status(name: str, path: Path, command: list[str]) -> ToolStatus:
        if path.exists():
            return ToolStatus(name=name, available=True, command=command, version=str(path))
        return ToolStatus(name=name, available=False, command=command, error=f"Missing path: {path}")

    def check_all(self) -> list[ToolStatus]:
        return [
            self._check_executable("java", [str(self._settings.java_path), "-version"]),
            self._check_jar(
                "apktool",
                self._settings.apktool_jar_path,
                [str(self._settings.java_path), "-jar", str(self._settings.apktool_jar_path), "--version"],
            ),
            self._check_jar(
                "jadx",
                self._settings.jadx_jar_path,
                [
                    str(self._settings.java_path),
                    "-cp",
                    str(self._settings.jadx_jar_path),
                    "jadx.cli.JadxCLI",
                    "--version",
                ],
            ),
        ]

    def _check_jar(self, name: str, jar_path: Path, command: list[str]) -> ToolStatus:
        if not jar_path.exists():
            return ToolStatus(name=name, available=False, command=command, error=f"Missing jar: {jar_path}")
        return self._check_executable(name, command)

    def _check_executable(self, name: str, command: list[str]) -> ToolStatus:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._settings.health_tool_timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolStatus(name=name, available=False, command=command, error=str(exc))

        output = (completed.stdout or completed.stderr).strip()
        if completed.returncode != 0:
            return ToolStatus(name=name, available=False, command=command, error=output)
        return ToolStatus(name=name, available=True, command=command, version=output.splitlines()[0] if output else None)
