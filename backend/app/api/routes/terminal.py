from __future__ import annotations

import subprocess
import tempfile
import os
import sys
import shlex
import hmac
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import PROJECT_ROOT
from app.core.config import Settings, get_settings


router = APIRouter(prefix="/terminal", tags=["terminal"])


class TerminalCommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=4000)
    cwd: str | None = None
    previous_cwd: str | None = None


class TerminalCommandResponse(BaseModel):
    command: str
    cwd: str
    output: str
    exit_code: int


class LocalTerminal:
    """Runs scoped local shell commands on Windows or Linux."""

    TIMEOUT_SECONDS = 30
    BLOCKED_INTERACTIVE_COMMANDS = {
        "opencode", "codex", "claude", "aider", "gemini", "cursor",
        "ollama", "top", "htop", "btop", "watch", "less", "more",
        "vim", "vi", "nano", "emacs", "ssh", "telnet", "screen", "tmux",
    }
    BLOCKED_ESCAPE_COMMANDS = {
        "bash", "sh", "dash", "zsh", "fish", "pwsh", "powershell", "cmd", "command", "env",
        "sudo", "doas", "su", "mount", "umount", "chroot", "nsenter", "systemctl",
        "service", "docker", "podman", "eval", "exec", "source",
    }
    INTERPRETER_CODE_FLAGS = {"-c", "--command", "-command", "-encodedcommand"}
    SAFE_SYSTEM_EXECUTABLES = {
        "cd", "clear", "true", "false", "ls", "pwd", "echo", "printf", "cat", "head", "tail", "grep", "rg",
        "find", "sort", "cut", "tr", "sed", "awk", "wc", "date", "file",
        "git",
    }
    SAFE_GIT_SUBCOMMANDS = {"status", "log", "diff", "branch", "show", "rev-parse"}
    BLOCKED_TOOL_COMMANDS = {"python", "python3", "perl", "ruby", "node", "pgcli", "psql", "adb", "java"}
    BLOCKED_FIND_ARGUMENTS = {"-exec", "-execdir", "-delete", "-ok", "-okdir"}
    CWD_MARKER = "__CODEX_TERMINAL_CWD__"
    EXIT_MARKER = "__CODEX_TERMINAL_EXIT__"

    def __init__(self, default_cwd: Path) -> None:
        self.default_cwd = default_cwd.resolve()

    def run(self, command: str, cwd: str | None = None, previous_cwd: str | None = None) -> TerminalCommandResponse:
        working_directory = self._resolve_cwd(cwd)
        self._validate_command_paths(command, working_directory)
        self._validate_command_mode(command)
        previous_directory = self._resolve_cwd(previous_cwd) if previous_cwd else working_directory
        try:
            if os.name == "nt":
                completed = self._run_powershell(command, working_directory)
                output, final_cwd, marker_exit_code = self._parse_output(
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    fallback_cwd=working_directory,
                    fallback_exit_code=completed.returncode,
                )
            else:
                completed = subprocess.run(
                    ["/bin/bash", "--noprofile", "--norc", "-c", self._wrap_posix_command(command, previous_directory)],
                    cwd=str(working_directory),
                    capture_output=True,
                    text=True,
                    timeout=self.TIMEOUT_SECONDS,
                )
                output, final_cwd, marker_exit_code = self._parse_output(
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    fallback_cwd=working_directory,
                    fallback_exit_code=completed.returncode,
                )
            self._validate_final_cwd(final_cwd)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="A local shell was not found on this machine.") from exc
        except subprocess.TimeoutExpired:
            return TerminalCommandResponse(
                command=command,
                cwd=str(working_directory),
                output=f"Command timed out after {self.TIMEOUT_SECONDS} seconds.",
                exit_code=-1,
            )

        return TerminalCommandResponse(
            command=command,
            cwd=final_cwd,
            output=output or "(no output)",
            exit_code=marker_exit_code,
        )

    def _validate_command_mode(self, command: str) -> None:
        """Reject programs that require an interactive TTY or run indefinitely."""
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return
        operators = {";", "&&", "||", "|", "&", ">", ">>", "<"}
        expecting_command = True
        for index, token in enumerate(tokens):
            if token in operators:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Pipelines, command chaining, and shell redirection are disabled in the MASA terminal.",
                )
            if not expecting_command:
                continue
            command_name = Path(token).name.lower()
            if command_name in self.BLOCKED_ESCAPE_COMMANDS or command_name in self.BLOCKED_INTERACTIVE_COMMANDS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"'{command_name}' is interactive or long-running and cannot run inside MASA's request terminal. "
                        "Run it in a separate system terminal instead."
                    ),
                )
            if command_name in self.BLOCKED_TOOL_COMMANDS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"'{command_name}' is not available in the MASA terminal allowlist.",
                )
            if command_name == "find" and any(argument.lower() in self.BLOCKED_FIND_ARGUMENTS for argument in tokens[index + 1 :]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Process execution and deletion options are disabled for find.",
                )
            if command_name == "git":
                subcommand = next((argument.lower() for argument in tokens[index + 1 :] if not argument.startswith("-")), None)
                if subcommand not in self.SAFE_GIT_SUBCOMMANDS:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Only read-only Git inspection commands are available in the MASA terminal.",
                    )
            if command_name not in self.SAFE_SYSTEM_EXECUTABLES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Command '{command_name}' is not in the MASA terminal allowlist.",
                )
            expecting_command = False

    def _validate_command_paths(self, command: str, working_directory: Path) -> None:
        """Reject explicit filesystem paths outside the MASA project root."""
        if any(marker in command for marker in ("$(", "`", "<(", ">(")):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Shell command substitution and process substitution are blocked in the MASA terminal.",
            )
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid shell syntax: {exc}") from exc

        for index, token in enumerate(tokens):
            if "://" in token:
                continue
            candidates = [token]
            if "=" in token:
                candidates.append(token.split("=", 1)[1])
            for candidate in candidates:
                if not candidate.startswith(("/", "./", "../")):
                    continue
                path = Path(candidate)
                resolved = path.resolve() if path.is_absolute() else (working_directory / path).resolve()
                if not self._is_allowed_path(resolved):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Terminal access is restricted to the MASA project root; external system paths are blocked.",
                    )

    def _is_allowed_path(self, path: Path) -> bool:
        try:
            path.relative_to(self.default_cwd)
            return True
        except ValueError:
            return False

    def _validate_final_cwd(self, cwd: str) -> None:
        if not self._is_allowed_path(Path(cwd).resolve()):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Terminal working directory escaped the MASA project root.",
            )

    def _resolve_cwd(self, cwd: str | None) -> Path:
        if cwd:
            candidate = Path(cwd).expanduser()
            if not candidate.is_absolute():
                candidate = self.default_cwd / candidate
        else:
            candidate = self.default_cwd

        resolved = candidate.resolve()
        if not resolved.exists() or not resolved.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Working directory does not exist: {resolved}",
            )
        if not self._is_allowed_path(resolved):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Working directory must remain inside the MASA project root.",
            )
        return resolved

    def _run_powershell(self, command: str, working_directory: Path) -> subprocess.CompletedProcess[str]:
        script = self._wrap_powershell(command)
        with tempfile.NamedTemporaryFile(delete=False, encoding="utf-16", mode="w", suffix=".ps1") as script_file:
            script_file.write(script)
            script_path = Path(script_file.name)
        try:
            executable = "powershell.exe" if sys.platform == "win32" else "pwsh"
            return subprocess.run(
                [executable, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                cwd=str(working_directory), capture_output=True, text=True, timeout=self.TIMEOUT_SECONDS,
            )
        finally:
            script_path.unlink(missing_ok=True)

    def _wrap_powershell(self, command: str) -> str:
        return f"""
$Error.Clear()
$ErrorActionPreference = 'Continue'
{command}

if ($null -ne $LASTEXITCODE) {{
    $codexExitCode = $LASTEXITCODE
}} elseif ($Error.Count -gt 0) {{
    $codexExitCode = 1
}} else {{
    $codexExitCode = 0
}}
Write-Output "{self.CWD_MARKER}$((Get-Location).Path)"
Write-Output "{self.EXIT_MARKER}$codexExitCode"
"""

    def _wrap_posix_command(self, command: str, previous_cwd: Path) -> str:
        oldpwd = shlex.quote(str(previous_cwd))
        return f"set +e\nexport OLDPWD={oldpwd}\n{command}\ncode=$?\nprintf '%s%s\\n' '{self.CWD_MARKER}' \"$(pwd)\"\nprintf '%s%s\\n' '{self.EXIT_MARKER}' \"$code\"\nexit $code\n"

    def _parse_output(
        self,
        stdout: str,
        stderr: str,
        fallback_cwd: Path,
        fallback_exit_code: int,
    ) -> tuple[str, str, int]:
        final_cwd = str(fallback_cwd)
        exit_code = fallback_exit_code
        output_lines: list[str] = []

        for line in stdout.splitlines():
            if line.startswith(self.CWD_MARKER):
                final_cwd = line.removeprefix(self.CWD_MARKER).strip() or final_cwd
                continue
            if line.startswith(self.EXIT_MARKER):
                raw_exit_code = line.removeprefix(self.EXIT_MARKER).strip()
                if raw_exit_code:
                    try:
                        exit_code = int(raw_exit_code)
                    except ValueError:
                        exit_code = fallback_exit_code
                continue
            output_lines.append(line)

        output = "\n".join(output_lines).strip()
        if stderr.strip():
            output = f"{output}\n{stderr.strip()}".strip()
        return output, final_cwd, exit_code


PowerShellTerminal = LocalTerminal


def get_terminal() -> LocalTerminal:
    return LocalTerminal(PROJECT_ROOT)


@router.post("/run", response_model=TerminalCommandResponse)
def run_terminal_command(
    request: TerminalCommandRequest,
    terminal_token: str | None = Header(default=None, alias="X-Terminal-Token"),
    settings: Settings = Depends(get_settings),
) -> TerminalCommandResponse:
    if not settings.enable_terminal:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Terminal is disabled.")
    if not settings.terminal_token or not terminal_token or not hmac.compare_digest(terminal_token, settings.terminal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="A valid X-Terminal-Token is required.")
    terminal = get_terminal()
    return terminal.run(request.command, request.cwd, request.previous_cwd)
