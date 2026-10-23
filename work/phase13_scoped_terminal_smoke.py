from pathlib import Path
import sys
import os

sys.path.insert(0, str(Path.cwd() / "backend"))

from app.api.routes.terminal import PowerShellTerminal
from app.core.config import PROJECT_ROOT, get_settings


def main() -> None:
    settings = get_settings()
    settings.storage_root.mkdir(parents=True, exist_ok=True)
    sample = settings.storage_root / "terminal-smoke.txt"
    sample.write_text("hello real terminal\nsecond line\n", encoding="utf-8")

    terminal = PowerShellTerminal(PROJECT_ROOT)
    if os.name == "nt":
        hello_command = "Write-Output 'hello-terminal'"
        list_command = "Get-ChildItem -Name"
        read_command = "Get-Content terminal-smoke.txt"
        cd_command = "Set-Location ..; Get-Location"
    else:
        hello_command = "printf 'hello-terminal\\n'"
        list_command = "ls -1"
        read_command = "cat terminal-smoke.txt"
        cd_command = "cd .. && pwd"

    hello = terminal.run(hello_command)
    storage_ls = terminal.run(list_command, str(settings.storage_root))
    read_file = terminal.run(read_command, str(settings.storage_root))
    changed_directory = terminal.run(cd_command, str(settings.storage_root))

    assert hello.exit_code == 0
    assert "hello-terminal" in hello.output
    assert "terminal-smoke.txt" in storage_ls.output
    assert "hello real terminal" in read_file.output
    assert changed_directory.exit_code == 0
    assert changed_directory.cwd == str(settings.storage_root.parent.resolve())

    print("real_local_shell_ok=True")
    print("storage_cwd_ok=True")
    print("file_read_ok=True")
    print("cd_persists_ok=True")


if __name__ == "__main__":
    main()
