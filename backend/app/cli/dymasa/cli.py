"""Interactive and non-destructive Stage A CLI foundation."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import sys


try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:  # Keep the launcher useful before optional CLI dependencies are installed.
    Console = None
    Panel = None


class Output:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.console = Console() if Console else None

    def print(self, value: object = "") -> None:
        if not self.quiet:
            if self.console:
                self.console.print(value)
            else:
                print(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dy-masa",
        description="DY-MASA local Android APK security analysis CLI.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the interactive banner.")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal styling.")
    parser.add_argument("command", nargs="?", choices=("check",), help="Run a non-interactive command.")
    return parser


def _banner(output: Output) -> None:
    if output.quiet:
        return
    banner = "[bold cyan]DY-MASA[/bold cyan]  [dim]Android security analysis[/dim]"
    if output.console and Panel:
        output.print(Panel(banner, border_style="cyan"))
    else:
        output.print("DY-MASA - Android security analysis")


def _dependency_rows() -> list[tuple[str, str, str]]:
    rows = [
        ("Python", sys.version.split()[0], "required"),
        ("Java", shutil.which("java") or "not found", "required for APK analysis"),
        ("apktool", shutil.which("apktool") or "configured JAR", "required for APK analysis"),
        ("JADX", shutil.which("jadx") or "configured JAR", "required for APK analysis"),
        ("ADB", shutil.which("adb") or "not found", "optional for dynamic analysis"),
        ("Rich", "installed" if importlib.util.find_spec("rich") else "not installed", "optional CLI styling"),
    ]
    return rows


def check(output: Output) -> int:
    """Report environment facts without creating a database or running analysis."""

    from .database import project_root

    output.print(f"Project root: {project_root()}")
    output.print(f"Database URL: {os.environ.get('MOBILE_PENTEST_DATABASE_URL', 'not selected')}")
    output.print(f"Storage directory: {project_root() / 'storage'}")
    for name, value, note in _dependency_rows():
        output.print(f"{name}: {value} ({note})")
    return 0


def interactive(output: Output) -> int:
    _banner(output)
    while True:
        output.print("\n1. Overview / Dashboard\n2. Scan APK\n3. Findings\n4. Evidence\n")
        output.print("5. Reasoning\n6. Reports\n7. Jobs\n8. Dynamic Analysis\n9. Health / System Diagnostics\n0. Exit")
        try:
            choice = input("\nSelect an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            output.print("\nExiting.")
            return 0
        if choice == "0":
            return 0
        if choice == "9":
            check(output)
        else:
            output.print("This menu item will be enabled in a later CLI stage.")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    output = Output(quiet=args.quiet)
    if args.command == "check":
        return check(output)
    return interactive(output)
