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
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("check", help="Check configuration and available dependencies.")
    analyze = subparsers.add_parser("analyze", help="Analyze one authorized APK and monitor its job.")
    analyze.add_argument("apk_path", type=Path)
    analyze.add_argument("--poll-interval", type=float, default=1.0)
    subparsers.add_parser("jobs", help="List existing analysis jobs.")
    jobs_show = subparsers.add_parser("job", help="Show one job and its stored results.")
    jobs_show.add_argument("job_id")
    findings = subparsers.add_parser("findings", help="List stored findings.")
    findings.add_argument("--job-id")
    findings.add_argument("--severity")
    evidence = subparsers.add_parser("evidence", help="List stored evidence.")
    evidence.add_argument("--job-id")
    reports = subparsers.add_parser("reports", help="List stored reports.")
    reports.add_argument("--job-id")
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


def _with_session(callback):
    """Run one read-only operation in a short-lived session."""

    from app.db.session import SessionLocal

    try:
        with SessionLocal() as db:
            return callback(db)
    except LookupError as exc:
        raise ValueError(str(exc)) from exc
    except Exception as exc:
        if "database is locked" in str(exc).lower():
            raise ValueError("Database is busy or locked; retry the command shortly.") from exc
        raise ValueError(f"Database read failed: {exc}") from exc


def _read_command(args, output: Output) -> int:
    from app.core.config import get_settings
    from . import read

    settings = get_settings()
    if args.command == "jobs":
        jobs = _with_session(read.list_jobs)
        if not jobs:
            output.print("No analysis jobs found.")
        for job in jobs:
            output.print(f"{job.id}  {job.status.value}  {job.progress}%  {job.original_filename}  {job.current_step}")
        return 0
    if args.command == "job":
        details = _with_session(lambda db: read.job_details(db, args.job_id))
        job = details["job"]
        output.print(f"Job: {job.id}\nAPK: {job.original_filename}\nStatus: {job.status.value}\nProgress: {job.progress}%")
        output.print(f"Current step: {job.current_step}")
        if job.error_message:
            output.print(f"Error: {job.error_message}")
        output.print(
            "Counts: "
            f"stages={len(details['stages'])}, findings={len(details['findings'])}, "
            f"evidence={len(details['evidence'])}, artifacts={len(details['artifacts'])}, "
            f"reasoning={len(details['reasoning'])}, reports={len(details['reports'])}"
        )
        for report in details["reports"]:
            path, exists = read.report_path(report.path, settings.storage_root)
            output.print(f"Report [{report.report_type}]: {path} ({'present' if exists else 'missing'})")
        return 0
    if args.command == "findings":
        findings = _with_session(lambda db: read.list_findings(db, args.job_id, args.severity))
        for finding in findings:
            output.print(f"{finding.id}  {finding.severity.value}  {finding.title}  job={finding.job_id}")
        if not findings:
            output.print("No findings found.")
        return 0
    if args.command == "evidence":
        evidence = _with_session(lambda db: read.list_evidence(db, args.job_id))
        for item in evidence:
            output.print(f"{item.id}  {item.category.value}  {item.label}  {item.source_path}  job={item.job_id}")
        if not evidence:
            output.print("No evidence found.")
        return 0
    if args.command == "reports":
        reports = _with_session(lambda db: read.list_reports(db, args.job_id))
        for report in reports:
            path, exists = read.report_path(report.path, settings.storage_root)
            output.print(f"{report.id}  {report.report_type}  {path}  {'present' if exists else 'missing'}  job={report.job_id}")
        if not reports:
            output.print("No reports found.")
        return 0
    return 2


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
    if args.command == "analyze":
        from .runner import run_analysis
        from app.core.config import get_settings

        return run_analysis(args.apk_path, get_settings(), output, args.poll_interval)
    if args.command in {"jobs", "job", "findings", "evidence", "reports"}:
        try:
            return _read_command(args, output)
        except ValueError as exc:
            output.print(f"Error: {exc}")
            return 1
    return interactive(output)
