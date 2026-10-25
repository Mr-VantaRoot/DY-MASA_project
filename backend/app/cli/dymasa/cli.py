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
    def __init__(self, quiet: bool = False, no_color: bool = False) -> None:
        self.quiet = quiet
        self.console = Console(no_color=no_color) if Console else None

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
    subparsers.add_parser("overview", help="Show real job and result totals.")
    subparsers.add_parser("check", help="Check configuration and available dependencies.")
    analyze = subparsers.add_parser("analyze", help="Analyze one authorized APK and monitor its job.")
    analyze.add_argument("apk_path", type=Path)
    analyze.add_argument("--poll-interval", type=float, default=1.0)
    jobs = subparsers.add_parser("jobs", help="List existing analysis jobs.")
    jobs.add_argument("--limit", type=int, help="Optional display limit; history is unlimited by default.")
    jobs_show = subparsers.add_parser("job", help="Show one job and its stored results.")
    jobs_show.add_argument("job_id")
    findings = subparsers.add_parser("findings", help="List stored findings.")
    findings.add_argument("--job-id")
    findings.add_argument("--severity")
    evidence = subparsers.add_parser("evidence", help="List stored evidence.")
    evidence.add_argument("--job-id")
    reports = subparsers.add_parser("reports", help="List stored reports.")
    reports.add_argument("--job-id")
    reasoning = subparsers.add_parser("reasoning", help="Show deterministic reasoning summaries.")
    reasoning.add_argument("--job-id")
    subparsers.add_parser("health", help="Check the configured database and analysis tools.")
    subparsers.add_parser("config", help="Show non-secret CLI configuration.")
    dynamic = subparsers.add_parser("dynamic", help="Inspect or start safe dynamic analysis.")
    dynamic_subparsers = dynamic.add_subparsers(dest="dynamic_command")
    dynamic_subparsers.add_parser("status", help="Show ADB/emulator status.")
    dynamic_start = dynamic_subparsers.add_parser("start", help="Start dynamic analysis for a completed static job.")
    dynamic_start.add_argument("job_id")
    dynamic_events = dynamic_subparsers.add_parser("events", help="Show dynamic stages for a job.")
    dynamic_events.add_argument("job_id")
    dynamic_evidence = dynamic_subparsers.add_parser("evidence", help="Show runtime evidence for a job.")
    dynamic_evidence.add_argument("job_id")
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
    if args.command == "overview":
        totals = _with_session(read.overview)
        output.print("Overview")
        output.print("Jobs: " + ", ".join(f"{key}={value}" for key, value in totals.items() if key in {"total", "queued", "running", "completed", "failed", "cancelled"}))
        output.print(f"Findings: {totals['findings']}  Evidence: {totals['evidence']}  Reports: {totals['reports']}")
        return 0
    if args.command == "jobs":
        jobs = _with_session(lambda db: read.list_jobs(db, args.limit))
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
    if args.command == "reasoning":
        reasoning = _with_session(lambda db: read.list_reasoning(db, args.job_id))
        for item in reasoning:
            output.print(f"{item.id}  provider={item.provider}  job={item.job_id}\n{item.summary}")
        if not reasoning:
            output.print("No reasoning summaries found.")
        return 0
    return 2


def _health_command(output: Output) -> int:
    from app.db.session import check_database
    from app.core.config import get_settings
    from app.services.tool_checker import ToolChecker

    settings = get_settings()
    try:
        database_ok = check_database()
    except Exception as exc:
        database_ok = False
        output.print(f"Database: unavailable ({exc})")
    if database_ok:
        output.print("Database: available")
    tools_ok = True
    for tool in ToolChecker(settings).check_all():
        output.print(f"{tool.name}: {'available' if tool.available else 'unavailable'}{f' ({tool.error})' if tool.error else ''}")
        tools_ok = tools_ok and tool.available
    return 0 if database_ok and tools_ok else 1


def _config_command(output: Output) -> int:
    from app.core.config import get_settings

    settings = get_settings()
    output.print(f"Project root: {Path(__file__).resolve().parents[4]}")
    output.print(f"Storage root: {settings.storage_root}")
    output.print(f"Upload limit: {settings.max_upload_bytes} bytes")
    output.print(f"Analysis workers: {settings.max_concurrent_analysis_jobs}")
    output.print(f"Dynamic device: {settings.dynamic_device_serial or 'automatic (emulator preferred)'}")
    output.print(f"Physical device allowed: {settings.dynamic_allow_physical_device}")
    output.print(f"Terminal enabled: {settings.enable_terminal}")
    return 0


def _dynamic_command(args, output: Output) -> int:
    from app.core.config import get_settings

    settings = get_settings()
    if args.dynamic_command == "status":
        from dynamic.emulator.manager import EmulatorManager

        manager = EmulatorManager(
            sdk_path=settings.android_sdk_path,
            adb_path=settings.adb_path,
            emulator_path=settings.emulator_path,
            avd_name=settings.avd_name,
            boot_timeout_seconds=settings.emulator_boot_timeout_seconds,
            status_timeout_seconds=settings.dynamic_status_timeout_seconds,
            avd_home=settings.android_avd_home,
            device_serial=settings.dynamic_device_serial,
            allow_physical_device=settings.dynamic_allow_physical_device,
        )
        status = manager.status()
        output.print(f"ADB available: {status.adb_available}")
        output.print(f"Emulator available: {status.emulator_available}")
        output.print(f"Ready device: {status.ready_device or 'none'}")
        output.print(f"Android: {status.android_version or 'unknown'}")
        output.print(f"Model: {status.device_model or 'unknown'}")
        for device in status.devices:
            output.print(f"Device: {device['serial']} ({device['state']})")
        return 0
    if args.dynamic_command == "start":
        from app.services.dynamic_service import start_dynamic_run

        try:
            result = _with_session(lambda db: start_dynamic_run(db, settings, args.job_id))
        except ValueError as exc:
            output.print(f"Dynamic analysis not started: {exc}")
            return 1
        output.print(f"Dynamic analysis accepted for job {result['job_id']}.")
        return 0
    if args.dynamic_command in {"events", "evidence"}:
        from . import read

        try:
            if args.dynamic_command == "events":
                rows = _with_session(lambda db: read.list_dynamic_stages(db, args.job_id))
                for row in rows:
                    output.print(f"{row.created_at}  {row.stage}  {row.status}  {row.message}  {row.detail or ''}")
            else:
                rows = _with_session(lambda db: read.list_runtime_evidence(db, args.job_id))
                for row in rows:
                    output.print(f"{row.id}  {row.evidence_type}  {row.label}  {row.source_path}")
            if not rows:
                output.print("No dynamic records found.")
            return 0
        except ValueError as exc:
            output.print(f"Dynamic read failed: {exc}")
            return 1
    output.print("Choose a dynamic command: status, start, events, or evidence.")
    return 2


def interactive(output: Output) -> int:
    _banner(output)
    while True:
        output.print("\n1. Overview / Dashboard\n2. Scan APK\n3. Findings\n4. Evidence\n")
        output.print("5. Reasoning\n6. Reports\n7. Jobs\n8. Dynamic Analysis\n9. Health / System Diagnostics\n10. Configuration\n0. Exit")
        try:
            choice = input("\nSelect an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            output.print("\nExiting.")
            return 0
        if choice == "0":
            return 0
        if choice == "1":
            main(["--quiet", "overview"])
        elif choice == "3":
            main(["--quiet", "findings"])
        elif choice == "4":
            main(["--quiet", "evidence"])
        elif choice == "5":
            main(["--quiet", "reasoning"])
        elif choice == "6":
            main(["--quiet", "reports"])
        elif choice == "7":
            main(["--quiet", "jobs"])
        elif choice == "9":
            main(["--quiet", "health"])
        elif choice == "10":
            main(["--quiet", "config"])
        elif choice == "2":
            output.print("Use the non-interactive command: dy-masa analyze /path/to/app.apk")
        elif choice == "8":
            output.print("Use the non-interactive command: dy-masa dynamic status")
        else:
            output.print("Unknown menu option.")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    output = Output(quiet=args.quiet, no_color=args.no_color)
    if args.command == "check":
        return check(output)
    if args.command == "analyze":
        from .runner import run_analysis
        from app.core.config import get_settings

        return run_analysis(args.apk_path, get_settings(), output, args.poll_interval)
    if args.command in {"overview", "jobs", "job", "findings", "evidence", "reports", "reasoning"}:
        try:
            return _read_command(args, output)
        except ValueError as exc:
            output.print(f"Error: {exc}")
            return 1
    if args.command == "dynamic":
        return _dynamic_command(args, output)
    if args.command == "health":
        try:
            return _health_command(output)
        except Exception as exc:
            output.print(f"Health check failed: {exc}")
            return 1
    if args.command == "config":
        return _config_command(output)
    return interactive(output)
