"""Interactive and non-destructive Stage A CLI foundation."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import sys

from .ui import TerminalUI


Output = TerminalUI


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dy-masa",
        description="DY-MASA local Android APK security analysis CLI.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the interactive banner.")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal styling.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("overview", help="Show real job and result totals.")
    subparsers.add_parser("history", help="Browse all persisted analysis scans.")
    subparsers.add_parser("check", help="Check configuration and available dependencies.")
    analyze = subparsers.add_parser("analyze", help="Analyze one authorized APK and monitor its job.")
    analyze.add_argument("apk_path", type=Path)
    analyze.add_argument("--poll-interval", type=float, default=1.0)
    ghidra = analyze.add_mutually_exclusive_group()
    ghidra.add_argument("--ghidra", dest="ghidra_enabled", action="store_true", help="Enable optional Ghidra native analysis for this scan.")
    ghidra.add_argument("--no-ghidra", dest="ghidra_enabled", action="store_false", help="Disable Ghidra native analysis for this scan.")
    analyze.set_defaults(ghidra_enabled=None)
    jobs = subparsers.add_parser("jobs", help="List existing analysis jobs.")
    jobs.add_argument("--limit", type=int, help="Optional display limit; history is unlimited by default.")
    jobs_show = subparsers.add_parser("job", help="Show one job and its stored results.")
    jobs_show.add_argument("job_id")
    findings = subparsers.add_parser("findings", help="List stored findings.")
    findings.add_argument("--job-id")
    findings.add_argument("--severity")
    findings.add_argument("--page", type=int, default=1)
    findings.add_argument("--page-size", type=int, default=12)
    findings.add_argument("--detail", help="Show one finding by ID.")
    evidence = subparsers.add_parser("evidence", help="List stored evidence.")
    evidence.add_argument("--job-id")
    evidence.add_argument("--page", type=int, default=1)
    evidence.add_argument("--page-size", type=int, default=12)
    evidence.add_argument("--detail", help="Show one evidence record by ID.")
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
    dynamic_artifacts = dynamic_subparsers.add_parser("artifacts", help="List runtime artifacts for a job.")
    dynamic_artifacts.add_argument("job_id")
    return parser


def _banner(output: Output) -> None:
    if output.quiet:
        return
    banner = "[bold cyan]D Y - M A S A[/bold cyan]\n[dim]MOBILE APPLICATION SECURITY ASSESSMENT[/dim]"
    if output.rich:
        output.panel("LOCAL SECURITY WORKBENCH", banner, "bright_cyan", markup=True)
    else:
        output.print("D Y - M A S A | MOBILE APPLICATION SECURITY ASSESSMENT")


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

    from app.db.session import SessionLocal, ensure_local_schema_updates

    try:
        ensure_local_schema_updates()
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
        jobs = _with_session(lambda db: read.list_jobs(db, 5))
        output.panel(
            "DY-MASA // DASHBOARD",
            f"Jobs tracked: {totals['total']}    Findings: {totals['findings']}    Evidence: {totals['evidence']}    Reports: {totals['reports']}\n"
            f"Completed: {totals['completed']}    Running: {totals['running']}    Queued: {totals['queued']}    Failed: {totals['failed']}    Cancelled: {totals['cancelled']}",
            "bright_cyan",
        )
        output.table(
            "Recent jobs",
            ("APK", "Status", "Progress", "Current stage"),
            ((job.original_filename, job.status.value, f"{job.progress}%", job.current_step) for job in jobs),
        )
        return 0
    if args.command in {"jobs", "history"}:
        jobs = _with_session(lambda db: read.list_jobs(db, args.limit))
        if not jobs:
            output.panel("JOB HISTORY", "No analysis jobs found.", "yellow")
        output.table(
            "Job history",
            ("#", "APK", "Status", "Progress", "Ghidra", "Stage", "Job ID"),
            ((index, job.original_filename, job.status.value, f"{job.progress}%", "ON" if getattr(job, "ghidra_enabled", False) else "OFF", job.current_step, job.id[:8]) for index, job in enumerate(jobs, 1)),
        )
        return 0
    if args.command == "job":
        details = _with_session(lambda db: read.job_details(db, args.job_id))
        job = details["job"]
        output.panel("JOB DETAIL", f"{job.original_filename}\nStatus: {job.status.value}    Progress: {job.progress}%\nGhidra native analysis: {'ENABLED' if getattr(job, 'ghidra_enabled', False) else 'DISABLED'}\nStage: {job.current_step}\nJob ID: {job.id}", "bright_cyan")
        if job.error_message:
            output.panel("ERROR", job.error_message, "red")
        output.table(
            "Stored results",
            ("Stages", "Findings", "Evidence", "Artifacts", "Reasoning", "Reports"),
            ((len(details["stages"]), len(details["findings"]), len(details["evidence"]), len(details["artifacts"]), len(details["reasoning"]), len(details["reports"])),),
        )
        for report in details["reports"]:
            path, exists = read.report_path(report.path, settings.storage_root)
            output.print(f"{report.report_type.upper()}: {path}  {'present' if exists else 'missing'}")
        return 0
    if args.command == "findings":
        findings = _with_session(lambda db: read.list_findings(db, args.job_id, args.severity))
        if args.detail:
            finding = next((item for item in findings if item.id == args.detail or item.id.startswith(args.detail)), None)
            if finding is None:
                output.panel("FINDING", "Finding not found. Use `findings` to see available records.", "yellow")
                return 1
            output.panel("FINDING DETAIL", f"{finding.title}\nSeverity: {finding.severity.value}\nCategory: {finding.category}\nRule: {finding.rule_id}\n\n{finding.description}\n\nRemediation: {finding.remediation}\n\nEvidence references: {finding.evidence_ids_json}", "red" if finding.severity.value in {"critical", "high"} else "yellow")
            return 0
        total = len(findings)
        start = max(0, (max(1, args.page) - 1) * max(1, args.page_size))
        visible = findings[start : start + max(1, args.page_size)]
        output.table(
            f"Findings // page {max(1, args.page)} ({start + 1 if visible else 0}-{start + len(visible)} of {total})",
            ("#", "Severity", "Title", "Category", "ID"),
            ((start + index, output.severity(finding.severity), finding.title, finding.category, finding.id[:8]) for index, finding in enumerate(visible, 1)),
        )
        if not findings:
            output.panel("FINDINGS", "No findings found for the selected filters.", "green")
        return 0
    if args.command == "evidence":
        evidence = _with_session(lambda db: read.list_evidence(db, args.job_id))
        if args.detail:
            item = next((candidate for candidate in evidence if candidate.id == args.detail or candidate.id.startswith(args.detail)), None)
            if item is None:
                output.panel("EVIDENCE", "Evidence record not found.", "yellow")
                return 1
            output.panel("EVIDENCE DETAIL", f"{item.label}\nCategory: {item.category.value}\nType: {item.evidence_type}\nSource: {item.source_path}:{item.source_node or ''}\n\n{item.value_json}", "cyan")
            return 0
        total = len(evidence)
        start = max(0, (max(1, args.page) - 1) * max(1, args.page_size))
        visible = evidence[start : start + max(1, args.page_size)]
        output.table(
            f"Evidence // page {max(1, args.page)} ({start + 1 if visible else 0}-{start + len(visible)} of {total})",
            ("#", "Category", "Label", "Source", "ID"),
            ((start + index, item.category.value, item.label, f"{item.source_path}:{item.source_node or ''}", item.id[:8]) for index, item in enumerate(visible, 1)),
        )
        if not evidence:
            output.panel("EVIDENCE", "No evidence found for the selected job.", "green")
        return 0
    if args.command == "reports":
        reports = _with_session(lambda db: read.list_reports(db, args.job_id))
        for report in reports:
            path, exists = read.report_path(report.path, settings.storage_root)
            output.print(f"{report.report_type.upper():<5} {'READY' if exists else 'MISSING':<7} {path}  job={report.job_id[:8]}")
        if not reports:
            output.print("No reports found.")
        return 0
    if args.command == "reasoning":
        reasoning = _with_session(lambda db: read.list_reasoning(db, args.job_id))
        for item in reasoning:
            output.panel(f"REASONING // {item.provider}", f"Job: {item.job_id}\n\n{item.summary}\n\nLimitations: {item.limitations}", "magenta")
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
    if args.dynamic_command in {"events", "evidence", "artifacts"}:
        from . import read

        try:
            if args.dynamic_command == "events":
                rows = _with_session(lambda db: read.list_dynamic_stages(db, args.job_id))
                for row in rows:
                    output.print(f"{row.created_at}  {row.stage}  {row.status}  {row.message}  {row.detail or ''}")
            elif args.dynamic_command == "evidence":
                evidence = _with_session(lambda db: read.list_runtime_evidence(db, args.job_id))
                rows = evidence
                for row in evidence:
                    output.print(f"{row.id}  {row.evidence_type}  {row.label}  {row.source_path}")
            else:
                rows = _with_session(lambda db: read.list_runtime_artifacts(db, args.job_id))
                for artifact in rows:
                    output.print(f"{artifact.id}  {artifact.tool_name}  {artifact.path}")
            if not rows:
                output.print(_with_session(lambda db: read.dynamic_result_message(db, args.job_id, args.dynamic_command)))
            return 0
        except ValueError as exc:
            output.print(f"Dynamic read failed: {exc}")
            return 1
    output.print("Choose a dynamic command: status, start, events, evidence, or artifacts.")
    return 2


def _interactive_dynamic(output: Output, job_id: str | None = None) -> int:
    """Show one runtime section at a time without returning to the main menu."""

    while True:
        choice = output.prompt(
            "dynamic › (s) Runtime Status · (e) Dynamic Events · (v) Runtime Evidence · (a) Runtime Artifacts · (t) Start · (x) Back"
        ).strip().lower() or "x"
        if choice in {"x", "back"}:
            return 0
        if choice in {"s", "status"}:
            if job_id:
                output.print("Runtime Status · current device state (not historical scan data)")
            _dynamic_command(type("Args", (), {"dynamic_command": "status"})(), output)
        elif choice in {"e", "events"}:
            if not job_id:
                output.print("Select a scan first to view Dynamic Events.")
                continue
            _interactive_dynamic_events(output, job_id)
        elif choice in {"v", "evidence"}:
            if not job_id:
                output.print("Select a scan first to view Runtime Evidence.")
                continue
            _dynamic_command(type("Args", (), {"dynamic_command": "evidence", "job_id": job_id})(), output)
        elif choice in {"a", "artifacts"}:
            if not job_id:
                output.print("Select a scan first to view Runtime Artifacts.")
                continue
            _dynamic_command(type("Args", (), {"dynamic_command": "artifacts", "job_id": job_id})(), output)
        elif choice in {"t", "start"}:
            selected_job_id = job_id or output.prompt("Completed static job ID")
            if selected_job_id:
                _dynamic_command(type("Args", (), {"dynamic_command": "start", "job_id": selected_job_id})(), output)
        else:
            output.print("Unknown dynamic action. Use s, e, v, a, t, or x.")


def _interactive_dynamic_events(output: Output, job_id: str) -> int:
    from . import read

    filter_text = output.prompt("Event filter (blank for all)").strip().lower()
    try:
        rows = _with_session(lambda db: read.list_dynamic_stages(db, job_id))
    except ValueError as exc:
        output.print(f"Dynamic events unavailable: {exc}")
        return 1
    if filter_text:
        rows = [
            row for row in rows
            if filter_text in " ".join((row.stage, row.status, row.message, row.detail or "")).lower()
        ]
    if not rows:
        output.print("No matching dynamic events for this scan.")
        return 0
    page_size = 12
    page = 0
    while page * page_size < len(rows):
        visible = rows[page * page_size : (page + 1) * page_size]
        for row in visible:
            output.print(f"{row.created_at}  {row.stage}  {row.status}  {row.message}  {row.detail or ''}")
        if (page + 1) * page_size >= len(rows):
            return 0
        action = output.prompt(
            f"events › page {page + 1}/{(len(rows) + page_size - 1) // page_size}; n=next, x=back"
        ).strip().lower() or "x"
        if action not in {"n", "next", "more"}:
            return 0
        page += 1
    return 0


def _interactive_scan(output: Output) -> int:
    from app.core.config import get_settings
    from .runner import run_analysis

    raw_path = output.prompt("APK path")
    if not raw_path:
        output.panel("SCAN", "No APK path entered.", "yellow")
        return 1
    settings = get_settings()
    default = "on" if settings.ghidra_enabled else "off"
    selected = output.prompt("Enable Ghidra native analysis? (on/off)", default).strip().lower()
    if selected not in {"on", "off", "yes", "no", "y", "n"}:
        output.panel("SCAN", "Choose on or off for Ghidra analysis.", "yellow")
        return 1
    ghidra_enabled = selected in {"on", "yes", "y"}
    output.panel("SCAN CONFIGURATION", f"APK: {Path(raw_path).expanduser()}\nGhidra native analysis: {'ENABLED' if ghidra_enabled else 'DISABLED'}", "bright_cyan")
    return run_analysis(Path(raw_path).expanduser(), settings, output, 0.75, ghidra_enabled=ghidra_enabled)


def _interactive_records(output: Output, command: str, job_id: str | None = None) -> int:
    from argparse import Namespace
    from . import read

    severity = (output.prompt("Severity filter (blank for all)") or None) if command == "findings" else None
    page = 1
    page_size = 12
    while True:
        if command == "findings":
            args = Namespace(command=command, job_id=job_id, severity=severity, page=page, page_size=page_size, detail=None)
        elif command == "evidence":
            args = Namespace(command=command, job_id=job_id, page=page, page_size=page_size, detail=None)
        elif command == "jobs":
            args = Namespace(command=command, limit=None)
        elif command == "reports":
            args = Namespace(command=command, job_id=job_id)
        else:
            args = Namespace(command="reasoning", job_id=job_id)
        try:
            result = _read_command(args, output)
        except ValueError as exc:
            output.panel("DATABASE", str(exc), "red")
            return 1
        if command not in {"findings", "evidence"}:
            return result
        try:
            total = (
                _with_session(lambda db: read.count_findings(db, job_id, severity))
                if command == "findings"
                else _with_session(lambda db: read.count_evidence(db, job_id))
            )
        except ValueError as exc:
            output.panel("DATABASE", str(exc), "red")
            return 1
        if page * page_size >= total:
            return result
        action = output.prompt(f"records › page {page}/{(total + page_size - 1) // page_size}; n=next, x=back", "x").strip().lower()
        if action not in {"n", "next", "more"}:
            return result
        page += 1


def _history_overview(output: Output, job_id: str) -> int:
    from . import read

    try:
        details = _with_session(lambda db: read.job_details(db, job_id))
    except (LookupError, ValueError) as exc:
        output.panel("HISTORY", str(exc), "red")
        return 1
    job = details["job"]
    output.panel(
        "SCAN OVERVIEW",
        f"{job.original_filename}\nStatus: {job.status.value}    Progress: {job.progress}%\n"
        f"Ghidra: {'ON' if getattr(job, 'ghidra_enabled', False) else 'OFF'}\n"
        f"Created: {job.created_at}\nJob ID: {job.id}",
        "bright_cyan",
    )
    output.table(
        "Persisted scan records",
        ("Stages", "Findings", "Evidence", "Artifacts", "Reasoning", "Reports"),
        ((len(details["stages"]), len(details["findings"]), len(details["evidence"]), len(details["artifacts"]), len(details["reasoning"]), len(details["reports"])),),
    )
    if job.error_message:
        output.panel("SCAN ERROR", job.error_message, "red")
    return 0


def _history_detail(output: Output, job_id: str) -> int:
    """Navigate records for one job without mixing in global history."""

    while True:
        _history_overview(output, job_id)
        choice = output.prompt(
            "scan › (o) Overview · (f) Findings · (e) Evidence · (w) Reasoning · (r) Reports · (j) Job details · (d) Dynamic · (x) Back · (n) New scan"
        ).strip().lower() or "x"
        if choice in {"x", "back"}:
            return 0
        if choice in {"n", "new", "scan"}:
            return _interactive_scan(output)
        if choice in {"o", "overview"}:
            continue
        if choice in {"f", "findings"}:
            _interactive_records(output, "findings", job_id)
        elif choice in {"e", "evidence"}:
            _interactive_records(output, "evidence", job_id)
        elif choice in {"w", "reasoning"}:
            _interactive_records(output, "reasoning", job_id)
        elif choice in {"r", "reports"}:
            _interactive_records(output, "reports", job_id)
        elif choice in {"j", "job", "details"}:
            from argparse import Namespace

            try:
                _read_command(Namespace(command="job", job_id=job_id), output)
            except ValueError as exc:
                output.panel("DATABASE", str(exc), "red")
        elif choice in {"d", "dynamic"}:
            _interactive_dynamic(output, job_id)
        else:
            output.panel("HISTORY", "Unknown scan view. Choose f, e, w, r, j, d, x, or n.", "yellow")


def _interactive_history(output: Output) -> int:
    """Browse persisted scans and open a scan-scoped submenu."""

    from . import read

    while True:
        try:
            jobs = _with_session(lambda db: read.list_jobs(db))
        except ValueError as exc:
            output.panel("HISTORY", str(exc), "red")
            return 1
        output.table(
            "SCAN HISTORY",
            ("#", "APK", "Status", "Ghidra", "Created", "Job ID"),
            ((index, job.original_filename, job.status.value, "ON" if getattr(job, "ghidra_enabled", False) else "OFF", str(job.created_at), job.id[:8]) for index, job in enumerate(jobs, 1)),
        )
        if not jobs:
            output.print("No previous scans are stored.")
        choice = output.prompt("history › number · (n) New scan · (x) Back").strip().lower() or "x"
        if choice in {"x", "back"}:
            return 0
        if choice in {"n", "new", "scan"}:
            _interactive_scan(output)
            continue
        try:
            selected = jobs[int(choice) - 1]
        except (ValueError, IndexError):
            output.panel("HISTORY", "Choose a scan number, n for New Scan, or x to go back.", "yellow")
            continue
        _history_detail(output, selected.id)


def interactive(output: Output) -> int:
    _banner(output)
    menu_options = (
        ("1 / o", "Overview", "dashboard"),
        ("2", "Scan APK", "authorized APK"),
        ("3 / f", "Findings", "severity results"),
        ("4 / e", "Evidence", "source observations"),
        ("5", "Reasoning", "structured summaries"),
        ("6 / r", "Reports", "HTML and PDF"),
        ("7 / j", "Jobs", "analysis history"),
        ("8", "Dynamic", "safe ADB runtime"),
        ("9", "Health", "tools and database"),
        ("10 / s", "Settings", "configuration"),
        ("11 / hst", "History", "browse a scan"),
        ("h", "Help", "show this menu"),
        ("q / 0", "Exit", "close DY-MASA"),
    )
    try:
        from app.core.config import get_settings

        settings = get_settings()
        ghidra_state = "ON" if settings.ghidra_enabled else "OFF"
    except Exception:
        ghidra_state = "unknown"
    output.status_line(f"interactive  |  Ghidra {ghidra_state}  |  shortcuts: 1 2 f e r j s h q")
    output.menu(menu_options)
    while True:
        try:
            choice = output.prompt("dy-masa ›").strip().lower()
        except (EOFError, KeyboardInterrupt):
            output.print("\nExiting.")
            return 0
        if choice in {"q", "quit", "exit", "0"}:
            return 0
        if choice in {"h", "help", "menu", "?"}:
            output.menu(menu_options)
            continue
        try:
            if choice in {"1", "o", "overview"}:
                _read_command(type("Args", (), {"command": "overview"})(), output)
            elif choice == "2":
                _interactive_scan(output)
            elif choice in {"3", "f", "findings"}:
                _interactive_records(output, "findings")
            elif choice in {"4", "e", "evidence"}:
                _interactive_records(output, "evidence")
            elif choice in {"5", "reasoning"}:
                _interactive_records(output, "reasoning")
            elif choice in {"6", "r", "reports"}:
                _interactive_records(output, "reports")
            elif choice in {"7", "j", "jobs"}:
                _interactive_records(output, "jobs")
            elif choice in {"11", "hst", "history"}:
                _interactive_history(output)
            elif choice == "8":
                _interactive_dynamic(output)
            elif choice in {"9", "health"}:
                _health_command(output)
            elif choice in {"10", "s", "settings", "config"}:
                _config_command(output)
            else:
                output.panel("INPUT", "Unknown command. Press h for the compact menu.", "yellow")
        except KeyboardInterrupt:
            output.panel("CANCELLED", "Returning to the dashboard. No job was deleted.", "yellow")
        except Exception as exc:
            output.panel("ERROR", str(exc), "red")


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

        return run_analysis(args.apk_path, get_settings(), output, args.poll_interval, ghidra_enabled=args.ghidra_enabled)
    if args.command in {"overview", "history", "jobs", "job", "findings", "evidence", "reports", "reasoning"}:
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
