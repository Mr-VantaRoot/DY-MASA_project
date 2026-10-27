"""Interactive and non-destructive Stage A CLI foundation."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import sys

from .ui import TerminalUI


Output = TerminalUI
EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_NOT_READY = 3
EXIT_CANCELLED = 130

FINDING_SEARCH_TARGETS = ("Finding title", "Rule ID")


class DatabaseNotReadyError(ValueError):
    """The selected database is reachable but has no analysis schema."""


class InvalidInputError(ValueError):
    """CLI input is invalid before analysis or database work begins."""


class InteractiveQuit(Exception):
    """Signal a clean quit from any nested interactive screen."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dy-masa",
        description="DY-MASA local Android APK security analysis CLI.",
        epilog="Exit codes: 0 success; 1 analysis/runtime failure; 2 invalid input or usage; 3 dependency or database not ready; 130 cancelled.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the interactive banner.")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal styling.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("overview", help="Show real job and result totals.")
    subparsers.add_parser("history", help="Browse all persisted analysis scans.")
    subparsers.add_parser("check", help="Check configuration and available dependencies.")
    subparsers.add_parser("init", help="Create the existing analysis schema without deleting data.")
    analyze = subparsers.add_parser("analyze", help="Analyze one authorized APK and monitor its job.")
    analyze.add_argument("apk_path", type=Path)
    analyze.add_argument("--poll-interval", type=float, default=1.0)
    ghidra = analyze.add_mutually_exclusive_group()
    ghidra.add_argument("--ghidra", dest="ghidra_enabled", action="store_true", help="Enable optional Ghidra native analysis for this scan.")
    ghidra.add_argument("--no-ghidra", dest="ghidra_enabled", action="store_false", help="Disable Ghidra native analysis for this scan.")
    analyze.set_defaults(ghidra_enabled=None)
    jobs = subparsers.add_parser("jobs", help="List existing analysis jobs.")
    jobs.add_argument("--limit", type=int, help="Optional display limit.")
    jobs.add_argument("--page", type=int, default=1)
    jobs.add_argument("--page-size", type=int, default=None)
    jobs.add_argument("--search")
    jobs.add_argument("--status")
    jobs_show = subparsers.add_parser("job", help="Show one job and its stored results.")
    jobs_show.add_argument("job_id")
    findings = subparsers.add_parser("findings", help="List stored findings.")
    findings.add_argument("--job-id")
    findings.add_argument("--severity")
    findings.add_argument("--search")
    findings.add_argument("--category")
    findings.add_argument("--page", type=int, default=1)
    findings.add_argument("--page-size", type=int, default=None)
    findings.add_argument("--detail", help="Show one finding by ID.")
    evidence = subparsers.add_parser("evidence", help="List stored evidence.")
    evidence.add_argument("--job-id")
    evidence.add_argument("--page", type=int, default=1)
    evidence.add_argument("--page-size", type=int, default=None)
    evidence.add_argument("--search")
    evidence.add_argument("--category")
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
    try:
        from app.core.config import get_settings

        settings = get_settings()
        version = settings.app_version
        ghidra = "ON" if settings.ghidra_enabled else "OFF"
    except Exception:
        version = "unknown"
        ghidra = "unknown"
    database = "configured" if os.environ.get("MOBILE_PENTEST_DATABASE_URL") else "default selection"
    output.welcome(version, Path.cwd().name, database, ghidra)


def _safe_database_url(value: str) -> str:
    """Display database selection without exposing embedded credentials."""
    if "://" not in value:
        return value
    scheme, separator, rest = value.partition("://")
    if "@" not in rest:
        return value
    credentials, _, host = rest.rpartition("@")
    username = credentials.split(":", 1)[0]
    return f"{scheme}{separator}{username}:<redacted>@{host}"


def check(output: Output) -> int:
    """Verify configured prerequisites without creating data or running tools."""

    from app.core.config import get_settings
    from .database import project_root

    settings = get_settings()
    output.screen("Tools & Environment", "configured paths and database selection (no tool execution)")
    output.print(f"Project root: {project_root()}")
    output.print(f"Database URL: {_safe_database_url(settings.database_url)}")

    required_failures = 0

    def report(name: str, value: str, status: str, requirement: str) -> None:
        nonlocal required_failures
        if requirement == "REQUIRED" and status != "OK":
            required_failures += 1
        output.print(f"{status:<16} {requirement:<8} {name}: {value}")

    report("Python", sys.version.split()[0], "OK" if sys.version_info >= (3, 11) else "MISSING", "REQUIRED")

    def path_status(path: Path | None, executable: bool = False) -> tuple[str, str]:
        if path is None or not str(path).strip():
            return "NOT CONFIGURED", "not configured"
        usable = path.is_file() and (not executable or os.access(path, os.X_OK))
        return ("OK" if usable else "MISSING"), str(path)

    for name, path, executable in (
        ("Java", settings.java_path, True),
        ("apktool JAR", settings.apktool_jar_path, False),
        ("JADX JAR", settings.jadx_jar_path, False),
    ):
        status, value = path_status(path, executable)
        report(name, value, status, "REQUIRED")

    database_ok = bool(settings.database_url.strip())
    report("Database selection", _safe_database_url(settings.database_url), "OK" if database_ok else "MISSING", "REQUIRED")

    storage = settings.storage_root
    storage_ok = storage.is_dir() and os.access(storage, os.W_OK)
    report("Storage directory", str(storage), "OK" if storage_ok else "MISSING", "REQUIRED")

    for name, path in (("Ghidra analyzeHeadless", settings.ghidra_headless_path), ("ADB", settings.adb_path), ("Android emulator", settings.emulator_path)):
        status, value = path_status(path, True)
        report(name, value, status, "OPTIONAL")
    rich_status = "OK" if importlib.util.find_spec("rich") else "MISSING"
    report("Rich", "installed" if rich_status == "OK" else "not installed", rich_status, "OPTIONAL")
    return EXIT_NOT_READY if required_failures else EXIT_OK


def _require_analysis_tables() -> None:
    from .database import analysis_tables_exist
    from app.core.config import get_settings

    try:
        ready = analysis_tables_exist()
    except Exception as exc:
        raise DatabaseNotReadyError(f"Database is not ready ({exc}). Run `dy-masa init`, or start the web backend once.") from exc
    if not ready:
        raise DatabaseNotReadyError(
            f"Database is not initialized (no analysis tables found at {_safe_database_url(get_settings().database_url)}). "
            "Run `dy-masa init`, or start the web backend once."
        )


def _validate_apk_input(path: Path) -> str | None:
    if not path.exists():
        return f"APK does not exist: {path}"
    if not path.is_file():
        return f"APK path is not a file: {path}"
    if path.suffix.lower() != ".apk":
        return f"Input must have a .apk extension: {path}"
    if not os.access(path, os.R_OK):
        return f"APK is not readable: {path}"
    return None


def init_database(output: Output) -> int:
    from sqlalchemy import inspect

    from app.core.config import get_settings
    from app.db.session import engine, init_db

    settings = get_settings()
    before = set(inspect(engine).get_table_names())
    init_db()
    after = set(inspect(engine).get_table_names())
    state = "created" if "analysis_jobs" not in before and "analysis_jobs" in after else "already existed"
    output.print(f"Database: {_safe_database_url(settings.database_url)}")
    output.print(f"Analysis schema: {state}; existing data was preserved.")
    return EXIT_OK


def _with_session(callback):
    """Run one read-only operation in a short-lived session."""

    from app.db.session import SessionLocal

    try:
        _require_analysis_tables()
        with SessionLocal() as db:
            return callback(db)
    except DatabaseNotReadyError:
        raise
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
        return _overview_command(output, interactive=False)
    if args.command in {"jobs", "history"}:
        output.screen("Scan History" if args.command == "history" else "Jobs", "persisted analysis jobs")
        page = max(1, getattr(args, "page", 1))
        requested_page_size = getattr(args, "page_size", None)
        if getattr(args, "limit", None) is not None:
            requested_page_size = args.limit
        page_size = max(1, requested_page_size) if requested_page_size is not None else None
        offset = 0 if page_size is None else (page - 1) * page_size
        search = getattr(args, "search", None)
        status_filter = getattr(args, "status", None)
        jobs, total = _with_session(lambda db: (read.list_jobs(db, limit=page_size, offset=offset, search=search, status=status_filter), read.count_jobs(db, search, status_filter)))
        if not jobs:
            output.panel("JOB HISTORY", "No analysis jobs found.", "yellow")
        output.table(
            f"Job history // {'all records' if page_size is None else f'page {page} ({offset + 1 if jobs else 0}-{offset + len(jobs)} of {total})'}",
            ("#", "APK", "Status", "Progress", "Ghidra", "Stage", "Job ID"),
            ((index, job.original_filename, job.status.value, f"{job.progress}%", "ON" if getattr(job, "ghidra_enabled", False) else "OFF", job.current_step, job.id[:8]) for index, job in enumerate(jobs, 1)),
        )
        return 0
    if args.command == "job":
        output.screen("Job Details", "selected scan and stored outputs")
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
        output.screen("Findings", "evidence-backed results")
        page = max(1, getattr(args, "page", 1))
        requested_page_size = getattr(args, "page_size", None)
        page_size = max(1, requested_page_size) if requested_page_size is not None else None
        offset = 0 if page_size is None else (page - 1) * page_size
        severity = read.normalize_severity(args.severity)
        search = getattr(args, "search", None)
        category = getattr(args, "category", None)
        output.status_line(
            f"filters  job={'selected' if args.job_id else 'All jobs'}  "
            f"severity={severity or 'All severities'}  category={category or 'All categories'}  "
            f"search={search or 'none'}"
        )
        findings, total = _with_session(lambda db: (read.list_findings(db, args.job_id, severity, offset, page_size, search, category), read.count_findings(db, args.job_id, severity, search, category)))
        if args.detail:
            all_findings = _with_session(lambda db: read.list_findings(db, args.job_id, severity, search=search, category=category))
            finding = next((item for item in all_findings if item.id == args.detail or item.id.startswith(args.detail)), None)
            if finding is None:
                output.panel("FINDING", "Finding not found. Use `findings` to see available records.", "yellow")
                return 1
            output.panel("FINDING DETAIL", f"{finding.title}\nSeverity: {finding.severity.value}\nCategory: {finding.category}\nRule: {finding.rule_id}\n\n{finding.description}\n\nRemediation: {finding.remediation}\n\nEvidence references: {finding.evidence_ids_json}", "red" if finding.severity.value in {"critical", "high"} else "yellow")
            return 0
        output.table(
            f"Findings // {'all records' if page_size is None else f'page {page} ({offset + 1 if findings else 0}-{offset + len(findings)} of {total})'}",
            ("#", "Severity", "Title", "Category", "ID"),
            ((offset + index, output.severity(finding.severity), finding.title, finding.category, finding.id[:8]) for index, finding in enumerate(findings, 1)),
        )
        if not findings:
            output.panel("FINDINGS", "No findings found for the selected filters.", "green")
        return 0
    if args.command == "evidence":
        output.screen("Evidence", "persisted analysis observations")
        page = max(1, getattr(args, "page", 1))
        requested_page_size = getattr(args, "page_size", None)
        page_size = max(1, requested_page_size) if requested_page_size is not None else None
        offset = 0 if page_size is None else (page - 1) * page_size
        evidence_search = getattr(args, "search", None)
        evidence_category = getattr(args, "category", None)
        output.status_line(
            f"filters  job={'selected' if args.job_id else 'All jobs'}  "
            f"category={evidence_category or 'All categories'}  search={evidence_search or 'none'}"
        )
        evidence, total = _with_session(lambda db: (read.list_evidence(db, args.job_id, offset, page_size, evidence_search, evidence_category), read.count_evidence(db, args.job_id, evidence_search, evidence_category)))
        if args.detail:
            all_evidence = _with_session(lambda db: read.list_evidence(db, args.job_id, search=evidence_search, category=evidence_category))
            item = next((candidate for candidate in all_evidence if candidate.id == args.detail or candidate.id.startswith(args.detail)), None)
            if item is None:
                output.panel("EVIDENCE", "Evidence record not found.", "yellow")
                return 1
            source = read.safe_source_path(item.source_path, settings.storage_root)
            output.panel("EVIDENCE DETAIL", f"{item.label}\nCategory: {item.category.value}\nType: {item.evidence_type}\nSource: {source}:{item.source_node or ''}\n\n{item.value_json}", "cyan")
            return 0
        output.table(
            f"Evidence // {'all records' if page_size is None else f'page {page} ({offset + 1 if evidence else 0}-{offset + len(evidence)} of {total})'}",
            ("#", "Category", "Label", "Source", "ID"),
            ((offset + index, item.category.value, item.label, f"{read.safe_source_path(item.source_path, settings.storage_root)}:{item.source_node or ''}", item.id[:8]) for index, item in enumerate(evidence, 1)),
        )
        if not evidence:
            output.panel("EVIDENCE", "No evidence found for the selected job.", "green")
        return 0
    if args.command == "reports":
        output.screen("Reports", "validated report files")
        reports = _with_session(lambda db: read.list_reports(db, args.job_id))
        for report in reports:
            path, exists = read.report_path(report.path, settings.storage_root)
            output.print(f"{report.report_type.upper():<5} {'READY' if exists else 'MISSING':<7} {path}  job={report.job_id[:8]}")
        if not reports:
            output.print("No reports found.")
        return 0
    if args.command == "reasoning":
        output.screen("Structured Reasoning", "deterministic summaries")
        reasoning = _with_session(lambda db: read.list_reasoning(db, args.job_id))
        for item in reasoning:
            output.panel(f"REASONING // {item.provider}", f"Job: {item.job_id}\n\n{item.summary}\n\nLimitations: {item.limitations}", "magenta")
        if not reasoning:
            output.print("No reasoning summaries found.")
        return 0
    return 2


def _overview_command(output: Output, interactive: bool = True) -> int:
    """Show the dashboard and page through the complete scan history."""

    from . import read

    output.screen("Overview", "fleet-wide scan and result totals")
    totals = _with_session(read.overview)
    output.panel(
        "DY-MASA // DASHBOARD",
        f"Jobs tracked: {totals['total']}    Findings: {totals['findings']}    Evidence: {totals['evidence']}    Reports: {totals['reports']}\n"
        f"Completed: {totals['completed']}    Running: {totals['running']}    Queued: {totals['queued']}    Failed: {totals['failed']}    Cancelled: {totals['cancelled']}",
        "bright_cyan",
    )
    page_size = 5
    page = 1
    while True:
        offset = (page - 1) * page_size
        jobs, total = _with_session(
            lambda db: (
                read.list_jobs(db, limit=page_size, offset=offset),
                read.count_jobs(db),
            )
        )
        output.table(
            f"Recent jobs // page {page} ({offset + 1 if jobs else 0}-{offset + len(jobs)} of {total})",
            ("#", "APK", "Status", "Progress", "Current stage"),
            ((offset + index, job.original_filename, job.status.value, f"{job.progress}%", job.current_step) for index, job in enumerate(jobs, 1)),
        )
        if not interactive or offset + len(jobs) >= total:
            return 0
        choice = output.prompt("overview › n=next page · x=back").strip().lower() or "x"
        if choice in {"q", "quit", "exit"}:
            raise InteractiveQuit
        if choice not in {"n", "next"}:
            return 0
        page += 1


def _health_command(output: Output) -> int:
    from app.db.session import check_database
    from app.core.config import get_settings
    from app.services.tool_checker import ToolChecker

    settings = get_settings()
    output.screen("Health", "live database connectivity and configured tool execution")
    try:
        database_ok = check_database()
    except Exception as exc:
        database_ok = False
        output.print(f"Database: unavailable ({_safe_database_url(str(exc))})")
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
    output.screen("Configuration", "read-only effective settings")
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
                    detail = " ".join(str(row.detail or "").split())
                    output.print(f"{row.created_at}  {row.stage}  {row.status}  {row.message}  {detail[:180]}{'…' if len(detail) > 180 else ''}")
            elif args.dynamic_command == "evidence":
                evidence = _with_session(lambda db: read.list_runtime_evidence(db, args.job_id))
                rows = evidence
                for row in evidence:
                    output.print(f"{row.id}  {row.evidence_type}  {row.label}  {read.safe_source_path(row.source_path, settings.storage_root)}")
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

    output.screen("Dynamic Analysis", f"job {job_id[:8]}" if job_id else "live device context")
    while True:
        choice = output.prompt(
            "dynamic › (s) Runtime Status · (e) Dynamic Events · (v) Runtime Evidence · (a) Runtime Artifacts · (t) Start · (x) Back"
        ).strip().lower() or "x"
        if choice in {"q", "quit", "exit"}:
            raise InteractiveQuit
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
            _interactive_dynamic_records(output, job_id, "evidence")
        elif choice in {"a", "artifacts"}:
            if not job_id:
                output.print("Select a scan first to view Runtime Artifacts.")
                continue
            _interactive_dynamic_records(output, job_id, "artifacts")
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
            detail = " ".join(str(row.detail or "").split())
            output.print(f"{row.created_at}  {row.stage}  {row.status}  {row.message}  {detail[:180]}{'…' if len(detail) > 180 else ''}")
        if (page + 1) * page_size >= len(rows):
            return 0
        action = output.prompt(
            f"events › page {page + 1}/{(len(rows) + page_size - 1) // page_size}; n=next, x=back"
        ).strip().lower() or "x"
        if action in {"q", "quit", "exit"}:
            raise InteractiveQuit
        if action not in {"n", "next", "more"}:
            return 0
        page += 1
    return 0


def _interactive_dynamic_records(output: Output, job_id: str, kind: str) -> int:
    from . import read

    page_size = 12
    page = 1
    while True:
        offset = (page - 1) * page_size
        try:
            if kind == "evidence":
                rows, total = _with_session(lambda db: (read.list_runtime_evidence(db, job_id, offset, page_size), read.count_runtime_evidence(db, job_id)))
            else:
                rows, total = _with_session(lambda db: (read.list_runtime_artifacts(db, job_id, offset, page_size), read.count_runtime_artifacts(db, job_id)))
        except ValueError as exc:
            output.print(f"Runtime {kind} unavailable: {exc}")
            return 1
        if kind == "evidence":
            for row in rows:
                output.print(f"{row.id}  {row.evidence_type}  {row.label}  {row.source_path}")
        else:
            for artifact in rows:
                output.print(f"{artifact.id}  {artifact.tool_name}  {artifact.path}")
        if not rows:
            message = "No runtime evidence was collected for this scan." if kind == "evidence" else "No runtime artifacts are available for this scan."
            output.print(message)
            return 0
        if page * page_size >= total:
            return 0
        action = output.prompt(f"{kind} › page {page}/{(total + page_size - 1) // page_size}; n=next · x=back").strip().lower() or "x"
        if action in {"q", "quit", "exit"}:
            raise InteractiveQuit
        if action not in {"n", "next", "more"}:
            return 0
        page += 1


def _interactive_scan(output: Output) -> int:
    from app.core.config import get_settings
    from .runner import run_analysis

    output.screen("New Analysis", "select an authorized APK")
    raw_path = output.prompt("APK path (x to cancel)").strip()
    if not raw_path or raw_path.lower() in {"x", "cancel", "q"}:
        output.notice("Analysis cancelled.", "warning")
        return 1
    apk_path = Path(raw_path).expanduser()
    if not apk_path.is_file():
        output.notice(f"APK does not exist: {apk_path}", "error")
        return 1
    if apk_path.suffix.lower() != ".apk":
        output.notice("The selected file must have an .apk extension.", "error")
        return 1
    if not os.access(apk_path, os.R_OK):
        output.notice(f"APK is not readable: {apk_path}", "error")
        return 1
    output.status_line(f"APK  {apk_path.resolve()}  ·  {apk_path.stat().st_size:,} bytes")
    settings = get_settings()
    default = "on" if settings.ghidra_enabled else "off"
    selected = output.prompt("Enable Ghidra native analysis? (on/off)", default).strip().lower()
    if selected not in {"on", "off", "yes", "no", "y", "n"}:
        output.panel("SCAN", "Choose on or off for Ghidra analysis.", "yellow")
        return 1
    ghidra_enabled = selected in {"on", "yes", "y"}
    output.status_line(f"configuration  static ON  ·  Ghidra {'ON' if ghidra_enabled else 'OFF'}")
    return run_analysis(apk_path, settings, output, 0.75, ghidra_enabled=ghidra_enabled)


def _interactive_records(output: Output, command: str, job_id: str | None = None) -> int:
    from argparse import Namespace
    from . import read

    severity = None
    search = None
    category = None
    job_search = None
    job_status = None
    if command == "findings":
        severity_choice = (output.prompt("Severity filter [1 Critical · 2 High · 3 Medium · 4 Low · 5 Info · 0 All]") or "0").strip().lower()
        severity_choices = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "info"}
        if severity_choice in severity_choices:
            severity = severity_choices[severity_choice]
        elif severity_choice not in {"", "0", "all"}:
            severity = severity_choice
        search_value = output.prompt("Finding search [text in title or rule ID · l List targets · 0 All]")
        if search_value and search_value.strip().lower() == "l":
            output.panel("SEARCH TARGETS", "\n".join(f"{index}. {target}" for index, target in enumerate(FINDING_SEARCH_TARGETS, 1)), "cyan")
            search_value = output.prompt("Finding search [text in title or rule ID · 0 All]")
        category_value = output.prompt("Finding category [type a category · l List categories · 0 All]")
        if category_value and category_value.strip().lower() == "l":
            try:
                categories = _with_session(lambda db: read.list_finding_categories(db, job_id))
            except ValueError as exc:
                output.panel("DATABASE", str(exc), "red")
                return 1
            if categories:
                output.panel("FINDING CATEGORIES", "\n".join(f"{index}. {category}" for index, category in enumerate(categories, 1)), "cyan")
            else:
                output.empty("No finding categories are available for this scan.")
            category_value = output.prompt("Finding category [number or exact category · 0 All]")
            if category_value and category_value.strip().isdigit() and categories:
                selected_index = int(category_value.strip())
                if selected_index < 1 or selected_index > len(categories):
                    output.notice("Choose a listed category number, an exact category, or 0.", "warning")
                    return 1
                category_value = categories[selected_index - 1]
        search = None if not search_value or search_value.strip().lower() == "0" else search_value
        category = None if not category_value or category_value.strip().lower() == "0" else category_value
    if command == "jobs":
        job_search_value = output.prompt("Job search [APK filename · 0 All]")
        status_value = output.prompt(
            "Job status [1 queued · 2 running · 3 completed · 4 failed · 5 cancelled · 0 All]"
        )
        job_search = None if not job_search_value or job_search_value.strip().lower() == "0" else job_search_value
        status_choices = {str(index): value for index, value in enumerate(read.JOB_STATUSES, 1)}
        status_value = (status_value or "0").strip().lower()
        if status_value in status_choices:
            job_status = status_choices[status_value]
        elif status_value not in {"", "0", "all"}:
            job_status = status_value
    page = 1
    page_size = 12
    while True:
        if command == "findings":
            args = Namespace(
                command=command,
                job_id=job_id,
                severity=severity,
                search=search,
                category=category,
                page=page,
                page_size=page_size,
                detail=None,
            )
        elif command == "evidence":
            search = (output.prompt("Evidence search (blank for all)") or None) if page == 1 else search
            if page == 1:
                categories: list[str] = []
                category_value = output.prompt("Evidence category [type value · l List categories · 0 All]")
                if category_value and category_value.strip().lower() == "l":
                    try:
                        categories = _with_session(lambda db: read.list_evidence_categories(db, job_id))
                    except ValueError as exc:
                        output.panel("DATABASE", str(exc), "red")
                        return 1
                    if categories:
                        output.panel("EVIDENCE CATEGORIES", "\n".join(f"{index}. {category}" for index, category in enumerate(categories, 1)), "cyan")
                    else:
                        output.empty("No evidence categories are available for this scope.")
                    category_value = output.prompt("Evidence category [number or exact category · 0 All]")
                    if category_value and category_value.strip().isdigit() and categories:
                        selected_index = int(category_value.strip())
                        if selected_index < 1 or selected_index > len(categories):
                            output.notice("Choose a listed category number, an exact category, or 0.", "warning")
                            return 1
                        category_value = categories[selected_index - 1]
                category = None if not category_value or category_value.strip().lower() == "0" else category_value
            args = Namespace(command=command, job_id=job_id, page=page, page_size=page_size, detail=None, search=search, category=category)
        elif command == "jobs":
            args = Namespace(command=command, limit=None, page=page, page_size=20, search=job_search, status=job_status)
        elif command == "reports":
            args = Namespace(command=command, job_id=job_id)
        else:
            args = Namespace(command="reasoning", job_id=job_id)
        try:
            result = _read_command(args, output)
        except ValueError as exc:
            output.panel("DATABASE", str(exc), "red")
            return 1
        if command == "jobs":
            total = _with_session(lambda db: read.count_jobs(db, job_search, job_status))
            if page * page_size >= total:
                return result
            action = output.prompt(f"jobs › page {page}/{(total + page_size - 1) // page_size}; > next · x back").strip().lower() or "x"
            if action in {">", "n", "next"}:
                page += 1
                continue
            return result
        if command not in {"findings", "evidence"}:
            return result
        try:
            total = (
                _with_session(lambda db: read.count_findings(db, job_id, severity, search, category))
                if command == "findings"
                else _with_session(lambda db: read.count_evidence(db, job_id, search, category))
            )
        except ValueError as exc:
            output.panel("DATABASE", str(exc), "red")
            return 1
        if page * page_size >= total:
            action = output.prompt("records › ID=details · x=back").strip().lower() or "x"
        else:
            action = output.prompt(f"records › page {page}/{(total + page_size - 1) // page_size}; n=next · ID=details · x=back").strip().lower() or "x"
        if action in {"n", "next", "more"} and page * page_size < total:
            page += 1
            continue
        if action in {"q", "quit", "exit"}:
            raise InteractiveQuit
        if action not in {"x", "back"}:
            detail_args = Namespace(command=command, job_id=job_id, page=1, page_size=12, detail=action, severity=severity, search=search, category=category)
            try:
                _read_command(detail_args, output)
            except ValueError as exc:
                output.panel("DATABASE", str(exc), "red")
            return result
        return result


def _history_overview(output: Output, job_id: str) -> int:
    from . import read

    try:
        details = _with_session(lambda db: read.job_details(db, job_id))
    except (LookupError, ValueError) as exc:
        output.panel("HISTORY", str(exc), "red")
        return 1
    job = details["job"]
    output.status_line(
        f"scan // {job.original_filename}  ·  {job.status.value.upper()} {job.progress}%  ·  "
        f"Ghidra {'ON' if getattr(job, 'ghidra_enabled', False) else 'OFF'}  ·  {job.id[:8]}"
    )
    output.print(
        f"records  stages={len(details['stages'])}  findings={len(details['findings'])}  "
        f"evidence={len(details['evidence'])}  artifacts={len(details['artifacts'])}  "
        f"reasoning={len(details['reasoning'])}  reports={len(details['reports'])}"
    )
    if job.error_message:
        error_line = " ".join(str(job.error_message).split())
        output.print(f"error  {error_line[:220]}{'…' if len(error_line) > 220 else ''}")
    return 0


def _history_detail(output: Output, job_id: str) -> int:
    """Navigate records for one job without mixing in global history."""

    output.screen("Scan Workspace", f"job {job_id[:8]}")
    while True:
        choice = output.prompt(
            "scan › (o) Overview · (f) Findings · (e) Evidence · (w) Reasoning · (r) Reports · (j) Job details · (d) Dynamic · (x) Back · (n) New scan"
        ).strip().lower() or "x"
        if choice in {"q", "quit", "exit"}:
            raise InteractiveQuit
        if choice in {"x", "back"}:
            return 0
        if choice in {"n", "new", "scan"}:
            return _interactive_scan(output)
        if choice in {"o", "overview"}:
            _history_overview(output, job_id)
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

    show_history = True
    page = 1
    page_size = 20
    search = None
    status_filter = None
    while True:
        if status_filter and status_filter not in {"queued", "running", "completed", "failed", "cancelled"}:
            output.notice("Status must be queued, running, completed, failed, or cancelled.", "warning")
            status_filter = None
            show_history = True
            continue
        try:
            jobs, total = _with_session(lambda db: (read.list_jobs(db, limit=page_size, offset=(page - 1) * page_size, search=search, status=status_filter), read.count_jobs(db, search, status_filter)))
        except ValueError as exc:
            output.panel("HISTORY", str(exc), "red")
            return 1
        if show_history:
            filters = "  ".join(part for part in (f"search={search}" if search else "", f"status={status_filter}" if status_filter else "") if part)
            output.screen("Scan History", f"page {page}{'  ' + filters if filters else ''}")
            def display_created(job):
                value = job.created_at
                return value.strftime("%Y-%m-%d %H:%M") if hasattr(value, "strftime") else str(value)

            output.table(
                "SCAN HISTORY",
                ("#", "APK", "Status", "Ghidra", "Created", "ID"),
                [
                    (
                        ((page - 1) * page_size) + index,
                        job.original_filename,
                        job.status.value,
                        "ON" if getattr(job, "ghidra_enabled", False) else "OFF",
                        display_created(job),
                        job.id[:8],
                    )
                for index, job in enumerate(jobs, 1)
                ]
            )
            if not jobs:
                output.print("No previous scans are stored.")
            show_history = False
        choice = output.prompt(f"history › number · (s) Search · (f) Filter · > next · < previous · (n) New scan · (x) Back").strip().lower() or "x"
        if choice in {"q", "quit", "exit"}:
            raise InteractiveQuit
        if choice in {"x", "back"}:
            return 0
        if choice in {"n", "new", "scan"}:
            _interactive_scan(output)
            show_history = True
            continue
        if choice in {"s", "search"}:
            search = output.prompt("Filename search (blank clears)").strip() or None
            page = 1
            show_history = True
            continue
        if choice in {"f", "filter"}:
            status_filter = output.prompt("Status filter: queued/running/completed/failed/cancelled (blank clears)").strip().lower() or None
            page = 1
            show_history = True
            continue
        if choice in {">", "next"}:
            if page * page_size < total:
                page += 1
                show_history = True
            continue
        if choice in {"<", "previous", "prev"}:
            if page > 1:
                page -= 1
                show_history = True
            continue
        try:
            selection = int(choice)
            local_selection = selection - ((page - 1) * page_size)
            if local_selection < 1 or local_selection > len(jobs):
                raise ValueError
            selected = jobs[local_selection - 1]
        except (ValueError, IndexError):
            output.panel("HISTORY", "Choose a scan number, n for New Scan, or x to go back.", "yellow")
            continue
        _history_overview(output, selected.id)
        _history_detail(output, selected.id)
        show_history = False


def interactive(output: Output) -> int:
    _banner(output)
    menu_options = (
        ("1", "Overview", "dashboard"),
        ("2", "Scan APK", "authorized APK"),
        ("3", "Findings", "severity results"),
        ("4", "Evidence", "source observations"),
        ("5", "Reasoning", "structured summaries"),
        ("6", "Reports", "HTML and PDF"),
        ("7", "Jobs", "analysis history"),
        ("8", "Dynamic", "safe ADB runtime"),
        ("9", "Health", "tools and database"),
        ("10", "Settings", "configuration"),
        ("11", "History", "browse a scan"),
        ("?", "Help", "show this menu"),
        ("0", "Exit", "close DY-MASA"),
    )
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
                _overview_command(output)
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
        except InteractiveQuit:
            output.notice("Exiting.", "info")
            return 0
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
    if args.command == "init":
        try:
            return init_database(output)
        except Exception as exc:
            output.print(f"Database initialization failed: {exc}")
            return EXIT_NOT_READY
    if args.command == "analyze":
        invalid = _validate_apk_input(args.apk_path)
        if invalid:
            output.print(f"Invalid input: {invalid}")
            return EXIT_USAGE
        from .runner import run_analysis
        from app.core.config import get_settings

        return run_analysis(args.apk_path, get_settings(), output, args.poll_interval, ghidra_enabled=args.ghidra_enabled)
    if args.command in {"overview", "history", "jobs", "job", "findings", "evidence", "reports", "reasoning"}:
        try:
            return _read_command(args, output)
        except DatabaseNotReadyError as exc:
            output.print(str(exc))
            return EXIT_NOT_READY
        except InvalidInputError as exc:
            output.print(f"Invalid input: {exc}")
            return EXIT_USAGE
        except ValueError as exc:
            output.print(f"Error: {exc}")
            return EXIT_FAILURE
    if args.command == "dynamic":
        return _dynamic_command(args, output)
    if args.command == "health":
        try:
            return _health_command(output)
        except DatabaseNotReadyError as exc:
            output.print(str(exc))
            return EXIT_NOT_READY
        except Exception as exc:
            output.print(f"Health check failed: {exc}")
            return EXIT_NOT_READY
    if args.command == "config":
        return _config_command(output)
    return interactive(output)
