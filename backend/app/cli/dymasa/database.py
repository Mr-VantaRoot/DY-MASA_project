"""Database environment selection used before importing SQLAlchemy modules.

This mirrors ``work/start-backend.sh`` without importing the application engine.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


def project_root() -> Path:
    return Path(__file__).resolve().parents[4]


def sqlite_url(root: Path | None = None) -> str:
    database_path = (root or project_root()) / "storage" / "masa.sqlite3"
    return f"sqlite:///{database_path.resolve()}"


def postgres_is_ready() -> bool:
    """Return whether the configured PostgreSQL host accepts readiness checks."""

    executable = shutil.which("pg_isready")
    if not executable:
        return False
    try:
        result = subprocess.run(
            [executable, "-q"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=4,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def configure_database_environment(root: Path | None = None) -> str:
    """Select the same database policy as the backend startup script.

    The returned URL is set before any module that creates the SQLAlchemy engine.
    An explicitly configured URL is always retained. Only when no URL is
    configured does readiness select PostgreSQL or the canonical project
    SQLite database.
    """

    # An explicit URL is an operator choice. Do not replace it with the local
    # fallback merely because PostgreSQL readiness checks fail.
    configured = os.environ.get("MOBILE_PENTEST_DATABASE_URL", "").strip()
    if configured:
        return configured
    if postgres_is_ready():
        return os.environ.get("MOBILE_PENTEST_DATABASE_URL", "postgresql (configured)")
    fallback = sqlite_url(root)
    os.environ["MOBILE_PENTEST_DATABASE_URL"] = fallback
    return fallback


def analysis_tables_exist() -> bool:
    """Check for the primary analysis table without creating or altering tables."""
    from app.core.config import get_settings

    database_url = get_settings().database_url
    if database_url.startswith("sqlite:///"):
        database_path = Path(database_url.removeprefix("sqlite:///"))
        if not database_path.exists():
            return False
    from sqlalchemy import inspect

    from app.db.session import engine

    return "analysis_jobs" in inspect(engine).get_table_names()
