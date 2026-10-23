from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.base import Base


def create_db_engine() -> Engine:
    settings = get_settings()
    if settings.database_url.startswith("sqlite"):
        return create_engine(
            settings.database_url,
            connect_args={"check_same_thread": False},
        )
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_timeout=settings.postgres_pool_timeout_seconds,
        connect_args={"connect_timeout": settings.postgres_connect_timeout_seconds},
    )


engine = create_db_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database() -> bool:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return True


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_local_schema_updates()


def ensure_local_schema_updates() -> None:
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as connection:
        for enum_name, enum_values in {
            "analysis_evidence_category": ["code_secret", "code_risk", "runtime"],
            "analysis_finding_severity": ["critical"],
            "analysis_job_status": ["cancelled"],
            "analysis_artifact_type": ["dynamic_artifact"],
        }.items():
            for enum_value in enum_values:
                exists = connection.scalar(
                    text(
                        """
                        SELECT 1
                        FROM pg_enum e
                        JOIN pg_type t ON t.oid = e.enumtypid
                        WHERE t.typname = :enum_name
                        AND e.enumlabel = :enum_value
                        """
                    ),
                    {"enum_name": enum_name, "enum_value": enum_value},
                )
                if not exists:
                    connection.execute(text(f"ALTER TYPE {enum_name} ADD VALUE '{enum_value}'"))
