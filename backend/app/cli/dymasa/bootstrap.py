"""CLI bootstrap code that must run before application imports."""

from .database import configure_database_environment


def bootstrap() -> str:
    return configure_database_environment()
