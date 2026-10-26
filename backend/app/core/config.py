from functools import lru_cache
from pathlib import Path
import shutil

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _executable_path(name: str, windows_path: str) -> Path:
    """Use a native executable when available, retaining Windows defaults for old setups."""
    discovered = shutil.which(name)
    return Path(discovered) if discovered else Path(windows_path)


def _first_existing(*paths: Path) -> Path:
    for path in paths:
        if path.exists():
            return path
    return paths[0]


class Settings(BaseSettings):
    app_name: str = "MASA"
    app_version: str = "0.1.0"
    environment: str = "local"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "MASA_DB"
    postgres_user: str = "postgres"
    postgres_password: str = Field(default="", repr=False)
    postgres_connect_timeout_seconds: int = 3
    postgres_pool_timeout_seconds: int = 3
    database_url_override: str | None = Field(default=None, validation_alias="MOBILE_PENTEST_DATABASE_URL")

    java_path: Path = _executable_path("java", "C:/Program Files/Java/jdk-21.0.11/bin/java.exe")
    apktool_jar_path: Path = Path("C:/tools/apktool.jar")
    jadx_jar_path: Path = _first_existing(
        Path.home() / ".local" / "opt" / "jadx" / "lib" / "jadx-1.5.2-all.jar",
        Path.home() / ".local" / "share" / "masa" / "jadx-cli-all.jar",
        Path("C:/tools/jadx/lib/jadx-cli-all.jar"),
    )
    tool_timeout_seconds: int = 600
    health_tool_timeout_seconds: int = 4

    android_sdk_path: Path = Path.home() / "Android" / "Sdk"
    adb_path: Path = _first_existing(
        Path(shutil.which("adb") or "adb"),
        android_sdk_path / "platform-tools" / "adb",
        Path("C:/Android/Sdk/platform-tools/adb.exe"),
    )
    emulator_path: Path = _first_existing(
        Path(shutil.which("emulator") or "emulator"),
        android_sdk_path / "emulator" / "emulator",
        Path("C:/Android/Sdk/emulator/emulator.exe"),
    )
    avd_name: str = "Dy-MASA"
    android_avd_home: Path = Path.home() / ".android" / "avd"
    dynamic_timeout_seconds: int = 180
    dynamic_status_timeout_seconds: int = 2
    emulator_boot_timeout_seconds: int = 180
    dynamic_device_serial: str | None = None
    dynamic_allow_physical_device: bool = False
    dynamic_scan_personal_storage: bool = False
    dynamic_baseline_seconds: int = 3
    enable_terminal: bool = False
    terminal_token: str | None = Field(default=None, repr=False)
    max_upload_bytes: int = 300 * 1024 * 1024
    max_concurrent_analysis_jobs: int = 1

    ghidra_enabled: bool = False
    ghidra_headless_path: Path | None = None
    ghidra_timeout_seconds: int = 900
    ghidra_library_timeout_seconds: int = 300
    ghidra_auto_extend_timeout: bool = True

    storage_root: Path = PROJECT_ROOT / "storage"
    upload_dir: Path = PROJECT_ROOT / "storage" / "uploads"
    workspace_dir: Path = PROJECT_ROOT / "storage" / "workspaces"
    report_dir: Path = PROJECT_ROOT / "storage" / "reports"

    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        env_prefix="MOBILE_PENTEST_",
        extra="ignore",
    )

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
