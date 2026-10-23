from pathlib import Path
import sys

sys.path.insert(0, str(Path.cwd()))
sys.path.insert(0, str(Path.cwd() / "backend"))

from app.core.config import get_settings
from dynamic.emulator.manager import EmulatorManager


def main() -> None:
    settings = get_settings()
    manager = EmulatorManager(
        sdk_path=settings.android_sdk_path,
        adb_path=settings.adb_path,
        emulator_path=settings.emulator_path,
        avd_name=settings.avd_name,
        boot_timeout_seconds=settings.emulator_boot_timeout_seconds,
    )
    status = manager.status()
    assert status.adb_available, status.adb_path
    assert status.emulator_available, status.emulator_path
    print("adb_available=True")
    print(f"emulator_available={status.emulator_available}")
    print(f"avd_name={status.avd_name}")
    print(f"avd_available={status.avd_available}")
    print(f"ready_device={status.ready_device}")
    print(f"android_version={status.android_version}")


if __name__ == "__main__":
    main()
