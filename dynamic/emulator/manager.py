from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import time
import shutil

from dynamic.adb.client import AdbClient, AdbDevice


@dataclass(frozen=True)
class EmulatorStatus:
    adb_available: bool
    emulator_available: bool
    avd_name: str | None
    avd_available: bool
    devices: list[dict[str, str]]
    ready_device: str | None
    android_version: str | None
    device_model: str | None
    sdk_path: str
    adb_path: str
    emulator_path: str


class EmulatorManager:
    def __init__(
        self,
        sdk_path: Path,
        adb_path: Path,
        emulator_path: Path,
        avd_name: str | None,
        boot_timeout_seconds: int = 180,
        status_timeout_seconds: int = 2,
        avd_home: Path | None = None,
        device_serial: str | None = None,
        allow_physical_device: bool = False,
    ) -> None:
        self.sdk_path = sdk_path
        self.adb_path = Path(shutil.which("adb")) if not adb_path.exists() and shutil.which("adb") else adb_path
        self.emulator_path = Path(shutil.which("emulator")) if not emulator_path.exists() and shutil.which("emulator") else emulator_path
        self.avd_name = avd_name
        self.boot_timeout_seconds = boot_timeout_seconds
        self.status_timeout_seconds = status_timeout_seconds
        self.avd_home = avd_home or Path.home() / ".android" / "avd"
        self.device_serial = device_serial
        self.allow_physical_device = allow_physical_device
        self.adb = AdbClient(self.adb_path)

    def _select_ready_device(self, devices: list[AdbDevice] | None = None, preferred_serial: str | None = None) -> AdbDevice | None:
        ready = [device for device in (devices if devices is not None else self.adb.devices(timeout=self.status_timeout_seconds)) if device.state == "device"]
        selected_serial = preferred_serial or self.device_serial
        if selected_serial:
            return next((device for device in ready if device.serial == selected_serial), None)
        emulator = next((device for device in ready if device.serial.startswith("emulator-")), None)
        if emulator:
            return emulator
        return ready[0] if self.allow_physical_device and ready else None

    def status(self) -> EmulatorStatus:
        devices = self.adb.devices(timeout=self.status_timeout_seconds)
        ready = self._select_ready_device(devices)
        android_version = self.adb.getprop("ro.build.version.release", ready.serial, timeout=5) if ready else None
        device_model = self.adb.getprop("ro.product.model", ready.serial, timeout=5) if ready else None
        return EmulatorStatus(
            adb_available=self.adb_path.exists(),
            emulator_available=self.emulator_path.exists(),
            avd_name=self.avd_name,
            avd_available=self.avd_exists(timeout=self.status_timeout_seconds),
            devices=[{"serial": device.serial, "state": device.state} for device in devices],
            ready_device=ready.serial if ready else None,
            android_version=android_version,
            device_model=device_model,
            sdk_path=str(self.sdk_path),
            adb_path=str(self.adb_path),
            emulator_path=str(self.emulator_path),
        )

    def ready_device(self) -> AdbDevice | None:
        """Return the configured/safely selected ready device."""
        return self._select_ready_device()

    def avd_exists(self, timeout: int = 20) -> bool:
        if not self.emulator_path.exists() or not self.avd_name:
            return False
        if (self.avd_home / f"{self.avd_name}.ini").exists() or (self.avd_home / f"{self.avd_name}.avd").exists():
            return True
        try:
            completed = subprocess.run(
                [str(self.emulator_path), "-list-avds"],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        listed_avds = {line.strip() for line in completed.stdout.splitlines()}
        return self.avd_name in listed_avds

    def ensure_ready_device(self, preferred_serial: str | None = None) -> AdbDevice | None:
        ready = self._select_ready_device(preferred_serial=preferred_serial)
        if ready:
            return ready if self.adb.wait_for_boot_completed(ready.serial, timeout=30) else None
        self.start()
        return self.wait_until_ready(preferred_serial or self.device_serial)

    def start(self) -> None:
        if not self.emulator_path.exists() or not self.avd_name:
            return
        if self._select_ready_device():
            return
        subprocess.Popen(
            [str(self.emulator_path), "-avd", self.avd_name, "-no-snapshot-save"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def wait_until_ready(self, preferred_serial: str | None = None) -> AdbDevice | None:
        deadline = time.monotonic() + self.boot_timeout_seconds
        while time.monotonic() < deadline:
            ready = self._select_ready_device()
            if ready:
                if self.adb.wait_for_boot_completed(ready.serial, timeout=5):
                    return ready
            time.sleep(2)
        return None
