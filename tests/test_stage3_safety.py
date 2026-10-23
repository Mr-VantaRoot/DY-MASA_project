from __future__ import annotations

from pathlib import Path
import unittest

from fastapi import HTTPException

from app.api.routes.terminal import TerminalCommandRequest, run_terminal_command
from app.core.config import Settings
from dynamic.adb.client import AdbClient, AdbDevice, AdbResult
from dynamic.emulator.manager import EmulatorManager


class FakeStorageAdb(AdbClient):
    def __init__(self) -> None:
        super().__init__(Path("/does/not/exist"))
        self.commands: list[list[str]] = []

    def shell(self, command: list[str], device: str, timeout: int | None = None) -> AdbResult:
        self.commands.append(command)
        if command[:2] == ["df", "-k"]:
            return AdbResult([], 0, "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev 100 40 60 40% /sdcard\n", "")
        return AdbResult([], 0, "1024 /sdcard/Movies\n", "")


class Stage3SafetyTests(unittest.TestCase):
    def test_emulator_is_preferred_and_phone_requires_opt_in(self) -> None:
        manager = EmulatorManager(Path("/sdk"), Path("/adb"), Path("/emulator"), "Dy-MASA")
        devices = [AdbDevice("1047433361006458", "device"), AdbDevice("emulator-5554", "device")]
        self.assertEqual(manager._select_ready_device(devices).serial, "emulator-5554")
        phone_manager = EmulatorManager(Path("/sdk"), Path("/adb"), Path("/emulator"), "Dy-MASA", device_serial="1047433361006458")
        self.assertEqual(phone_manager._select_ready_device(devices).serial, "1047433361006458")
        blocked = EmulatorManager(Path("/sdk"), Path("/adb"), Path("/emulator"), "Dy-MASA")
        self.assertIsNone(blocked._select_ready_device([devices[0]]))

    def test_personal_storage_scan_is_opt_in(self) -> None:
        adb = FakeStorageAdb()
        report = adb.storage_breakdown("device")
        self.assertEqual(report.scanned_paths, [])
        self.assertEqual(report.video_bytes, 0)
        self.assertEqual([command[0] for command in adb.commands], ["df"])
        report = adb.storage_breakdown("device", scan_personal=True)
        self.assertGreater(report.video_bytes, 0)
        self.assertEqual([command[0] for command in adb.commands], ["df", "df", "du"])

    def test_terminal_disabled_is_not_mounted(self) -> None:
        with self.assertRaises(HTTPException) as error:
            run_terminal_command(TerminalCommandRequest(command="pwd"), settings=Settings(enable_terminal=False))
        self.assertEqual(error.exception.status_code, 404)

    def test_terminal_enabled_requires_token(self) -> None:
        with self.assertRaises(HTTPException) as error:
            run_terminal_command(TerminalCommandRequest(command="pwd"), terminal_token=None, settings=Settings(enable_terminal=True, terminal_token="secret"))
        self.assertIn(error.exception.status_code, {401, 403})


if __name__ == "__main__":
    unittest.main()
