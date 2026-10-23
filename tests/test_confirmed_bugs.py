from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import unittest

from fastapi import HTTPException

from app.api.routes.jobs import _resolve_storage_file, stream_job_events
from app.api.routes.dynamic import _manager
from app.core.config import Settings
from app.db.base import AnalysisJobStatus
from app.services.job_events import emit_job_event, job_event_store
from dynamic.adb.client import AdbResult
from dynamic.runtime.orchestrator import DynamicAnalysisError, DynamicRuntimeOrchestrator


class ConfirmedBugTests(unittest.TestCase):
    def _settings(self, root: Path) -> SimpleNamespace:
        return SimpleNamespace(
            dynamic_baseline_seconds=0,
            dynamic_timeout_seconds=10,
            storage_root=root,
            dynamic_device_serial="configured-phone",
            dynamic_allow_physical_device=True,
            android_sdk_path=Path("/sdk"),
            adb_path=Path("/adb"),
            emulator_path=Path("/emulator"),
            avd_name="Dy-MASA",
            emulator_boot_timeout_seconds=1,
            android_avd_home=root / "avd",
        )

    def _fake_runtime(self, root: Path, launch: AdbResult) -> tuple[DynamicRuntimeOrchestrator, MagicMock]:
        settings = self._settings(root)
        manager = MagicMock()
        manager.ensure_ready_device.return_value = SimpleNamespace(serial="configured-phone")
        adb = MagicMock()
        adb.dump_logcat.return_value = AdbResult(["adb", "logcat"], 0, "", "")
        adb.install.return_value = AdbResult(["adb", "install"], 0, "Success\n", "")
        adb.launch_package.return_value = launch
        adb.capture_ready_screenshot.return_value = AdbResult(["adb", "screencap"], 0, "", "")
        adb.storage_summary.return_value = ""
        orchestrator = DynamicRuntimeOrchestrator(settings, adb=adb, manager=manager)
        return orchestrator, adb

    def test_successful_dynamic_run_returns_the_real_logcat_artifact(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            orchestrator, adb = self._fake_runtime(root, AdbResult(["adb", "monkey"], 0, "Status: ok\n", ""))
            job = SimpleNamespace(id="job-1", workspace_path=str(root / "workspace"))
            capture = {"tier_a": [], "tier_b": [], "tier_c": [], "pids": [], "uids": [], "crashes": [], "lines": []}
            with patch.object(orchestrator, "_package_name", return_value="example.app"), \
                patch.object(orchestrator, "_dynamic_workspace", return_value=root / "workspace"), \
                patch.object(orchestrator, "_apk_path", return_value=root / "app.apk"), \
                patch.object(orchestrator, "_package_pids", return_value=[]), \
                patch.object(orchestrator, "_save_logcat_capture", return_value=capture), \
                patch.object(orchestrator, "_stage"), patch.object(orchestrator, "_record_evidence"), \
                patch.object(orchestrator, "_record_command_artifact"), patch.object(orchestrator, "_record_artifact"), \
                patch.object(orchestrator, "_validate_static_attack_surface"), \
                patch.object(orchestrator, "_write_capture_metadata"), patch.object(orchestrator, "_write_adb_audit"):
                summary = orchestrator.run(MagicMock(), job)
            self.assertEqual(summary.logcat_path, str(root / "workspace" / "dynamic" / "logcat.txt"))
            self.assertEqual(summary.device, "configured-phone")
            self.assertTrue(adb.launch_package.called)

    def test_failed_launch_stops_dynamic_run_without_report_refresh(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            failed_launch = AdbResult(["adb", "monkey"], 1, "", "Error: launch failed")
            orchestrator, _ = self._fake_runtime(root, failed_launch)
            job = SimpleNamespace(id="job-2", workspace_path=str(root / "workspace"))
            capture = {"tier_a": [], "tier_b": [], "tier_c": [], "pids": [], "uids": [], "crashes": [], "lines": []}
            with patch.object(orchestrator, "_package_name", return_value="example.app"), \
                patch.object(orchestrator, "_dynamic_workspace", return_value=root / "workspace"), \
                patch.object(orchestrator, "_apk_path", return_value=root / "app.apk"), \
                patch.object(orchestrator, "_package_pids", return_value=[]), \
                patch.object(orchestrator, "_save_logcat_capture", return_value=capture), \
                patch.object(orchestrator, "_stage"), patch.object(orchestrator, "_record_evidence"), \
                patch.object(orchestrator, "_record_command_artifact"), patch.object(orchestrator, "_record_artifact"):
                with self.assertRaises(DynamicAnalysisError):
                    orchestrator.run(MagicMock(), job)

    def test_dynamic_manager_receives_device_policy(self) -> None:
        with TemporaryDirectory() as temp:
            settings = self._settings(Path(temp))
            with patch("dynamic.runtime.orchestrator.EmulatorManager") as manager_class:
                DynamicRuntimeOrchestrator(settings, adb=MagicMock())
            kwargs = manager_class.call_args.kwargs
            self.assertEqual(kwargs["device_serial"], "configured-phone")
            self.assertTrue(kwargs["allow_physical_device"])
            configured = _manager(Settings(dynamic_device_serial="serial-1", dynamic_allow_physical_device=True))
            self.assertEqual(configured.device_serial, "serial-1")
            self.assertTrue(configured.allow_physical_device)

    def test_sse_rejects_unknown_job_and_ends_after_terminal_event(self) -> None:
        missing_db = MagicMock()
        missing_db.get.return_value = None
        with self.assertRaises(HTTPException) as error:
            stream_job_events("missing", db=missing_db, settings=Settings())
        self.assertEqual(error.exception.status_code, 404)

        job_id = "terminal-job"
        job = SimpleNamespace(status="completed", current_step="Done", error_message=None)
        initial_db = MagicMock()
        initial_db.get.return_value = job
        state_db = MagicMock()
        state_db.get.return_value = job
        session = MagicMock()
        session.__enter__.return_value = state_db
        session.__exit__.return_value = False
        job_event_store.clear(job_id)
        emit_job_event(job_id, "job_completed", "completed", "Done")
        with patch("app.api.routes.jobs.SessionLocal", return_value=session), \
            patch.object(job_event_store, "wait_for", return_value=[]):
            response = stream_job_events(job_id, db=initial_db, settings=Settings())
            async def collect() -> list[bytes]:
                return [chunk async for chunk in response.body_iterator]

            chunks = asyncio.run(collect())
        self.assertEqual(len(chunks), 1)
        self.assertIn("job_completed", chunks[0])
        job_event_store.clear(job_id)

        for terminal_status in (AnalysisJobStatus.failed, AnalysisJobStatus.cancelled):
            terminal_id = f"terminal-{terminal_status.value}"
            terminal_job = SimpleNamespace(status=terminal_status, current_step="Stopped", error_message="reason")
            initial_db.get.return_value = terminal_job
            state_db.get.return_value = terminal_job
            job_event_store.clear(terminal_id)
            with patch("app.api.routes.jobs.SessionLocal", return_value=session), \
                patch("app.api.routes.jobs.asyncio.sleep", new=AsyncMock()):
                response = stream_job_events(terminal_id, db=initial_db, settings=Settings())

                async def collect_terminal() -> list[bytes]:
                    return [chunk async for chunk in response.body_iterator]

                terminal_chunks = asyncio.run(collect_terminal())
            self.assertEqual(len(terminal_chunks), 1)
            self.assertIn(f"job_{terminal_status.value}", terminal_chunks[0])
            job_event_store.clear(terminal_id)

    def test_report_download_resolution_rejects_outside_and_symlink_paths(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp) / "storage"
            root.mkdir()
            inside = root / "report.html"
            inside.write_text("ok", encoding="utf-8")
            self.assertEqual(_resolve_storage_file(inside, root, "Report"), inside)
            outside = Path(temp) / "outside.html"
            outside.write_text("secret", encoding="utf-8")
            with self.assertRaises(HTTPException) as error:
                _resolve_storage_file(outside, root, "Report")
            self.assertEqual(error.exception.status_code, 403)
            link = root / "link.html"
            link.symlink_to(outside)
            with self.assertRaises(HTTPException) as error:
                _resolve_storage_file(link, root, "Report")
            self.assertEqual(error.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
