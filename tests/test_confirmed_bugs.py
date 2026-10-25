from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import unittest

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes.jobs import _events_after, _resolve_storage_file, stream_job_events
from app.api.routes.dynamic import _manager
from app.core.config import Settings
from app.db.base import AnalysisJobStatus, Base
from app.services.job_events import JobEventStore, JobStageEvent, emit_job_event, job_event_store
from app.services.job_service import JobService, analysis_executor, dispatch_queued_jobs
from dynamic.adb.client import AdbResult
from dynamic.runtime.orchestrator import DynamicAnalysisError, DynamicRuntimeOrchestrator


class ConfirmedBugTests(unittest.TestCase):
    def test_live_cache_is_global_and_cache_only_ids_cannot_collide_with_database_ids(self) -> None:
        store = JobEventStore()
        store.MAX_CACHED_EVENTS = 2
        store.publish("job-a", "one", "running", "one")
        store.publish("job-b", "two", "running", "two")
        memory_id = store.snapshot("job-a")[0].event_id
        store.publish("job-a", "three", "running", "three", event_id=1, persistent=True)
        self.assertEqual(sum(len(store.snapshot(job)) for job in ("job-a", "job-b")), 2)
        self.assertNotEqual(memory_id, 1)
        self.assertLess(memory_id, 0)

    def test_sse_merge_and_reconnect_handles_negative_cache_and_positive_persistent_ids(self) -> None:
        job_id = "mixed-event-id-history"
        job_event_store.clear(job_id)
        emit_job_event(job_id, "cache-first", "running", "Cache first")
        first_id = job_event_store.snapshot(job_id)[0].event_id
        emit_job_event(job_id, "cache-newer", "running", "Cache newer")
        persisted = JobStageEvent(10, "database-event", "completed", "Database event")
        with patch("app.api.routes.jobs._persistent_events", return_value=[persisted]):
            initial = _events_after(job_id)
            reconnect = _events_after(job_id, after_event_id=first_id)
        self.assertEqual([event.stage for event in initial], ["cache-first", "cache-newer", "database-event"])
        self.assertEqual([event.stage for event in reconnect], ["cache-newer", "database-event"])
        job_event_store.clear(job_id)

    def test_job_history_listing_has_no_persistent_50_item_cap(self) -> None:
        db = MagicMock()
        db.scalars.return_value.all.return_value = []
        JobService(db, Settings()).list_jobs()
        statement = db.scalars.call_args.args[0]
        self.assertIsNone(statement._limit_clause)

    def test_event_history_is_durable_and_cache_cleanup_is_recoverable(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)
        db = session_factory()
        job_id = "durable-history"
        job_event_store.clear(job_id)
        for index in range(3):
            emit_job_event(job_id, f"stage-{index}", "running", f"Stage {index}", db=db)

        original_limit = job_event_store.MAX_CACHED_EVENTS
        job_event_store.MAX_CACHED_EVENTS = 2
        try:
            emit_job_event(job_id, "stage-3", "completed", "Done", db=db)
            emit_job_event(job_id, "job_completed", "completed", "Finished", db=db)
            self.assertEqual(len(job_event_store.snapshot(job_id)), 2)
            context = MagicMock()
            context.__enter__.return_value = db
            context.__exit__.return_value = False
            with patch("app.api.routes.jobs.SessionLocal", return_value=context):
                recovered = _events_after(job_id)
                reconnected = _events_after(job_id, after_event_id=recovered[1].event_id)
            self.assertEqual(len(recovered), 5)
            self.assertEqual([event.event_id for event in recovered], sorted(event.event_id for event in recovered))
            self.assertEqual([event.event_id for event in reconnected], [event.event_id for event in recovered[2:]])
            self.assertEqual(recovered[-1].stage, "job_completed")
        finally:
            job_event_store.MAX_CACHED_EVENTS = original_limit
            job_event_store.clear(job_id)
            db.close()

    def test_multiple_sse_clients_recover_history_after_cache_cleanup(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        job_id = "concurrent-history"
        job_event_store.clear(job_id)
        emit_job_event(job_id, "job_started", "running", "Started", db=db)
        emit_job_event(job_id, "job_completed", "completed", "Finished", db=db)
        job_event_store.clear(job_id)
        job = SimpleNamespace(status=AnalysisJobStatus.completed, current_step="Finished", error_message=None)
        request_db = MagicMock()
        request_db.get.return_value = job
        context = MagicMock()
        context.__enter__.return_value = db
        context.__exit__.return_value = False
        with patch("app.api.routes.jobs.SessionLocal", return_value=context):
            first = stream_job_events(job_id, db=request_db, settings=Settings())
            second = stream_job_events(job_id, db=request_db, settings=Settings())

            async def collect(response: object) -> list[bytes]:
                return [chunk async for chunk in response.body_iterator]

            async def collect_both() -> tuple[list[bytes], list[bytes]]:
                return await asyncio.gather(collect(first), collect(second))

            first_chunks, second_chunks = asyncio.run(collect_both())
        self.assertEqual(len(first_chunks), 2)
        self.assertEqual(len(second_chunks), 2)
        self.assertIn("job_started", first_chunks[0])
        self.assertIn("job_completed", second_chunks[1])
        job_event_store.clear(job_id)
        db.close()

    def test_analysis_concurrency_limit_and_queued_dispatch(self) -> None:
        settings = SimpleNamespace(max_concurrent_analysis_jobs=2)
        self.assertEqual(analysis_executor(settings)._max_workers, 2)

        fake_db = MagicMock()
        fake_db.execute.side_effect = [
            SimpleNamespace(first=lambda: SimpleNamespace(id="queued-1", created_at=1)),
            SimpleNamespace(first=lambda: None),
            SimpleNamespace(first=lambda: SimpleNamespace(id="queued-2", created_at=2)),
            SimpleNamespace(first=lambda: None),
        ]
        context = MagicMock()
        context.__enter__.return_value = fake_db
        context.__exit__.return_value = False
        with patch("app.db.session.SessionLocal", return_value=context), \
            patch.object(analysis_executor(settings), "submit", return_value=MagicMock()) as submit:
            self.assertEqual(dispatch_queued_jobs(settings), 2)
        self.assertEqual(submit.call_count, 2)
        self.assertEqual(fake_db.execute.call_count, 4)

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
            patch("app.api.routes.jobs.asyncio.to_thread", new=AsyncMock(return_value=[])):
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
                patch("app.api.routes.jobs.asyncio.to_thread", new=AsyncMock(return_value=[])), \
                patch("app.api.routes.jobs.TERMINAL_EVENT_GRACE_SECONDS", 0.0):
                response = stream_job_events(terminal_id, db=initial_db, settings=Settings())

                async def collect_terminal() -> list[bytes]:
                    return [chunk async for chunk in response.body_iterator]

                terminal_chunks = asyncio.run(collect_terminal())
            self.assertEqual(len(terminal_chunks), 1)
            self.assertIn(f"job_{terminal_status.value}", terminal_chunks[0])
            job_event_store.clear(terminal_id)

    def test_sse_job_started_then_each_terminal_event_preserves_order(self) -> None:
        for terminal_status in (AnalysisJobStatus.completed, AnalysisJobStatus.failed, AnalysisJobStatus.cancelled):
            job_id = f"ordered-{terminal_status.value}"
            job = SimpleNamespace(status=terminal_status, current_step="Finished", error_message=None)
            initial_db = MagicMock()
            initial_db.get.return_value = job
            state_db = MagicMock()
            state_db.get.return_value = job
            session = MagicMock()
            session.__enter__.return_value = state_db
            session.__exit__.return_value = False
            job_event_store.clear(job_id)
            emit_job_event(job_id, "job_started", "running", "Started")
            emit_job_event(job_id, f"job_{terminal_status.value}", terminal_status.value, "Finished")
            with patch("app.api.routes.jobs.SessionLocal", return_value=session), \
                patch("app.api.routes.jobs.asyncio.to_thread", new=AsyncMock(return_value=[])):
                response = stream_job_events(job_id, db=initial_db, settings=Settings())

                async def collect_ordered() -> list[bytes]:
                    return [chunk async for chunk in response.body_iterator]

                chunks = asyncio.run(collect_ordered())
            self.assertEqual(len(chunks), 2)
            self.assertIn("job_started", chunks[0])
            self.assertIn(f"job_{terminal_status.value}", chunks[1])
            job_event_store.clear(job_id)

    def test_sse_waits_for_event_published_after_terminal_database_state(self) -> None:
        job_id = "database-before-event"
        job = SimpleNamespace(status=AnalysisJobStatus.failed, current_step="Failed", error_message="failure")
        initial_db = MagicMock()
        initial_db.get.return_value = job
        state_db = MagicMock()
        state_db.get.return_value = job
        session = MagicMock()
        session.__enter__.return_value = state_db
        session.__exit__.return_value = False
        job_event_store.clear(job_id)
        emit_job_event(job_id, "job_started", "running", "Started")

        async def publish_after_database_state(_function: object, *_args: object) -> list[object]:
            emit_job_event(job_id, "job_failed", "failed", "Failed", "failure")
            return []

        with patch("app.api.routes.jobs.SessionLocal", return_value=session), \
            patch("app.api.routes.jobs.asyncio.to_thread", new=publish_after_database_state):
            response = stream_job_events(job_id, db=initial_db, settings=Settings())

            async def collect_race() -> list[bytes]:
                return [chunk async for chunk in response.body_iterator]

            chunks = asyncio.run(collect_race())
        self.assertEqual(len(chunks), 2)
        self.assertIn("job_started", chunks[0])
        self.assertIn("job_failed", chunks[1])
        job_event_store.clear(job_id)

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
