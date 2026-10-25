from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import unittest
import json
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.routes.jobs import _events_after, _resolve_storage_file, stream_job_events, view_job_artifact
from app.api.routes.dynamic import _manager, start_dynamic_analysis
from app.core.config import Settings
from app.db.base import AnalysisArtifact, AnalysisEvidence, AnalysisFinding, AnalysisJob, AnalysisJobStage, AnalysisJobStatus, AnalysisReasoning, AnalysisReport, ArtifactType, Base, EvidenceCategory, FindingSeverity
from app.services.job_events import JobEventStore, JobStageEvent, emit_job_event, job_event_store
from app.services.job_service import JobRunner, JobService, _job_finished, _submitted_jobs, analysis_executor, cleanup_interrupted_jobs, dispatch_queued_jobs
from ai.reasoning import AttackPath, ReasoningResult
from analysis.decompilation import DecompilationResult
from analysis.evidence import EvidenceItem
from analysis.findings import FindingCandidate
from dynamic.adb.client import AdbResult
from dynamic.runtime.orchestrator import DynamicAnalysisError, DynamicRuntimeOrchestrator


class ConfirmedBugTests(unittest.TestCase):
    def test_empty_step_artifact_view_explains_filtered_log(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            step = root / "workspace" / "dynamic" / "steps" / "01-check.txt"
            step.parent.mkdir(parents=True)
            step.write_text("", encoding="utf-8")
            artifact_query = MagicMock()
            artifact_query.filter.return_value.first.return_value = SimpleNamespace(
                path=str(step), tool_name="adb-logcat-step"
            )
            db = MagicMock()
            db.get.return_value = SimpleNamespace(id="job-1")
            db.query.return_value = artifact_query
            response = view_job_artifact("job-1", "artifact-1", db, SimpleNamespace(storage_root=root))
        self.assertIn(b"No target-matching logcat lines", response.body)
        self.assertIn(b"not a missing artifact", response.body)

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

    def test_concurrent_database_claim_allows_only_one_worker(self) -> None:
        with TemporaryDirectory() as temp:
            engine = create_engine(f"sqlite+pysqlite:///{Path(temp) / 'claim.db'}")
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            with sessions() as db:
                db.add(AnalysisJob(
                    id="claim-job",
                    original_filename="claim.apk",
                    stored_filename="claim.apk",
                    apk_path="/tmp/claim.apk",
                    file_size_bytes=1,
                    status=AnalysisJobStatus.queued,
                    current_step="Queued",
                ))
                db.commit()

            def claim() -> bool:
                with sessions() as db:
                    return JobRunner._claim_job(db, "claim-job")

            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(lambda _index: claim(), (1, 2)))
            self.assertEqual(sum(results), 1)
            with sessions() as db:
                self.assertEqual(db.get(AnalysisJob, "claim-job").status, AnalysisJobStatus.running)

    def test_normal_worker_rejects_already_running_job(self) -> None:
        db = MagicMock()
        db.get.return_value = SimpleNamespace(status=AnalysisJobStatus.running)
        context = MagicMock()
        context.__enter__.return_value = db
        context.__exit__.return_value = False
        with patch("app.db.session.SessionLocal", return_value=context), patch.object(JobRunner, "_claim_job") as claim:
            JobRunner(SimpleNamespace()).prepare_uploaded_apk("already-running")
        claim.assert_not_called()

    def test_restart_requeues_interrupted_work_without_deleting_it(self) -> None:
        with TemporaryDirectory() as temp:
            engine = create_engine(f"sqlite+pysqlite:///{Path(temp) / 'restart.db'}")
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            with sessions() as db:
                db.add(AnalysisJob(
                    id="restart-job",
                    original_filename="restart.apk",
                    stored_filename="restart.apk",
                    apk_path="/tmp/restart.apk",
                    file_size_bytes=1,
                    status=AnalysisJobStatus.running,
                    current_step="Running JADX",
                ))
                db.commit()
            context = MagicMock()
            session = sessions()
            context.__enter__.return_value = session
            context.__exit__.side_effect = lambda *_args: session.close()
            with patch("app.db.session.SessionLocal", return_value=context):
                self.assertEqual(cleanup_interrupted_jobs(SimpleNamespace()), 1)
            with sessions() as db:
                recovered = db.get(AnalysisJob, "restart-job")
                self.assertEqual(recovered.status, AnalysisJobStatus.queued)
                self.assertTrue(Path(recovered.apk_path).name == "restart.apk")

    def test_restart_recovers_only_interrupted_dynamic_runs(self) -> None:
        with TemporaryDirectory() as temp:
            engine = create_engine(f"sqlite+pysqlite:///{Path(temp) / 'dynamic-restart.db'}")
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            with sessions() as db:
                db.add(AnalysisJob(
                    id="dynamic-restart-job",
                    original_filename="dynamic.apk",
                    stored_filename="dynamic.apk",
                    apk_path="/tmp/dynamic.apk",
                    file_size_bytes=1,
                    sha256="a" * 64,
                    status=AnalysisJobStatus.completed,
                    current_step="Static reports generated",
                ))
                db.add_all([
                    AnalysisJobStage(job_id="dynamic-restart-job", stage="dynamic_run", status="running", message="running", detail="active"),
                    AnalysisJobStage(job_id="dynamic-restart-job", stage="dynamic_run", status="completed", message="done", detail="complete"),
                    AnalysisJobStage(job_id="dynamic-restart-job", stage="dynamic_run", status="failed", message="failed", detail="failure"),
                ])
                db.commit()
            session = sessions()
            context = MagicMock()
            context.__enter__.return_value = session
            context.__exit__.side_effect = lambda *_args: session.close()
            with patch("app.db.session.SessionLocal", return_value=context):
                self.assertEqual(cleanup_interrupted_jobs(SimpleNamespace()), 1)
            with sessions() as db:
                stages = db.query(AnalysisJobStage).order_by(AnalysisJobStage.created_at.asc()).all()
                self.assertEqual([stage.status for stage in stages], ["failed", "completed", "failed"])
                self.assertEqual(stages[0].message, "DY-MASA analysis interrupted by backend restart")
            session2 = sessions()
            context2 = MagicMock()
            context2.__enter__.return_value = session2
            context2.__exit__.side_effect = lambda *_args: session2.close()
            with patch("app.db.session.SessionLocal", return_value=context2):
                self.assertEqual(cleanup_interrupted_jobs(SimpleNamespace()), 0)
            with sessions() as db:
                self.assertEqual(db.query(AnalysisJobStage).count(), 3)
            with sessions() as db, patch("app.api.routes.dynamic.submit_dynamic_job", return_value=True):
                response = start_dynamic_analysis("dynamic-restart-job", db=db, settings=Settings())
                self.assertEqual(response["status"], "accepted")

    def test_dynamic_evidence_and_artifacts_deduplicate_only_identical_records(self) -> None:
        with TemporaryDirectory() as temp:
            engine = create_engine(f"sqlite+pysqlite:///{Path(temp) / 'dynamic-dedupe.db'}")
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            with sessions() as db:
                job = AnalysisJob(
                    id="dynamic-dedupe-job",
                    original_filename="dynamic.apk",
                    stored_filename="dynamic.apk",
                    apk_path="/tmp/dynamic.apk",
                    file_size_bytes=1,
                    status=AnalysisJobStatus.completed,
                    current_step="Complete",
                )
                db.add(job)
                db.commit()
                orchestrator = DynamicRuntimeOrchestrator(SimpleNamespace(), adb=MagicMock(), manager=MagicMock())
                orchestrator._record_evidence(db, job, "dynamic_test", "same", {"path": "a", "value": 1})
                orchestrator._record_evidence(db, job, "dynamic_test", "same", {"path": "a", "value": 1})
                orchestrator._record_evidence(db, job, "dynamic_test", "different", {"path": "a", "value": 1})
                orchestrator._record_artifact(db, job, Path(temp) / "step.txt", "adb-logcat-step", 0)
                orchestrator._record_artifact(db, job, Path(temp) / "step.txt", "adb-logcat-step", 0)
                orchestrator._record_artifact(db, job, Path(temp) / "other.txt", "adb-logcat-step", 0)
                self.assertEqual(db.query(AnalysisEvidence).count(), 2)
                self.assertEqual(db.query(AnalysisArtifact).count(), 2)

    def test_worker_failure_releases_slot_and_dispatches_next_job(self) -> None:
        settings = SimpleNamespace(max_concurrent_analysis_jobs=1)
        _submitted_jobs.add("failed-worker")
        with patch("app.services.job_service._dispatch_available") as dispatch:
            _job_finished("failed-worker", settings)
        self.assertNotIn("failed-worker", _submitted_jobs)
        dispatch.assert_called_once_with(settings)

    def test_retry_persistence_deduplicates_partial_records_without_deleting_history(self) -> None:
        with TemporaryDirectory() as temp:
            engine = create_engine(f"sqlite+pysqlite:///{Path(temp) / 'retry.db'}")
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            source = Path(temp) / "AndroidManifest.xml"
            source.write_text("<manifest />", encoding="utf-8")
            job = AnalysisJob(
                id="retry-job",
                original_filename="retry.apk",
                stored_filename="retry.apk",
                apk_path="/tmp/retry.apk",
                file_size_bytes=1,
                status=AnalysisJobStatus.queued,
                current_step="Queued",
            )
            evidence = EvidenceItem(EvidenceCategory.manifest, "manifest_metadata", "Manifest", {"package": "x"}, source, "manifest")
            finding = FindingCandidate("retry-rule", "Retry finding", FindingSeverity.info, "Test", "fact", "review", ["evidence"])
            reasoning = ReasoningResult("deterministic", "summary", [AttackPath("path", ["step"], ["evidence"])], "limits")
            decompilation = DecompilationResult("apktool", Path(temp) / "decoded", Path(temp) / "apktool.log", 0, True)
            with sessions() as db:
                db.add(job)
                db.commit()
                JobRunner._record_evidence(db, job, [evidence])
                JobRunner._record_evidence(db, job, [evidence])
                JobRunner._record_findings(db, job, [finding])
                JobRunner._record_findings(db, job, [finding])
                JobRunner._record_reasoning(db, job, reasoning)
                JobRunner._record_reasoning(db, job, reasoning)
                JobRunner._record_decompilation_artifacts(db, job, decompilation, ArtifactType.apktool_output)
                JobRunner._record_decompilation_artifacts(db, job, decompilation, ArtifactType.apktool_output)
                JobRunner._record_report(db, job, "html", Path(temp) / "retry.html")
                JobRunner._record_report(db, job, "html", Path(temp) / "retry.html")
                self.assertEqual(db.query(AnalysisEvidence).count(), 1)
                self.assertEqual(db.query(AnalysisFinding).count(), 1)
                self.assertEqual(db.query(AnalysisReasoning).count(), 1)
                self.assertEqual(db.query(AnalysisArtifact).count(), 2)
                self.assertEqual(db.query(AnalysisReport).count(), 1)

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

    def test_runtime_step_clears_logcat_before_writing_marker(self) -> None:
        with TemporaryDirectory() as temp:
            orchestrator, adb = self._fake_runtime(Path(temp), AdbResult(["adb", "start"], 0, "Status: ok\n", ""))
            adb.start_activity.return_value = AdbResult(["adb", "start"], 0, "Status: ok\n", "")
            item = SimpleNamespace(
                id="component-1",
                category=EvidenceCategory.component,
                evidence_type="activity",
                label=".MainActivity",
                value_json=json.dumps({"name": ".MainActivity", "component_type": "activity", "exported_effective": True}),
            )
            db = MagicMock()
            db.scalars.side_effect = [SimpleNamespace(all=lambda: [item]), SimpleNamespace(all=lambda: [])]
            capture = {"tier_a": [], "tier_b": [], "tier_c": [], "pids": [], "uids": [], "crashes": [], "lines": []}
            with patch.object(orchestrator, "_package_pids", return_value=[]), \
                patch.object(orchestrator, "_save_logcat_capture", return_value=capture), \
                patch.object(orchestrator, "_record_artifact"), patch.object(orchestrator, "_write_lines"), \
                patch.object(orchestrator, "_record_evidence"), patch("dynamic.runtime.orchestrator.time.sleep"):
                orchestrator._validate_static_attack_surface(db, SimpleNamespace(id="job"), "device", "example.app", Path(temp))
            names = [call[0] for call in adb.method_calls]
            self.assertLess(names.index("clear_logcat"), names.index("log_marker"))
            self.assertLess(names.index("log_marker"), names.index("start_activity"))
            self.assertLess(names.index("start_activity"), names.index("dump_logcat"))

    def test_activity_validation_uses_explicit_package_class_syntax(self) -> None:
        self.assertEqual(
            DynamicRuntimeOrchestrator._explicit_activity_component(
                "b3nac.injuredandroid", "b3nac.injuredandroid.MainActivity"
            ),
            "b3nac.injuredandroid/b3nac.injuredandroid.MainActivity",
        )
        self.assertIsNone(DynamicRuntimeOrchestrator._explicit_activity_component("pkg", "Main Activity"))
        self.assertIsNone(DynamicRuntimeOrchestrator._explicit_activity_component("pkg", "other.Main"))

    def test_code_risk_validation_does_not_execute_true(self) -> None:
        with TemporaryDirectory() as temp:
            orchestrator, adb = self._fake_runtime(Path(temp), AdbResult(["adb"], 0, "", ""))
            item = SimpleNamespace(
                id="risk-1",
                category=EvidenceCategory.code_risk,
                evidence_type="cleartext_http_endpoint",
                label="HTTP endpoint",
                value_json=json.dumps({"description": "risk"}),
            )
            db = MagicMock()
            db.scalars.side_effect = [SimpleNamespace(all=lambda: [item]), SimpleNamespace(all=lambda: [])]
            with patch.object(orchestrator, "_record_evidence") as record, patch.object(orchestrator, "_record_artifact"):
                orchestrator._validate_static_attack_surface(db, SimpleNamespace(id="job"), "device", "example.app", Path(temp))
            self.assertFalse(any(call[0] == "shell" for call in adb.method_calls))
            self.assertTrue(record.called)

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
