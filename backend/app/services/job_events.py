from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from threading import Condition, Lock
from typing import Any

from sqlalchemy.orm import Session

from app.db.base import AnalysisJobEvent


@dataclass(frozen=True)
class JobStageEvent:
    event_id: int
    stage: str
    status: str
    message: str
    detail: str | None = None
    timestamp: str = ""


class JobEventStore:
    MAX_CACHED_EVENTS_PER_JOB = 512

    def __init__(self) -> None:
        self._history: dict[str, list[JobStageEvent]] = defaultdict(list)
        self._sequence = 0
        self._lock = Lock()
        self._condition = Condition(self._lock)

    def publish(
        self,
        job_id: str,
        stage: str,
        status: str,
        message: str,
        detail: str | None = None,
        event_id: int | None = None,
        timestamp: str | None = None,
        persistent: bool = False,
    ) -> None:
        with self._condition:
            if event_id is None:
                self._sequence += 1
                event_id = self._sequence
            else:
                self._sequence = max(self._sequence, event_id)
            event = JobStageEvent(
                event_id=event_id,
                stage=stage,
                status=status,
                message=message,
                detail=detail,
                timestamp=timestamp or datetime.utcnow().isoformat(timespec="seconds"),
            )
            self._history[job_id].append(event)
            if persistent and len(self._history[job_id]) > self.MAX_CACHED_EVENTS_PER_JOB:
                self._history[job_id] = self._history[job_id][-self.MAX_CACHED_EVENTS_PER_JOB :]
            self._condition.notify_all()

    def snapshot(self, job_id: str, after_event_id: int = 0) -> list[JobStageEvent]:
        with self._condition:
            return [event for event in self._history.get(job_id, []) if event.event_id > after_event_id]

    def clear(self, job_id: str) -> None:
        with self._condition:
            self._history.pop(job_id, None)
            self._condition.notify_all()

    def wait_for(self, job_id: str, after_event_id: int = 0, timeout_seconds: float = 2.0) -> list[JobStageEvent]:
        with self._condition:
            deadline = datetime.utcnow().timestamp() + timeout_seconds
            while True:
                new_events = [event for event in self._history.get(job_id, []) if event.event_id > after_event_id]
                if new_events:
                    return new_events
                remaining = deadline - datetime.utcnow().timestamp()
                if remaining <= 0:
                    return []
                self._condition.wait(timeout=remaining)


job_event_store = JobEventStore()


def emit_job_event(
    job_id: str,
    stage: str,
    status: str,
    message: str,
    detail: str | None = None,
    db: Session | None = None,
) -> None:
    """Persist an event before publishing it to the live cache when a DB is supplied.

    Direct callers without a session retain the lightweight in-memory behavior used by
    isolated tooling/tests; application lifecycle callers pass their active session.
    """
    if db is not None:
        event = AnalysisJobEvent(
            job_id=job_id,
            stage=stage,
            status=status,
            message=message,
            detail=detail,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        job_event_store.publish(
            job_id,
            stage,
            status,
            message,
            detail,
            event_id=event.event_id,
            timestamp=event.created_at.isoformat(timespec="seconds"),
            persistent=True,
        )
        return
    job_event_store.publish(job_id, stage, status, message, detail)


def as_event_payload(event: JobStageEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "stage": event.stage,
        "status": event.status,
        "message": event.message,
        "detail": event.detail,
        "timestamp": event.timestamp,
    }
