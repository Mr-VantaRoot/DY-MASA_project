from __future__ import annotations

from collections import defaultdict, deque
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
    cursor: str = ""


class JobEventStore:
    # This is only a live notification cache. Durable events remain in the DB.
    MAX_CACHED_EVENTS = 2048

    def __init__(self) -> None:
        self._history: dict[str, list[JobStageEvent]] = defaultdict(list)
        self._database_sequence = 0
        self._memory_sequence = -1
        self._cache_order: deque[tuple[str, int]] = deque()
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
                # Cache-only events use a separate negative namespace. Production
                # events use PostgreSQL/SQLite's positive global primary key.
                event_id = self._memory_sequence
                self._memory_sequence -= 1
            else:
                self._database_sequence = max(self._database_sequence, event_id)
            event = JobStageEvent(
                event_id=event_id,
                stage=stage,
                status=status,
                message=message,
                detail=detail,
                timestamp=timestamp or datetime.utcnow().isoformat(timespec="seconds"),
            )
            self._history[job_id].append(event)
            self._cache_order.append((job_id, event_id))
            cached_count = sum(len(events) for events in self._history.values())
            while cached_count > self.MAX_CACHED_EVENTS:
                if not self._cache_order:
                    break
                oldest_job, oldest_id = self._cache_order.popleft()
                events = self._history.get(oldest_job, [])
                for index, candidate in enumerate(events):
                    if candidate.event_id == oldest_id:
                        events.pop(index)
                        cached_count -= 1
                        break
                if not events:
                    self._history.pop(oldest_job, None)
            self._condition.notify_all()

    def snapshot(self, job_id: str, after_event_id: int = 0) -> list[JobStageEvent]:
        with self._condition:
            return [event for event in self._history.get(job_id, []) if self._after(event.event_id, after_event_id)]

    def clear(self, job_id: str) -> None:
        with self._condition:
            self._history.pop(job_id, None)
            self._cache_order = deque(candidate for candidate in self._cache_order if candidate[0] != job_id)
            # Clear is intentionally cache-only and never touches durable history.
            self._condition.notify_all()

    def wait_for(self, job_id: str, after_event_id: int | str = 0, timeout_seconds: float = 2.0) -> list[JobStageEvent]:
        with self._condition:
            deadline = datetime.utcnow().timestamp() + timeout_seconds
            while True:
                new_events = [event for event in self._history.get(job_id, []) if self._after_cursor(event.event_id, after_event_id)]
                if new_events:
                    return new_events
                remaining = deadline - datetime.utcnow().timestamp()
                if remaining <= 0:
                    return []
                self._condition.wait(timeout=remaining)

    @staticmethod
    def _after(event_id: int, after_event_id: int) -> bool:
        # Negative IDs belong to the isolated cache-only namespace. They must
        # still be visible to a fresh stream, while positive persisted IDs use
        # normal Last-Event-ID ordering.
        if event_id < 0 and after_event_id < 0:
            return event_id < after_event_id
        return event_id > after_event_id or (after_event_id == 0 and event_id < 0)

    @classmethod
    def _after_cursor(cls, event_id: int, cursor: int | str) -> bool:
        if isinstance(cursor, str) and cursor.startswith("p:"):
            try:
                parts = dict(part.split(":", 1) for part in cursor.split(";") if ":" in part)
                persisted = int(parts.get("p", 0))
                memory = int(parts.get("m", 0))
                return (event_id < 0 and abs(event_id) > memory) or (event_id >= 0 and event_id > persisted)
            except (TypeError, ValueError):
                return True
        return cls._after(event_id, int(cursor))


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
        "cursor": event.cursor,
    }
