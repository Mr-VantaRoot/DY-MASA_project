from __future__ import annotations

from threading import Event, Lock


class JobCancelled(RuntimeError):
    """Raised when a running APK analysis job is cancelled by the user."""


class JobCancellationRegistry:
    def __init__(self) -> None:
        self._events: dict[str, Event] = {}
        self._lock = Lock()

    def register(self, job_id: str) -> Event:
        with self._lock:
            event = self._events.get(job_id)
            if event is None:
                event = Event()
                self._events[job_id] = event
            return event

    def cancel(self, job_id: str) -> None:
        with self._lock:
            event = self._events.get(job_id)
            if event is None:
                event = Event()
                self._events[job_id] = event
            event.set()

    def is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            event = self._events.get(job_id)
            return bool(event and event.is_set())

    def clear(self, job_id: str) -> None:
        with self._lock:
            self._events.pop(job_id, None)


job_cancellation_registry = JobCancellationRegistry()
