from __future__ import annotations

import queue
import time
from dataclasses import dataclass


@dataclass(slots=True)
class LogEvent:
    level: str
    message: str
    created_at: float


class LogBus:
    def __init__(self) -> None:
        self._queue: queue.Queue[LogEvent] = queue.Queue()

    def write(self, level: str, message: str) -> None:
        self._queue.put(
            LogEvent(
                level=str(level or "info").lower(),
                message=str(message or "").strip(),
                created_at=time.time(),
            )
        )

    def drain(self) -> list[LogEvent]:
        events: list[LogEvent] = []
        while True:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events
