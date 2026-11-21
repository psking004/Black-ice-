from __future__ import annotations

import threading
from collections import defaultdict


class TaskLockRegistry:
    """Process-local serialization; deployment must use one worker until shared locking exists."""

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: defaultdict[str, threading.RLock] = defaultdict(threading.RLock)

    def for_task(self, task_id: str) -> threading.RLock:
        with self._guard:
            return self._locks[task_id]
