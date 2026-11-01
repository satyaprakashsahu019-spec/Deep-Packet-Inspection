"""
Thread-safe queue with capacity limit and shutdown signaling.
Corresponds to include/thread_safe_queue.h.
"""

from __future__ import annotations
import queue
import threading
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


class ThreadSafeQueue(Generic[T]):
    """
    Thread-safe bounded queue for passing packets between Reader -> LB -> FP -> Output.
    """

    def __init__(self, max_size: int = 10000) -> None:
        self.max_size = max_size
        self._queue: queue.Queue = queue.Queue(maxsize=max_size)
        self._shutdown = threading.Event()

    def push(self, item: T) -> bool:
        """Push item to queue. Blocks if full; returns False if shutdown."""
        while not self._shutdown.is_set():
            try:
                self._queue.put(item, timeout=0.1)
                return True
            except queue.Full:
                continue
        return False

    def try_push(self, item: T) -> bool:
        """Try to push item without blocking. Returns False if full or shutdown."""
        if self._shutdown.is_set():
            return False
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            return False

    def pop(self, timeout: Optional[float] = None) -> Optional[T]:
        """Pop item from queue. Returns None on timeout or if shutdown with empty queue."""
        timeout_to_use = 0.1 if timeout is None else timeout
        try:
            return self._queue.get(timeout=timeout_to_use)
        except queue.Empty:
            return None

    def pop_with_timeout(self, timeout_seconds: float) -> Optional[T]:
        return self.pop(timeout=timeout_seconds)

    def shutdown(self) -> None:
        """Signal queue shutdown to unblock waiting threads."""
        self._shutdown.set()

    def is_shutdown(self) -> bool:
        return self._shutdown.is_set()

    def empty(self) -> bool:
        return self._queue.empty()

    def size(self) -> int:
        return self._queue.qsize()
