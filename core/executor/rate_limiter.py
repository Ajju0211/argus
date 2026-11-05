"""Tool execution rate and concurrency limiter for ARGUS.

Enforces the operational throttles declared in the scope document so a single
assessment cannot burst through the authorized request rate or exceed the
configured concurrent tool executions.
"""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager


class ToolRateLimiter:
    """Thread-safe token-spacing limiter with a concurrency cap."""

    def __init__(self, max_requests_per_second: int = 20, max_concurrency: int = 2) -> None:
        self.max_requests_per_second = max(1, int(max_requests_per_second))
        self.max_concurrency = max(1, int(max_concurrency))
        self._min_interval = 1.0 / self.max_requests_per_second
        self._concurrency = threading.BoundedSemaphore(self.max_concurrency)
        self._clock_lock = threading.Lock()
        self._last_start = 0.0

    @contextmanager
    def limit(self) -> Iterator[None]:
        """Blocks until the next request is allowed and a concurrency slot is free."""
        with self._concurrency:
            with self._clock_lock:
                now = time.monotonic()
                wait_for = self._min_interval - (now - self._last_start)
                if wait_for > 0:
                    time.sleep(wait_for)
                self._last_start = time.monotonic()
            yield
