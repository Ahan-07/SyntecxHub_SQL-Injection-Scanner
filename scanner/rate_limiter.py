import threading
import time


class RateLimiter:
    def __init__(self, rate_per_second: float):
        self.rate = rate_per_second
        self.interval = 1.0 / rate_per_second if rate_per_second > 0 else 0
        self._lock = threading.Lock()
        self._next_time = time.monotonic()
        self.count = 0

    def wait(self):
        with self._lock:
            now = time.monotonic()

            if self.rate > 0 and now < self._next_time:
                time.sleep(self._next_time - now)

            now = time.monotonic()

            if self.rate > 0:
                self._next_time = max(now, self._next_time) + self.interval

            self.count += 1
