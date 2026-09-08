"""Process-wide Compliance API pacing and bounded throttling retries."""
import asyncio
import math
import time
import weakref
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


def retry_delay(value, fallback):
    try:
        delay = float(value)
    except (ValueError, TypeError):
        try:
            delay = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return fallback
    return max(0, delay) if math.isfinite(delay) else fallback


class ComplianceGate:
    def __init__(self, interval=0.25, retries=5, clock=time.monotonic, sleep=asyncio.sleep):
        self.interval = interval
        self.retries = retries
        self.clock = clock
        self.sleep = sleep
        self.lock = asyncio.Lock()
        self.next_request = 0

    async def get(self, client, url, **kwargs):
        for attempt in range(self.retries + 1):
            # Hold the shared gate through the response so every worker observes
            # a 429 cooldown before another request can start.
            async with self.lock:
                await self.sleep(max(0, self.next_request - self.clock()))
                self.next_request = self.clock() + self.interval
                response = await client.get(url, **kwargs)
                if response.status_code == 429:
                    delay = retry_delay(response.headers.get("retry-after"), min(60, 2 ** (attempt + 1)))
                    self.next_request = max(self.next_request, self.clock() + delay)
            if response.status_code != 429:
                return response
        return response


_gates = weakref.WeakKeyDictionary()


def compliance_gate():
    # Async locks must not be shared between separate application/test loops.
    loop = asyncio.get_running_loop()
    if loop not in _gates:
        _gates[loop] = ComplianceGate()
    return _gates[loop]
