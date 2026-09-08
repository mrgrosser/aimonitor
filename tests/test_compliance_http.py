import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import httpx
from app.compliance_http import ComplianceGate, retry_delay


class ComplianceHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_cooldown_and_same_request_retry(self):
        now = [0.0]
        calls = []
        async def sleep(delay):
            now[0] += delay
            await asyncio.sleep(0)
        async def handle(request):
            calls.append((now[0], str(request.url)))
            return httpx.Response(429, headers={"retry-after": "7"}) if len(calls) == 1 else httpx.Response(200, json={"data": []})
        gate = ComplianceGate(clock=lambda: now[0], sleep=sleep)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            results = await asyncio.gather(gate.get(client, "https://test/a?after_id=cursor"), gate.get(client, "https://test/b"))
        self.assertTrue(all(r.status_code == 200 for r in results))
        self.assertGreaterEqual(calls[1][0], 7)
        self.assertGreaterEqual(calls[2][0] - calls[1][0], .25)
        self.assertEqual(sum(url.endswith("a?after_id=cursor") for _, url in calls), 2)

    async def test_exhaustion_is_bounded_and_preserves_cooldown(self):
        now = [0.0]
        calls = []
        async def sleep(delay):
            now[0] += delay
        async def handle(request):
            calls.append(now[0])
            return httpx.Response(429, headers={"retry-after": "4"})
        gate = ComplianceGate(retries=2, clock=lambda: now[0], sleep=sleep)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            response = await gate.get(client, "https://test/a")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(calls, [0, 4, 8])
        self.assertEqual(gate.next_request, 12)

    async def test_permission_errors_are_not_retried(self):
        calls = []
        async def handle(request):
            calls.append(request)
            return httpx.Response(403)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            response = await ComplianceGate().get(client, "https://test/a")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(calls), 1)

    def test_invalid_retry_headers_use_fallback(self):
        for value in (None, "garbage", "nan", "inf"):
            self.assertEqual(retry_delay(value, 8), 8)
        self.assertEqual(retry_delay("-1", 8), 0)
        self.assertEqual(retry_delay("2.5", 8), 2.5)

    def test_http_date_retry_header(self):
        value=format_datetime(datetime.now(timezone.utc)+timedelta(seconds=30),usegmt=True)
        self.assertGreater(retry_delay(value,8),28)
        self.assertLessEqual(retry_delay(value,8),30)
