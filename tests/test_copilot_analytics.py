import io
import unittest
from unittest.mock import patch
import httpx
from app import copilot_analytics as analytics
from app.compliance_http import ComplianceGate
from app.report_charts import charts_html
from app.executive_reporting import executive_xlsx
from openpyxl import load_workbook

class CopilotAnalyticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_graph_contract_and_exports(self):
        requests=[]
        def respond(request):
            requests.append(request)
            row={'anyAppActiveUsers':8,'anyAppEnabledUsers':12,'wordActiveUsers':5,'wordEnabledUsers':12}
            if 'Trend' in request.url.path:
                data={'reportRefreshDate':'2026-09-06','reportPeriod':30,'adoptionByDate':[{'reportDate':'2026-09-05',**row}]}
            else:data={'reportRefreshDate':'2026-09-06','adoptionByProduct':[{'reportPeriod':30,**row}]}
            return httpx.Response(200,json={'value':[data]})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            with patch.object(analytics,'compliance_gate',return_value=ComplianceGate(interval=0)):
                data=await analytics.collect(client,'test-token',30)
        self.assertEqual(data['summary']['copilot_active_users'],8)
        self.assertNotIn('copilot_interactions',data['summary'])
        self.assertNotIn('claude_requests',data['summary'])
        self.assertEqual(data['report_refresh_date'],'2026-09-06')
        self.assertIn('last 30 days',data['period'])
        self.assertTrue(all(r.headers['authorization']=='Bearer test-token' for r in requests))
        self.assertTrue(all('/v1.0/copilot/reports/' in r.url.path for r in requests))
        self.assertIn('Copilot active users by app',charts_html(data))
        self.assertIn('Copilot daily active users',charts_html(data))
        book=load_workbook(io.BytesIO(executive_xlsx(data)))
        self.assertEqual(len(book['Copilot users by app']._charts),1)

    def test_csv_response(self):
        response=httpx.Response(200,content=b'\xef\xbb\xbfReport Refresh Date,Report Period,Any App Active Users,Any App Enabled Users,Microsoft Teams Active Users\n2026-09-06,30,8,12,4\n',headers={'content-type':'application/octet-stream'})
        row=analytics.parse(response)[0]
        self.assertEqual(row['microsoftTeamsActiveUsers'],'4')
        self.assertEqual(row['anyAppActiveUsers'],'8')

    async def test_access_denied(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(403))) as client:
            with patch.object(analytics,'compliance_gate',return_value=ComplianceGate(interval=0)):
                with self.assertRaises(httpx.HTTPStatusError):await analytics.collect(client,'test',30)

    async def test_inconsistent_refresh_not_published(self):
        from unittest.mock import AsyncMock
        with patch.object(analytics,'fetch',AsyncMock(side_effect=[[{'reportPeriod':30,'reportRefreshDate':'2026-09-06'}],[{'reportPeriod':30,'reportRefreshDate':'2026-09-05'}]])):
            with self.assertRaises(ValueError):await analytics.collect(None,'test',30)
