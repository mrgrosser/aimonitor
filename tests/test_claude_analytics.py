import unittest
from datetime import datetime,timezone
from unittest.mock import patch
import httpx
from app.claude_analytics import collect,pages,months
from app.compliance_http import ComplianceGate

class AnalyticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_live_totals_use_ungrouped_pages_and_count_users(self):
        calls=[]
        def respond(request):
            calls.append(request)
            if 'user_usage' in request.url.path:
                return httpx.Response(200,json={'data':[{'actor':{'user_id':'a'},'requests':2},{'actor':{'user_id':'b'},'requests':0}], 'has_more':False})
            cost='cost_report' in request.url.path
            row={'amount':'12.34','currency':'USD'} if cost else {'requests':9}
            dimension=request.url.params.get('group_by[]')
            if dimension:row[dimension]='chat' if dimension=='product' else 'model';row['amount' if cost else 'requests']='1' if cost else 1
            return httpx.Response(200,json={'data':[{'starting_at':'2026-08-01T00:00:00Z','results':[row]}],'has_more':False})
        async with httpx.AsyncClient(base_url='https://example.test',transport=httpx.MockTransport(respond)) as client:
            with patch('app.claude_analytics.compliance_gate',return_value=ComplianceGate(interval=0)):
                data=await collect(client,datetime(2026,8,1,tzinfo=timezone.utc),datetime(2026,9,1,tzinfo=timezone.utc))
        self.assertEqual(data['summary']['claude_usage_spend'],12.34)
        self.assertEqual(data['summary']['claude_requests'],9)
        self.assertEqual(data['summary']['claude_active_users'],1)
        self.assertNotIn('copilot_interactions',data['summary'])
        self.assertEqual(len(calls),7)
        self.assertEqual(data['mode'],'live')

    async def test_pagination_and_403(self):
        def respond(request):
            if request.url.path=='/denied':return httpx.Response(403)
            second=request.url.params.get('page')=='two'
            return httpx.Response(200,json={'data':[2 if second else 1],'has_more':not second,'next_page':'two'})
        async with httpx.AsyncClient(base_url='https://example.test',transport=httpx.MockTransport(respond)) as client:
            with patch('app.claude_analytics.compliance_gate',return_value=ComplianceGate(interval=0)):
                self.assertEqual(await pages(client,'/ok',{}),[1,2])
                with self.assertRaises(httpx.HTTPStatusError):await pages(client,'/denied',{})

    async def test_repeated_cursor_is_rejected(self):
        async with httpx.AsyncClient(base_url='https://example.test',transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'data':[],'has_more':True,'next_page':'same'}))) as client:
            with patch('app.claude_analytics.compliance_gate',return_value=ComplianceGate(interval=0)):
                with self.assertRaises(ValueError):await pages(client,'/ok',{})

    def test_month_boundaries(self):
        windows=months(datetime(2026,9,8,tzinfo=timezone.utc))
        self.assertEqual(windows[0][0].day,1)
        self.assertEqual(windows[1][0].month,8)
        self.assertTrue(all((b-a).days<=31 and a<b for a,b in windows))

class AnalyticsCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_refresh_keeps_saved_snapshot(self):
        import tempfile,json,asyncio
        from pathlib import Path
        from unittest.mock import AsyncMock
        from app import claude_analytics as analytics
        from app import usage_reporting
        with tempfile.TemporaryDirectory() as directory, patch.object(usage_reporting,'DB_PATH',Path(directory)/'test.db'):
            db=analytics.database()
            db.execute('INSERT INTO claude_analytics VALUES (?,?,?)',('2026-08',json.dumps({'period':'2026-08','collected_at':'2026-08-01T00:00:00+00:00','summary':{'claude_requests':10}}),'old'));db.commit();db.close()
            with patch.object(analytics,'collect',AsyncMock(side_effect=ValueError('failed'))),patch.object(analytics,'sleep',AsyncMock(side_effect=asyncio.CancelledError)):
                with self.assertRaises(asyncio.CancelledError):await analytics.run('fake','https://example.test')
            self.assertEqual(analytics.saved('2026-08')['summary']['claude_requests'],10)
            self.assertEqual(analytics.status['state'],'error')

    def test_live_exports(self):
        import io
        from openpyxl import load_workbook
        from app.executive_reporting import executive_xlsx
        from app.usage_reporting import usage_pdf,usage_html
        data={'mode':'live','period':'2026-08','summary':{'claude_requests':10,'claude_usage_spend':5},'claude_daily':[{'Date':'2026-08-01','Requests':10}], 'claude_products':[{'name':'chat','requests':10,'spend':5}],'executive_sections':[{'name':'Claude Daily Trend','rows':[['Date','Requests'],['2026-08-01',10]]}]}
        self.assertTrue(usage_pdf(data,'test','test').startswith(b'%PDF'))
        self.assertIn('Unavailable',usage_html(data,'test','test'))
        workbook=load_workbook(io.BytesIO(executive_xlsx(data)))
        self.assertEqual(len(workbook['Claude Daily Trend']._charts),1)
