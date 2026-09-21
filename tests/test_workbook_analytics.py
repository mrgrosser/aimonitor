import io
import json
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch
import httpx
from openpyxl import load_workbook
from app import purview_analytics as p, usage_directory as d, workbook_reporting as w, claude_analytics as c
from app.compliance_http import ComplianceGate
from app.executive_reporting import executive_xlsx
from app.usage_reporting import usage_csv, usage_html

START=datetime(2026,8,1,tzinfo=timezone.utc)
END=datetime(2026,9,1,tzinfo=timezone.utc)

def event(rid='one',user='a@example.test',when='2026-08-01T12:00:00Z',app='OutlookSidepane'):
    return {'Id':rid,'UserId':user,'CreationTime':when,'Operation':'CopilotInteraction',
            'CopilotEventData':{'AppHost':app,'TargetAgentName':'Draft agent','AccessedResources':[{'Name':'DO NOT RETAIN','Url':'https://private'}]},'Prompt':'DO NOT RETAIN'}

class WorkbookAnalyticsTests(unittest.TestCase):
    def test_audit_metadata_only_and_month_boundaries(self):
        raw=event();row=p.normalize({'auditData':json.dumps(raw)})
        self.assertNotIn('DO NOT RETAIN',json.dumps(row))
        result=p.aggregate([row,row,p.normalize(event('two','b@example.test',app='Office')),p.normalize(event('outside',when='2026-09-01T00:00:00Z'))],START,END)
        self.assertEqual(result['summary']['copilot_interactions'],2)
        self.assertEqual(result['summary']['copilot_active_users'],2)
        self.assertEqual(result['top_users'][0]['active_days'],1)
        self.assertEqual(len(result['copilot_daily']),31)
        self.assertEqual(result['copilot_daily'][1]['Interactions'],0)
        self.assertEqual(result['copilot_detail'][0]['license_type'],'Unknown')
        self.assertEqual(result['copilot_detail'][0]['resources'],1)
        self.assertEqual(result['summary']['agent_interactions'],2)
        result['executive_sections']=w.sections(result)
        names={r['name'] for r in result['executive_sections']}
        self.assertTrue({'Copilot User by App','Copilot Detail','Copilot Daily Trend','Copilot Agents','Copilot App Totals'}<=names)
        book=load_workbook(io.BytesIO(executive_xlsx(result)))
        self.assertEqual(book['Copilot Detail'].max_row,3);book.close()
        self.assertIn('Copilot Detail',usage_csv(result).decode('utf-8-sig'))
        self.assertNotIn('<h2>Copilot Detail</h2>',usage_html(result,'tester','test'))

    def test_conflicting_duplicate_rejected(self):
        with self.assertRaises(ValueError):p.aggregate([p.normalize(event()),p.normalize(event(app='Word'))],START,END)

    def test_usage_and_cost_join_without_counting_cost_as_requests(self):
        actor={'user_id':'one','email':'a@example.test'}
        usage=[{'actor':actor,'product':'chat','model':'model','requests':2,'uncached_input_tokens':10,'cache_read_input_tokens':20,'cache_creation':{'a':5},'output_tokens':4}]
        cost=[{'actor':actor,'product':'chat','model':'model','amount':'125','list_amount':'150','requests':999}]
        details=c.user_detail(usage,cost);users=c.user_rows(details)
        self.assertEqual(users[0]['volume'],2)
        self.assertEqual(users[0]['spend'],1.25)
        self.assertEqual(users[0]['tokens'],39)
        self.assertEqual(details[0]['gross_spend'],1.5)
        self.assertEqual(users[0]['products'],['chat'])

    def test_directory_dated_mapping_includes_zero_usage_departments(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(p.usage_reporting,'DB_PATH',Path(tmp)/'db'):
            d.save([{'id':'1','userPrincipalName':'a@example.test','mail':'alias@example.test','department':'IT','accountEnabled':True},
                    {'id':'2','userPrincipalName':'b@example.test','department':'HR','accountEnabled':True},
                    {'id':'3','department':'Disabled','accountEnabled':False}], '2026-09-02T00:00:00+00:00')
            data=p.aggregate([p.normalize(event(user='alias@example.test'))],START,END)
            result=d.enrich(data)
            self.assertEqual(result['directory_as_of'],'2026-09-02T00:00:00+00:00')
            self.assertEqual(result['top_users'][0]['department'],'IT')
            rows={r['Department']:r for r in result['department_adoption']}
            self.assertIsNone(rows['IT']['Adoption'])
            self.assertEqual([r['Department'] for r in result['department_usage']],['IT'])
            self.assertEqual(rows['HR']['Users'],0)
            self.assertNotIn('Disabled',rows)

class DepartmentNormalizationTests(unittest.TestCase):
    def test_existing_snapshot_variants_merge_without_merging_abbreviations(self):
        people=[{'id':str(i),'upn':f'{i}@example.test','mail':'','department':dep}
                for i,dep in enumerate(['PreMedia',' premedia ', 'Human  Resources','human resources','IT','Information Technology','   '])]
        data={'user_report_schema':True,'top_users':[
            {'user':'0@example.test','volume':2,'spend':1},
            {'user':'1@example.test','volume':3,'spend':2},
            {'user':'unknown@example.test','volume':4,'spend':0}]}
        with patch.object(d,'snapshot',return_value=('2026-09-01',people)):
            result=d.enrich(data)
        rows={r['Department']:r for r in result['department_adoption']}
        self.assertEqual(rows['PreMedia']['Directory accounts'],2)
        self.assertEqual(rows['PreMedia']['Users'],2)
        self.assertEqual(rows['PreMedia']['Volume'],5)
        self.assertEqual(rows['PreMedia']['Spend (USD)'],3)
        self.assertIsNone(rows['PreMedia']['Adoption'])
        self.assertEqual(rows['Human Resources']['Directory accounts'],2)
        self.assertEqual(rows['(no department)']['Directory accounts'],1)
        self.assertIsNone(rows['(unmapped)']['Adoption'])
        self.assertIn('IT',rows)
        self.assertIn('Information Technology',rows)
        self.assertEqual(result['top_users'][1]['department'],'PreMedia')
        self.assertEqual(people[1]['department'],' premedia ')

class LeadershipReportingTests(unittest.TestCase):
    def report(self,people):
        data={'user_report_schema':2,'summary':{'claude_requests':10,'claude_usage_spend':6},'top_users':[
            {'user':'person@example.test','provider':'Claude Enterprise','volume':4,'spend':2},
            {'user':'guest#ext#@example.test','provider':'Claude Enterprise','volume':3,'spend':1},
            {'user':'unmatched@example.test','provider':'Claude Enterprise','volume':3,'spend':3}],
            'caveats':[]}
        with patch.object(d,'snapshot',return_value=('2026-09-01',people) if people is not None else None):
            return d.enrich(data)

    def test_leadership_totals_preserve_guest_and_unmatched_usage(self):
        people=[{'id':'1','upn':'person@example.test','mail':'','department':'IT'},
                {'id':'2','upn':'guest#ext#@example.test','mail':'','department':''},
                {'id':'3','upn':'test@example.test','mail':'','department':'Unused'}]
        result=self.report(people)
        self.assertEqual(sum(r['Volume'] for r in result['department_usage']),10)
        self.assertEqual(sum(r['Spend (USD)'] for r in result['department_usage']),6)
        self.assertNotIn('Unused',[r['Department'] for r in result['department_usage']])
        self.assertTrue(all(r['Headcount'] is None and r['Adoption'] is None for r in result['department_adoption']))
        q=result['directory_quality']
        self.assertEqual((q['active_accounts'],q['department_mapped_active_accounts'],q['unmapped_active_accounts']),(3,1,1))
        self.assertEqual((q['enabled_accounts'],q['missing_department'],q['guest_style_accounts']),(3,1,1))
        result['executive_sections']=w.sections(result)
        self.assertEqual(result['executive_sections'][0]['name'],'Leadership Summary')
        book=load_workbook(io.BytesIO(executive_xlsx(result)))
        self.assertEqual(list(book['Department Summary'].values)[0],('Department','Active accounts','Requests','Spend (USD)'))
        self.assertTrue(any(row[0]=='Unused' for row in book['Directory Coverage'].values))
        book.close()
        rendered=usage_html(result,'tester','test')
        self.assertIn('employee roster has not been verified',rendered)
        self.assertNotIn('person@example.test',rendered)
        self.assertNotIn('top 10',rendered)
        self.assertNotIn('Unused',rendered)
        self.assertIn('(unmapped)',rendered)
        from app.usage_reporting import usage_pdf
        self.assertTrue(usage_pdf(result,'tester','test').startswith(b'%PDF'))

    def test_missing_snapshot_retains_all_usage_as_unmapped(self):
        result=self.report(None)
        self.assertEqual(result['department_usage'][0]['Volume'],10)
        self.assertEqual(result['department_usage'][0]['Department'],'(unmapped)')
        self.assertEqual(result['directory_quality']['unmapped_active_accounts'],3)
        self.assertIsNone(result['directory_as_of'])

    def test_rolling_activity_keeps_unknown_volume_and_omits_inactive_roster(self):
        people=[{'id':'1','upn':'active@example.test','mail':'','department':'Sales'},
                {'id':'2','upn':'inactive@example.test','mail':'','department':'Unused'}]
        data={'user_report_schema':1,'summary':{'copilot_active_users':1},'top_users':[
            {'user':'active@example.test','activity_status':'Active in period','volume':None,'spend':None},
            {'user':'inactive@example.test','activity_status':'No activity','volume':None,'spend':None}]}
        with patch.object(d,'snapshot',return_value=('2026-09-01',people)):
            result=d.enrich(data)
        self.assertEqual(len(result['department_usage']),1)
        self.assertEqual(result['department_usage'][0]['Department'],'Sales')
        self.assertIsNone(result['department_usage'][0]['Volume'])
        self.assertEqual(result['directory_quality']['active_accounts'],1)
        sections=w.sections(result)
        self.assertNotIn('Spend (USD)',next(s for s in sections if s['name']=='Department Summary')['rows'][0])

    def test_ambiguous_alias_is_not_assigned_a_department(self):
        result=self.report([{'id':'1','upn':'a@example.test','mail':'person@example.test','department':'Sales'},
                            {'id':'2','upn':'b@example.test','mail':'person@example.test','department':'IT'}])
        self.assertEqual(result['top_users'][0]['department'],'(unmapped)')
        self.assertEqual(result['directory_quality']['department_mapped_active_accounts'],0)

class PurviewCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_saved_query_resume_paginate_and_publish(self):
        calls=[]
        def respond(request):
            calls.append(request)
            if request.method=='POST':
                self.assertEqual(json.loads(request.content)['operationFilters'],['CopilotInteraction'])
                return httpx.Response(201,json={'id':'query'})
            if request.url.path.endswith('/records'):
                if request.url.params.get('page')=='two':return httpx.Response(200,json={'value':[{'auditData':event('two')}]})
                return httpx.Response(200,json={'value':[{'auditData':event()}],'@odata.nextLink':p.GRAPH+'/security/auditLog/queries/query/records?page=two'})
            return httpx.Response(200,json={'status':'succeeded'})
        with tempfile.TemporaryDirectory() as tmp,patch.object(p.usage_reporting,'DB_PATH',Path(tmp)/'db'),patch.object(p,'compliance_gate',return_value=ComplianceGate(interval=0)):
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                self.assertFalse(await p.collect_step(client,'secret',START,END))
                self.assertIsNone(p.saved('2026-08'))
                self.assertTrue(await p.collect_step(client,'secret',START,END))
                self.assertEqual(p.saved('2026-08')['summary']['copilot_interactions'],2)
                self.assertEqual(sum(r.method=='POST' for r in calls),1)

    async def test_pagination_does_not_send_credentials_to_other_host(self):
        calls=[]
        def respond(request):
            calls.append(request)
            return httpx.Response(200,json={'value':[],'@odata.nextLink':'https://evil.test/records'})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            with patch.object(p,'compliance_gate',return_value=ComplianceGate(interval=0)):
                with self.assertRaises(ValueError):await p.graph_pages(client,'secret',p.GRAPH+'/users','/v1.0/users')
        self.assertEqual(len(calls),1)

class PurviewDiagnosticTests(unittest.TestCase):
    def test_permission_failure_includes_stage_and_request_id(self):
        request=httpx.Request('GET','https://graph.microsoft.com/v1.0/security/auditLog/queries/q')
        response=httpx.Response(403,request=request,json={'error':{'code':'Forbidden','message':'Permission denied'}},headers={'request-id':'diagnostic-id'})
        with patch.dict(p.status,{'stage':'check audit query','period':'2026-08'}):
            message=p.http_failure(httpx.HTTPStatusError('failure',request=request,response=response))
        self.assertIn('check audit query',message)
        self.assertIn('2026-08',message)
        self.assertIn('diagnostic-id',message)
        self.assertIn('AuditLogsQuery.Read.All',message)

    def test_authentication_failure_is_not_reported_as_consent_failure(self):
        request=httpx.Request('POST','https://login.microsoftonline.com/tenant/oauth2/v2.0/token')
        response=httpx.Response(401,request=request)
        message=p.http_failure(httpx.HTTPStatusError('failure',request=request,response=response))
        self.assertIn('configured Microsoft credentials',message)
        self.assertNotIn('AuditLogsQuery.Read.All',message)


class SummaryReportTests(unittest.TestCase):
    def test_summary_excludes_raw_records_and_formats_departments(self):
        from app.usage_reporting import summary_tables
        data={'summary':{'copilot_interactions':5000,'copilot_active_users':1},
            'executive_sections':[{'name':'Copilot Detail','rows':[['User'],*[[f'raw-{i}'] for i in range(5000)]]}],
            'department_usage':[{'Department':'Sales','Users':1,'Volume':5000,'Spend (USD)':None}]}
        rendered=usage_html(data,'tester','test')
        self.assertNotIn('raw-4999',rendered)
        self.assertNotIn('Claude',rendered)
        self.assertIn('Department usage',rendered)
        self.assertNotIn('Headcount',rendered)
        self.assertNotIn('10.0%',rendered)
        self.assertLess(len(rendered),10000)
        self.assertNotIn('Spend (USD)',str(summary_tables(data)))
