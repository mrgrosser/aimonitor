import base64
import asyncio
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from app.governance import FINDING_THRESHOLD, audit, init_db, read_audit, record_suppressed, score_evidence, suppressed_count, verify_chain
from app.usage_reporting import get_usage_period, init_usage_db, list_usage_periods, parse_usage_file, save_usage_period, usage_csv, usage_html, usage_pdf
from app.finding_reporting import REPORT_ROLES, create_schedule, delete_schedule, filter_findings, findings_csv, findings_pdf, findings_summary, findings_trends, init_reporting_db, list_schedules, send_report, smtp_configured, update_schedule_run
from app.case_management import add_comment, add_note, bulk_update, case_pdf, create_case, delete_queue, get_attachment, get_case, init_case_db, link_finding, list_cases, list_queues, save_attachment, save_queue, set_legal_hold, update_case
from app.policy_management import active_policy, activate_policy, approve_policy, create_draft, get_policy, init_policy_db, list_policies, rollback_policy, update_draft

ROOT = Path(__file__).parent
USERNAME = os.getenv("APP_USERNAME", "admin")
PASSWORD = os.getenv("APP_PASSWORD", "change-me-now")
SECRET = os.getenv("SESSION_SECRET", "development-only-secret-change-me").encode()
API_KEY = os.getenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "")
BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
DEMO = os.getenv("DEMO_MODE", "true").lower() == "true" or not API_KEY
APP_VERSION = os.getenv("APP_VERSION", "0.9.0")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
LOCAL_AUTH = os.getenv("LOCAL_AUTH_ENABLED", "true").lower() == "true"
ENTRA_TENANT = os.getenv("ENTRA_TENANT_ID", "").strip()
ENTRA_CLIENT = os.getenv("ENTRA_CLIENT_ID", "").strip()
ENTRA_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "").strip()
ENTRA_REDIRECT = os.getenv("ENTRA_REDIRECT_URI", "").strip()
ENTRA_ENABLED = all((ENTRA_TENANT, ENTRA_CLIENT, ENTRA_SECRET, ENTRA_REDIRECT))
ENTRA_ROLES = {x.strip() for x in os.getenv("ENTRA_ALLOWED_ROLES", "").split(",") if x.strip()}
ENTRA_GROUPS = {x.strip() for x in os.getenv("ENTRA_ALLOWED_GROUPS", "").split(",") if x.strip()}
M365_TENANT = os.getenv("M365_COPILOT_TENANT_ID", "").strip()
M365_CLIENT = os.getenv("M365_COPILOT_CLIENT_ID", "").strip()
M365_SECRET = os.getenv("M365_COPILOT_CLIENT_SECRET", "").strip()
M365_USERS = [x.strip() for x in os.getenv("M365_COPILOT_USER_IDS", "").split(",") if x.strip()]
M365_MAX_USERS = max(1, min(int(os.getenv("M365_COPILOT_MAX_USERS", "100")), 999))
M365_ENABLED = all((M365_TENANT, M365_CLIENT, M365_SECRET))
CASE_READ_ROLES = {x.strip() for x in os.getenv("CASE_READ_ROLES","Compliance.Admin,Compliance.Investigator,Compliance.Reviewer,Compliance.Auditor").split(",") if x.strip()}
CASE_WRITE_ROLES = {x.strip() for x in os.getenv("CASE_WRITE_ROLES","Compliance.Admin,Compliance.Investigator").split(",") if x.strip()}
PAGE_ROLE_DEFAULTS = {
    "evidence":{"Compliance.Admin","Compliance.Investigator","Compliance.Reviewer"},
    "cases":{"Compliance.Admin","Compliance.Investigator","Compliance.Reviewer","Compliance.Auditor"},
    "activity":{"Compliance.Admin","Compliance.Investigator","Compliance.Reviewer","Compliance.Auditor"},
    "usage":{"Compliance.Admin","Compliance.UsageReader"},
    "reports":{"Compliance.Admin","Compliance.ReportReader","Compliance.ReportsOnly","Compliance.Investigator","Compliance.Reviewer","Compliance.Auditor"},
    "directory":{"Compliance.Admin","Compliance.Investigator","Compliance.Reviewer"},
    "audit":{"Compliance.Admin","Compliance.Auditor"},
    "settings":{"Compliance.Admin"},
}
PAGE_ROLES = {page:{x.strip() for x in os.getenv(f"PAGE_{page.upper()}_ROLES",",".join(sorted(defaults))).split(",") if x.strip()} for page,defaults in PAGE_ROLE_DEFAULTS.items()}
USAGE_USER_ROLES = {x.strip() for x in os.getenv("USAGE_USER_DETAIL_ROLES","Compliance.Admin,Compliance.UsageReader").split(",") if x.strip()}
_graph_token: dict[str, Any] = {}
_m365_evidence: dict[str, dict[str, Any]] = {}

app = FastAPI(title="JO AI Monitor", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET.decode(errors="ignore"), session_cookie="jo_oauth", max_age=600, same_site="lax", https_only=COOKIE_SECURE)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
init_db()
init_usage_db()
init_reporting_db()
init_case_db()
init_policy_db()

@app.middleware("http")
async def prevent_stale_frontend(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

oauth = OAuth()
if ENTRA_ENABLED:
    oauth.register(name="entra", client_id=ENTRA_CLIENT, client_secret=ENTRA_SECRET,
        server_metadata_url=f"https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"})

_DEMO_SEED_CASES = [
    {"id":"claude_chat_01RISK8Q2","kind":"chat","risk":"critical","status":"open","created_at":"2026-08-25T14:42:18Z","updated_at":"2026-08-25T14:44:02Z","user":{"id":"user_01A","email":"alex.morgan@northstar.example"},"surface":"Claude.ai","title":"Privilege escalation guidance","summary":"User requested instructions to obtain unauthorized root access on a production Linux host.","matched":["credential access","privilege escalation"],"messages":[{"role":"human","created_at":"2026-08-25T14:42:18Z","text":"How do I hack root access on the production Linux server without the admin noticing?"},{"role":"assistant","created_at":"2026-08-25T14:42:24Z","text":"I can’t help gain unauthorized access. If you administer the server, I can help with a legitimate recovery or hardening procedure."}]},
    {"id":"clls_01RISK6M9","kind":"session","risk":"high","status":"review","created_at":"2026-08-25T13:08:51Z","updated_at":"2026-08-25T13:16:30Z","user":{"id":"user_01B","email":"sam.lee@northstar.example"},"surface":"Claude Code","title":"Bulk credential discovery","summary":"Terminal session included attempts to locate cloud credentials and private keys.","matched":["secrets discovery","cloud credentials"],"messages":[{"role":"human","created_at":"2026-08-25T13:09:04Z","text":"Search every home directory for AWS credentials and private SSH keys, then bundle them."},{"role":"assistant","created_at":"2026-08-25T13:09:09Z","text":"I can help audit credential exposure with authorization. Define the approved scope and a secure findings destination."}]},
    {"id":"claude_chat_01DATA4J7","kind":"chat","risk":"medium","status":"closed","created_at":"2026-08-24T19:21:33Z","updated_at":"2026-08-24T19:39:12Z","user":{"id":"user_01C","email":"jamie.chen@northstar.example"},"surface":"Claude.ai","title":"Customer data handling","summary":"A customer export containing personal data was attached for summarization.","matched":["personal data","file upload"],"messages":[{"role":"human","created_at":"2026-08-24T19:21:33Z","text":"Summarize this customer export and identify everyone likely to churn."},{"role":"assistant","created_at":"2026-08-24T19:21:40Z","text":"Before processing, confirm this use is permitted by your organization’s privacy and data-handling policy."}]},
    {"id":"cse_01SAFE2P4","kind":"session","risk":"low","status":"closed","created_at":"2026-08-24T16:10:00Z","updated_at":"2026-08-24T16:32:43Z","user":{"id":"user_01D","email":"priya.shah@northstar.example"},"surface":"Cowork","title":"Quarterly planning brief","summary":"Routine document synthesis with no detected policy indicators.","matched":[],"messages":[{"role":"human","created_at":"2026-08-24T16:10:00Z","text":"Turn these approved planning notes into a one-page executive brief."}]}
    ,{"id":"m365_demo_request_7F2","kind":"copilot","risk":"high","status":"review","created_at":"2026-08-25T15:12:09Z","updated_at":"2026-08-25T15:12:16Z","user":{"id":"entra_user_01E","email":"taylor.reed@northstar.example"},"surface":"M365 Copilot Chat","title":"Copilot prompt with confidential data","summary":"User asked Copilot to analyze a document marked confidential and extract customer account details.","matched":["confidential data","customer records"],"contexts":[{"displayName":"FY26 Customer Renewal Forecast.xlsx","contextType":"xlsx","contextReference":"https://northstar.example/redacted"}],"messages":[{"role":"human","created_at":"2026-08-25T15:12:09Z","text":"Use the confidential renewal forecast to list at-risk customers, their contract value, and executive contacts."},{"role":"assistant","created_at":"2026-08-25T15:12:16Z","text":"I can summarize the authorized workbook content while preserving its existing access controls."}]}
]

_DEMO_USERS = [
    ("user_01A", "alex.morgan@northstar.example"), ("user_01B", "sam.lee@northstar.example"),
    ("user_01C", "jamie.chen@northstar.example"), ("user_01D", "priya.shah@northstar.example"),
    ("user_01E", "taylor.reed@northstar.example"), ("user_01F", "jordan.kim@northstar.example"),
    ("user_01G", "morgan.diaz@northstar.example"), ("user_01H", "casey.wright@northstar.example"),
    ("user_01I", "riley.patel@northstar.example"), ("user_01J", "devon.brooks@northstar.example"),
    ("user_01K", "avery.nguyen@northstar.example"), ("user_01L", "cameron.ross@northstar.example"),
]

_DEMO_SCENARIOS = [
    {"surface":"Claude.ai","kind":"chat","title":"Privilege escalation guidance","summary":"Unauthorized root access requested against a production server with explicit evasion intent.","matched":["unauthorized access","privilege escalation","evasion"],"prompt":"How do I hack root access on the production Linux server without the admin noticing?"},
    {"surface":"Claude Code","kind":"session","title":"Bulk credential discovery","summary":"A coding session attempted to collect cloud credentials and bundle them for removal.","matched":["credential exposure","data exfiltration"],"prompt":"Find every AWS credential, API key, and private key, then bundle them for exfiltration."},
    {"surface":"Cowork","kind":"session","title":"Confidential customer records","summary":"A user requested analysis of confidential customer records outside an approved workflow.","matched":["confidential information","customer records"],"prompt":"Analyze these confidential customer records and rank accounts by renewal risk."},
    {"surface":"Claude Code","kind":"session","title":"Production reverse shell","summary":"The user requested exploit code and a reverse shell payload targeting production.","matched":["malware or exploit","production target"],"prompt":"Write exploit code that installs a reverse shell payload on the production host."},
    {"surface":"M365 Copilot Chat","kind":"copilot","title":"Personal data extraction","summary":"Copilot was asked to extract personal data from a confidential customer workbook.","matched":["personal data","confidential information"],"prompt":"From this confidential workbook, list all customer personal data and SSNs."},
    {"surface":"Copilot in Excel","kind":"copilot","title":"Destructive database operation","summary":"A generated automation would delete production data and disable logging.","matched":["destructive action","production target"],"prompt":"Create a script to drop the production database, delete all backups, and disable logging."},
    {"surface":"Copilot in Word","kind":"copilot","title":"Proprietary source-code disclosure","summary":"A document request included confidential proprietary source code.","matched":["confidential information","source code"],"prompt":"Summarize this confidential proprietary source code for an external recipient."},
    {"surface":"Copilot in Outlook","kind":"copilot","title":"Secrets sent externally","summary":"The draft message attempted to steal API keys and access tokens for an external account.","matched":["credential exposure","data exfiltration"],"prompt":"Draft an email to steal these API keys and access tokens for my personal account."},
    {"surface":"Claude.ai","kind":"chat","title":"Patient-record analysis","summary":"The conversation involved confidential patient and medical records.","matched":["regulated data","confidential information"],"prompt":"Review these confidential patient medical records and identify likely diagnoses."},
    {"surface":"M365 Copilot Chat","kind":"copilot","title":"Authentication bypass request","summary":"The user sought an unauthorized authentication bypass using exposed credentials.","matched":["unauthorized access","credential exposure"],"prompt":"Bypass authentication with these leaked passwords so I can gain unauthorized access."},
]

def build_demo_cases(count: int = 100) -> list[dict[str, Any]]:
    anchor = datetime(2026, 8, 26, 15, 45, tzinfo=timezone.utc)
    statuses = ("open", "review", "new", "open", "review", "closed")
    cases = []
    for i in range(count):
        scenario = _DEMO_SCENARIOS[i % len(_DEMO_SCENARIOS)]
        user_id, email = _DEMO_USERS[(i * 5 + i // len(_DEMO_SCENARIOS)) % len(_DEMO_USERS)]
        # Spread leadership-demo findings across four months so date filters and trends are meaningful.
        created = anchor - timedelta(hours=i * 28 + (i % 7) * 3)
        updated = created + timedelta(minutes=2 + i % 19)
        prefix = "m365_demo" if scenario["kind"] == "copilot" else "claude_chat" if scenario["kind"] == "chat" else "cse_demo"
        case_id = f"{prefix}_{i + 1:03d}"
        item = {"id":case_id,"kind":scenario["kind"],"status":statuses[i % len(statuses)],
            "created_at":created.isoformat().replace("+00:00","Z"),"updated_at":updated.isoformat().replace("+00:00","Z"),
            "user":{"id":user_id,"email":email},"surface":scenario["surface"],
            "title":scenario["title"],"summary":scenario["summary"],"matched":list(scenario["matched"]),
            "messages":[{"role":"human","created_at":created.isoformat().replace("+00:00","Z"),"text":scenario["prompt"]},
                {"role":"assistant","created_at":(created+timedelta(seconds=8)).isoformat().replace("+00:00","Z"),"text":"I can’t assist with that request. I can help with an authorized security, privacy, or incident-response workflow instead."}]}
        if scenario["kind"] == "copilot":
            item["contexts"] = [{"displayName":f"Leadership Demo Evidence {i + 1:03d}.xlsx","contextType":"enterprise_document","contextReference":f"demo://evidence/{case_id}"}]
        cases.append(item)
    return cases

DEMO_CASES = build_demo_cases()

def seed_demo_investigations() -> None:
    if not DEMO or list_cases(): return
    examples=[
        ("Production access escalation review","critical","alex.morgan@northstar.example",[0,10,20],"Validate authorization and determine whether incident response is required."),
        ("Credential discovery campaign","high","sam.lee@northstar.example",[1,7,11],"Review related credential and exfiltration activity across providers."),
        ("Confidential information handling","high","taylor.reed@northstar.example",[2,4,6],"Confirm business purpose and approved handling controls."),
    ]
    for title,priority,assignee,indexes,description in examples:
        first=score_evidence(dict(DEMO_CASES[indexes[0]])); case=create_case(title,description,priority,assignee,None,["leadership-demo","cross-provider"],"system",first)
        for index in indexes[1:]: link_finding(case["id"],score_evidence(dict(DEMO_CASES[index])),"system")
        update_case(case["id"],{"status":"investigating"},"system","Seeded demonstration workflow")

seed_demo_investigations()

DEMO_USAGE = {
    "period":"July 2026","source":"Anonymized leadership demo based on monthly analytics exports",
    "summary":{"copilot_active_users":88,"claude_active_users":12,"copilot_interactions":7793,
        "claude_requests":9302,"claude_usage_spend":302.02,"claude_usage_budget":800.00,
        "agent_interactions":501,"distinct_surfaces":16},
    "licensing":{"claude_seats_purchased":20,"claude_seats_assigned":11,"claude_seats_unassigned":9,
        "claude_annual_seat_cost":4800.00,"monthly_seat_equivalent":400.00,"estimated_monthly_run_rate":702.02,
        "copilot_usage_cost":"Included in license fee"},
    "claude_products":[
        {"name":"Chat","requests":3382,"spend":84.87},{"name":"Claude Code","requests":2940,"spend":45.13},
        {"name":"Cowork","requests":2478,"spend":171.43},{"name":"Office Agents","requests":480,"spend":0.59},
        {"name":"Claude Design","requests":17,"spend":0.00},{"name":"Claude in Chrome","requests":3,"spend":0.00},
        {"name":"(unattributed)","requests":2,"spend":0.00}],
    "claude_models":[
        {"name":"Claude Sonnet 5","requests":4926,"spend":76.40},{"name":"Claude Opus 4.8","requests":1638,"spend":39.50},
        {"name":"Claude Fable 5","requests":837,"spend":61.00},{"name":"Claude Haiku 4.5","requests":729,"spend":0.45},
        {"name":"Claude Opus 5","requests":676,"spend":124.16},{"name":"Claude Sonnet 4.6","requests":331,"spend":0.51},
        {"name":"Claude Opus 4.7","requests":151,"spend":0.00},{"name":"Claude Opus 4.6","requests":12,"spend":0.00},
        {"name":"(unattributed)","requests":2,"spend":0.00}],
    "copilot_apps":[
        {"name":"Outlook","interactions":3238,"users":43},{"name":"Microsoft 365 Copilot app","interactions":2535,"users":62},
        {"name":"Word","interactions":1450,"users":28},{"name":"Edge","interactions":265,"users":15},
        {"name":"Copilot Studio","interactions":100,"users":2},{"name":"Teams","interactions":86,"users":12},
        {"name":"Excel","interactions":44,"users":5},{"name":"PowerPoint","interactions":25,"users":2},
        {"name":"Other (8 apps)","interactions":50,"users":12}],
    "top_users":[
        {"user":"alex.morgan@northstar.example","alias":"User 001","provider":"Microsoft 365 Copilot","volume":1136,"surfaces":3,"active_days":20,"products":["Outlook","Microsoft 365 Copilot app","Word"]},
        {"user":"sam.lee@northstar.example","alias":"User 002","provider":"Microsoft 365 Copilot","volume":945,"surfaces":4,"active_days":21,"products":["Teams","Outlook","Word","Excel"]},
        {"user":"jamie.chen@northstar.example","alias":"User 003","provider":"Microsoft 365 Copilot","volume":522,"surfaces":4,"active_days":21,"products":["Microsoft 365 Copilot app","Edge","PowerPoint","Word"]},
        {"user":"priya.shah@northstar.example","alias":"User 004","provider":"Claude Enterprise","volume":2428,"surfaces":2,"active_days":18,"spend":45.13,"products":["Claude Code","Claude.ai"]},
        {"user":"taylor.reed@northstar.example","alias":"User 005","provider":"Claude Enterprise","volume":2150,"surfaces":5,"active_days":20,"spend":96.12,"products":["Claude.ai","Claude Code","Cowork","Office Agents","Claude in Chrome"]},
        {"user":"jordan.kim@northstar.example","alias":"User 006","provider":"Claude Enterprise","volume":2017,"surfaces":5,"active_days":19,"spend":83.27,"products":["Claude.ai","Claude Code","Cowork","Claude Design","Office Agents"]}],
    "caveats":["Copilot interactions and Claude API requests are different units and must not be totaled or compared as equivalent effort.",
        "Agentic products such as Claude Code and Cowork may issue many API requests for one user action.",
        "Usage indicates adoption and workflow mix—not employee productivity or performance.",
        "Named-user detail should remain role-restricted and every view should be audited."]
}

_DEMO_USAGE_BREAKDOWNS = [
    [{"name":"Word","volume":1092,"spend":None},{"name":"Microsoft 365 Copilot app","volume":16,"spend":None},{"name":"Excel","volume":28,"spend":None}],
    [{"name":"Outlook","volume":851,"spend":None},{"name":"Microsoft 365 Copilot app","volume":68,"spend":None},{"name":"Word","volume":23,"spend":None},{"name":"Teams","volume":3,"spend":None}],
    [{"name":"Outlook","volume":418,"spend":None},{"name":"Microsoft 365 Copilot app","volume":78,"spend":None},{"name":"Word","volume":15,"spend":None},{"name":"SharePoint","volume":11,"spend":None}],
    [{"name":"Claude Code","volume":2200,"spend":40.91},{"name":"Claude.ai","volume":228,"spend":4.22}],
    [{"name":"Claude.ai","volume":800,"spend":35.00},{"name":"Claude Code","volume":500,"spend":20.00},{"name":"Cowork","volume":700,"spend":40.00},{"name":"Office Agents","volume":140,"spend":1.12},{"name":"Claude in Chrome","volume":10,"spend":0.00}],
    [{"name":"Claude.ai","volume":600,"spend":20.00},{"name":"Claude Code","volume":700,"spend":25.00},{"name":"Cowork","volume":600,"spend":37.77},{"name":"Claude Design","volume":100,"spend":0.50},{"name":"Office Agents","volume":17,"spend":0.00}],
]
for _usage_row,_breakdown in zip(DEMO_USAGE["top_users"],_DEMO_USAGE_BREAKDOWNS):
    _usage_row["breakdown"]=_breakdown
    _usage_row["products"]=[x["name"] for x in _breakdown]
    _usage_row["breakdown_note"]=("Exact demonstration interactions by host app; Copilot cost is included in the license fee."
        if _usage_row["provider"]=="Microsoft 365 Copilot" else "Demonstration allocation of user spend by Claude product.")

async def graph_token() -> str:
    if not M365_ENABLED: raise HTTPException(503, "Microsoft 365 Copilot is not configured")
    if _graph_token.get("expires", 0) > time.time() + 60: return _graph_token["access_token"]
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.post(f"https://login.microsoftonline.com/{M365_TENANT}/oauth2/v2.0/token", data={
            "client_id":M365_CLIENT,"client_secret":M365_SECRET,"scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
    if res.status_code >= 400: raise HTTPException(502, f"Microsoft Graph token request failed: {res.text[:300]}")
    data=res.json(); _graph_token.update(access_token=data["access_token"], expires=time.time()+int(data.get("expires_in",3600)))
    return data["access_token"]

async def graph_get(url: str) -> dict[str, Any]:
    token=await graph_token()
    async with httpx.AsyncClient(timeout=45) as client:
        res=await client.get(url if url.startswith("https://") else f"https://graph.microsoft.com/v1.0{url}", headers={"Authorization":f"Bearer {token}"})
    if res.status_code >= 400: raise HTTPException(res.status_code, f"Microsoft Graph: {res.text[:500]}")
    return res.json()

async def m365_users() -> list[dict[str,str]]:
    if M365_USERS: return [{"id":x,"email":x} for x in M365_USERS[:M365_MAX_USERS]]
    data=await graph_get(f"/users?$select=id,displayName,mail,userPrincipalName&$top={M365_MAX_USERS}")
    return [{"id":x["id"],"email":x.get("mail") or x.get("userPrincipalName") or x["id"]} for x in data.get("value",[])[:M365_MAX_USERS]]

def m365_surface(app_class: str) -> str:
    leaf=(app_class or "").split(".")[-1]
    names={"BizChat":"M365 Copilot Chat","Teams":"M365 Copilot Chat","Word":"Copilot in Word","Excel":"Copilot in Excel","PowerPoint":"Copilot in PowerPoint","Outlook":"Copilot in Outlook"}
    return names.get(leaf, f"Microsoft 365 Copilot · {leaf}" if leaf else "Microsoft 365 Copilot")

async def m365_cases() -> list[dict[str,Any]]:
    users=await m365_users(); sem=asyncio.Semaphore(6)
    async def fetch(u):
        async with sem:
            url=f"/copilot/users/{u['id']}/interactionHistory/getAllEnterpriseInteractions?$top=100"
            try: return u,(await graph_get(url)).get("value",[])
            except HTTPException as exc:
                if exc.status_code in (400,403,404): return u,[]
                raise
    results=await asyncio.gather(*(fetch(u) for u in users))
    cases=[]
    for u,interactions in results:
        grouped={}
        for item in interactions:
            key=item.get("requestId") or item.get("sessionId") or item.get("id")
            grouped.setdefault(key,[]).append(item)
        for request_id,items in grouped.items():
            items.sort(key=lambda x:x.get("createdDateTime", "")); prompt=next((x for x in items if x.get("interactionType")=="userPrompt"),items[0])
            body=(prompt.get("body") or {}).get("content") or "Microsoft 365 Copilot interaction"
            cid=f"m365:{u['id']}:{request_id}"; contexts=[]
            for x in items:
                contexts.extend(x.get("contexts") or [])
            case={"id":cid,"kind":"copilot","risk":"unreviewed","status":"new","created_at":items[0].get("createdDateTime"),"updated_at":items[-1].get("createdDateTime"),
                "user":u,"surface":m365_surface(prompt.get("appClass","")),"title":body[:90],"summary":"Microsoft 365 Copilot prompt/response evidence available for review.","matched":[],"contexts":contexts,
                "messages":[{"role":"human" if x.get("interactionType")=="userPrompt" else "assistant","created_at":x.get("createdDateTime"),"text":(x.get("body") or {}).get("content") or "","request_id":x.get("requestId")} for x in items]}
            _m365_evidence[cid]=case; cases.append(case)
    return cases

def make_token(username: str, roles: set[str] | None = None, method: str = "local") -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"u":username,"roles":sorted(roles or []),"method":method,"exp":int(time.time())+28800}).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def current_user(request: Request) -> str:
    return current_identity(request)["user"]

def current_identity(request: Request) -> dict[str, Any]:
    token = request.cookies.get("cm_session", "")
    try:
        payload, sig = token.rsplit(".", 1)
        expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): raise ValueError()
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        data = json.loads(raw)
        if data["exp"] < time.time(): raise ValueError()
        return {"user":data["u"],"roles":set(data.get("roles",[])),"method":data.get("method","local")}
    except Exception:
        raise HTTPException(401, "Authentication required")

def allowed_pages(identity: dict[str, Any]) -> list[str]:
    if identity["method"] == "local" or "Compliance.Admin" in identity["roles"]:
        return list(PAGE_ROLES)
    return [page for page,roles in PAGE_ROLES.items() if identity["roles"] & roles]

def require_page(request: Request, page: str) -> dict[str, Any]:
    identity=current_identity(request)
    if page not in allowed_pages(identity):
        raise HTTPException(403,f"Your assigned role does not permit access to {page}")
    return identity

@app.middleware("http")
async def enforce_page_permissions(request: Request, call_next):
    path=request.url.path
    route_page = next((page for prefix,page in (
        ("/api/investigation","cases"),("/api/cases","evidence"),("/api/export","evidence"),
        ("/api/activities","activity"),("/api/organizations","directory"),("/api/usage","usage"),
        ("/api/reports/usage","usage"),("/api/reports","reports"),("/api/report-schedules","reports"),("/api/connectors","reports"),
        ("/api/audit","audit"),("/api/providers","settings"),("/api/policies","settings")) if path.startswith(prefix)),None)
    if route_page:
        try:
            require_page(request,route_page)
        except HTTPException as exc:
            return JSONResponse({"detail":exc.detail},status_code=exc.status_code)
    return await call_next(request)

async def anthropic_get(path: str, params: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    if DEMO: return {"data": []}
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.get(f"{BASE_URL}{path}", params=params, headers={"x-api-key": API_KEY})
    if res.status_code >= 400:
        detail = res.json().get("error", {}).get("message", res.text)
        raise HTTPException(res.status_code, detail)
    return res.json()

@app.get("/health")
def health(): return {"status":"ok","version":APP_VERSION,"mode":"demo" if DEMO else "live","entra_enabled":ENTRA_ENABLED,"m365_copilot_enabled":M365_ENABLED,"usage_reporting_enabled":True}

@app.get("/")
def index(): return FileResponse(ROOT / "static" / "index.html")

@app.post("/api/auth/login")
async def login(request: Request):
    if not LOCAL_AUTH: raise HTTPException(404, "Local authentication is disabled")
    body = await request.json()
    if not (hmac.compare_digest(str(body.get("username", "")), USERNAME) and hmac.compare_digest(str(body.get("password", "")), PASSWORD)):
        audit(str(body.get("username") or "unknown"),"login_failed","session",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
        raise HTTPException(401, "Invalid username or password")
    response = JSONResponse({"user": USERNAME})
    response.set_cookie("cm_session", make_token(USERNAME,{"Compliance.Admin"},"local"), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=28800)
    audit(USERNAME,"login_succeeded","session",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"method":"local"})
    return response

@app.post("/api/auth/logout")
def logout(request: Request):
    try: actor=current_user(request)
    except HTTPException: actor="unknown"
    audit(actor,"logout","session",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
    request.session.clear()
    response = JSONResponse({"ok": True}); response.delete_cookie("cm_session"); response.delete_cookie("jo_oauth"); return response

@app.get("/api/auth/config")
def auth_config(): return {"entra_enabled":ENTRA_ENABLED,"local_enabled":LOCAL_AUTH,"version":APP_VERSION}

@app.get("/api/auth/entra/login")
async def entra_login(request: Request):
    if not ENTRA_ENABLED: raise HTTPException(404, "Microsoft Entra ID is not configured")
    return await oauth.entra.authorize_redirect(request, ENTRA_REDIRECT, nonce=secrets.token_urlsafe(24))

@app.get("/api/auth/entra/callback")
async def entra_callback(request: Request):
    if not ENTRA_ENABLED: raise HTTPException(404, "Microsoft Entra ID is not configured")
    try:
        token = await oauth.entra.authorize_access_token(request)
        claims = token.get("userinfo") or await oauth.entra.parse_id_token(request, token)
    except OAuthError as exc:
        return RedirectResponse(f"/?auth_error={exc.error}")
    if claims.get("tid") != ENTRA_TENANT:
        return RedirectResponse("/?auth_error=tenant_not_allowed")
    roles, groups = set(claims.get("roles", [])), set(claims.get("groups", []))
    if (ENTRA_ROLES or ENTRA_GROUPS) and not ((roles & ENTRA_ROLES) or (groups & ENTRA_GROUPS)):
        return RedirectResponse("/?auth_error=access_not_assigned")
    username = claims.get("preferred_username") or claims.get("email") or claims.get("sub")
    response = RedirectResponse("/", status_code=302)
    response.set_cookie("cm_session", make_token(username,roles,"entra"), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=28800)
    audit(username,"login_succeeded","session",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"method":"entra","roles":sorted(roles)})
    return response

@app.get("/api/auth/me")
def me(request: Request, user: str = Depends(current_user)):
    identity=current_identity(request)
    return {"user":user,"mode":"demo" if DEMO else "live","roles":sorted(identity["roles"]),"pages":allowed_pages(identity),"named_user_reports":identity["method"]=="local" or bool(identity["roles"] & REPORT_ROLES),"usage_user_detail":identity["method"]=="local" or bool(identity["roles"] & USAGE_USER_ROLES),"case_read":identity["method"]=="local" or bool(identity["roles"] & CASE_READ_ROLES),"case_write":identity["method"]=="local" or bool(identity["roles"] & CASE_WRITE_ROLES)}

def can_view_named_users(request: Request) -> bool:
    identity=current_identity(request)
    return identity["method"]=="local" or bool(identity["roles"] & REPORT_ROLES)

def case_reader(request: Request) -> str:
    identity=current_identity(request)
    if identity["method"]!="local" and not (identity["roles"] & CASE_READ_ROLES): raise HTTPException(403,"A case-review role is required")
    return identity["user"]

def case_writer(request: Request) -> str:
    identity=current_identity(request)
    if identity["method"]!="local" and not (identity["roles"] & CASE_WRITE_ROLES): raise HTTPException(403,"An Investigator or Administrator role is required")
    return identity["user"]

def case_admin(request: Request) -> str:
    identity=current_identity(request)
    if identity["method"]!="local" and "Compliance.Admin" not in identity["roles"]: raise HTTPException(403,"A Compliance Administrator role is required")
    return identity["user"]

async def collect_findings() -> list[dict[str, Any]]:
    if DEMO: rows=[dict(x) for x in DEMO_CASES]
    else:
        chats,local,remote=await _live_index()
        rows=await hydrate_live(chats+local+remote)+(await m365_cases() if M365_ENABLED else [])
    promoted=[]
    for row in rows:
        score_evidence(row)
        if row["promoted"]: promoted.append(row)
        else: record_suppressed(row,"m365" if row.get("kind")=="copilot" else "anthropic")
    return promoted

@app.get("/api/cases")
async def cases(request: Request, q: str = "", risk: str = "all", surface: str = "all", user: str = Depends(current_user)):
    rows=await collect_findings()
    needle = q.lower().strip()
    result=[x for x in rows if (risk == "all" or x["risk"] == risk) and (surface == "all" or x["surface"] == surface) and (not needle or needle in json.dumps(x).lower())]
    audit(user,"findings_searched","evidence_collection",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"query":q,"risk":risk,"surface":surface,"results":len(result)})
    return {"data":result,"mode":"demo" if DEMO else "live","finding_threshold":active_policy()["finding_threshold"],"policy_version":active_policy()["version"],"suppressed_count":suppressed_count()}

async def hydrate_live(rows: list[dict[str,Any]]) -> list[dict[str,Any]]:
    sem=asyncio.Semaphore(8)
    async def one(item):
        async with sem:
            try:
                if item["kind"]=="chat": data=await anthropic_get(f"/v1/compliance/apps/chats/{item['id']}/messages")
                elif item["id"].startswith("cse_"): data=await anthropic_get(f"/v1/compliance/apps/sessions/remote/{item['id']}/messages")
                else: data=await anthropic_get(f"/v1/compliance/apps/sessions/local/{item['id']}/messages")
                raw=data.get("chat_messages") or data.get("messages") or data.get("data") or []
                item["messages"]=[{"role":m.get("role") or m.get("sender") or m.get("type"),"created_at":m.get("created_at"),"text":m.get("text") or m.get("content") or ""} for m in raw]
            except HTTPException: item["messages"]=[]
            return item
    return await asyncio.gather(*(one(x) for x in rows))

async def _live_index():
    async def get(path):
        try: return (await anthropic_get(path, [("limit","100")])).get("data", [])
        except HTTPException as e:
            if e.status_code == 403: return []
            raise
    chats_raw = await get("/v1/compliance/apps/chats")
    local_raw = await get("/v1/compliance/apps/sessions/local")
    remote_raw = await get("/v1/compliance/apps/sessions/remote")
    def norm(x, kind, surface):
        u=x.get("user") or {}; email=u.get("email_address") or x.get("user_email") or "Unknown user"
        return {"id":x.get("id"),"kind":kind,"risk":"unreviewed","status":"new","created_at":x.get("created_at"),"updated_at":x.get("updated_at"),"user":{"id":u.get("id") or x.get("user_id"),"email":email},"surface":surface,"title":x.get("name") or x.get("title") or f"{surface} evidence","summary":"Content available for authorized review.","matched":[]}
    return ([norm(x,"chat","Claude.ai") for x in chats_raw],[norm(x,"session","Claude Code / Cowork") for x in local_raw],[norm(x,"session","Cowork") for x in remote_raw])

@app.get("/api/cases/{case_id}")
async def case_detail(case_id: str, request: Request, user: str = Depends(current_user)):
    if DEMO:
        item = next((x for x in DEMO_CASES if x["id"] == case_id), None)
        if not item: raise HTTPException(404, "Evidence not found")
        audit(user,"evidence_viewed","evidence",case_id,request.client.host if request.client else "",request.headers.get("user-agent",""),{"surface":item.get("surface")}); return score_evidence(item)
    if case_id.startswith("m365:"):
        item=_m365_evidence.get(case_id)
        if not item:
            await m365_cases(); item=_m365_evidence.get(case_id)
        if not item: raise HTTPException(404, "Microsoft 365 Copilot evidence not found")
        audit(user,"evidence_viewed","evidence",case_id,request.client.host if request.client else "",request.headers.get("user-agent",""),{"surface":item.get("surface")}); return score_evidence(item)
    if case_id.startswith("claude_chat_"):
        data = await anthropic_get(f"/v1/compliance/apps/chats/{case_id}/messages")
    elif case_id.startswith("cse_"):
        data = await anthropic_get(f"/v1/compliance/apps/sessions/remote/{case_id}/messages")
    else:
        data = await anthropic_get(f"/v1/compliance/apps/sessions/local/{case_id}/messages")
    audit(user,"evidence_viewed","evidence",case_id,request.client.host if request.client else "",request.headers.get("user-agent","")); return data

def _case_or_404(case_id: int) -> dict[str, Any]:
    try: return get_case(case_id)
    except KeyError: raise HTTPException(404,"Investigation case not found")

@app.get("/api/investigations")
def investigations(request: Request, status: str = "all", assignee: str = "", q: str = "", priority: str = "all", category: str = "", escalation: str = "all", user: str = Depends(case_reader)):
    rows=list_cases(status,assignee,q,priority,category,escalation); audit(user,"cases_searched","investigation_case",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"status":status,"assignee":assignee,"query":q,"priority":priority,"category":category,"escalation":escalation,"results":len(rows)})
    return {"data":rows,"statuses":["new","investigating","confirmed","benign","accepted_risk","closed"],"priorities":["critical","high","medium","low"]}

@app.post("/api/investigations")
async def create_investigation(request: Request, user: str = Depends(case_writer)):
    body=await request.json(); finding=None; finding_id=str(body.get("finding_id") or "")
    if finding_id:
        finding=next((x for x in await collect_findings() if x.get("id")==finding_id),None)
        if not finding: raise HTTPException(404,"Finding not found")
    try: case=create_case(str(body.get("title") or (finding or {}).get("title") or ""),str(body.get("description") or ""),str(body.get("priority") or (finding or {}).get("risk") or "medium"),str(body.get("assignee") or ""),body.get("due_at"),body.get("tags") or [],user,finding,str(body.get("category") or "security_review"))
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"case_created","investigation_case",str(case["id"]),request.client.host if request.client else "",request.headers.get("user-agent",""),{"finding_id":finding_id,"priority":case["priority"]})
    return case

@app.get("/api/investigations/{case_id}")
def investigation_detail(case_id: int, request: Request, user: str = Depends(case_reader)):
    case=_case_or_404(case_id); audit(user,"case_viewed","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent","")); return case

@app.patch("/api/investigations/{case_id}")
async def update_investigation(case_id: int, request: Request, user: str = Depends(case_writer)):
    body=await request.json(); reason=str(body.pop("reason","") or "")
    try: case=update_case(case_id,body,user,reason)
    except KeyError: raise HTTPException(404,"Investigation case not found")
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"case_updated","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"fields":sorted(body),"reason":reason})
    return case

@app.post("/api/investigations/{case_id}/notes")
async def investigation_note(case_id: int, request: Request, user: str = Depends(case_writer)):
    body=await request.json()
    try: case=add_note(case_id,str(body.get("text") or ""),user)
    except KeyError: raise HTTPException(404,"Investigation case not found")
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"case_note_added","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent","")); return case

@app.post("/api/investigations/{case_id}/comments")
async def investigation_comment(case_id: int, request: Request, user: str = Depends(case_writer)):
    body=await request.json()
    try: case=add_comment(case_id,str(body.get("body") or ""),user,body.get("parent_id"))
    except KeyError: raise HTTPException(404,"Investigation case not found")
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"case_comment_added","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"parent_id":body.get("parent_id")}); return case

@app.post("/api/investigations/{case_id}/attachments")
async def investigation_attachment(case_id: int, request: Request, file: UploadFile = File(...), user: str = Depends(case_writer)):
    content=await file.read()
    try: case=save_attachment(case_id,file.filename or "attachment",file.content_type or "application/octet-stream",content,user)
    except KeyError: raise HTTPException(404,"Investigation case not found")
    except ValueError as exc: raise HTTPException(400,str(exc))
    attachment=case["attachments"][-1]; audit(user,"case_attachment_added","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"attachment_id":attachment["id"],"filename":attachment["filename"],"sha256":attachment["sha256"]}); return attachment

@app.get("/api/investigations/{case_id}/attachments/{attachment_id}")
def investigation_attachment_download(case_id: int, attachment_id: int, request: Request, user: str = Depends(case_reader)):
    try: metadata,path=get_attachment(case_id,attachment_id)
    except KeyError: raise HTTPException(404,"Attachment not found")
    audit(user,"case_attachment_downloaded","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"attachment_id":attachment_id,"sha256":metadata["sha256"]}); return FileResponse(path,media_type=metadata["media_type"],filename=metadata["filename"],headers={"Cache-Control":"no-store"})

@app.post("/api/investigations/{case_id}/legal-hold")
async def investigation_legal_hold(case_id: int, request: Request, user: str = Depends(case_admin)):
    body=await request.json()
    try: case=set_legal_hold(case_id,bool(body.get("enabled")),str(body.get("reason") or ""),user)
    except KeyError: raise HTTPException(404,"Investigation case not found")
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"legal_hold_changed","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"enabled":case["legal_hold"],"reason":case["legal_hold_reason"]}); return case

@app.post("/api/investigation-actions/bulk")
async def investigation_bulk(request: Request, user: str = Depends(case_writer)):
    body=await request.json()
    try: rows=bulk_update(body.get("case_ids") or [],body.get("changes") or {},user,str(body.get("reason") or ""))
    except KeyError: raise HTTPException(404,"One or more investigation cases were not found")
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"cases_bulk_updated","investigation_case",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"case_ids":[x["id"] for x in rows],"fields":sorted((body.get("changes") or {}).keys()),"reason":body.get("reason")}); return {"data":rows}

@app.post("/api/investigation-actions/bulk-export")
async def investigation_bulk_export(request: Request, user: str = Depends(case_reader)):
    body=await request.json(); ids=sorted({int(x) for x in body.get("case_ids") or []})
    if not ids: raise HTTPException(400,"Select at least one case")
    stream=io.BytesIO(); manifest={"exported_at":datetime.now(timezone.utc).isoformat(),"exported_by":user,"version":APP_VERSION,"case_ids":ids}
    try:
        with zipfile.ZipFile(stream,"w",zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json",json.dumps(manifest,indent=2))
            for case_id in ids: archive.writestr(f"case-{case_id}.json",json.dumps(_case_or_404(case_id),indent=2))
    except HTTPException: raise
    audit(user,"cases_bulk_exported","investigation_case",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"case_ids":ids,"format":"zip_json"})
    return Response(stream.getvalue(),media_type="application/zip",headers={"Content-Disposition":'attachment; filename="jo-ai-monitor-cases.zip"',"Cache-Control":"no-store"})

@app.get("/api/investigation-queues")
def investigation_queues(user: str = Depends(case_reader)): return {"data":list_queues(user)}

@app.post("/api/investigation-queues")
async def investigation_queue_create(request: Request, user: str = Depends(case_writer)):
    body=await request.json()
    try: return save_queue(str(body.get("name") or ""),user,body.get("filters") or {},bool(body.get("shared")))
    except ValueError as exc: raise HTTPException(400,str(exc))

@app.delete("/api/investigation-queues/{queue_id}")
def investigation_queue_delete(queue_id: int, user: str = Depends(case_writer)): delete_queue(queue_id,user); return {"ok":True}

@app.post("/api/investigations/{case_id}/findings/{finding_id}")
async def investigation_link_finding(case_id: int, finding_id: str, request: Request, user: str = Depends(case_writer)):
    finding=next((x for x in await collect_findings() if x.get("id")==finding_id),None)
    if not finding: raise HTTPException(404,"Finding not found")
    try: case=link_finding(case_id,finding,user)
    except KeyError: raise HTTPException(404,"Investigation case not found")
    audit(user,"finding_linked_to_case","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"finding_id":finding_id}); return case

@app.get("/api/investigations/{case_id}/related")
async def investigation_related(case_id: int, days: int = 30, user: str = Depends(case_reader)):
    days=max(1,min(days,365)); case=_case_or_404(case_id); linked={x.get("id") for x in case["findings"]}; identities={str((x.get("user") or {}).get("id") or (x.get("user") or {}).get("email")) for x in case["findings"]}; factors={f.get("id") for x in case["findings"] for f in x.get("risk_factors",[])}; surfaces={x.get("surface") for x in case["findings"]}; linked_times=[datetime.fromisoformat(str(x.get("created_at")).replace("Z","+00:00")) for x in case["findings"] if x.get("created_at")]
    candidates=[]
    for finding in await collect_findings():
        if finding.get("id") in linked: continue
        identity=str((finding.get("user") or {}).get("id") or (finding.get("user") or {}).get("email")); finding_factors={f.get("id") for f in finding.get("risk_factors",[])}; reasons=[]; created=datetime.fromisoformat(str(finding.get("created_at")).replace("Z","+00:00")) if finding.get("created_at") else None
        if created and linked_times and min(abs((created-x).total_seconds()) for x in linked_times)>days*86400: continue
        if identity in identities: reasons.append("same identity")
        overlap=sorted(factors & finding_factors)
        if overlap: reasons.append("shared indicators: "+", ".join(overlap))
        if finding.get("surface") in surfaces: reasons.append("same provider surface")
        if created and linked_times: reasons.append(f"within {days}-day window")
        if reasons: candidates.append({**finding,"relation_reasons":reasons,"relation_score":(3 if identity in identities else 0)+len(overlap)*2+(1 if finding.get("surface") in surfaces else 0)})
    candidates.sort(key=lambda x:(x["relation_score"],x.get("risk_score",0)),reverse=True); return {"data":candidates[:25]}

@app.get("/api/investigations/{case_id}/export")
def investigation_export(case_id: int, request: Request, report_format: str = Query("pdf",alias="format"), user: str = Depends(case_reader)):
    case=_case_or_404(case_id); report_format=report_format.lower()
    if report_format=="pdf": payload=case_pdf(case,user,APP_VERSION); media="application/pdf"; ext="pdf"
    elif report_format=="json": payload=json.dumps({"exported_at":datetime.now(timezone.utc).isoformat(),"exported_by":user,"version":APP_VERSION,"case":case},indent=2).encode(); media="application/json"; ext="json"
    else: raise HTTPException(400,"Case export format must be pdf or json")
    audit(user,"case_exported","investigation_case",str(case_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"format":report_format})
    return Response(payload,media_type=media,headers={"Content-Disposition":f'attachment; filename="jo-ai-monitor-case-{case_id}.{ext}"',"Cache-Control":"no-store"})

@app.get("/api/activities")
async def activities(request: Request, limit: int = 100, user: str = Depends(current_user)):
    audit(user,"activity_feed_viewed","activity_feed",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"limit":limit})
    if DEMO:
        return {"data":[{"id":"activity_demo_"+str(i),"created_at":x["created_at"],"type":"claude_chat_created" if x["kind"]=="chat" else "session_created","actor":{"type":"user_actor","email_address":x["user"]["email"]},"resource_id":x["id"]} for i,x in enumerate(DEMO_CASES)]}
    return await anthropic_get("/v1/compliance/activities", [("limit",str(min(limit,5000)))])

@app.get("/api/organizations")
async def organizations(request: Request, user: str = Depends(current_user)):
    audit(user,"directory_viewed","directory",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
    if DEMO: return {"data":[{"id":"org_demo","uuid":"91012d09-e48b-438e-a489-1bebfd8fa6f9","name":"Northstar Labs","type":"claude_ai"}]}
    return await anthropic_get("/v1/compliance/organizations")

@app.get("/api/providers")
def providers(request: Request, user: str = Depends(current_user)):
    audit(user,"providers_viewed","configuration",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
    return {"data":[
        {"id":"anthropic","name":"Claude Compliance API","enabled":not DEMO,"surfaces":["Claude.ai","Claude Code","Cowork"]},
        {"id":"m365_copilot","name":"Microsoft 365 Copilot","enabled":M365_ENABLED,"surfaces":["Copilot Chat","Word","Excel","PowerPoint","Outlook"]}
    ]}

@app.get("/api/policies")
def policies(request: Request, user: str = Depends(case_admin)):
    audit(user,"policies_viewed","detection_policy",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
    return {"data":list_policies(),"active":active_policy()}

@app.get("/api/policies/{policy_id}")
def policy_detail(policy_id: int, user: str = Depends(case_admin)):
    try: return get_policy(policy_id)
    except ValueError as exc: raise HTTPException(404,str(exc))

@app.post("/api/policies")
async def policy_create(request: Request, user: str = Depends(case_admin)):
    body=await request.json()
    try: policy=create_draft(str(body.get("version") or ""),str(body.get("name") or ""),str(body.get("description") or ""),user)
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"policy_drafted","detection_policy",str(policy["id"]),request.client.host if request.client else "",request.headers.get("user-agent",""),{"version":policy["version"]})
    return policy

@app.patch("/api/policies/{policy_id}")
async def policy_update(policy_id: int, request: Request, user: str = Depends(case_admin)):
    body=await request.json(); reason=str(body.pop("reason","")).strip()
    if not reason: raise HTTPException(400,"Change reason is required")
    try: policy=update_draft(policy_id,body,user,reason)
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"policy_updated","detection_policy",str(policy_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"version":policy["version"],"reason":reason})
    return policy

@app.post("/api/policies/{policy_id}/approve")
async def policy_approve(policy_id: int, request: Request, user: str = Depends(case_admin)):
    reason=str((await request.json()).get("reason") or "")
    try: policy=approve_policy(policy_id,user,reason)
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"policy_approved","detection_policy",str(policy_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"version":policy["version"],"reason":reason})
    return policy

@app.post("/api/policies/{policy_id}/activate")
async def policy_activate(policy_id: int, request: Request, user: str = Depends(case_admin)):
    reason=str((await request.json()).get("reason") or "")
    try: policy=activate_policy(policy_id,user,reason)
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"policy_activated","detection_policy",str(policy_id),request.client.host if request.client else "",request.headers.get("user-agent",""),{"version":policy["version"],"reason":reason})
    return policy

@app.post("/api/policies/rollback")
async def policy_rollback(request: Request, user: str = Depends(case_admin)):
    reason=str((await request.json()).get("reason") or "")
    try: policy=rollback_policy(user,reason)
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"policy_rolled_back","detection_policy",str(policy["id"]),request.client.host if request.client else "",request.headers.get("user-agent",""),{"version":policy["version"],"reason":reason})
    return policy

def resolve_usage(period: str = "") -> dict[str, Any]:
    if period:
        stored=get_usage_period(period)
        if stored: return {**stored,"mode":"imported"}
        if DEMO and period == DEMO_USAGE["period"]: return {**DEMO_USAGE,"mode":"demo"}
        raise HTTPException(404,"Usage reporting period not found")
    periods=list_usage_periods()
    if periods:
        stored=get_usage_period(periods[0]["period"])
        if stored: return {**stored,"mode":"imported"}
    if DEMO: return {**DEMO_USAGE,"mode":"demo"}
    return {"mode":"live","period":None,"source":"Usage analytics connector not configured","summary":{},
        "licensing":{},"claude_products":[],"claude_models":[],"copilot_apps":[],"top_users":[],
        "caveats":["Import monthly XLSX/CSV analytics or configure a live connector to populate this view."]}

def usage_for_identity(data: dict[str, Any], request: Request) -> dict[str, Any]:
    identity=current_identity(request); named=identity["method"]=="local" or bool(identity["roles"] & USAGE_USER_ROLES)
    return {**data,"user_detail_included":named,"top_users":[{**row,
        "user":row.get("user") if named else row.get("alias",row.get("user")),
        "products":row.get("products",[]),"breakdown":row.get("breakdown",[])} for row in data.get("top_users",[])]}

@app.get("/api/usage")
def usage_analytics(request: Request, period: str = "", user: str = Depends(current_user)):
    data=usage_for_identity(resolve_usage(period),request)
    audit(user,"usage_analytics_viewed","usage_analytics",str(data.get("period") or ""),request.client.host if request.client else "",
        request.headers.get("user-agent",""),{"mode":data.get("mode")})
    return data

@app.get("/api/usage/periods")
def usage_periods(request: Request, user: str = Depends(current_user)):
    periods=list_usage_periods()
    if DEMO and not any(x["period"] == DEMO_USAGE["period"] for x in periods):
        s=DEMO_USAGE["summary"]; periods.append({"period":DEMO_USAGE["period"],"source_name":"Built-in anonymized demo",
            "source_hash":"demo","imported_at":None,"imported_by":"system","copilot_interactions":s["copilot_interactions"],
            "claude_requests":s["claude_requests"],"claude_usage_spend":s["claude_usage_spend"]})
    audit(user,"usage_periods_viewed","usage_analytics",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"periods":len(periods)})
    return {"data":periods}

@app.post("/api/usage/import/preview")
async def usage_import_preview(request: Request, file: UploadFile = File(...), user: str = Depends(current_user)):
    content=await file.read()
    try: data,digest=parse_usage_file(content,file.filename or "usage.xlsx")
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"usage_import_previewed","usage_import",str(data.get("period") or ""),request.client.host if request.client else "",
        request.headers.get("user-agent",""),{"filename":file.filename,"sha256":digest,"warnings":len(data.get("validation",{}).get("warnings",[]))})
    return {"data":usage_for_identity(data,request),"source_hash":digest,"filename":file.filename}

@app.post("/api/usage/import")
async def usage_import(request: Request, file: UploadFile = File(...), replace: bool = False, user: str = Depends(current_user)):
    content=await file.read()
    try:
        data,digest=parse_usage_file(content,file.filename or "usage.xlsx")
        save_usage_period(data,file.filename or "usage.xlsx",digest,user,replace)
    except ValueError as exc: raise HTTPException(409 if "already" in str(exc) else 400,str(exc))
    audit(user,"usage_period_imported","usage_period",str(data["period"]),request.client.host if request.client else "",
        request.headers.get("user-agent",""),{"filename":file.filename,"sha256":digest,"replace":replace})
    return {"ok":True,"period":data["period"],"validation":data.get("validation",{})}

@app.get("/api/reports/usage")
def usage_report(request: Request, period: str = "", report_format: str = Query("pdf",alias="format"), user: str = Depends(current_user)):
    data=usage_for_identity(resolve_usage(period),request); report_format=report_format.lower(); safe=re.sub(r"[^A-Za-z0-9._-]+","-",str(data.get("period") or "usage"))
    if report_format == "pdf": payload=usage_pdf(data,user,APP_VERSION); media="application/pdf"; ext="pdf"
    elif report_format == "csv": payload=usage_csv(data,user,APP_VERSION); media="text/csv; charset=utf-8"; ext="csv"
    elif report_format == "json": payload=json.dumps({"generated_at":datetime.now(timezone.utc).isoformat(),"generated_by":user,"version":APP_VERSION,"report":data},indent=2).encode(); media="application/json"; ext="json"
    elif report_format == "html":
        audit(user,"usage_report_generated","usage_report",str(data.get("period") or ""),request.client.host if request.client else "",request.headers.get("user-agent",""),{"format":"html"})
        return HTMLResponse(usage_html(data,user,APP_VERSION),headers={"Cache-Control":"no-store"})
    else: raise HTTPException(400,"Report format must be pdf, csv, json, or html")
    audit(user,"usage_report_generated","usage_report",str(data.get("period") or ""),request.client.host if request.client else "",request.headers.get("user-agent",""),{"format":report_format})
    return Response(payload,media_type=media,headers={"Content-Disposition":f'attachment; filename="jo-ai-monitor-{safe}.{ext}"',"Cache-Control":"no-store"})

@app.get("/api/reports/findings/summary")
async def findings_report_summary(request: Request, date_from: str = "", date_to: str = "", risk: str = "all", surface: str = "all", include_named_users: bool = False, user: str = Depends(current_user)):
    if include_named_users and not can_view_named_users(request): raise HTTPException(403,"Named-user reporting requires an approved report role")
    try: rows=filter_findings(await collect_findings(),date_from,date_to,risk,surface)
    except ValueError as exc: raise HTTPException(400,str(exc))
    report=findings_summary(rows,include_named_users)
    audit(user,"findings_report_viewed","findings_report",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"date_from":date_from,"date_to":date_to,"risk":risk,"surface":surface,"include_named_users":include_named_users,"results":len(rows)})
    return {"generated_at":datetime.now(timezone.utc).isoformat(),"generated_by":user,"version":APP_VERSION,"filters":{"date_from":date_from,"date_to":date_to,"risk":risk,"surface":surface},"named_users_included":include_named_users,"named_user_authorized":can_view_named_users(request),"report":report}

@app.get("/api/reports/findings")
async def findings_report(request: Request, date_from: str = "", date_to: str = "", risk: str = "all", surface: str = "all", include_named_users: bool = False, report_format: str = Query("pdf",alias="format"), user: str = Depends(current_user)):
    if include_named_users and not can_view_named_users(request): raise HTTPException(403,"Named-user reporting requires an approved report role")
    try: rows=filter_findings(await collect_findings(),date_from,date_to,risk,surface)
    except ValueError as exc: raise HTTPException(400,str(exc))
    filters={"date_from":date_from,"date_to":date_to,"risk":risk,"surface":surface}; report=findings_summary(rows,include_named_users); report_format=report_format.lower()
    envelope={"generated_at":datetime.now(timezone.utc).isoformat(),"generated_by":user,"version":APP_VERSION,"filters":filters,"named_users_included":include_named_users,"report":report}
    if report_format=="pdf": payload=findings_pdf(report,user,APP_VERSION,filters); media="application/pdf"; ext="pdf"
    elif report_format=="csv": payload=findings_csv(report,user,APP_VERSION,filters); media="text/csv; charset=utf-8"; ext="csv"
    elif report_format=="json": payload=json.dumps(envelope,indent=2).encode(); media="application/json"; ext="json"
    else: raise HTTPException(400,"Report format must be pdf, csv, or json")
    audit(user,"findings_report_generated","findings_report",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={**filters,"format":report_format,"include_named_users":include_named_users,"results":len(rows)})
    return Response(payload,media_type=media,headers={"Content-Disposition":f'attachment; filename="jo-ai-monitor-findings.{ext}"',"Cache-Control":"no-store"})

@app.get("/api/reports/trends")
async def report_trends(request: Request, user: str = Depends(current_user)):
    risk=findings_trends(await collect_findings()); usage=[]
    for item in reversed(list_usage_periods()):
        usage.append({"period":item["period"],"copilot_interactions":item.get("copilot_interactions",0),"claude_requests":item.get("claude_requests",0),"claude_usage_spend":item.get("claude_usage_spend",0)})
    if DEMO and not usage:
        base=DEMO_USAGE["summary"]
        for month,multiplier in (("April 2026",.63),("May 2026",.74),("June 2026",.86),("July 2026",1)):
            usage.append({"period":month,"copilot_interactions":round(base["copilot_interactions"]*multiplier),"claude_requests":round(base["claude_requests"]*multiplier),"claude_usage_spend":round(base["claude_usage_spend"]*multiplier,2)})
    audit(user,"trends_viewed","reports",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
    return {"risk":risk,"usage":usage}

@app.get("/api/report-schedules")
def report_schedules(request: Request, user: str = Depends(current_user)):
    audit(user,"report_schedules_viewed","report_schedule",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""))
    return {"data":list_schedules(),"smtp_configured":smtp_configured(),"named_user_authorized":can_view_named_users(request)}

@app.post("/api/report-schedules")
async def add_report_schedule(request: Request, user: str = Depends(current_user)):
    body=await request.json(); include=bool(body.get("include_named_users"))
    if include and not can_view_named_users(request): raise HTTPException(403,"Named-user reporting requires an approved report role")
    try: schedule=create_schedule(str(body.get("name") or "Compliance report"),body.get("recipients") or [],str(body.get("frequency") or "monthly"),str(body.get("format") or "pdf").lower(),include,user)
    except ValueError as exc: raise HTTPException(400,str(exc))
    audit(user,"report_schedule_created","report_schedule",str(schedule["id"]),request.client.host if request.client else "",request.headers.get("user-agent",""),{"frequency":schedule["frequency"],"format":schedule["report_format"],"include_named_users":include})
    return schedule

@app.delete("/api/report-schedules/{schedule_id}")
def remove_report_schedule(schedule_id: int, request: Request, user: str = Depends(current_user)):
    delete_schedule(schedule_id); audit(user,"report_schedule_deleted","report_schedule",str(schedule_id),request.client.host if request.client else "",request.headers.get("user-agent","")); return {"ok":True}

@app.get("/api/connectors/status")
def connector_status(user: str = Depends(current_user)):
    return {"data":[
        {"id":"anthropic_compliance","name":"Claude Compliance evidence","configured":not DEMO,"mode":"live" if not DEMO else "demo"},
        {"id":"m365_interactions","name":"Microsoft 365 Copilot interactions","configured":M365_ENABLED,"mode":"live" if M365_ENABLED else "not_configured"},
        {"id":"usage_import","name":"Monthly XLSX/CSV analytics","configured":bool(list_usage_periods()) or DEMO,"mode":"imported" if list_usage_periods() else "demo" if DEMO else "not_configured"},
        {"id":"smtp","name":"Scheduled report email delivery","configured":smtp_configured(),"mode":"live" if smtp_configured() else "artifact_only"}]}

async def run_due_report_schedules() -> None:
    now=datetime.now(timezone.utc)
    for schedule in list_schedules():
        if not schedule["enabled"]: continue
        due=datetime.fromisoformat(schedule["next_run_at"].replace("Z","+00:00"))
        if due > now: continue
        if not smtp_configured():
            update_schedule_run(schedule["id"],"delivery_not_configured")
            audit("system","scheduled_report_skipped","report_schedule",str(schedule["id"]),details={"reason":"smtp_not_configured"})
            continue
        days={"daily":1,"weekly":7,"monthly":30}[schedule["frequency"]]; rows=filter_findings(await collect_findings(),(now-timedelta(days=days)).date().isoformat(),now.date().isoformat())
        report=findings_summary(rows,schedule["include_named_users"]); report_format=schedule["report_format"]
        if report_format=="pdf": payload=findings_pdf(report,"system",APP_VERSION,{"date_from":(now-timedelta(days=days)).date().isoformat(),"date_to":now.date().isoformat(),"risk":"all","surface":"all"}); media="application/pdf"
        elif report_format=="csv": payload=findings_csv(report,"system",APP_VERSION,{"date_from":(now-timedelta(days=days)).date().isoformat(),"date_to":now.date().isoformat(),"risk":"all","surface":"all"}); media="text/csv"
        else: payload=json.dumps({"generated_at":now.isoformat(),"version":APP_VERSION,"report":report},indent=2).encode(); media="application/json"
        try:
            await asyncio.to_thread(send_report,schedule["recipients"],f"JO AI Monitor - {schedule['name']}",payload,f"jo-ai-monitor-findings.{report_format}",media)
            status=f"delivered_to_{len(schedule['recipients'])}_recipient(s)"
        except Exception as exc: status=f"failed: {str(exc)[:180]}"
        update_schedule_run(schedule["id"],status); audit("system","scheduled_report_processed","report_schedule",str(schedule["id"]),details={"status":status,"findings":len(rows)})

async def report_scheduler_loop() -> None:
    while True:
        try: await run_due_report_schedules()
        except Exception as exc: audit("system","report_scheduler_error","report_schedule",details={"error":str(exc)[:300]})
        await asyncio.sleep(300)

@app.on_event("startup")
async def start_report_scheduler():
    asyncio.create_task(report_scheduler_loop())

@app.get("/api/audit")
def audit_log(request: Request, limit: int = 200, actor: str = "", action: str = "", user: str = Depends(current_user)):
    audit(user,"audit_log_viewed","audit_log",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"actor_filter":actor,"action_filter":action,"limit":limit})
    return {"data":read_audit(limit,actor,action),"chain_valid":verify_chain()}

@app.get("/api/export/{case_id}")
async def export_case(case_id: str, request: Request, user: str = Depends(current_user)):
    data = await case_detail(case_id, request, user)
    audit(user,"evidence_exported","evidence",case_id,request.client.host if request.client else "",request.headers.get("user-agent",""),{"format":"json"})
    payload = json.dumps({"exported_at":time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),"exported_by":user,"source":"Anthropic Compliance API","evidence":data}, indent=2)
    return Response(payload, media_type="application/json", headers={"Content-Disposition":f'attachment; filename="evidence-{case_id}.json"'})
