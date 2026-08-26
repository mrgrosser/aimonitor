import base64
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from app.governance import FINDING_THRESHOLD, audit, init_db, read_audit, record_suppressed, score_evidence, suppressed_count, verify_chain

ROOT = Path(__file__).parent
USERNAME = os.getenv("APP_USERNAME", "admin")
PASSWORD = os.getenv("APP_PASSWORD", "change-me-now")
SECRET = os.getenv("SESSION_SECRET", "development-only-secret-change-me").encode()
API_KEY = os.getenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "")
BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
DEMO = os.getenv("DEMO_MODE", "true").lower() == "true" or not API_KEY
APP_VERSION = os.getenv("APP_VERSION", "0.6.1")
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
_graph_token: dict[str, Any] = {}
_m365_evidence: dict[str, dict[str, Any]] = {}

app = FastAPI(title="JO AI Monitor", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET.decode(errors="ignore"), session_cookie="jo_oauth", max_age=600, same_site="lax", https_only=COOKIE_SECURE)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
init_db()

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
        created = anchor - timedelta(minutes=i * 37 + (i % 7) * 11)
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
        {"user":"User 001","provider":"Microsoft 365 Copilot","volume":1136,"surfaces":3,"active_days":20},
        {"user":"User 002","provider":"Microsoft 365 Copilot","volume":945,"surfaces":4,"active_days":21},
        {"user":"User 003","provider":"Microsoft 365 Copilot","volume":522,"surfaces":4,"active_days":21},
        {"user":"User 004","provider":"Claude Enterprise","volume":2428,"surfaces":2,"active_days":18,"spend":45.13},
        {"user":"User 005","provider":"Claude Enterprise","volume":2150,"surfaces":5,"active_days":20,"spend":96.12},
        {"user":"User 006","provider":"Claude Enterprise","volume":2017,"surfaces":5,"active_days":19,"spend":83.27}],
    "caveats":["Copilot interactions and Claude API requests are different units and must not be totaled or compared as equivalent effort.",
        "Agentic products such as Claude Code and Cowork may issue many API requests for one user action.",
        "Usage indicates adoption and workflow mix—not employee productivity or performance.",
        "Named-user detail should remain role-restricted and every view should be audited."]
}

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

def make_token(username: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"u": username, "exp": int(time.time()) + 28800}).encode()).decode().rstrip("=")
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def current_user(request: Request) -> str:
    token = request.cookies.get("cm_session", "")
    try:
        payload, sig = token.rsplit(".", 1)
        expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): raise ValueError()
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        data = json.loads(raw)
        if data["exp"] < time.time(): raise ValueError()
        return data["u"]
    except Exception:
        raise HTTPException(401, "Authentication required")

async def anthropic_get(path: str, params: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    if DEMO: return {"data": []}
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.get(f"{BASE_URL}{path}", params=params, headers={"x-api-key": API_KEY})
    if res.status_code >= 400:
        detail = res.json().get("error", {}).get("message", res.text)
        raise HTTPException(res.status_code, detail)
    return res.json()

@app.get("/health")
def health(): return {"status":"ok","version":APP_VERSION,"mode":"demo" if DEMO else "live","entra_enabled":ENTRA_ENABLED,"m365_copilot_enabled":M365_ENABLED}

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
    response.set_cookie("cm_session", make_token(USERNAME), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=28800)
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
    response.set_cookie("cm_session", make_token(username), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=28800)
    audit(username,"login_succeeded","session",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"method":"entra","roles":sorted(roles)})
    return response

@app.get("/api/auth/me")
def me(user: str = Depends(current_user)): return {"user":user,"mode":"demo" if DEMO else "live"}

@app.get("/api/cases")
async def cases(request: Request, q: str = "", risk: str = "all", surface: str = "all", user: str = Depends(current_user)):
    if DEMO:
        rows = DEMO_CASES
    else:
        chats, local, remote = await _live_index()
        rows = await hydrate_live(chats + local + remote) + (await m365_cases() if M365_ENABLED else [])
    promoted=[]
    for row in rows:
        score_evidence(row)
        if row["promoted"]: promoted.append(row)
        else: record_suppressed(row,"m365" if row.get("kind")=="copilot" else "anthropic")
    rows=promoted
    needle = q.lower().strip()
    result=[x for x in rows if (risk == "all" or x["risk"] == risk) and (surface == "all" or x["surface"] == surface) and (not needle or needle in json.dumps(x).lower())]
    audit(user,"findings_searched","evidence_collection",source_ip=request.client.host if request.client else "",user_agent=request.headers.get("user-agent",""),details={"query":q,"risk":risk,"surface":surface,"results":len(result)})
    return {"data":result,"mode":"demo" if DEMO else "live","finding_threshold":FINDING_THRESHOLD,"suppressed_count":suppressed_count()}

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

@app.get("/api/usage")
def usage_analytics(request: Request, user: str = Depends(current_user)):
    audit(user,"usage_analytics_viewed","usage_analytics",source_ip=request.client.host if request.client else "",
        user_agent=request.headers.get("user-agent",""),details={"period":DEMO_USAGE["period"],"mode":"demo" if DEMO else "live"})
    if DEMO:
        return {**DEMO_USAGE,"mode":"demo"}
    return {"mode":"live","period":None,"source":"Usage analytics connector not configured","summary":{},
        "licensing":{},"claude_products":[],"claude_models":[],"copilot_apps":[],"top_users":[],
        "caveats":["Configure monthly usage analytics ingestion to populate this view."]}

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
