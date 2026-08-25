import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).parent
USERNAME = os.getenv("APP_USERNAME", "admin")
PASSWORD = os.getenv("APP_PASSWORD", "change-me-now")
SECRET = os.getenv("SESSION_SECRET", "development-only-secret-change-me").encode()
API_KEY = os.getenv("ANTHROPIC_COMPLIANCE_ACCESS_KEY", "")
BASE_URL = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
DEMO = os.getenv("DEMO_MODE", "true").lower() == "true" or not API_KEY
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
LOCAL_AUTH = os.getenv("LOCAL_AUTH_ENABLED", "true").lower() == "true"
ENTRA_TENANT = os.getenv("ENTRA_TENANT_ID", "").strip()
ENTRA_CLIENT = os.getenv("ENTRA_CLIENT_ID", "").strip()
ENTRA_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "").strip()
ENTRA_REDIRECT = os.getenv("ENTRA_REDIRECT_URI", "").strip()
ENTRA_ENABLED = all((ENTRA_TENANT, ENTRA_CLIENT, ENTRA_SECRET, ENTRA_REDIRECT))
ENTRA_ROLES = {x.strip() for x in os.getenv("ENTRA_ALLOWED_ROLES", "").split(",") if x.strip()}
ENTRA_GROUPS = {x.strip() for x in os.getenv("ENTRA_ALLOWED_GROUPS", "").split(",") if x.strip()}

app = FastAPI(title="JO AI Monitor", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET.decode(errors="ignore"), session_cookie="jo_oauth", max_age=600, same_site="lax", https_only=COOKIE_SECURE)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

oauth = OAuth()
if ENTRA_ENABLED:
    oauth.register(name="entra", client_id=ENTRA_CLIENT, client_secret=ENTRA_SECRET,
        server_metadata_url=f"https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"})

DEMO_CASES = [
    {"id":"claude_chat_01RISK8Q2","kind":"chat","risk":"critical","status":"open","created_at":"2026-08-25T14:42:18Z","updated_at":"2026-08-25T14:44:02Z","user":{"id":"user_01A","email":"alex.morgan@northstar.example"},"surface":"Claude.ai","title":"Privilege escalation guidance","summary":"User requested instructions to obtain unauthorized root access on a production Linux host.","matched":["credential access","privilege escalation"],"messages":[{"role":"human","created_at":"2026-08-25T14:42:18Z","text":"How do I hack root access on the production Linux server without the admin noticing?"},{"role":"assistant","created_at":"2026-08-25T14:42:24Z","text":"I can’t help gain unauthorized access. If you administer the server, I can help with a legitimate recovery or hardening procedure."}]},
    {"id":"clls_01RISK6M9","kind":"session","risk":"high","status":"review","created_at":"2026-08-25T13:08:51Z","updated_at":"2026-08-25T13:16:30Z","user":{"id":"user_01B","email":"sam.lee@northstar.example"},"surface":"Claude Code","title":"Bulk credential discovery","summary":"Terminal session included attempts to locate cloud credentials and private keys.","matched":["secrets discovery","cloud credentials"],"messages":[{"role":"human","created_at":"2026-08-25T13:09:04Z","text":"Search every home directory for AWS credentials and private SSH keys, then bundle them."},{"role":"assistant","created_at":"2026-08-25T13:09:09Z","text":"I can help audit credential exposure with authorization. Define the approved scope and a secure findings destination."}]},
    {"id":"claude_chat_01DATA4J7","kind":"chat","risk":"medium","status":"closed","created_at":"2026-08-24T19:21:33Z","updated_at":"2026-08-24T19:39:12Z","user":{"id":"user_01C","email":"jamie.chen@northstar.example"},"surface":"Claude.ai","title":"Customer data handling","summary":"A customer export containing personal data was attached for summarization.","matched":["personal data","file upload"],"messages":[{"role":"human","created_at":"2026-08-24T19:21:33Z","text":"Summarize this customer export and identify everyone likely to churn."},{"role":"assistant","created_at":"2026-08-24T19:21:40Z","text":"Before processing, confirm this use is permitted by your organization’s privacy and data-handling policy."}]},
    {"id":"cse_01SAFE2P4","kind":"session","risk":"low","status":"closed","created_at":"2026-08-24T16:10:00Z","updated_at":"2026-08-24T16:32:43Z","user":{"id":"user_01D","email":"priya.shah@northstar.example"},"surface":"Cowork","title":"Quarterly planning brief","summary":"Routine document synthesis with no detected policy indicators.","matched":[],"messages":[{"role":"human","created_at":"2026-08-24T16:10:00Z","text":"Turn these approved planning notes into a one-page executive brief."}]}
]

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
def health(): return {"status":"ok","mode":"demo" if DEMO else "live","entra_enabled":ENTRA_ENABLED}

@app.get("/")
def index(): return FileResponse(ROOT / "static" / "index.html")

@app.post("/api/auth/login")
async def login(request: Request):
    if not LOCAL_AUTH: raise HTTPException(404, "Local authentication is disabled")
    body = await request.json()
    if not (hmac.compare_digest(str(body.get("username", "")), USERNAME) and hmac.compare_digest(str(body.get("password", "")), PASSWORD)):
        raise HTTPException(401, "Invalid username or password")
    response = JSONResponse({"user": USERNAME})
    response.set_cookie("cm_session", make_token(USERNAME), httponly=True, secure=COOKIE_SECURE, samesite="lax", max_age=28800)
    return response

@app.post("/api/auth/logout")
def logout(request: Request):
    request.session.clear()
    response = JSONResponse({"ok": True}); response.delete_cookie("cm_session"); response.delete_cookie("jo_oauth"); return response

@app.get("/api/auth/config")
def auth_config(): return {"entra_enabled":ENTRA_ENABLED,"local_enabled":LOCAL_AUTH}

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
    return response

@app.get("/api/auth/me")
def me(user: str = Depends(current_user)): return {"user":user,"mode":"demo" if DEMO else "live"}

@app.get("/api/cases")
async def cases(q: str = "", risk: str = "all", surface: str = "all", user: str = Depends(current_user)):
    if DEMO:
        rows = DEMO_CASES
    else:
        chats, local, remote = await _live_index()
        rows = chats + local + remote
    needle = q.lower().strip()
    return {"data":[x for x in rows if (risk == "all" or x["risk"] == risk) and (surface == "all" or x["surface"] == surface) and (not needle or needle in json.dumps(x).lower())],"mode":"demo" if DEMO else "live"}

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
async def case_detail(case_id: str, user: str = Depends(current_user)):
    if DEMO:
        item = next((x for x in DEMO_CASES if x["id"] == case_id), None)
        if not item: raise HTTPException(404, "Evidence not found")
        return item
    if case_id.startswith("claude_chat_"):
        data = await anthropic_get(f"/v1/compliance/apps/chats/{case_id}/messages")
    elif case_id.startswith("cse_"):
        data = await anthropic_get(f"/v1/compliance/apps/sessions/remote/{case_id}/messages")
    else:
        data = await anthropic_get(f"/v1/compliance/apps/sessions/local/{case_id}/messages")
    return data

@app.get("/api/activities")
async def activities(limit: int = 100, user: str = Depends(current_user)):
    if DEMO:
        return {"data":[{"id":"activity_demo_"+str(i),"created_at":x["created_at"],"type":"claude_chat_created" if x["kind"]=="chat" else "session_created","actor":{"type":"user_actor","email_address":x["user"]["email"]},"resource_id":x["id"]} for i,x in enumerate(DEMO_CASES)]}
    return await anthropic_get("/v1/compliance/activities", [("limit",str(min(limit,5000)))])

@app.get("/api/organizations")
async def organizations(user: str = Depends(current_user)):
    if DEMO: return {"data":[{"id":"org_demo","uuid":"91012d09-e48b-438e-a489-1bebfd8fa6f9","name":"Northstar Labs","type":"claude_ai"}]}
    return await anthropic_get("/v1/compliance/organizations")

@app.get("/api/export/{case_id}")
async def export_case(case_id: str, user: str = Depends(current_user)):
    data = await case_detail(case_id, user)
    payload = json.dumps({"exported_at":time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),"exported_by":user,"source":"Anthropic Compliance API","evidence":data}, indent=2)
    return Response(payload, media_type="application/json", headers={"Content-Disposition":f'attachment; filename="evidence-{case_id}.json"'})
