import hashlib
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

CORRELATION_WINDOW_DAYS=max(1,min(int(os.getenv("ALERT_CORRELATION_WINDOW_DAYS","30")),365))
CORRELATION_MIN_EVENTS=max(2,min(int(os.getenv("ALERT_CORRELATION_MIN_EVENTS","3")),100))
BUDGET_PERCENT=max(1,min(int(os.getenv("ALERT_BUDGET_PERCENT","80")),1000))
UNUSED_SEAT_MIN=max(1,int(os.getenv("ALERT_UNUSED_SEAT_MIN","1")))
RUN_RATE_LIMIT=max(0,float(os.getenv("ALERT_MONTHLY_RUN_RATE_LIMIT_USD","0")))
MODEL_SPEND_SHARE=max(1,min(float(os.getenv("ALERT_MODEL_SPEND_SHARE_PERCENT","40")),100))
MODEL_REQUEST_SHARE_MAX=max(0,min(float(os.getenv("ALERT_MODEL_REQUEST_SHARE_MAX_PERCENT","20")),100))

def _number(value: Any) -> float:
    try: return float(value or 0)
    except (TypeError,ValueError): return 0

def _identity_hash(row: dict[str,Any]) -> str:
    user=row.get("user") or {}; identity=str(user.get("id") or user.get("email") or "unknown").casefold()
    return hashlib.sha256(identity.encode()).hexdigest()[:16]

def correlate_findings(rows: list[dict[str,Any]], now: datetime | None=None) -> list[dict[str,Any]]:
    now=now or datetime.now(timezone.utc); cutoff=now-timedelta(days=CORRELATION_WINDOW_DAYS); groups=defaultdict(list)
    for row in rows:
        try: observed=datetime.fromisoformat(str(row.get("created_at") or "").replace("Z","+00:00"))
        except ValueError: continue
        if observed.tzinfo is None: observed=observed.replace(tzinfo=timezone.utc)
        if observed<cutoff: continue
        identity=_identity_hash(row)
        for factor in row.get("risk_factors") or []: groups[(identity,str(factor.get("id") or "unknown"))].append(row)
    alerts=[]
    for (identity,factor),matches in groups.items():
        if len(matches)<CORRELATION_MIN_EVENTS: continue
        surfaces=sorted({str(x.get("surface") or "Unknown") for x in matches}); bucket=now.strftime("%Y-%m")
        alerts.append({"event_key":f"correlation:{bucket}:{identity}:{factor}","alert_type":"behavioral_correlation","severity":"high",
            "title":f"Repeated {factor.replace('_',' ')} findings","summary":f"{len(matches)} related findings occurred across {len(surfaces)} AI surfaces within {CORRELATION_WINDOW_DAYS} days.",
            "finding_id":str(matches[-1].get("id") or ""),"metadata":{"event_count":len(matches),"surfaces":surfaces,"factor_id":factor,"identity_hash":identity,"window_days":CORRELATION_WINDOW_DAYS}})
    return alerts

def usage_alerts(data: dict[str,Any]) -> list[dict[str,Any]]:
    period=str(data.get("period") or "unknown-period"); summary=data.get("summary") or {}; licensing=data.get("licensing") or {}; alerts=[]
    spend=_number(summary.get("claude_usage_spend")); budget=_number(summary.get("claude_usage_budget")); utilization=spend/budget*100 if budget else 0
    if budget and utilization>=BUDGET_PERCENT:
        alerts.append({"event_key":f"usage:{period}:budget","alert_type":"budget","severity":"critical" if utilization>=100 else "high",
            "title":"Claude usage budget threshold reached","summary":f"Usage spend is {utilization:.1f}% of the configured budget for {period}.","metadata":{"period":period,"spend":spend,"budget":budget,"utilization_percent":round(utilization,1)}})
    unused=int(_number(licensing.get("claude_seats_unassigned")))
    if unused>=UNUSED_SEAT_MIN:
        alerts.append({"event_key":f"usage:{period}:unused-seats","alert_type":"unused_license","severity":"medium","title":"Unused Claude licenses detected",
            "summary":f"{unused} purchased Claude seats are unassigned for {period}.","metadata":{"period":period,"unassigned_seats":unused,"purchased_seats":int(_number(licensing.get("claude_seats_purchased")))}})
    run_rate=_number(licensing.get("estimated_monthly_run_rate"))
    if RUN_RATE_LIMIT and run_rate>=RUN_RATE_LIMIT:
        alerts.append({"event_key":f"usage:{period}:run-rate","alert_type":"cost","severity":"high","title":"AI monthly run-rate limit reached",
            "summary":f"Estimated monthly AI run rate is ${run_rate:,.2f} for {period}.","metadata":{"period":period,"run_rate":run_rate,"limit":RUN_RATE_LIMIT}})
    models=data.get("claude_models") or []; total_spend=sum(_number(x.get("spend")) for x in models); total_requests=sum(_number(x.get("requests")) for x in models)
    for model in models:
        spend_share=_number(model.get("spend"))/total_spend*100 if total_spend else 0; request_share=_number(model.get("requests"))/total_requests*100 if total_requests else 0
        if spend_share>=MODEL_SPEND_SHARE and request_share<=MODEL_REQUEST_SHARE_MAX:
            name=str(model.get("name") or "Unknown model")
            alerts.append({"event_key":f"usage:{period}:model:{hashlib.sha256(name.encode()).hexdigest()[:12]}","alert_type":"model_economics","severity":"medium",
                "title":"Model cost concentration requires review","summary":f"{name} represents {spend_share:.1f}% of Claude spend and {request_share:.1f}% of requests for {period}.",
                "metadata":{"period":period,"model":name,"spend_share_percent":round(spend_share,1),"request_share_percent":round(request_share,1)}})
    return alerts
