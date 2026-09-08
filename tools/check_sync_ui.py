"""Mocked browser regression for audit diagnostics and scoring explanations."""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]/"app"/"static"
ITEM={"id":"test-record","risk":"high","title":"Test evidence","summary":"", "surface":"Claude.ai", "created_at":"2026-09-08T00:00:00Z", "user":{"email":"test@example.com"}, "messages":[{"role":"human","text":"Test prompt"},{"role":"assistant","text":"Test response"}], "risk_scoring_basis":"user_text", "risk_review_notes":["Workflow approval unknown: <script>bad()</script>"],"risk_factors":[{"id":"unauthorized_app_generation","points":60}]}

def route_app(route):
    path=route.request.url.split("monitor.test",1)[-1].split("?",1)[0]
    if path=="/api/auth/config": route.fulfill(json={"local_enabled":True,"version":"0.9.8"})
    elif path=="/api/auth/me": route.fulfill(json={"pages":["evidence","audit"]})
    elif path=="/api/cases": route.fulfill(json={"data":[ITEM],"mode":"live","sync":{"state":"partial","error":"Retry pending"}})
    elif path=="/api/cases/test-record": route.fulfill(json=ITEM)
    elif path=="/api/audit": route.fulfill(json={"chain_valid":True,"data":[{"created_at":"2026-09-08T00:00:00Z","actor":"system","action":"finding_hydration_failed","object_type":"evidence","object_id":"test-record","details":{"status":429,"error_type":"<img src=x onerror=bad()>"}}]})
    elif path.startswith("/api/"): route.fulfill(json={"data":[]})
    else:
        file=ROOT/("index.html" if path=="/" else path.removeprefix("/static/"))
        route.fulfill(body=file.read_text(encoding="utf-8"),content_type={".html":"text/html",".js":"application/javascript",".css":"text/css",".svg":"image/svg+xml"}.get(file.suffix,"text/plain"))

with sync_playwright() as p:
    browser=p.chromium.launch(channel="msedge",headless=True)
    page=browser.new_page();errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
    page.route("http://monitor.test/**",route_app);page.goto("http://monitor.test/")
    page.locator("#auditNav").click()
    page.locator("summary",has_text="HTTP 429").click()
    assert "<img" in page.locator("#infoBody pre").inner_text()
    assert page.locator("#infoBody img").count()==0
    page.locator("#evidenceNav").click();page.evaluate("detail('test-record')")
    page.locator("#detail h3",has_text="SCORING").wait_for()
    assert "Workflow approval unknown" in page.locator("#detail").inner_text()
    assert page.locator("#detail script").count()==0
    assert page.locator("#detail .message b").nth(0).inner_text().startswith("test@example.com")
    assert page.locator("#detail .message b").nth(1).inner_text().startswith("assistant")
    assert page.locator('link[rel="icon"]').get_attribute("href").startswith("/static/favicon.svg")
    page.evaluate("closeDetail(); all[0].id='clls_'+ 'A'.repeat(2000); all[0].title='Long evidence title '.repeat(30); render()")
    for width in (1920,1280):
        page.set_viewport_size({"width":width,"height":900})
        sizes=page.evaluate("""() => {
            const table=document.querySelector('.evidence-table'), wrap=table.parentElement;
            const id=document.querySelector('#rows td:nth-child(2) .sub');
            return {table:table.getBoundingClientRect().width,wrap:wrap.clientWidth,
                idWidth:id.clientWidth,idScroll:id.scrollWidth,full:id.title.length,
                page:document.documentElement.scrollWidth,viewport:innerWidth};
        }""")
        assert sizes['table'] <= max(980,sizes['wrap'])+1,sizes
        assert sizes['idScroll'] > sizes['idWidth'],sizes
        assert sizes['full']==2005,sizes
        assert sizes['page'] <= sizes['viewport'],sizes
    assert not errors,errors
    browser.close()
    print("PASS: audit HTTP details, escaped diagnostics, scoring explanations, favicon, no browser errors")
