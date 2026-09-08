from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.report_charts import charts_html
CHARTS=charts_html({"copilot_apps":[{"name":"Word","interactions":70},{"name":"Outlook","interactions":30}],"claude_products":[{"name":"Claude Code","spend":60},{"name":"Chat","spend":20}],"copilot_daily":[{"Date":f"2026-08-{i:02}","Interactions":i*5%37} for i in range(1,20)]})
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]/"app"/"static"
def route_app(route):
    path=route.request.url.split("monitor.test",1)[-1].split("?",1)[0]
    if path=="/api/auth/config": route.fulfill(json={"local_enabled":True,"version":"test"})
    elif path=="/api/auth/me": route.fulfill(json={"pages":["reports"],"usage_import":False})
    elif path in ("/api/reports/executive/periods","/api/usage/periods"):route.fulfill(json={"current_month":"2026-09","data":[{"period":"2026-09"},{"period":"2026-08"},{"period":"Copilot - last 30 days"},{"period":"Copilot - month 2026-08"}]})
    elif path in ("/api/usage","/api/reports/executive") and "Copilot" in route.request.url:route.fulfill(json={"summary":{"copilot_active_users":8,"copilot_enabled_users":12},"report_refresh_date":"2026-09-06","charts_html":"","executive_sections":[]})
    elif path in ("/api/reports/executive","/api/usage"):route.fulfill(json={"period":"August 2026","mode":"imported","source":"Monthly workbook","summary":{"copilot_active_users":10,"copilot_interactions":100,"claude_requests":20,"claude_usage_spend":3.5},"executive_sections":[{"name":"Department Summary","rows":[["Department","Users"],["<script>bad()</script>",2]]},{"name":"Daily trend","rows":[[str(i),i] for i in range(65)]}],"user_detail_included":False,"charts_html":CHARTS})
    elif path.startswith("/api/"):route.fulfill(json={"data":[]})
    else:
        file=ROOT/("index.html" if path=="/" else path.removeprefix("/static/"))
        route.fulfill(body=file.read_text(encoding="utf-8"),content_type={".html":"text/html",".js":"application/javascript",".css":"text/css"}.get(file.suffix,"text/plain"))
with sync_playwright() as p:
    browser=p.chromium.launch(channel="msedge",headless=True)
    page=browser.new_page(viewport={"width":1440,"height":1000});errors=[]
    page.on("pageerror",lambda e:errors.append(str(e)));page.route("http://monitor.test/**",route_app)
    page.goto("http://monitor.test/#reports")
    page.locator("#executiveSection").wait_for()
    assert page.locator("#manageUsageImports").count()==0
    assert page.locator("#evidenceNav").is_hidden()
    assert page.locator("#executiveTable script").count()==0
    assert "pseudonymized" not in page.locator("#executiveReport").inner_text()
    assert "format=xlsx" in page.get_by_text("Download Excel",exact=True).get_attribute("href")
    page.locator("#executiveSection").select_option("1")
    page.locator("#executiveNext").click()
    assert page.locator("#executivePage").inner_text()=="31–60 of 65 rows"
    page.locator("#executiveNext").click()
    assert page.locator("#executiveNext").is_disabled()
    assert page.locator(".report-chart").count()==3
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    assert page.locator("#executivePeriod option").all_text_contents()==["August 2026","Copilot — August 2026"]
    assert page.locator("#executiveReport h3").first.inner_text()=="Claude"
    assert page.locator("#executiveReport").get_attribute("data-provider")=="claude"
    page.locator("#viewCopilotDetail").click()
    page.wait_for_function("document.querySelector('#executiveReport')?.dataset.provider==='copilot'")
    assert "Copilot%20-%20month%202026-08" in page.get_by_text("Download Excel",exact=True).get_attribute("href")
    assert page.locator("#copilotOverview").is_hidden()
    page.evaluate("openExecutiveReports(true)")
    page.wait_for_function("document.querySelector('#executivePeriod')?.value==='2026-09'")
    assert page.locator("#executivePeriod option").all_text_contents()==["September 2026","Copilot - last 30 days"]
    page.locator("#viewCopilotDetail").wait_for()
    assert page.locator("#executiveReport h3").first.inner_text()=="Claude"
    assert page.locator("#executiveReport").evaluate("e=>getComputedStyle(e).getPropertyValue('--report-accent').trim()") == "#b65335"
    assert "Active users" in page.locator("#copilotOverview").inner_text()
    assert "8" in page.locator("#copilotOverview").inner_text()
    page.locator("#viewCopilotDetail").click()
    page.wait_for_function("document.querySelector('#executiveReport')?.dataset.provider==='copilot'")
    assert page.locator("#copilotOverview").is_hidden()
    page.evaluate("document.documentElement.setAttribute('data-theme','dark')")
    assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
    assert not errors,errors
    browser.close();print("PASS: reports-only monthly preview, section pagination, download links, escaped content")
