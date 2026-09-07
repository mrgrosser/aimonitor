"""Browser regression check. Run: uv run --with playwright python tools/check_theme.py"""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1] / "app" / "static"


def route_app(route):
    path = route.request.url.split("monitor.test", 1)[-1].split("?", 1)[0]
    if path == "/api/auth/config":
        route.fulfill(json={"local_enabled":True,"entra_enabled":False,"version":"0.9.7"})
    elif path.startswith("/api/"):
        route.fulfill(status=401,json={"detail":"Authentication required"})
    else:
        file = ROOT / ("index.html" if path == "/" else path.removeprefix("/static/"))
        mime = {".html":"text/html", ".js":"application/javascript", ".css":"text/css"}.get(file.suffix,"text/plain")
        route.fulfill(body=file.read_text(encoding="utf-8"),content_type=mime)


def check():
    with sync_playwright() as p:
        browser=p.chromium.launch(channel="msedge",headless=True)
        context=browser.new_context(color_scheme="dark")
        context.route("http://monitor.test/**",route_app)
        page=context.new_page(); errors=[];page.on("pageerror",lambda error:errors.append(str(error)))
        page.goto("http://monitor.test/")
        login=page.locator('#login [data-theme-select]')
        assert login.input_value()=="system"
        assert page.locator('html').get_attribute('data-theme')=="dark"
        assert login.locator('option').all_text_contents()==["System","Light","Dark"]
        page.emulate_media(color_scheme="light")
        page.wait_for_function("document.documentElement.dataset.theme === 'light'")
        login.select_option("dark")
        page.emulate_media(color_scheme="light")
        assert page.locator('html').get_attribute('data-theme')=="dark"
        page.reload()
        assert login.input_value()=="dark"
        # Both appearance controls share the same preference.
        page.evaluate("document.querySelector('#login').classList.add('hidden'); document.querySelector('#app').classList.remove('hidden')")
        sidebar=page.locator('aside [data-theme-select]')
        assert sidebar.input_value()=="dark"
        sidebar.select_option("system")
        page.emulate_media(color_scheme="dark")
        page.wait_for_function("document.documentElement.dataset.theme === 'dark'")
        assert login.input_value()=="system"
        page.evaluate("localStorage.setItem('jo-theme', 'invalid')")
        page.reload()
        assert login.input_value()=="system"
        # Storage restrictions must not stop sign-in initialization.
        blocked=browser.new_context(color_scheme="dark")
        blocked.route("http://monitor.test/**",route_app)
        blocked.add_init_script("Storage.prototype.getItem = Storage.prototype.setItem = () => { throw new Error('Blocked storage'); };")
        restricted=blocked.new_page();restricted.on("pageerror",lambda error:errors.append(str(error)))
        restricted.goto("http://monitor.test/")
        restricted.locator('#login [data-theme-select]').select_option("light")
        assert restricted.locator('html').get_attribute('data-theme')=="light"
        assert restricted.locator('#loginForm').is_visible()
        assert not errors,errors
        browser.close()
        print("PASS: System/Light/Dark, OS changes, reload persistence, both controls, invalid preference, blocked storage, no browser errors")


if __name__ == "__main__": check()
