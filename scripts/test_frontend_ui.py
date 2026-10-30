"""Browser regression checks against a deployed UI with isolated API fixtures.

Run in the sandbox browser image, or with Playwright installed. API fixtures
never modify production accounts, scans, model gates, or datasets.
"""
import argparse
import asyncio
import base64
import json
from pathlib import Path

from playwright.async_api import async_playwright


async def run(origin: str, output: str | None) -> dict:
    calls = []
    failures = []
    scan_id = "11111111-1111-4111-8111-111111111111"
    older_id = "22222222-2222-4222-8222-222222222222"
    pending_id = "33333333-3333-4333-8333-333333333333"
    bearer = "fixture.header.signature"
    fixture = {
        "scan_id": scan_id, "status": "risk_fusion_done",
        "url": "https://example.org/<script>alert(1)</script>",
        "risk_score": None,
        "risk_report": {"risk_score": 99, "is_placeholder": True, "reasons": ["Model unavailable"]},
    }

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(args=["--no-sandbox"])
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        page.on("pageerror", lambda error: failures.append(str(error)))
        page.on("console", lambda message: failures.append(message.text) if "Content Security Policy" in message.text else None)

        async def route_api(route):
            request = route.request
            path = request.url.split("/api", 1)[1]
            calls.append({"path": path, "method": request.method, "authorized": request.headers.get("authorization") == f"Bearer {bearer}"})
            if path == "/auth/login":
                assert "username=analyst%40example.test" in request.post_data
                data = {"access_token": bearer}
            elif path == "/scans/full":
                assert json.loads(request.post_data)["url"] == "https://example.org/"
                data = {"scan_id": scan_id, "status": "queued"}
            elif path == f"/scans/{scan_id}":
                data = fixture
            elif path.startswith("/scans?limit=50&offset=0"):
                data = {"items": [{"scan_id": scan_id, "url": "https://example.org/", "status": "risk_fusion_done", "created_at": "2026-10-15T00:00:00Z"}], "next_offset": 50}
            elif path.startswith("/scans?limit=50&offset=50"):
                data = {"items": [{"scan_id": older_id, "url": None, "status": "file_scan_done", "created_at": "2026-10-14T00:00:00Z"}], "next_offset": None}
            elif path.endswith("/browser.png"):
                await route.fulfill(content_type="image/png", body=base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a8VQAAAAASUVORK5CYII="))
                return
            elif "/artifacts/" in path:
                await route.fulfill(status=404, content_type="application/json", body=json.dumps({"detail": "Artifact not found."}))
                return
            elif path == "/email":
                data = {"emails": [{"email_id": "fixture_email", "subject": "Fixture message", "from_address": "sender@example.test", "status": "ingested"}], "total": 1}
            elif path == "/email/investigate":
                assert json.loads(request.post_data) == {"email_id": "fixture_email"}
                data = {"email_id": "fixture_email", "status": "email_analysis_queued"}
            elif path == "/auth/logout":
                await route.fulfill(status=204)
                return
            else:
                raise AssertionError(f"Unexpected API request: {path}")
            await route.fulfill(content_type="application/json", body=json.dumps(data))

        await page.route("**/api/**", route_api)
        base = origin.rstrip("/") + "/dashboard/components/"
        await page.goto(base + "dashboard.html")
        await page.get_by_role("heading", name="Sign in required").wait_for()
        await page.goto(base + "auth.html")
        await page.evaluate("id => { sessionStorage.setItem('scythe_recent_scans', JSON.stringify([id])); sessionStorage.setItem('scythe_email', 'previous@example.test'); }", older_id)
        await page.get_by_label("Email", exact=True).fill("analyst@example.test")
        await page.get_by_label("Password", exact=True).fill("TestOnly!Credential-42")
        await page.get_by_role("button", name="Sign in", exact=True).click()
        await page.get_by_text("Signed in. Open New scan", exact=False).wait_for()
        assert await page.evaluate("localStorage.getItem('scythe_token')") is None
        assert await page.evaluate("sessionStorage.getItem('scythe_recent_scans')") is None
        await page.goto(base + "scan.html")
        await page.get_by_label("URL", exact=True).fill("https://example.org/")
        await page.get_by_label("URL scan mode").select_option("full")
        await page.get_by_role("button", name="Scan URL").click()
        await page.get_by_role("link", name=scan_id, exact=True).click()
        await page.get_by_text("UNKNOWN · model verdict unavailable", exact=True).wait_for()
        await page.get_by_role("button", name="browser.png", exact=True).click()
        await page.locator("img.evidence").wait_for()
        await page.get_by_role("button", name="network.har", exact=True).click()
        await page.get_by_text("Artifact not found.", exact=True).wait_for()
        await page.goto(base + "email.html")
        await page.get_by_role("heading", name="Fixture message").wait_for()
        await page.get_by_role("button", name="Investigate", exact=True).click()
        await page.get_by_text("Investigation queued:", exact=False).wait_for()
        await page.evaluate("ids => sessionStorage.setItem('scythe_recent_scans', JSON.stringify(ids))", [scan_id, pending_id])
        await page.goto(base + "dashboard.html")
        await page.get_by_role("link", name=scan_id, exact=True).wait_for()
        await page.get_by_role("link", name=pending_id, exact=True).wait_for()
        assert await page.get_by_role("link", name=scan_id, exact=True).count() == 1
        # A fresh tab storage session must recover history from the server,
        # rather than relying on locally remembered submission IDs.
        await page.evaluate("sessionStorage.removeItem('scythe_recent_scans')")
        await page.goto(base + "dashboard.html")
        await page.get_by_role("link", name=scan_id, exact=True).wait_for()
        assert await page.evaluate("sessionStorage.getItem('scythe_recent_scans')") is None
        await page.get_by_role("button", name="Load more scans", exact=True).click()
        await page.get_by_role("link", name=older_id, exact=True).wait_for()
        await page.reload()
        await page.get_by_role("link", name=scan_id, exact=True).wait_for()
        await page.goto(base + "settings.html")
        await page.get_by_role("button", name="Sign out and revoke token").click()
        await page.get_by_text("Signed out; the server token was revoked.").wait_for()
        assert await page.evaluate("sessionStorage.getItem('scythe_token')") is None
        await page.go_back(wait_until="domcontentloaded")
        await page.get_by_role("heading", name="Sign in required").wait_for()
        assert await page.get_by_role("link", name=scan_id, exact=True).count() == 0
        assert all(item["authorized"] for item in calls if item["path"] != "/auth/login")
        assert not failures, failures
        await browser.close()
    report = {"passed": True, "api_calls": calls, "browser_errors": failures, "fixture_only": True}
    if output:
        Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://localhost:8443")
    parser.add_argument("--output")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.origin, args.output)), indent=2))
