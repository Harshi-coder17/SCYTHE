"""Live HTTPS dashboard smoke: disposable accounts, benign URL/file, ownership.

Credentials/tokens remain in memory. Writes only account emails, scan IDs,
statuses and checks; creates no real email and sends no notifications.
Run after rollout, for example:
  python scripts/frontend_workflow_smoke.py --origin https://localhost:8443
Playwright Chromium must be installed (the sandbox image already includes it).
"""
import argparse
import asyncio
import json
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.async_api import async_playwright


async def run(origin: str, target: str, output: str | None) -> dict:
    run_id = secrets.token_hex(6)
    accounts = [f"scythe-ui-{run_id}-{index}@example.test" for index in (1, 2)]
    passwords = [secrets.token_urlsafe(24) + "aA4!" for _ in accounts]
    results = {"run_id": run_id, "accounts_to_disable_after_test": accounts, "scans": [], "checks": {}, "passed": False, "step": "setup"}
    def checkpoint(step):
        results["step"] = step
        if output:
            Path(output).write_text(json.dumps(results, indent=2), encoding="utf-8")
    checkpoint("registration")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(args=["--no-sandbox"])
        context = await browser.new_context(ignore_https_errors=True)
        errors = []
        page = await context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("console", lambda message: errors.append(message.text) if "Content Security Policy" in message.text else None)
        for email, password in zip(accounts, passwords):
            response = await context.request.post(origin + "/api/auth/register", data={"email": email, "password": password})
            assert response.status == 202, f"Registration unavailable: {response.status}"
        base = origin + "/dashboard/components/"
        checkpoint("ui_login")
        await page.goto(base + "auth.html")
        await page.get_by_label("Email", exact=True).fill(accounts[0])
        await page.get_by_label("Password", exact=True).fill(passwords[0])
        await page.get_by_role("button", name="Sign in", exact=True).click()
        await page.get_by_text("Signed in. Open New scan", exact=False).wait_for(timeout=60000)
        bearer = await page.evaluate("sessionStorage.getItem('scythe_token')")
        assert bearer
        assert await page.evaluate("localStorage.getItem('scythe_token')") is None
        results["checks"]["ui_login_session_storage"] = True

        async def wait_report(scan_id):
            end = time.monotonic() + 240
            statuses = []
            completed_samples = 0
            completed_status = None
            while time.monotonic() < end:
                response = await context.request.get(origin + f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {bearer}"})
                assert response.status == 200, f"Owned report unavailable: {response.status}"
                data = await response.json()
                if not statuses or statuses[-1] != data["status"]:
                    statuses.append(data["status"])
                if data.get("risk_report") is not None and data["status"] in {"risk_fusion_done", "file_scan_done"}:
                    completed_samples = completed_samples + 1 if completed_status == data["status"] else 1
                    completed_status = data["status"]
                    if completed_samples < 2:
                        await asyncio.sleep(3)
                        continue
                    is_placeholder = bool(data["risk_report"].get("is_placeholder"))
                    results["scans"].append({"scan_id": scan_id, "statuses": statuses, "final_status": data["status"], "is_placeholder": is_placeholder})
                    return
                completed_samples = 0
                completed_status = None
                if "failed" in data["status"] or "unavailable" in data["status"]:
                    raise AssertionError(f"Scan failed: {data['status']}")
                await asyncio.sleep(3)
            raise AssertionError("Scan report exceeded the 240-second smoke budget")

        checkpoint("full_url_scan")
        await page.goto(base + "scan.html")
        await page.get_by_label("URL", exact=True).fill(target)
        await page.get_by_label("URL scan mode").select_option("full")
        await page.get_by_role("button", name="Scan URL").click()
        link = page.locator("#app section a[href*='report.html?scan_id=']")
        await link.wait_for(timeout=60000)
        await link.click()
        scan_id = parse_qs(urlparse(page.url).query)["scan_id"][0]
        await wait_report(scan_id)
        await page.get_by_role("button", name="Refresh status").click()
        await page.locator("p.status").wait_for(timeout=10000)
        await page.get_by_role("button", name="browser.png", exact=True).click()
        await page.locator("img.evidence").wait_for(timeout=10000)
        results["checks"]["url_scan_progress_unknown_and_evidence"] = True

        checkpoint("file_scan")
        await page.goto(base + "scan.html")
        await page.get_by_label("Choose a file").set_input_files({"name": "scythe-benign-fixture.txt", "mimeType": "text/plain", "buffer": b"SCYTHE benign local workflow fixture.\n"})
        await page.get_by_role("button", name="Scan file", exact=True).click()
        await link.wait_for(timeout=60000)
        await link.click()
        file_id = parse_qs(urlparse(page.url).query)["scan_id"][0]
        await wait_report(file_id)
        results["checks"]["file_async_report"] = True
        await page.goto(base + "dashboard.html")
        await page.get_by_role("link", name=scan_id, exact=True).wait_for()
        await page.get_by_role("link", name=file_id, exact=True).wait_for()
        results["checks"]["session_history"] = True

        checkpoint("fresh_session_history")
        fresh = await browser.new_context(ignore_https_errors=True)
        fresh_page = await fresh.new_page()
        await fresh_page.goto(base + "auth.html")
        await fresh_page.get_by_label("Email", exact=True).fill(accounts[0])
        await fresh_page.get_by_label("Password", exact=True).fill(passwords[0])
        await fresh_page.get_by_role("button", name="Sign in", exact=True).click()
        await fresh_page.get_by_text("Signed in. Open New scan", exact=False).wait_for(timeout=60000)
        assert await fresh_page.evaluate("sessionStorage.getItem('scythe_recent_scans')") is None
        await fresh_page.goto(base + "dashboard.html")
        await fresh_page.get_by_role("link", name=scan_id, exact=True).wait_for()
        await fresh_page.get_by_role("link", name=file_id, exact=True).wait_for()
        await fresh_page.reload()
        await fresh_page.get_by_role("link", name=scan_id, exact=True).wait_for()
        fresh_token = await fresh_page.evaluate("sessionStorage.getItem('scythe_token')")
        await fresh.request.post(origin + "/api/auth/logout", headers={"Authorization": f"Bearer {fresh_token}"})
        await fresh.close()
        results["checks"]["fresh_session_cross_session_history"] = True

        checkpoint("cross_user_isolation")
        response = await context.request.post(origin + "/api/auth/login", form={"username": accounts[1], "password": passwords[1]})
        assert response.status == 200, f"Second login failed: {response.status}"
        other = (await response.json())["access_token"]
        response = await context.request.get(origin + "/api/scans?limit=100&offset=0", headers={"Authorization": f"Bearer {other}"})
        assert response.status == 200
        other_history = await response.json()
        assert not {scan_id, file_id}.intersection(item["scan_id"] for item in other_history["items"]), "Cross-user history must not include another account's scans"
        for identity in (scan_id, file_id):
            response = await context.request.get(origin + f"/api/scans/{identity}", headers={"Authorization": f"Bearer {other}"})
            assert response.status == 404, "Cross-user scan metadata must remain hidden"
            response = await context.request.get(origin + f"/api/scans/{identity}/artifacts/risk_report.json", headers={"Authorization": f"Bearer {other}"})
            assert response.status == 404, "Cross-user evidence must remain hidden"
        results["checks"]["cross_user_isolation"] = True
        await context.request.post(origin + "/api/auth/logout", headers={"Authorization": f"Bearer {other}"})
        checkpoint("logout_revocation")
        await page.goto(base + "settings.html")
        await page.get_by_role("button", name="Sign out and revoke token").click()
        await page.get_by_text("Signed out; the server token was revoked.").wait_for()
        await page.go_back(wait_until="domcontentloaded")
        await page.get_by_role("heading", name="Sign in required").wait_for()
        results["checks"]["back_navigation_after_logout"] = True
        response = await context.request.get(origin + f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {bearer}"})
        assert response.status == 401, "Logged-out token must be revoked"
        results["checks"]["logout_revocation"] = True
        assert not errors, errors
        results.update(passed=True, browser_errors=errors, external_notifications_sent=False)
        checkpoint("complete")
        await browser.close()
    if output:
        Path(output).write_text(json.dumps(results, indent=2), encoding="utf-8")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://localhost:8443")
    parser.add_argument("--url", default="https://example.org/")
    parser.add_argument("--output", default="frontend-workflow-smoke.json")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(run(args.origin.rstrip("/"), args.url, args.output)), indent=2))
    except Exception as error:
        # Playwright action tracebacks can include form values. Preserve only
        # the stage and exception class, never credential-bearing call logs.
        result = json.loads(Path(args.output).read_text()) if Path(args.output).exists() else {}
        result.update(passed=False, failure_type=type(error).__name__, failure="Live UI smoke failed; inspect this stage's service logs.")
        frame = error.__traceback__
        result["failure_locations"] = []
        while frame:
            if Path(frame.tb_frame.f_code.co_filename).name == Path(__file__).name:
                result["failure_locations"].append({"function": frame.tb_frame.f_code.co_name, "line": frame.tb_lineno})
            frame = frame.tb_next
        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        sys.exit(1)
