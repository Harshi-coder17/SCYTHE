"""Load the real unpacked extension and verify the explicit auth bridge.

Uses a temporary copy with its origin pointed at an isolated local UI. No
installed browser profile, production token, or extension source is changed.
"""
import argparse
import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from playwright.async_api import async_playwright


async def run(origin: str, extension: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / "extension"
        shutil.copytree(extension, copy)
        (copy / "config.js").write_text(
            f"const SCYTHE_ORIGIN = {json.dumps(origin)};\n"
            "const SCYTHE_CONFIG = Object.freeze({ API_BASE_URL: SCYTHE_ORIGIN, "
            "DASHBOARD_URL: new URL('/dashboard/components/dashboard.html', SCYTHE_ORIGIN).href });\n"
        )
        async with async_playwright() as playwright:
            context = await playwright.chromium.launch_persistent_context(
                str(Path(directory) / "profile"), channel="chromium", headless=False,
                ignore_https_errors=True,
                args=["--no-sandbox", f"--disable-extensions-except={copy}", f"--load-extension={copy}"],
                # Playwright disables extensions by default. Explicitly remove
                # that default so the unpacked MV3 service worker can start.
                ignore_default_args=["--disable-extensions"],
            )
            bearer = "fixture.header.signature"

            async def auth(route):
                if route.request.url.endswith("/login"):
                    await route.fulfill(content_type="application/json", body=json.dumps({"access_token": bearer}))
                else:
                    await route.fulfill(status=204)

            await context.route("**/api/auth/**", auth)
            worker = context.service_workers[0] if context.service_workers else await context.wait_for_event("serviceworker")
            page = await context.new_page()
            await page.goto(origin + "/dashboard/components/auth.html")
            await page.get_by_label("Email", exact=True).fill("analyst@example.test")
            await page.get_by_label("Password", exact=True).fill("TestOnly!Credential-42")
            await page.get_by_role("button", name="Sign in", exact=True).click()
            await page.get_by_text("Signed in. Open New scan", exact=False).wait_for()
            await page.goto(origin + "/dashboard/components/settings.html")
            await page.get_by_role("button", name="Connect signed-in browser extension").click()
            await page.get_by_text("Extension session connected.", exact=True).wait_for()
            stored = await worker.evaluate("chrome.storage.local.get(['scythe_token'])")
            assert stored["scythe_token"] == bearer
            await page.get_by_role("button", name="Sign out and revoke token").click()
            await page.get_by_text("Signed out; the server token was revoked.").wait_for()
            await page.wait_for_timeout(200)
            assert "scythe_token" not in await worker.evaluate("chrome.storage.local.get(['scythe_token'])")
            await context.close()
            print(json.dumps({"passed": True, "real_unpacked_extension": True, "fixture_auth_only": True}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--extension", required=True)
    args = parser.parse_args()
    asyncio.run(run(args.origin.rstrip("/"), args.extension))
