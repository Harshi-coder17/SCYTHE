"""Passive isolated browser capture using the same DNS-pinning egress boundary."""
from datetime import datetime, timezone
import hashlib
import json
import os
from urllib.parse import urldefrag
from egress_proxy import start_egress_proxy
from ssrf_guard import is_target_allowed


def capture_metadata(url, final_url, response, capture_id, started, screenshot_started, completed, png, html,
                     final_document_response=None):
    """Bind recorded browser observations to the actual exported bytes."""
    chain = []
    request = response.request
    while request is not None:
        if len(chain) >= 20:
            raise ValueError("Capture redirect metadata exceeds limit")
        chain.append(request.url)
        request = request.redirected_from
    matching_response = (final_document_response is not None
                         and urldefrag(final_document_response.url)[0] == urldefrag(final_url)[0])
    return {"schema_version": "passive_capture_v1", "capture_id": capture_id,
            "requested_url": url, "final_url": final_url,
            "navigation_response_url": response.url, "navigation_status": response.status,
            "navigation_status_scope": "Original goto response, not necessarily final document",
            "final_document_status": final_document_response.status if matching_response else None,
            "final_document_response_url": final_document_response.url if matching_response else None,
            "final_document_status_scope": "Matching main-frame response" if matching_response else "unavailable",
            "http_redirect_chain": list(reversed(chain)),
            "redirect_history_scope": "HTTP redirects for goto response; client-side navigation may follow",
            "capture_started_at": started, "screenshot_started_at": screenshot_started,
            "capture_completed_at": completed,
            "screenshot_sha256": hashlib.sha256(png).hexdigest(),
            "html_sha256": hashlib.sha256(html).hexdigest()}


async def capture_page(url, output_dir, capture_id=None):
    from playwright.async_api import async_playwright
    started = datetime.now(timezone.utc).isoformat()
    if not await is_target_allowed(url):
        raise ValueError("Capture destination is not public HTTP(S)")
    server = await start_egress_proxy(port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-dev-shm-usage", "--disable-quic",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--disable-features=QUIC,HttpsFirstBalancedModeAutoEnable,WebRtcHideLocalIpsWithMdns",
            ])
            try:
                context = await browser.new_context(
                    viewport={"width": 1366, "height": 768}, accept_downloads=False,
                    service_workers="block", proxy={"server": f"http://127.0.0.1:{port}"},
                )
                try:
                    async def guard(route):
                        if await is_target_allowed(route.request.url):
                            await route.continue_()
                        else:
                            await route.abort()
                    await context.route("**/*", guard)
                    page = await context.new_page()
                    document_responses = []
                    def record_response(document_response):
                        request = document_response.request
                        if request.is_navigation_request() and request.frame == page.main_frame:
                            document_responses.append(document_response)
                            del document_responses[:-1]
                    page.on("response", record_response)
                    # Popup navigation must not create a second uncontrolled capture.
                    async def close_popup(popup):
                        await popup.close()
                    context.on("page", close_popup)
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    if response is None or response.status >= 400:
                        raise ValueError("Capture navigation failed")
                    await page.wait_for_timeout(1000)
                    final_url = page.url
                    html = await page.content()
                    if page.url != final_url:
                        raise ValueError("Page navigated while HTML was captured")
                    if len(html.encode("utf-8")) > 10 * 1024 * 1024:
                        raise ValueError("Capture HTML exceeds limit")
                    png_path = os.path.join(output_dir, "capture.png")
                    if not await is_target_allowed(final_url):
                        raise ValueError("Capture final destination is not public HTTP(S)")
                    screenshot_started = datetime.now(timezone.utc).isoformat()
                    await page.screenshot(path=png_path, timeout=5000)
                    if page.url != final_url:
                        raise ValueError("Page navigated while screenshot was captured")
                    completed = datetime.now(timezone.utc).isoformat()
                    final_response = document_responses[-1] if document_responses else None
                    if (final_response is not None
                            and urldefrag(final_response.url)[0] == urldefrag(final_url)[0]
                            and final_response.status >= 400):
                        raise ValueError("Capture final document returned an error")
                    html_path = os.path.join(output_dir, "capture.html")
                    with open(html_path, "w", encoding="utf-8", newline="") as stream:
                        stream.write(html)
                    with open(png_path, "rb") as stream:
                        png = stream.read()
                    metadata = capture_metadata(url, final_url, response, capture_id, started,
                                                screenshot_started, completed, png, html.encode("utf-8"), final_response)
                    metadata_path = os.path.join(output_dir, "capture_metadata.json")
                    with open(metadata_path, "w", encoding="utf-8") as stream:
                        json.dump(metadata, stream, sort_keys=True, allow_nan=False)
                    for path in (png_path, html_path, metadata_path):
                        os.chmod(path, 0o660)  # nosec B103 -- shared scan UID/GID, no world access
                finally:
                    await context.close()
            finally:
                await browser.close()
    finally:
        server.close()
        await server.wait_closed()
