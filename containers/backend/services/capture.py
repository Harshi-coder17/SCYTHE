"""Bounded server-side HTML capture using a connection pinned to validated DNS."""
import http.client
import logging
import socket
import ssl
from urllib.parse import urldefrag, urljoin, urlsplit


from services.url_policy import FetchTarget, UnsafeURL, resolve_fetch_target

logger = logging.getLogger(__name__)
_MAX_HTML_BYTES = 10 * 1024 * 1024
_TIMEOUT_SECONDS = 10
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _connect_addresses(addresses, port, timeout):
    last_error = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout)
        except OSError as exc:
            last_error = exc
    raise last_error or OSError("No validated addresses are available")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, target: FetchTarget):
        super().__init__(target.hostname, port=target.port, timeout=_TIMEOUT_SECONDS)
        self._addresses = target.addresses

    def connect(self):
        self.sock = _connect_addresses(self._addresses, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: FetchTarget):
        super().__init__(target.hostname, port=target.port, timeout=_TIMEOUT_SECONDS,
                         context=ssl.create_default_context())
        self._addresses = target.addresses

    def connect(self):
        sock = _connect_addresses(self._addresses, self.port, self.timeout)
        try:
            # Preserve SNI/certificate validation for the hostname while the
            # socket connects to the exact IP that passed the public-IP check.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _connection_for(target: FetchTarget):
    return _PinnedHTTPSConnection(target) if target.scheme == "https" else _PinnedHTTPConnection(target)


def fetch_url_html(url: str) -> str:
    """Fetch bounded HTML using only validated, pinned public addresses.

    Each redirect is resolved and validated independently. Connections use the
    exact validated IP; environment HTTP proxies cannot re-resolve the target.
    """
    html_content = ""
    try:
        current_url = url
        for _ in range(5):
            target = resolve_fetch_target(current_url)
            parsed = urlsplit(current_url)
            request_target = parsed.path or "/"
            if parsed.query:
                request_target += "?" + parsed.query
            host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
            default_port = 443 if target.scheme == "https" else 80
            authority = host if target.port == default_port else f"{host}:{target.port}"
            connection = _connection_for(target)
            try:
                connection.request("GET", request_target, headers={
                    "Host": authority, "Accept-Encoding": "identity",
                    "User-Agent": "SCYTHE-Capture/1.0",
                })
                response = connection.getresponse()
                if response.status in _REDIRECT_STATUSES:
                    location = response.getheader("Location")
                    if not location:
                        raise UnsafeURL("redirect did not include a location")
                    current_url = urljoin(current_url, location)
                    continue
                raw_bytes = response.read(_MAX_HTML_BYTES + 1)
                if len(raw_bytes) > _MAX_HTML_BYTES:
                    raise UnsafeURL("HTML response exceeds the capture size limit")
                encoding = response.headers.get_content_charset() or "utf-8"
                try:
                    html_content = raw_bytes.decode(encoding, errors="replace")
                except LookupError:
                    html_content = raw_bytes.decode("utf-8", errors="replace")
                break
            finally:
                connection.close()
        else:
            raise UnsafeURL("too many redirects")
    except UnsafeURL:
        raise
    except (OSError, http.client.HTTPException) as exc:
        logger.warning("capture_url failed to fetch %s: %s", url, exc)
        html_content = "<html><body>URL could not be safely fetched.</body></html>"

    return html_content


class CaptureUnavailable(RuntimeError):
    """An isolated browser could not produce verified capture artifacts."""


def capture_url(url: str, *, include_metadata: bool = False) -> tuple[bytes, str] | tuple[bytes, str, dict]:
    """Capture real page pixels in the isolated sandbox, never in the API.

    The admission service fixes the container shape; the browser uses the
    IP-pinning egress proxy for navigation, redirects and subresources.
    Temporary output is confined to a fresh UUID volume subdirectory.
    """
    import json
    import os
    import shutil
    import urllib.request
    import uuid
    from config import settings

    resolve_fetch_target(url)  # fail before creating a container for private input
    capture_id = str(uuid.uuid4())
    directory = os.path.join(settings.SHARED_DIR, capture_id)
    os.makedirs(directory, mode=0o770)
    os.chmod(directory, 0o770)  # nosec B103 -- isolated scan IPC, shared UID/GID, no world access
    runner = os.environ.get("SANDBOX_RUNNER_URL", "http://scythe_sandbox_runner:8002/detonate")
    payload = json.dumps({"scan_id": capture_id, "target_url": url,
                          "timeout_sec": 60, "mode": "capture"}).encode()
    request = urllib.request.Request(runner, data=payload, method="POST", headers={
        "Content-Type": "application/json",
        "X-Runner-Auth": os.environ.get("SANDBOX_RUNNER_SECRET", settings.SANDBOX_RUNNER_SECRET),
    })
    try:
        # Explicitly bypass environment proxies for this configured internal RPC.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=75) as response:
            result = json.loads(response.read(65537))
        if result.get("status") != "success" or result.get("returncode") != 0:
            raise CaptureUnavailable("Isolated browser capture failed")
        png_path = os.path.join(directory, "capture.png")
        html_path = os.path.join(directory, "capture.html")
        if os.path.getsize(png_path) > 10 * 1024 * 1024 or os.path.getsize(html_path) > _MAX_HTML_BYTES:
            raise CaptureUnavailable("Browser capture exceeds size limits")
        with open(png_path, "rb") as stream:
            png = stream.read()
        with open(html_path, encoding="utf-8", newline="") as stream:
            html = stream.read()
        if not png.startswith(b"\x89PNG\r\n\x1a\n") or not html.strip():
            raise CaptureUnavailable("Browser capture is incomplete")
        if include_metadata:
            metadata_path = os.path.join(directory, "capture_metadata.json")
            if os.path.getsize(metadata_path) > 256 * 1024:
                raise CaptureUnavailable("Browser capture metadata exceeds size limit")
            with open(metadata_path, encoding="utf-8") as stream:
                metadata = json.load(stream)
            _validate_capture_metadata(metadata, url, capture_id, png, html)
            return png, html, metadata
        return png, html
    except CaptureUnavailable:
        raise
    except Exception as exc:
        logger.warning("Isolated capture unavailable: %s", type(exc).__name__)
        raise CaptureUnavailable("Isolated browser capture unavailable; retry shortly") from exc
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _validate_capture_metadata(metadata, requested_url, capture_id, png, html):
    from datetime import datetime
    import hashlib

    if (not isinstance(metadata, dict) or metadata.get("schema_version") != "passive_capture_v1"
            or metadata.get("capture_id") != capture_id or metadata.get("requested_url") != requested_url
            or metadata.get("screenshot_sha256") != hashlib.sha256(png).hexdigest()
            or metadata.get("html_sha256") != hashlib.sha256(html.encode("utf-8")).hexdigest()):
        raise CaptureUnavailable("Browser capture metadata binding failed")
    chain = metadata.get("http_redirect_chain")
    status = metadata.get("navigation_status")
    if (not isinstance(chain, list) or not 1 <= len(chain) <= 20
            or isinstance(status, bool) or not isinstance(status, int) or not 200 <= status < 400):
        raise CaptureUnavailable("Browser capture navigation metadata invalid")
    for value in [metadata.get("final_url"), metadata.get("navigation_response_url"), *chain]:
        if not isinstance(value, str) or len(value) > 8192:
            raise CaptureUnavailable("Browser capture URL metadata invalid")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise CaptureUnavailable("Browser capture URL metadata invalid")
    if urldefrag(chain[-1])[0] != urldefrag(metadata["navigation_response_url"])[0]:
        raise CaptureUnavailable("Browser capture redirect chain binding failed")
    final_status = metadata.get("final_document_status")
    if final_status is not None:
        if (isinstance(final_status, bool) or not isinstance(final_status, int) or not 200 <= final_status < 400
                or not isinstance(metadata.get("final_document_response_url"), str)
                or urldefrag(metadata["final_document_response_url"])[0] != urldefrag(metadata["final_url"])[0]):
            raise CaptureUnavailable("Browser capture final document metadata invalid")
    times = [datetime.fromisoformat(metadata[key].replace("Z", "+00:00")) for key in
             ("capture_started_at", "screenshot_started_at", "capture_completed_at")]
    if any(value.tzinfo is None for value in times) or times != sorted(times):
        raise CaptureUnavailable("Browser capture timestamp metadata invalid")
