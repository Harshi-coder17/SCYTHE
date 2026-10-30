import json
import hashlib
from unittest.mock import MagicMock, patch

import pytest

from services import capture
from services.url_policy import FetchTarget


def metadata_fixture():
    png, html = b"image-bytes", "<html>real\r\npage</html>"
    metadata = {"schema_version": "passive_capture_v1", "capture_id": "fixture",
                "requested_url": "https://example.com/", "final_url": "https://example.net/login",
                "navigation_response_url": "https://example.net/login", "navigation_status": 200,
                "final_document_status": 200, "final_document_response_url": "https://example.net/login",
                "http_redirect_chain": ["https://example.com/", "https://example.net/login"],
                "capture_started_at": "2026-10-16T00:00:00Z",
                "screenshot_started_at": "2026-10-16T00:00:01Z",
                "capture_completed_at": "2026-10-16T00:00:02Z",
                "screenshot_sha256": hashlib.sha256(png).hexdigest(),
                "html_sha256": hashlib.sha256(html.encode()).hexdigest()}
    return metadata, png, html


def test_metadata_binds_redirects_times_and_exact_artifact_bytes():
    metadata, png, html = metadata_fixture()
    capture._validate_capture_metadata(metadata, "https://example.com/", "fixture", png, html)


@pytest.mark.parametrize("key,value", [
    ("capture_id", "different"), ("requested_url", "https://different.example/"),
    ("screenshot_sha256", "0" * 64), ("html_sha256", "0" * 64),
    ("final_url", "file:///etc/passwd"), ("final_url", "https://user:secret@example.net/"),
    ("navigation_status", True), ("http_redirect_chain", []),
    ("http_redirect_chain", ["https://unrelated.example/"]),
    ("final_document_status", 404), ("final_document_status", True),
    ("final_document_response_url", "https://different.example/"),
    ("http_redirect_chain", ["https://example.com/"] * 21),
    ("capture_completed_at", "2026-10-15T00:00:00Z"),
    ("capture_completed_at", "2026-10-16T00:00:02"),
])
def test_invalid_metadata_never_becomes_verified_capture(key, value):
    metadata, png, html = metadata_fixture()
    metadata[key] = value
    with pytest.raises(capture.CaptureUnavailable):
        capture._validate_capture_metadata(metadata, "https://example.com/", "fixture", png, html)


@pytest.mark.parametrize("include_metadata,corrupt", [(False, False), (True, False), (True, True)])
def test_isolated_capture_uses_fresh_uuid_and_removes_temporary_files(tmp_path, include_metadata, corrupt):
    target = FetchTarget("https", "example.com", 443, ("93.184.216.34",))
    captured = {}
    opener = MagicMock()
    response = opener.open.return_value.__enter__.return_value
    response.read.return_value = b'{"status":"success","returncode":0}'

    def run(request, timeout):
        body = json.loads(request.data)
        captured.update(body)
        directory = tmp_path / body["scan_id"]
        (directory / "capture.png").write_bytes(b"\x89PNG\r\n\x1a\nreal-pixels")
        (directory / "capture.html").write_text("<html>real page</html>")
        metadata, _, _ = metadata_fixture()
        metadata.update({"capture_id": body["scan_id"],
                         "screenshot_sha256": hashlib.sha256((directory / "capture.png").read_bytes()).hexdigest(),
                         "html_sha256": hashlib.sha256((directory / "capture.html").read_bytes()).hexdigest()})
        if corrupt:
            metadata["screenshot_sha256"] = "0" * 64
        (directory / "capture_metadata.json").write_text(json.dumps(metadata))
        return opener.open.return_value

    opener.open.side_effect = run
    with patch.object(capture, "resolve_fetch_target", return_value=target), \
         patch("config.settings.SHARED_DIR", str(tmp_path)), \
         patch("urllib.request.build_opener", return_value=opener):
        if corrupt:
            with pytest.raises(capture.CaptureUnavailable):
                capture.capture_url("https://example.com/", include_metadata=True)
            assert list(tmp_path.iterdir()) == []
            return
        result = capture.capture_url("https://example.com/", include_metadata=include_metadata)
        png, html = result[:2]
        if include_metadata:
            assert result[2]["final_url"] == "https://example.net/login"
        else:
            assert len(result) == 2
    assert captured["mode"] == "capture"
    assert captured["timeout_sec"] == 60
    assert captured["target_url"] == "https://example.com/"
    assert png.startswith(b"\x89PNG") and "real page" in html
    assert list(tmp_path.iterdir()) == []


def test_isolated_capture_errors_are_unavailable_never_placeholder(tmp_path):
    target = FetchTarget("https", "example.com", 443, ("93.184.216.34",))
    opener = MagicMock()
    opener.open.side_effect = TimeoutError()
    with patch.object(capture, "resolve_fetch_target", return_value=target), \
         patch("config.settings.SHARED_DIR", str(tmp_path)), \
         patch("urllib.request.build_opener", return_value=opener):
        with pytest.raises(capture.CaptureUnavailable):
            capture.capture_url("https://example.com/")
    assert list(tmp_path.iterdir()) == []


def test_full_scan_reports_unavailable_capture_without_starting_pipeline():
    from fastapi import HTTPException
    from api.routes import full_scan
    from schemas.full_scan import FullScanRequest
    with patch("api.routes.run_quickscan", return_value={}), \
         patch.object(capture, "capture_url", side_effect=capture.CaptureUnavailable("Unavailable")), \
         patch("api.routes.run_stage2_analysis") as stage2:
        with pytest.raises(HTTPException) as error:
            full_scan(FullScanRequest(url="https://example.com"), db=MagicMock(), current_user=MagicMock())
    assert error.value.status_code == 503
    stage2.assert_not_called()
